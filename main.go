package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var macRe = regexp.MustCompile(`[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}`)

type result struct {
	ip           string
	pingOK       bool
	arpMAC       string
	arpingDADHit bool // arping -D で衝突応答を観測
	nmapUp       bool // nmap -sn -PR で Up 判定
}

func main() {
	startIP := flag.String("start", "192.168.255.222", "開始IP")
	endIP := flag.String("end", "192.168.255.254", "終了IP")
	iface := flag.String("i", "", "arpingで使うインターフェース (例: eth0)。未指定なら ip route get から自動推定")
	pingCount := flag.Int("c", 2, "ping回数")
	timeout := flag.Int("w", 1, "ping/arping各回タイムアウト(秒)")
	concurrency := flag.Int("p", 8, "並列数")
	nmapTimeoutSec := flag.Int("nmap-timeout", 0, "nmap全体タイムアウト(秒)。0ならIP数から自動算出")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ips, err := expandRange(*startIP, *endIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, "IPレンジ解析エラー:", err)
		os.Exit(1)
	}

	if *iface == "" {
		if guessed := defaultIface(ctx); guessed != "" {
			*iface = guessed
			fmt.Fprintf(os.Stderr, "[情報] -i 未指定のため %q を自動選択しました\n", *iface)
		}
	}

	hasArping := false
	myMAC := ""
	if *iface != "" {
		if _, err := exec.LookPath("arping"); err == nil {
			myMAC = ifaceMAC(*iface)
			if myMAC == "" {
				fmt.Fprintf(os.Stderr, "[警告] インターフェース %q のMACが取得できないため、arpingをスキップします。\n", *iface)
			} else {
				hasArping = true
			}
		} else {
			fmt.Fprintln(os.Stderr, "[警告] arpingが見つかりません。-D モードはスキップします。")
		}
	}
	hasNmap := false
	if _, err := exec.LookPath("nmap"); err == nil {
		hasNmap = true
	} else {
		fmt.Fprintln(os.Stderr, "[警告] nmapが見つかりません。一括ARPスキャンはスキップします。")
	}

	fmt.Printf("対象: %s - %s (%d IP)\n", *startIP, *endIP, len(ips))
	methods := []string{"ping", "ip neigh"}
	if hasArping {
		methods = append(methods, "arping -D")
	}
	if hasNmap {
		methods = append(methods, "nmap -sn -PR")
	}
	fmt.Printf("方式: %s\n\n", strings.Join(methods, " + "))

	nmapUp := map[string]bool{}
	if hasNmap {
		fmt.Println("[1/2] nmap -sn -PR で一括ARPスキャン中...")
		budget := nmapBudget(*nmapTimeoutSec, len(ips))
		nmapUp, err = nmapScan(ctx, *startIP, *endIP, budget)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[警告] nmap失敗:", err, "(以降の表示では nmap=skip と扱います)")
			hasNmap = false
		} else {
			fmt.Printf("       %d 件 Up を検出\n", len(nmapUp))
		}
		fmt.Println("[2/2] 各IPに対し ping / arping -D を実行...")
	}

	results := make([]result, len(ips))
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	var printMu sync.Mutex

loop:
	for i, ip := range ips {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "[中断] 残りのスキャンをスキップします。")
			break loop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			r := result{ip: ip}
			r.pingOK = ping(ctx, ip, *pingCount, *timeout)
			r.arpMAC = arpLookup(ctx, ip)
			if hasArping {
				r.arpingDADHit = arpingDAD(ctx, ip, *iface, *timeout, myMAC)
			}
			if hasNmap {
				r.nmapUp = nmapUp[ip]
			}
			results[idx] = r

			printMu.Lock()
			fmt.Printf("  %-15s  ping=%-4s  arp=%-17s  arpingD=%-8s  nmap=%s\n",
				r.ip,
				yn(r.pingOK),
				orDash(r.arpMAC),
				statusOrSkip(hasArping, r.arpingDADHit, "CONFLICT", "-"),
				statusOrSkip(hasNmap, r.nmapUp, "OK", "-"),
			)
			printMu.Unlock()
		}(i, ip)
	}
	wg.Wait()

	var used, free []string
	fmt.Println("\n=== 結果 (IP順) ===")
	for _, r := range results {
		if r.ip == "" {
			continue // 中断によりスキャン未実施
		}
		fmt.Printf("  %-15s  ping=%-4s  arp=%-17s  arpingD=%-8s  nmap=%s\n",
			r.ip,
			yn(r.pingOK),
			orDash(r.arpMAC),
			statusOrSkip(hasArping, r.arpingDADHit, "CONFLICT", "-"),
			statusOrSkip(hasNmap, r.nmapUp, "OK", "-"),
		)
		inUse := r.pingOK || r.arpMAC != "" || r.arpingDADHit || r.nmapUp
		if inUse {
			used = append(used, fmt.Sprintf("%s (%s)", r.ip, reasonOf(r)))
		} else {
			free = append(free, r.ip)
		}
	}

	fmt.Printf("\n=== 使用中 (%d) ===\n", len(used))
	for _, s := range used {
		fmt.Println("  " + s)
	}
	fmt.Printf("\n=== 空き候補 (%d) ===\n", len(free))
	sort.Strings(free)
	for _, s := range free {
		fmt.Println("  " + s)
	}
	if !hasArping {
		fmt.Println("\n注意: arping -D 未使用のため、ICMPに応答せずARPキャッシュにも残っていない端末は")
		fmt.Println("      \"空き\" と誤判定されることがあります。可能なら sudo + -i <iface> を付けて再実行してください。")
	}
	if hasNmap && os.Geteuid() != 0 {
		fmt.Println("\nヒント: nmap -sn -PR は L2 ARP プローブを使うため、特権がないとTCP/ICMPフォールバックになります。")
		fmt.Println("        実行時は sudo を推奨します。")
	}
}

func expandRange(start, end string) ([]string, error) {
	sParts := strings.Split(start, ".")
	eParts := strings.Split(end, ".")
	if len(sParts) != 4 || len(eParts) != 4 {
		return nil, errors.New("IPv4形式ではありません")
	}
	for i := range 3 {
		if sParts[i] != eParts[i] {
			return nil, errors.New("最終オクテットのみ可変のレンジを指定してください")
		}
	}
	s, err := strconv.Atoi(sParts[3])
	if err != nil {
		return nil, fmt.Errorf("startの最終オクテットが数値ではありません: %w", err)
	}
	e, err := strconv.Atoi(eParts[3])
	if err != nil {
		return nil, fmt.Errorf("endの最終オクテットが数値ではありません: %w", err)
	}
	if s < 0 || s > 255 || e < 0 || e > 255 {
		return nil, errors.New("最終オクテットは 0-255 の範囲で指定してください")
	}
	if s > e {
		return nil, errors.New("startがendより大きい")
	}
	prefix := strings.Join(sParts[:3], ".") + "."
	out := make([]string, 0, e-s+1)
	for i := s; i <= e; i++ {
		out = append(out, fmt.Sprintf("%s%d", prefix, i))
	}
	return out, nil
}

func ping(ctx context.Context, ip string, count, timeoutSec int) bool {
	// Linux ping のデフォルト送信間隔は 1 秒なので、count*1s + 末尾の応答待ちに余裕を持たせる
	total := time.Duration(count)*time.Second + time.Duration(timeoutSec+2)*time.Second
	cctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ping", "-c", strconv.Itoa(count), "-W", strconv.Itoa(timeoutSec), "-n", "-q", ip)
	return cmd.Run() == nil
}

func arpLookup(ctx context.Context, ip string) string {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ip", "neigh", "show", ip).Output()
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "FAILED") || strings.Contains(line, "INCOMPLETE") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "lladdr" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

// arpingDAD は arping -D (RFC 5227 風の Duplicate Address Detection) を実行し、
// 衝突が観測されたら true を返す。送信元IPは 0.0.0.0 のため、相手側のARPキャッシュを汚染しない。
// 終了コードだけで判定すると、WSL2/Hyper-V vSwitch のように自分のARPプローブが
// 自分自身に反射する環境で全IPを誤って衝突判定してしまうため、出力から応答MACを抽出し、
// 自インターフェースのMAC以外からの応答があったときだけ衝突とみなす。
func arpingDAD(ctx context.Context, ip, iface string, timeoutSec int, myMAC string) bool {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec+2)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "arping", "-D", "-c", "3", "-w", strconv.Itoa(timeoutSec), "-I", iface, ip)
	out, _ := cmd.CombinedOutput()

	for _, m := range macRe.FindAllString(string(out), -1) {
		if !strings.EqualFold(m, myMAC) {
			return true
		}
	}
	return false
}

func ifaceMAC(name string) string {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	return ifc.HardwareAddr.String()
}

// defaultIface は `ip route get 1.1.1.1` の出力から既定の送出インターフェースを推定する。
func defaultIface(ctx context.Context) string {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ip", "-o", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// nmapBudget はユーザ指定が 0 なら IP 数から動的にタイムアウトを算出する (上限 300s)。
func nmapBudget(userSec, ipCount int) time.Duration {
	if userSec > 0 {
		return time.Duration(userSec) * time.Second
	}
	sec := min(30+(ipCount*200)/1000, 300) // 30s + 0.2s × IP数 (上限 300s)
	return time.Duration(sec) * time.Second
}

// nmapScan は -sn -PR で一括ARPスキャンし、Up と判定されたIPのセットを返す。
func nmapScan(ctx context.Context, start, end string, budget time.Duration) (map[string]bool, error) {
	sParts := strings.Split(start, ".")
	eParts := strings.Split(end, ".")
	target := fmt.Sprintf("%s.%s.%s.%s-%s", sParts[0], sParts[1], sParts[2], sParts[3], eParts[3])

	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	out, err := exec.CommandContext(cctx, "nmap", "-sn", "-PR", "-n", "-oG", "-", target).Output()
	if err != nil {
		return nil, err
	}
	up := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Host:") || !strings.Contains(line, "Status: Up") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			up[fields[1]] = true
		}
	}
	return up, nil
}

// statusOrSkip は機能が無効なら "skip"、有効なら hit に応じて hitStr / missStr を返す。
func statusOrSkip(enabled, hit bool, hitStr, missStr string) string {
	if !enabled {
		return "skip"
	}
	if hit {
		return hitStr
	}
	return missStr
}

func yn(b bool) string {
	if b {
		return "OK"
	}
	return "-"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func reasonOf(r result) string {
	var rs []string
	if r.pingOK {
		rs = append(rs, "ping")
	}
	if r.arpMAC != "" {
		rs = append(rs, "arp:"+r.arpMAC)
	}
	if r.arpingDADHit {
		rs = append(rs, "arping-D")
	}
	if r.nmapUp {
		rs = append(rs, "nmap")
	}
	return strings.Join(rs, ",")
}
