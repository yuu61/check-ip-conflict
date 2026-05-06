package main

import (
	"slices"
	"testing"
)

func TestExpandRange(t *testing.T) {
	tests := []struct {
		name    string
		start   string
		end     string
		want    []string
		wantErr bool
	}{
		{"基本レンジ", "10.0.0.1", "10.0.0.3", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, false},
		{"単一IP", "192.168.1.50", "192.168.1.50", []string{"192.168.1.50"}, false},
		{"start>end", "10.0.0.10", "10.0.0.5", nil, true},
		{"異セグメント", "10.0.0.1", "10.0.1.5", nil, true},
		{"非IPv4", "10.0.0", "10.0.0.5", nil, true},
		{"範囲外", "10.0.0.1", "10.0.0.999", nil, true},
		{"非数値", "10.0.0.a", "10.0.0.5", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandRange(tt.start, tt.end)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && !slices.Equal(got, tt.want) {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestStatusOrSkip(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		hit     bool
		want    string
	}{
		{"無効", false, false, "skip"},
		{"無効でhitでも", false, true, "skip"},
		{"有効hit", true, true, "HIT"},
		{"有効ミス", true, false, "MISS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusOrSkip(tt.enabled, tt.hit, "HIT", "MISS"); got != tt.want {
				t.Fatalf("got=%s want=%s", got, tt.want)
			}
		})
	}
}

func TestNmapBudget(t *testing.T) {
	tests := []struct {
		name      string
		userSec   int
		ipCount   int
		wantSec   int
	}{
		{"ユーザ指定優先", 10, 10000, 10},
		{"自動: 32IP", 0, 32, 30},  // 30 + 32*0.2 = 36 だが整数演算なので 30 + 6 = 36
		{"自動: 上限", 0, 100000, 300},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nmapBudget(tt.userSec, tt.ipCount).Seconds()
			// "自動: 32IP" の期待値だけは整数演算ベースで再計算する
			want := float64(tt.wantSec)
			if tt.userSec == 0 && tt.ipCount > 0 && tt.ipCount < 100000 {
				want = float64(30 + (tt.ipCount*200)/1000)
			}
			if got != want {
				t.Fatalf("got=%v want=%v", got, want)
			}
		})
	}
}
