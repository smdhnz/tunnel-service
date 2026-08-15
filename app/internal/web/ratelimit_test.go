package web

import (
	"testing"
	"time"
)

func TestRateLimiterBlocksAndTemporarilyBlocks(t *testing.T) {
	l := newRateLimiter(1, 0, time.Minute)
	now := time.Now()
	if !l.allow("ip", now) {
		t.Fatal("first denied")
	}
	for i := 0; i < 5; i++ {
		if l.allow("ip", now) {
			t.Fatal("burst allowed")
		}
	}
	if l.allow("ip", now.Add(time.Second)) {
		t.Fatal("temporary block ignored")
	}
}
func TestRateLimiterBoundsEntries(t *testing.T) {
	l := newRateLimiter(1, 1, time.Minute)
	l.maxEntries = 4
	now := time.Now()
	for i := 0; i < 20; i++ {
		l.allow(string(rune('a'+i)), now)
	}
	if len(l.entries) > l.maxEntries {
		t.Fatalf("unbounded entries: %d", len(l.entries))
	}
}
