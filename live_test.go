package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// Tests against the real internet. Run with SNISPLIT_LIVE=1 go test -run Live -v
func TestLiveDoHServers(t *testing.T) {
	if os.Getenv("SNISPLIT_LIVE") == "" {
		t.Skip("set SNISPLIT_LIVE=1 to query the real DoH servers")
	}
	r := newResolver(true)
	ok := 0
	for _, ep := range defaultDoH {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		start := time.Now()
		ips, ttl, err := r.doh(ctx, ep, "store.steampowered.com")
		cancel()
		if err != nil || len(ips) == 0 {
			t.Logf("%-36s FAILED: %v", ep, err) // one provider down is what the list is for
			continue
		}
		ok++
		t.Logf("%-36s %v ttl %d (%d ms)", ep, ips, ttl, time.Since(start).Milliseconds())
	}
	if ok < len(defaultDoH)/2 {
		t.Errorf("only %d of %d DoH servers answer", ok, len(defaultDoH))
	}
}
