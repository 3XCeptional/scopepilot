package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// ----------------------------
// TokenBucket tests
// ----------------------------

func TestTokenBucket_Allow(t *testing.T) {
	t.Run("allows burst then blocks", func(t *testing.T) {
		tb := NewTokenBucket(2, 2) // 2 tokens/sec, burst 2

		// Burst of 2 should be allowed immediately.
		if !tb.Allow() {
			t.Error("expected first Allow to return true (burst)")
		}
		if !tb.Allow() {
			t.Error("expected second Allow to return true (burst)")
		}
		// Third call within the same instant should be denied.
		if tb.Allow() {
			t.Error("expected third Allow to return false (rate limited)")
		}
	})

	t.Run("recovers after refill", func(t *testing.T) {
		tb := NewTokenBucket(10, 10)
		// Drain the bucket.
		for i := 0; i < 10; i++ {
			tb.Allow()
		}
		if tb.Allow() {
			t.Fatal("expected Allow to return false after draining")
		}

		// Wait for ~1 token to refill (100ms at 10/sec).
		time.Sleep(110 * time.Millisecond)
		if !tb.Allow() {
			t.Error("expected Allow to return true after refill")
		}
	})

	t.Run("never exceeds capacity", func(t *testing.T) {
		tb := NewTokenBucket(1, 1)
		// Sleep well past one refill interval.
		time.Sleep(500 * time.Millisecond)
		// Should still only have 1 token (capacity cap).
		if !tb.Allow() {
			t.Fatal("expected Allow to return true (burst=1)")
		}
		if tb.Allow() {
			t.Error("expected Allow to return false — capacity cap should prevent hoarding")
		}
	})
}

func TestTokenBucket_AllowN(t *testing.T) {
	t.Run("allows N within burst", func(t *testing.T) {
		tb := NewTokenBucket(5, 5)
		if !tb.AllowN(5) {
			t.Error("expected AllowN(5) to return true (burst=5)")
		}
		if tb.AllowN(1) {
			t.Error("expected AllowN(1) to return false after draining")
		}
	})

	t.Run("denies N larger than burst", func(t *testing.T) {
		tb := NewTokenBucket(5, 5)
		if tb.AllowN(6) {
			t.Error("expected AllowN(6) to return false (> burst)")
		}
	})
}

// ----------------------------
// PerHostLimiter tests
// ----------------------------

func TestPerHostLimiter_Allow(t *testing.T) {
	t.Run("rate limits at 2/s", func(t *testing.T) {
		l := NewPerHostLimiter(2, 2)
		host := "example.com"

		// Burst of 2 should pass.
		if !l.Allow(host) {
			t.Error("expected Allow to return true (burst)")
		}
		if !l.Allow(host) {
			t.Error("expected second Allow to return true (burst)")
		}
		// Third immediately should fail.
		if l.Allow(host) {
			t.Error("expected third Allow to return false")
		}
	})

	t.Run("refills over time", func(t *testing.T) {
		l := NewPerHostLimiter(10, 10)
		host := "example.com"
		// Drain.
		for i := 0; i < 10; i++ {
			l.Allow(host)
		}
		if l.Allow(host) {
			t.Fatal("expected Allow to return false after draining")
		}

		// Wait for ~1 token.
		time.Sleep(110 * time.Millisecond)
		if !l.Allow(host) {
			t.Error("expected Allow to return true after refill")
		}
	})

	t.Run("burst capacity", func(t *testing.T) {
		l := NewPerHostLimiter(5, 3) // 5/sec, but burst only 3
		host := "example.com"

		// Should allow exactly burst=3 immediately.
		for i := 0; i < 3; i++ {
			if !l.Allow(host) {
				t.Fatalf("expected Allow %d to return true (burst)", i+1)
			}
		}
		// Fourth should be denied (burst exhausted).
		if l.Allow(host) {
			t.Error("expected Allow to return false after burst exhausted")
		}
	})

	t.Run("per-host isolation", func(t *testing.T) {
		l := NewPerHostLimiter(1, 1) // 1/sec, burst 1
		hostA := "host-a.com"
		hostB := "host-b.com"

		// Drain host A.
		if !l.Allow(hostA) {
			t.Fatal("expected hostA Allow to return true")
		}
		// Host A should be blocked.
		if l.Allow(hostA) {
			t.Error("expected hostA Allow to return false (rate limited)")
		}
		// Host B should be unaffected.
		if !l.Allow(hostB) {
			t.Error("expected hostB Allow to return true (isolation)")
		}
	})

	t.Run("reset single host", func(t *testing.T) {
		l := NewPerHostLimiter(1, 1)
		host := "example.com"

		l.Allow(host)
		if l.Allow(host) {
			t.Fatal("expected Allow to return false before reset")
		}

		l.Reset(host)
		if !l.Allow(host) {
			t.Error("expected Allow to return true after Reset")
		}
	})

	t.Run("reset all hosts", func(t *testing.T) {
		l := NewPerHostLimiter(1, 1)

		l.Allow("a")
		l.Allow("b")

		l.ResetAll()

		if !l.Allow("a") {
			t.Error("expected Allow to return true for 'a' after ResetAll")
		}
		if !l.Allow("b") {
			t.Error("expected Allow to return true for 'b' after ResetAll")
		}
	})
}

// ----------------------------
// Concurrent access (race detector)
// ----------------------------

func TestPerHostLimiter_ConcurrentAccess(t *testing.T) {
	l := NewPerHostLimiter(100, 100)
	hosts := []string{"alpha", "beta", "gamma", "delta"}
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				host := hosts[j%len(hosts)]
				l.Allow(host)
				if j%10 == 0 {
					l.Reset(host)
				}
				if j%25 == 0 {
					l.ResetAll()
				}
			}
		}()
	}
	wg.Wait()
}

// ----------------------------
// TokenBucket concurrent access
// ----------------------------

func TestTokenBucket_ConcurrentAccess(t *testing.T) {
	tb := NewTokenBucket(1000, 1000)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tb.Allow()
			}
		}()
	}
	wg.Wait()
}

func TestPerHostLimiter_Snapshot(t *testing.T) {
	lim := NewPerHostLimiter(5, 10)

	lim.Allow("host-a")
	lim.Allow("host-a")
	lim.Allow("host-b")

	snap := lim.Snapshot()

	if len(snap) != 2 {
		t.Fatalf("expected 2 hosts in snapshot, got %d", len(snap))
	}

	seen := map[string]bool{}
	for _, hs := range snap {
		seen[hs.Host] = true
		if hs.Capacity != 10 {
			t.Errorf("host %s: expected capacity 10, got %d", hs.Host, hs.Capacity)
		}
		if hs.RatePerSecond != 5 {
			t.Errorf("host %s: expected rate 5, got %f", hs.Host, hs.RatePerSecond)
		}
		if hs.Tokens < 0 || hs.Tokens > float64(hs.Capacity) {
			t.Errorf("host %s: tokens %.1f out of range [0, %d]", hs.Host, hs.Tokens, hs.Capacity)
		}
	}
	if !seen["host-a"] {
		t.Error("expected host-a in snapshot")
	}
	if !seen["host-b"] {
		t.Error("expected host-b in snapshot")
	}
}

func TestPerHostLimiter_Snapshot_TokensDecremented(t *testing.T) {
	lim := NewPerHostLimiter(10, 20)

	lim.Allow("test-host")
	before := lim.Snapshot()
	var bTokens float64
	for _, hs := range before {
		if hs.Host == "test-host" {
			bTokens = hs.Tokens
		}
	}

	lim.Allow("test-host")

	after := lim.Snapshot()
	for _, hs := range after {
		if hs.Host == "test-host" {
			if hs.Tokens >= bTokens {
				t.Errorf("expected tokens to decrease after Allow: before=%f after=%f", bTokens, hs.Tokens)
			}
		}
	}
}
