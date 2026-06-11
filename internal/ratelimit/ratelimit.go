// Package ratelimit provides per-host and token-bucket rate limiting.
package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket implements a simple token-bucket rate limiter.
type TokenBucket struct {
	capacity int
	tokens   float64
	rate     float64 // tokens per second
	last     time.Time
	mu       sync.Mutex
}

// NewTokenBucket creates a new TokenBucket with the given rate (tokens/sec)
// and burst capacity. Burst is the maximum number of tokens that can
// accumulate.
func NewTokenBucket(rate, burst int) *TokenBucket {
	now := time.Now()
	return &TokenBucket{
		capacity: burst,
		tokens:   float64(burst),
		rate:     float64(rate),
		last:     now,
	}
}

// Allow reports whether one token can be consumed without exceeding the
// rate limit. It refills the bucket based on elapsed time before checking.
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN reports whether n tokens can be consumed without exceeding the
// rate limit. It refills the bucket based on elapsed time before checking.
func (tb *TokenBucket) AllowN(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Refill based on elapsed time.
	elapsed := time.Since(tb.last).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > float64(tb.capacity) {
		tb.tokens = float64(tb.capacity)
	}
	tb.last = time.Now()

	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}

// PerHostLimiter provides per-host rate limiting by managing a separate
// token bucket for each host.
type PerHostLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*tokenBucket
	rate    int
	burst   int
}

// tokenBucket is an unexported alias used internally by PerHostLimiter.
type tokenBucket TokenBucket

// NewPerHostLimiter creates a new PerHostLimiter that allows ratePerSec
// tokens per second per host, with a burst capacity of burst tokens.
func NewPerHostLimiter(ratePerSec, burst int) *PerHostLimiter {
	return &PerHostLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    ratePerSec,
		burst:   burst,
	}
}

// Allow is a shorthand for AllowN(host, 1).
func (l *PerHostLimiter) Allow(host string) bool {
	return l.AllowN(host, 1)
}

// AllowN reports whether n tokens can be consumed by the given host
// without exceeding the per-host rate limit. A bucket for the host is
// created lazily on first access.
func (l *PerHostLimiter) AllowN(host string, n int) bool {
	b := l.getOrCreateBucket(host)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Refill based on elapsed time.
	elapsed := time.Since(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}
	b.last = time.Now()

	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return true
	}
	return false
}

// HostSnapshot contains rate-limit state for a single host.
type HostSnapshot struct {
	Host          string  `json:"host"`
	Tokens        float64 `json:"tokens"`
	Capacity      int     `json:"capacity"`
	RatePerSecond float64 `json:"rate_per_second"`
}

// Snapshot returns a slice of per-host state read under the limiter's lock.
func (l *PerHostLimiter) Snapshot() []HostSnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()

	states := make([]HostSnapshot, 0, len(l.buckets))
	for host, tb := range l.buckets {
		tb.mu.Lock()
		states = append(states, HostSnapshot{
			Host:          host,
			Tokens:        tb.tokens,
			Capacity:      tb.capacity,
			RatePerSecond: tb.rate,
		})
		tb.mu.Unlock()
	}
	return states
}

// getOrCreateBucket returns the token bucket for the given host, creating
// one if it does not exist.
func (l *PerHostLimiter) getOrCreateBucket(host string) *tokenBucket {
	l.mu.RLock()
	b, ok := l.buckets[host]
	l.mu.RUnlock()
	if ok {
		return b
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check inside write lock.
	if b, ok := l.buckets[host]; ok {
		return b
	}

	now := time.Now()
	b = &tokenBucket{
		capacity: l.burst,
		tokens:   float64(l.burst),
		rate:     float64(l.rate),
		last:     now,
	}
	l.buckets[host] = b
	return b
}

// Reset removes the token bucket for the given host, effectively resetting
// its rate limit on the next Allow/AllowN call.
func (l *PerHostLimiter) Reset(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, host)
}

// ResetAll removes all per-host token buckets.
func (l *PerHostLimiter) ResetAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*tokenBucket)
}
