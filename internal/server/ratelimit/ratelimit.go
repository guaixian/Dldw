// Package ratelimit provides key based token bucket rate limiting and
// concurrency caps used by the API and tunnel (spec 5: per IP/device/token/
// host/task creation/tunnel concurrency).
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a token bucket keyed by arbitrary strings (IP, token id, host...).
// rate is tokens per second, burst is bucket capacity. Not safe to reconfigure
// after use; safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   int
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func New(rate float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

// Allow consumes one token for key, reporting whether it was available.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 65536 {
		l.gcLocked(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst), last: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rate
			if b.tokens > float64(l.burst) {
				b.tokens = float64(l.burst)
			}
		}
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *Limiter) gcLocked(now time.Time) {
	// Drop buckets that have fully refilled (idle >= burst/rate) or are stale.
	idle := time.Duration(float64(l.burst)/l.rate*1.5) * time.Second
	if idle < time.Minute {
		idle = time.Minute
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, k)
		}
	}
}

// Count counts events per key over a sliding window of size window. Used for
// e.g. "N tasks per token per hour".
type Count struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	events map[string][]time.Time
}

func NewCount(max int, window time.Duration) *Count {
	return &Count{max: max, window: window, events: map[string][]time.Time{}}
}

// Allow records an event for key if under the cap.
func (c *Count) Allow(key string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) > 65536 {
		for k, v := range c.events {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > c.window {
				delete(c.events, k)
			}
		}
	}
	evs := c.events[key]
	keep := evs[:0]
	for _, t := range evs {
		if now.Sub(t) <= c.window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= c.max {
		c.events[key] = keep
		return false
	}
	c.events[key] = append(keep, now)
	return true
}

// Conc caps concurrent holders per key (e.g. tunnel connections per token).
type Conc struct {
	mu  sync.Mutex
	max int
	cur map[string]int
}

func NewConc(max int) *Conc {
	if max < 1 {
		max = 1
	}
	return &Conc{max: max, cur: map[string]int{}}
}

// Acquire increments the counter for key. The returned release func must be
// called when done; ok is false when the cap is exceeded (no release needed).
func (c *Conc) Acquire(key string) (release func(), ok bool) {
	c.mu.Lock()
	if c.cur[key] >= c.max {
		c.mu.Unlock()
		return nil, false
	}
	c.cur[key]++
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.cur[key]--
			if c.cur[key] <= 0 {
				delete(c.cur, key)
			}
			c.mu.Unlock()
		})
	}, true
}
