package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestLimiterBurst(t *testing.T) {
	l := New(1000, 3) // effectively "3 concurrent-ish"
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("allow %d denied", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th allow should be denied at burst 3")
	}
	if !l.Allow("b") {
		t.Fatal("other key should be independent")
	}
}

func TestLimiterRefill(t *testing.T) {
	l := New(100, 1)
	if !l.Allow("k") {
		t.Fatal("first denied")
	}
	if l.Allow("k") {
		t.Fatal("second should be denied")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("should refill at 100/s")
	}
}

func TestCountWindow(t *testing.T) {
	c := NewCount(2, 40*time.Millisecond)
	if !c.Allow("k") || !c.Allow("k") {
		t.Fatal("first two should pass")
	}
	if c.Allow("k") {
		t.Fatal("third should be capped")
	}
	time.Sleep(60 * time.Millisecond)
	if !c.Allow("k") {
		t.Fatal("window should slide")
	}
}

func TestConc(t *testing.T) {
	c := NewConc(2)
	r1, ok := c.Acquire("t")
	if !ok {
		t.Fatal("first acquire failed")
	}
	r2, ok := c.Acquire("t")
	if !ok {
		t.Fatal("second acquire failed")
	}
	if _, ok := c.Acquire("t"); ok {
		t.Fatal("third acquire should fail")
	}
	if _, ok := c.Acquire("other"); !ok {
		t.Fatal("other key acquire failed")
	}
	r2()
	if _, ok := c.Acquire("t"); !ok {
		t.Fatal("acquire after release failed")
	}
	r1()
	// double release must not underflow
	r1()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, ok := c.Acquire("t"); ok {
				r()
			}
		}()
	}
	wg.Wait()
}
