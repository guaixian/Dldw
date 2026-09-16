package tasks

import (
	"sync"
)

// singleflight deduplicates concurrent calls with the same key: the first
// caller executes fn, the rest wait for and share its result (spec 4.3
// "resolve 幂等：同一 cache_key 并发 singleflight").
type singleflight struct {
	mu    sync.Mutex
	calls map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

func newSingleflight() *singleflight { return &singleflight{calls: map[string]*sfCall{}} }

// Do executes fn for key, deduplicating concurrent invocations.
func (g *singleflight) Do(key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &sfCall{}
	c.wg.Add(1)
	g.calls[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	if g.calls[key] == c {
		delete(g.calls, key)
	}
	g.mu.Unlock()
	return c.val, c.err
}

// InFlight reports whether key currently has a running call.
func (g *singleflight) InFlight(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.calls[key]
	return ok
}
