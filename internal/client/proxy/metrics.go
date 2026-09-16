package proxy

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Metrics tracks proxy activity for doctor/benchmark and debugging.
type Metrics struct {
	Connections  atomic.Int64
	TunnelConns  atomic.Int64
	DirectConns  atomic.Int64
	HTTPSConns   atomic.Int64
	HTTPReqs     atomic.Int64
	Errors       atomic.Int64
	BytesIn      atomic.Int64 // client -> remote
	BytesOut     atomic.Int64 // remote -> client
	ActiveConns  atomic.Int64

	mu    sync.Mutex
	hosts map[string]int64
}

func NewMetrics() *Metrics { return &Metrics{hosts: map[string]int64{}} }

func (m *Metrics) addHost(host string, n int64) {
	if m == nil || host == "" || n <= 0 {
		return
	}
	m.mu.Lock()
	m.hosts[host] += n
	m.mu.Unlock()
}

// TopHosts returns the top N hosts by connection count.
func (m *Metrics) TopHosts(n int) []HostCount {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	out := make([]HostCount, 0, len(m.hosts))
	for h, c := range m.hosts {
		out = append(out, HostCount{Host: h, Count: c})
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// HostCount is one entry of TopHosts.
type HostCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// Snapshot renders current counters.
func (m *Metrics) Snapshot() map[string]any {
	if m == nil {
		return nil
	}
	return map[string]any{
		"connections":   m.Connections.Load(),
		"tunnel_conns":  m.TunnelConns.Load(),
		"direct_conns":  m.DirectConns.Load(),
		"https_conns":   m.HTTPSConns.Load(),
		"http_requests": m.HTTPReqs.Load(),
		"errors":        m.Errors.Load(),
		"bytes_in":      m.BytesIn.Load(),
		"bytes_out":     m.BytesOut.Load(),
		"active":        m.ActiveConns.Load(),
	}
}
