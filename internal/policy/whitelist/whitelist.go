// Package whitelist implements domain matching for the tunnel allowlist.
// Entries are plain domains; matching is exact or on dot boundaries only, so
// "github.com.evil.com" can never match entry "github.com".
package whitelist

import (
	"net"
	"strings"
	"sync"
)

// List is an immutable whitelist; swap whole lists on refresh.
type List struct {
	version string
	exact   map[string]struct{}
	suffix  map[string]struct{} // entries stored WITH leading dot
}

// Parse builds a whitelist from entries. Supported entry forms:
//
//	github.com        -> github.com and any subdomain (a.b.github.com)
//	.GitHub.COM       -> same as above (leading dot tolerated)
//	*.github.com      -> subdomains only
func Parse(version string, entries []string) *List {
	l := &List{
		version: version,
		exact:   make(map[string]struct{}, len(entries)),
		suffix:  make(map[string]struct{}, len(entries)),
	}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		e = strings.TrimSuffix(e, ".")
		if e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(e, "*."):
			d := strings.TrimPrefix(e, "*")
			l.suffix[d] = struct{}{} // ".github.com"
		case strings.HasPrefix(e, "."):
			l.suffix[e] = struct{}{}
			l.exact[strings.TrimPrefix(e, ".")] = struct{}{}
		default:
			l.exact[e] = struct{}{}
			l.suffix["."+e] = struct{}{}
		}
	}
	return l
}

// Version returns the whitelist version tag.
func (l *List) Version() string { return l.version }

// Entries returns the sorted, deduplicated domain entries.
func (l *List) Entries() []string {
	seen := make(map[string]struct{}, len(l.exact)+len(l.suffix))
	out := make([]string, 0, len(seen))
	for d := range l.exact {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	for d := range l.suffix {
		d = strings.TrimPrefix(d, ".")
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	// simple insertion sort, lists are small
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Len reports the number of unique entries.
func (l *List) Len() int { return len(l.Entries()) }

// Match reports whether host is whitelisted. Host may carry a port (ignored)
// and is case-insensitive. IP literals never match: the whitelist is for
// domain names only (IP based tunneling is refused by SSRF policy anyway).
func (l *List) Match(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return false
	}
	if _, ok := l.exact[h]; ok {
		return true
	}
	// suffix entries carry a leading dot, guaranteeing label boundary
	// semantics: "github.com.evil.com" does not end with ".github.com".
	for suf := range l.suffix {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	// tolerate "host:port"
	if hIdx := strings.LastIndex(h, ":"); hIdx >= 0 {
		tail := h[hIdx+1:]
		if isAllDigits(tail) || strings.Contains(h, "]") && hIdx == len(h)-1 {
			// possible ipv6 "[::1]" with no port, or host:port
			if isAllDigits(tail) && !strings.HasPrefix(h, "[") || strings.HasSuffix(h, "]") {
				h = h[:hIdx]
			}
		}
	}
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return h
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Default returns a sensible default whitelist for development.
func Default() *List {
	return Parse("default", []string{
		"github.com",
		"objects.githubusercontent.com",
		"codeload.github.com",
		"raw.githubusercontent.com",
		"github-releases.githubusercontent.com",
		"gist.github.com",
		"api.github.com",
		"files.pythonhosted.org",
		"pypi.org",
		"registry.npmjs.org",
	})
}

// Store provides hot-swappable whitelist access.
type Store struct {
	mu   sync.RWMutex
	list *List
}

func NewStore(l *List) *Store {
	if l == nil {
		l = Parse("empty", nil)
	}
	return &Store{list: l}
}

func (s *Store) Get() *List {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list
}

func (s *Store) Swap(l *List) {
	s.mu.Lock()
	s.list = l
	s.mu.Unlock()
}
