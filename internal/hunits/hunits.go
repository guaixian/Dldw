// Package hunits parses human friendly byte sizes and durations from config
// strings, e.g. "16MiB", "1.5GB", "120s", "2h".
package hunits

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseBytes parses sizes with optional binary (KiB/MiB/GiB) or decimal
// (KB/MB/GB) units. Bare numbers are bytes.
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("hunits: empty size")
	}
	mult := int64(1)
	upper := strings.ToUpper(s)
	suffixes := []struct {
		suf string
		m   int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
		{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40},
		{"B", 1},
	}
	num := s
	for _, sf := range suffixes {
		if strings.HasSuffix(upper, sf.suf) {
			mult = sf.m
			num = s[:len(s)-len(sf.suf)]
			break
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil {
		return 0, fmt.Errorf("hunits: bad size %q", s)
	}
	return int64(f * float64(mult)), nil
}

// ParseDuration accepts Go duration strings ("120s", "2h30m") or bare seconds.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("hunits: empty duration")
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(f * float64(time.Second)), nil
	}
	return 0, fmt.Errorf("hunits: bad duration %q", s)
}
