package hunits

import (
	"testing"
	"time"
)

func TestParseBytes(t *testing.T) {
	cases := map[string]int64{
		"100":     100,
		"1KB":     1000,
		"1KiB":    1024,
		"16MiB":   16 << 20,
		"1.5GB":   1500000000,
		"2GiB":    2 << 30,
		"256MiB":  256 << 20,
		"1M":      1 << 20,
		"10B":     10,
	}
	for in, want := range cases {
		got, err := ParseBytes(in)
		if err != nil || got != want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "12x", "MiB"} {
		if _, err := ParseBytes(bad); err == nil {
			t.Errorf("ParseBytes(%q) should fail", bad)
		}
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"120s":  120 * time.Second,
		"2h":    2 * time.Hour,
		"1m30s": 90 * time.Second,
		"90":    90 * time.Second,
		"15m":   15 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseDuration(""); err == nil {
		t.Error("empty should fail")
	}
	if _, err := ParseDuration("abc"); err == nil {
		t.Error("garbage should fail")
	}
}
