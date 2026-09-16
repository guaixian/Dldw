package whitelist

import "testing"

func TestMatch(t *testing.T) {
	l := Parse("t", []string{
		"github.com",
		"*.pypi.org",
		".npmjs.org",
		"# comment line",
		"",
		"Registry.NPMJS.ORG.",
	})

	cases := []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"GITHUB.COM", true},
		{"api.github.com", true},
		{"a.b.github.com", true},
		{"github.com.evil.com", false}, // anti-spoof: must NOT match
		{"evilgithub.com", false},
		{"notgithub.com", false},
		{"github.com:443", true},
		{"pypi.org", false}, // *.pypi.org is subdomains only
		{"files.pypi.org", true},
		{"a.files.pypi.org", true},
		{"files.pypi.org.evil.com", false},
		{"npmjs.org", true}, // ".npmjs.org" includes bare domain
		{"registry.npmjs.org", true},
		{"registry.npmjs.org.", true},
		{"1.2.3.4", false}, // IP literals never match
		{"127.0.0.1", false},
		{"", false},
		{"evil.com", false},
	}
	for _, c := range cases {
		if got := l.Match(c.host); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestEntriesRoundTrip(t *testing.T) {
	l := Parse("t", []string{"github.com", "*.pypi.org"})
	e := l.Entries()
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (%v)", l.Len(), e)
	}
	l2 := Parse("t", e)
	for _, h := range []string{"github.com", "x.pypi.org"} {
		if !l2.Match(h) {
			t.Errorf("round trip lost %q", h)
		}
	}
}

func TestStoreSwap(t *testing.T) {
	s := NewStore(nil)
	if s.Get().Match("github.com") {
		t.Fatal("empty store should not match")
	}
	s.Swap(Parse("v2", []string{"github.com"}))
	if !s.Get().Match("github.com") || s.Get().Version() != "v2" {
		t.Fatal("swap failed")
	}
}
