package urlcanon

import "testing"

func TestCanonicalize(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "HTTPS://GitHub.COM:443/org/repo/releases/download/v1/app.tar.gz?x=1#frag",
			want: "https://github.com/org/repo/releases/download/v1/app.tar.gz?x=1"},
		{in: "http://example.com:80/a", want: "http://example.com/a"},
		{in: "http://example.com:8080/a", want: "http://example.com:8080/a"},
		{in: "https://example.com.", want: "https://example.com/"},
		{in: "https://user:pass@example.com/a", want: "https://example.com/a"},
		{in: "https://example.com", want: "https://example.com/"},
		{in: "https://example.com/a/../b", want: "https://example.com/a/../b"}, // path preserved verbatim
		{in: "ftp://example.com/a", wantErr: true},
		{in: "", wantErr: true},
		{in: "https:///nohost", wantErr: true},
		{in: "https://example.com:bad/a", wantErr: true},
		{in: "https://[2606:50c0:8000::153]:443/a", want: "https://[2606:50c0:8000::153]/a"},
	}
	for _, c := range cases {
		got, err := Canonicalize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Canonicalize(%q) expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Canonicalize(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCacheKeyStable(t *testing.T) {
	c1, _ := Canonicalize("HTTPS://GitHub.COM/org/repo/releases/download/v1/app.tar.gz")
	c2, _ := Canonicalize("https://github.com/org/repo/releases/download/v1/app.tar.gz")
	if c1 != c2 {
		t.Fatalf("canonical mismatch: %q vs %q", c1, c2)
	}
	k1 := CacheKey(c1, FamilyGithubRelease)
	k2 := CacheKey(c2, FamilyGithubRelease)
	if k1 != k2 {
		t.Fatalf("cache key not stable: %s vs %s", k1, k2)
	}
	if len(k1) != 64 {
		t.Fatalf("cache key should be sha256 hex, got len %d", len(k1))
	}
}

func TestClassifyFamily(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://github.com/org/repo/releases/download/v1/app.tar.gz", FamilyGithubRelease},
		{"https://github.com/org/repo/archive/refs/tags/v1.tar.gz", FamilyGithubRelease},
		{"https://objects.githubusercontent.com/github-production-release/x.zip?token=1", FamilyGithubRelease},
		{"https://github.com/org/repo", ""},
		{"https://files.pythonhosted.org/packages/ab/numpy.whl", FamilyPyPIFile},
		{"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", FamilyNpmTarball},
		{"https://production.cloudflare.docker.com/layer-blobs/sha256:abc", FamilyDockerBlob},
		{"https://example.com/files/data.tar.gz", FamilyGenericStatic},
		{"https://example.com/api/v1/items", ""},
		{"https://example.com/APP.EXE", FamilyGenericStatic},
	}
	for _, c := range cases {
		canonical, family, key, err := FamilyOfRaw(c.url)
		if err != nil {
			t.Fatalf("FamilyOfRaw(%q): %v", c.url, err)
		}
		if family != c.want {
			t.Errorf("FamilyOfRaw(%q) family = %q, want %q", c.url, family, c.want)
		}
		if (family == "") != (key == "") {
			t.Errorf("FamilyOfRaw(%q): family/key mismatch %q/%q", c.url, family, key)
		}
		if canonical == "" {
			t.Errorf("FamilyOfRaw(%q): empty canonical", c.url)
		}
	}
}

func TestHostPort(t *testing.T) {
	h, p, err := HostPort("https://github.com/a/b")
	if err != nil || h != "github.com" || p != "443" {
		t.Fatalf("got %q %q %v", h, p, err)
	}
	h, p, err = HostPort("http://example.com:8080/a")
	if err != nil || h != "example.com" || p != "8080" {
		t.Fatalf("got %q %q %v", h, p, err)
	}
}
