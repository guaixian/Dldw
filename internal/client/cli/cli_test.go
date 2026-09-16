package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoTarballURL(t *testing.T) {
	cases := []struct {
		in, wantURL, wantName string
	}{
		{"https://github.com/org/repo", "https://codeload.github.com/org/repo/tar.gz/HEAD", "repo"},
		{"https://github.com/org/repo.git", "https://codeload.github.com/org/repo/tar.gz/HEAD", "repo"},
		{"https://github.com/org/repo/", "https://codeload.github.com/org/repo/tar.gz/HEAD", "repo"},
		{"https://github.com/org/repo/tree/dev", "https://codeload.github.com/org/repo/tar.gz/refs/heads/dev", "repo"},
		{"http://github.com/org/repo", "https://codeload.github.com/org/repo/tar.gz/HEAD", "repo"},
	}
	for _, c := range cases {
		u, n, err := repoTarballURL(c.in)
		if err != nil || u != c.wantURL || n != c.wantName {
			t.Errorf("repoTarballURL(%q) = %q %q %v; want %q %q", c.in, u, n, err, c.wantURL, c.wantName)
		}
	}
	for _, bad := range []string{
		"https://gitlab.com/org/repo",
		"https://github.com/onlyowner",
		"not a url",
	} {
		if _, _, err := repoTarballURL(bad); err == nil {
			t.Errorf("repoTarballURL(%q) should fail", bad)
		}
	}
}

func TestExtractTarGz(t *testing.T) {
	// 构造带顶层目录的 tar.gz（github 形状，内容干净）
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := map[string]string{
		"repo-abc123/README.md":   "hello",
		"repo-abc123/src/main.go": "package main",
	}
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(content))
	}
	tw.WriteHeader(&tar.Header{Name: "repo-abc123/inner", Typeflag: tar.TypeDir})
	tw.Close()
	gz.Close()

	dest := filepath.Join(t.TempDir(), "out")
	if err := extractTarGz(writeTemp(t, buf.Bytes()), dest); err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		rel := strings.TrimPrefix(name, "repo-abc123/")
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil || string(got) != want {
			t.Errorf("extract %s: %q %v", rel, got, err)
		}
	}

	// 含路径穿越的档案必须整体拒绝（fail-closed）
	var evil bytes.Buffer
	egz := gzip.NewWriter(&evil)
	etw := tar.NewWriter(egz)
	etw.WriteHeader(&tar.Header{Name: "repo-x/ok.txt", Mode: 0o644, Size: 2})
	etw.Write([]byte("ok"))
	etw.WriteHeader(&tar.Header{Name: "repo-x/../evil.txt", Typeflag: tar.TypeReg, Size: 5})
	etw.Write([]byte("evil!"))
	etw.Close()
	egz.Close()
	dest2 := filepath.Join(t.TempDir(), "out2")
	if err := extractTarGz(writeTemp(t, evil.Bytes()), dest2); err == nil {
		t.Fatal("archive with traversal entry must be rejected")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest2), "evil.txt")); err == nil {
		t.Fatal("traversal escaped destination!")
	}

	// 空档案报错
	var empty bytes.Buffer
	egz2 := gzip.NewWriter(&empty)
	etw2 := tar.NewWriter(egz2)
	etw2.Close()
	egz2.Close()
	if err := extractTarGz(writeTemp(t, empty.Bytes()), filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("empty archive should fail")
	}
}

func writeTemp(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.tgz")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
