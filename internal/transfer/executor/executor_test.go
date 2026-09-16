package executor

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"dldw/internal/policy/ssrf"
)

// loopbackPolicy returns a policy that permits the httptest server.
func loopbackPolicy(url string) *ssrf.Policy {
	_, portStr, _ := net.SplitHostPort(url[len("http://"):])
	port, _ := strconv.Atoi(portStr)
	return &ssrf.Policy{AllowLoopback: true, Ports: []int{port}}
}

func TestBuiltinFetch(t *testing.T) {
	payload := []byte("artifact-bytes-0123456789")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok/file.zip":
			w.Header().Set("ETag", `"abc123"`)
			w.Header().Set("Content-Type", "application/zip")
			w.Write(payload)
		case "/boom":
			http.Error(w, "oops", http.StatusInternalServerError)
		case "/notfound":
			http.Error(w, "nope", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	pol := loopbackPolicy(srv.URL)

	b := NewBuiltin(BuiltinConfig{Retries: 1, Policy: pol})
	dir := t.TempDir()

	res, err := b.Fetch(context.Background(), srv.URL+"/ok/file.zip", dir, "file.zip")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(res.LocalPath)
	if string(got) != string(payload) {
		t.Fatalf("content mismatch: %q", got)
	}
	if res.Size != int64(len(payload)) || res.ETag != "abc123" || res.ContentType != "application/zip" {
		t.Fatalf("meta = %+v", res)
	}
	if len(res.SHA256) != 64 {
		t.Fatalf("sha256 = %q", res.SHA256)
	}

	if _, err := b.Fetch(context.Background(), srv.URL+"/notfound", dir, "x"); err == nil {
		t.Fatal("404 should fail")
	}
	if _, err := b.Fetch(context.Background(), srv.URL+"/boom", dir, "y"); err == nil {
		t.Fatal("5xx should fail after retries")
	}
}

func TestBuiltinSSRFLoopbackDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	}))
	defer srv.Close()
	b := NewBuiltin(BuiltinConfig{}) // default policy: loopback denied
	if _, err := b.Fetch(context.Background(), srv.URL+"/f", t.TempDir(), "f"); err == nil {
		t.Fatal("loopback fetch must be denied by SSRF policy")
	}
}

func TestBuiltinMaxBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024))
	}))
	defer srv.Close()
	b := NewBuiltin(BuiltinConfig{MaxBytes: 512, Policy: loopbackPolicy(srv.URL)})
	if _, err := b.Fetch(context.Background(), srv.URL+"/big", t.TempDir(), "big"); err == nil {
		t.Fatal("oversize artifact must fail")
	}
}

func TestBuiltinFilenameSanitized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	}))
	defer srv.Close()
	b := NewBuiltin(BuiltinConfig{Policy: loopbackPolicy(srv.URL)})
	res, err := b.Fetch(context.Background(), srv.URL+"/f", t.TempDir(), "../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(filepath.ToSlash(res.LocalPath))
	if base != "passwd" {
		t.Fatalf("unexpected filename %q", base)
	}
}

func TestBuiltinTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("x"))
	}))
	defer srv.Close()
	b := NewBuiltin(BuiltinConfig{Timeout: 50 * time.Millisecond, Retries: 0, Policy: loopbackPolicy(srv.URL)})
	if _, err := b.Fetch(context.Background(), srv.URL+"/slow", t.TempDir(), "slow"); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"normal.zip": "normal.zip",
		"..":         "",
		".":          "",
		"a/b/c.txt":  "c.txt",
		`..\..\win`:  "win", // basename neutralizes traversal
		"sp ace.zip": "sp_ace.zip",
		"":           "",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeURLForLog(t *testing.T) {
	if got := sanitizeURLForLog("https://x/y?token=secret"); got != "https://x/y?..." {
		t.Fatalf("got %q", got)
	}
	if got := sanitizeURLForLog("https://x/y"); got != "https://x/y" {
		t.Fatalf("got %q", got)
	}
}
