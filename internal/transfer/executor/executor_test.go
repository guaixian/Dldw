package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func TestBuiltinViaUpstreamProxy(t *testing.T) {
	// 源站（回环）：经代理 CONNECT 透传抓取
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"px"`)
		fmt.Fprint(w, "proxied-artifact")
	}))
	defer origin.Close()

	// 本地 HTTP 代理：CONNECT 透传 + 绝对形式转发（模拟 Xray mixed 入站）
	proxyFwd := &http.Transport{Proxy: nil}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			// absolute-form 转发（http URL 经代理的标准行为）
			req, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			req.Header = r.Header.Clone()
			resp, err := proxyFwd.RoundTrip(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return
		}
		hj := w.(http.Hijacker)
		client, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		target, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
		if err != nil {
			client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer target.Close()
		client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		done := make(chan struct{}, 2)
		go func() { io.Copy(target, client); done <- struct{}{} }()
		go func() { io.Copy(client, target); done <- struct{}{} }()
		<-done
	}))
	defer proxy.Close()

	// 端口白名单放行源站端口：上游代理模式下策略仅做本地端口检查，
	// 目标 DNS/SSRF 由代理负责（回环源站因此可达）
	ou, _ := url.Parse(origin.URL)
	oport, _ := strconv.Atoi(ou.Port())
	b := NewBuiltin(BuiltinConfig{
		UpstreamProxy: proxy.URL,
		Policy:        &ssrf.Policy{Ports: []int{oport}},
	})
	res, err := b.Fetch(context.Background(), origin.URL+"/ok/file.zip", t.TempDir(), "file.zip")
	if err != nil {
		t.Fatal(err)
	}
	if res.ETag != "px" || res.Size != int64(len("proxied-artifact")) {
		t.Fatalf("res = %+v", res)
	}

	// 端口白名单在上游代理模式下仍生效（本地拒绝，未出网）
	denied := NewBuiltin(BuiltinConfig{UpstreamProxy: proxy.URL}) // 默认端口 [80,443]
	_, err = denied.Fetch(context.Background(), "http://127.0.0.1:1/file", t.TempDir(), "x")
	if err == nil || !strings.Contains(err.Error(), "E_PORT_DENIED") {
		t.Fatalf("port policy must still apply when proxied, got %v", err)
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
