package openliststore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOpenList 模拟 OpenList 的关键 API 面：登录、mkdir、put、stat、get、
// remove，以及 /d/ 代理下载（Range 透传）。
type fakeOpenList struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
}

func newFakeOpenList(t *testing.T) *fakeOpenList {
	t.Helper()
	f := &fakeOpenList{files: map[string][]byte{}}
	mux := http.NewServeMux()

	api := func(w http.ResponseWriter, r *http.Request) {
		// 统一 JSON envelope 帮手
		ok := func(data any) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": data})
		}
		fail := func(code int, msg string) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"code": code, "message": msg})
		}
		// 除登录外都要求 token
		if r.URL.Path != "/api/auth/login" {
			if r.Header.Get("Authorization") != "tok-fresh" && r.Header.Get("Authorization") != "tok-static" {
				fail(401, "unauthorized")
				return
			}
		}
		switch r.URL.Path {
		case "/api/auth/login":
			var body struct{ Username, Password string }
			json.NewDecoder(r.Body).Decode(&body)
			if body.Username == "admin" && body.Password == "pass" {
				ok(map[string]string{"token": "tok-fresh"})
			} else {
				fail(401, "wrong password")
			}
		case "/api/fs/mkdir":
			ok(nil)
		case "/api/fs/put":
			fp := r.Header.Get("File-Path")
			if fp == "" {
				fail(400, "missing File-Path")
				return
			}
			buf, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.files[fp] = buf
			f.mu.Unlock()
			ok(nil)
		case "/api/fs/stat":
			var body struct{ Path string }
			json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			data, exists := f.files[body.Path]
			f.mu.Unlock()
			if !exists {
				fail(500, "failed get object: object not found")
				return
			}
			ok(map[string]any{"name": "x", "size": len(data), "is_dir": false})
		case "/api/fs/get":
			var body struct{ Path string }
			json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			data, exists := f.files[body.Path]
			f.mu.Unlock()
			if !exists {
				fail(500, "object not found")
				return
			}
			// 模拟无直链驱动：raw_url 为空 -> 驱动应回落到 /d/ 代理
			ok(map[string]any{"name": "x", "size": len(data), "is_dir": false, "raw_url": "", "sign": "s1"})
		case "/api/fs/remove":
			var body struct {
				Dir   string   `json:"dir"`
				Names []string `json:"names"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			for _, n := range body.Names {
				delete(f.files, body.Dir+"/"+n)
			}
			f.mu.Unlock()
			ok(nil)
		case "/api/me":
			ok(map[string]any{"username": "admin"})
		default:
			fail(404, "not implemented")
		}
	}
	mux.HandleFunc("/api/", api)
	// /d/ 代理下载：Range 透传
	mux.HandleFunc("/d/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/d")
		f.mu.Lock()
		data, exists := f.files[p]
		f.mu.Unlock()
		if !exists {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeContent(w, r, "bin", time.Time{}, bytes.NewReader(data))
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestRoundTripLoginMode(t *testing.T) {
	fk := newFakeOpenList(t)
	d, err := New(Config{
		BaseURL:  fk.srv.URL,
		Username: "admin",
		Password: "pass",
		RootPath: "/dldw-cache",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload := bytes.Repeat([]byte("openlist-artifact!"), 64) // 1KB

	// Put（含 mkdir）
	if _, err := d.Put(ctx, "ab/cd/x.bin", bytes.NewReader(payload), int64(len(payload)), "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	fk.mu.Lock()
	stored, ok := fk.files["/dldw-cache/ab/cd/x.bin"]
	fk.mu.Unlock()
	if !ok || !bytes.Equal(stored, payload) {
		t.Fatalf("stored = %d bytes ok=%v", len(stored), ok)
	}

	// Head
	obj, err := d.Head(ctx, "ab/cd/x.bin")
	if err != nil || obj.Size != int64(len(payload)) {
		t.Fatalf("head = %+v %v", obj, err)
	}
	if _, err := d.Head(ctx, "missing"); err == nil {
		t.Fatal("missing should be ErrNotFound")
	}

	// PresignGet：raw_url 为空 -> 回落 /d/ 代理地址
	u, err := d.PresignGet(ctx, "ab/cd/x.bin", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, fk.srv.URL+"/d/dldw-cache/ab/cd/x.bin") || !strings.Contains(u, "sign=s1") {
		t.Fatalf("presigned = %q", u)
	}

	// 通过代理 URL 下载 + Range
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(body, payload) {
		t.Fatalf("get via raw_url: %d len=%d", resp.StatusCode, len(body))
	}
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Range", "bytes=0-15")
	resp2, _ := http.DefaultClient.Do(req)
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusPartialContent || len(b2) != 16 {
		t.Fatalf("range: %d len=%d", resp2.StatusCode, len(b2))
	}

	// Get（流式）
	rc, err := d.Get(ctx, "ab/cd/x.bin")
	if err != nil {
		t.Fatal(err)
	}
	all, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(all, payload) {
		t.Fatal("Get content mismatch")
	}

	// Ping
	if err := d.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	// Delete -> NotFound
	if err := d.Delete(ctx, "ab/cd/x.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Head(ctx, "ab/cd/x.bin"); err == nil {
		t.Fatal("should be gone")
	}
}

func TestDirectRawURLMode(t *testing.T) {
	// 模拟挂载 S3 类驱动：fs/get 直接返回外部直链（另一个 origin）
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct-from-storage")
	}))
	defer origin.Close()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{
				"size": 19, "is_dir": false, "raw_url": origin.URL + "/obj.bin", "sign": "",
			}})
		case "/api/fs/stat":
			json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{
				"name": "x", "size": 19, "is_dir": false}})
		default:
			if r.URL.Path != "/api/auth/login" && r.Header.Get("Authorization") != "tok-static" {
				json.NewEncoder(w).Encode(map[string]any{"code": 401, "message": "unauthorized"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": nil})
		}
	}))
	defer srv.Close()

	d, err := New(Config{BaseURL: srv.URL, Token: "tok-static"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u, err := d.PresignGet(ctx, "aa/bb.bin", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if u != origin.URL+"/obj.bin" {
		t.Fatalf("raw_url passthrough failed: %q", u)
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "direct-from-storage" {
		t.Fatalf("body = %q", body)
	}
}

func TestKeyValidation(t *testing.T) {
	d, err := New(Config{BaseURL: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, bad := range []string{"../../etc/passwd", "A/B", "a b"} {
		if _, err := d.Put(ctx, bad, bytes.NewReader([]byte("x")), 1, ""); err == nil {
			t.Errorf("Put(%q) should fail key validation", bad)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty base_url should fail")
	}
	d, _ := New(Config{BaseURL: "http://x", RootPath: "relative"})
	if d.cfg.RootPath != "/relative" {
		t.Fatalf("root path normalization failed: %q", d.cfg.RootPath)
	}
}
