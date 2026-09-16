package webmirror

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dldw/internal/policy/ssrf"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/storage/localfs"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

type fixture struct {
	up    *httptest.Server // fake 上游（deb 仓库形状）
	stor  storage.Storage
	exec  executor.Executor
	store *tasks.Store
	hits  atomic.Int64
	tmp   string
}

func newFixture(t *testing.T, deb []byte) *fixture {
	t.Helper()
	f := &fixture{tmp: t.TempDir()}
	f.up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		switch {
		case strings.HasSuffix(r.URL.Path, ".deb"):
			w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
			w.Write(deb)
		case strings.Contains(r.URL.Path, "dists/") || strings.Contains(r.URL.Path, "repodata/"):
			// 仓库元数据（含 InRelease/Release/Packages.gz/repomd.xml 等）
			fmt.Fprintf(w, "metadata:%s\n", r.URL.Path)
		case strings.Contains(r.URL.Path, "/by-hash/"):
			w.Write(deb)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.up.Close)

	stor, err := localfs.New(localfs.Config{
		Root:       filepath.Join(f.tmp, "objects"),
		PublicBase: "http://mirror.local",
		Secret:     []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.stor = stor
	fport := 0
	if i := strings.LastIndexByte(f.up.URL, ':'); i >= 0 {
		fmt.Sscanf(f.up.URL[i+1:], "%d", &fport)
	}
	f.exec = executor.NewBuiltin(executor.BuiltinConfig{
		Policy: &ssrf.Policy{AllowLoopback: true, Ports: []int{fport}},
	})
	store, err := tasks.NewStore(filepath.Join(f.tmp, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	return f
}

func (f *fixture) mirror() *Mirror {
	return New(Config{}, nil, f.stor, f.exec, f.store, filepath.Join(f.tmp, "tmp"), time.Minute)
}

func TestDebCached(t *testing.T) {
	deb := bytes.Repeat([]byte("fake-deb!"), 100)
	f := newFixture(t, deb)
	m := f.mirror()

	mux := http.NewServeMux()
	mux.HandleFunc("/mirror/{scheme}/{host}/{path...}", m.ServeHTTP)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := strings.TrimPrefix(f.up.URL, "http://")
	url := srv.URL + "/mirror/http/" + host + "/debian/pool/main/x/x_1.0_amd64.deb"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 首次：抓取入库 -> 302
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first: %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "http://mirror.local/files/") {
		t.Fatalf("location: %q", resp.Header.Get("Location"))
	}

	// 任务 ready、二次不再回源
	canonical := f.up.URL + "/debian/pool/main/x/x_1.0_amd64.deb"
	task, err := f.store.GetByCacheKey(cacheKeyFor(t, canonical, "generic-static"))
	if err != nil || task.Status != tasks.StatusReady || task.Artifact.Size != int64(len(deb)) {
		t.Fatalf("task = %+v err=%v", task, err)
	}
	hits := f.hits.Load()
	resp2, _ := client.Get(url)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("second: %d", resp2.StatusCode)
	}
	if f.hits.Load() > hits {
		t.Fatalf("origin re-fetched: %d > %d", f.hits.Load(), hits)
	}
}

func TestMetadataPassthrough(t *testing.T) {
	f := newFixture(t, []byte("x"))
	m := f.mirror()
	mux := http.NewServeMux()
	mux.HandleFunc("/mirror/{scheme}/{host}/{path...}", m.ServeHTTP)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := strings.TrimPrefix(f.up.URL, "http://")
	resp, err := http.Get(srv.URL + "/mirror/http/" + host + "/debian/dists/bookworm/Release")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "metadata:") {
		t.Fatalf("release passthrough: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Dldw-Cache") != "" {
		t.Fatal("passthrough must not be marked cached")
	}

	// by-hash 路径走缓存（302）
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp2, _ := client.Get(srv.URL + "/mirror/http/" + host + "/debian/dists/bookworm/by-hash/sha256/abc123")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("by-hash should cache: %d", resp2.StatusCode)
	}

	// !! 元数据即使带压缩扩展名也必须透传（防止 apt 拿到过期索引）
	for _, meta := range []string{
		"/debian/dists/bookworm/main/binary-amd64/Packages.gz",
		"/debian/dists/bookworm/main/binary-amd64/Packages.xz",
		"/debian/dists/bookworm/InRelease",
		"/debian/dists/bookworm/Release",
		"/debian/dists/bookworm/Release.gpg",
	} {
		resp3, err := http.Get(srv.URL + "/mirror/http/" + host + meta)
		if err != nil {
			t.Fatal(err)
		}
		resp3.Body.Close()
		if resp3.StatusCode != http.StatusOK {
			t.Errorf("metadata %s should passthrough (200), got %d", meta, resp3.StatusCode)
		}
	}
	// yum repodata 透传（上游 404 透传，但不能是 302 缓存）
	resp4, _ := client.Get(srv.URL + "/mirror/http/" + host + "/centos/8/BaseOS/x86_64/os/repodata/repomd.xml")
	resp4.Body.Close()
	if resp4.StatusCode == http.StatusFound {
		t.Fatal("repodata must passthrough, not cache")
	}
}

func TestHostAllowlist(t *testing.T) {
	f := newFixture(t, []byte("x"))
	origin := strings.TrimPrefix(f.up.URL, "http://")
	m := New(Config{AllowedHosts: []string{"allowed.example"}}, nil, f.stor, f.exec, f.store, f.tmp, time.Minute)
	mux := http.NewServeMux()
	mux.HandleFunc("/mirror/{scheme}/{host}/{path...}", m.ServeHTTP)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/mirror/http/" + origin + "/debian/pool/x.deb")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlist: %d", resp.StatusCode)
	}
	resp2, _ := http.Get(srv.URL + "/mirror/http/allowed.example/debian/pool/x.deb")
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusForbidden {
		t.Fatal("allowed host should pass")
	}

	// 子域匹配
	resp3, _ := http.Get(srv.URL + "/mirror/http/cdn.allowed.example/debian/pool/x.deb")
	resp3.Body.Close()
	if resp3.StatusCode == http.StatusForbidden {
		t.Fatal("subdomain should pass")
	}
}

func TestBadPaths(t *testing.T) {
	f := newFixture(t, []byte("x"))
	m := f.mirror()
	mux := http.NewServeMux()
	mux.HandleFunc("/mirror/{scheme}/{host}/{path...}", m.ServeHTTP)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, u := range []string{
		srv.URL + "/mirror/ftp/x/p",
		srv.URL + "/mirror/http/127.0.0.1/p",
		srv.URL + "/mirror/http/localhost/p",
	} {
		resp, _ := http.Get(u)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s -> %d", u, resp.StatusCode)
		}
	}
}

func cacheKeyFor(t *testing.T, canonical, family string) string {
	t.Helper()
	return urlcanon.CacheKey(canonical, family)
}
