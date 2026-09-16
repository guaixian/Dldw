package gomod

import (
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
	"dldw/internal/transfer/storage/localfs"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

func newFixture(t *testing.T, zip []byte) (*Mirror, *httptest.Server, *tasks.Store, *atomic.Int64) {
	t.Helper()
	tmp := t.TempDir()
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		p := r.URL.EscapedPath()
		switch {
		case strings.HasSuffix(p, ".zip"):
			w.Header().Set("Content-Type", "application/zip")
			w.Write(zip)
		case strings.HasSuffix(p, ".mod"):
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "module github.com/example/mod\n")
		case strings.HasSuffix(p, ".info"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"Version":"v1.0.0"}`)
		case strings.HasSuffix(p, "/@v/list"):
			fmt.Fprint(w, "v1.0.0\nv1.1.0\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)

	stor, err := localfs.New(localfs.Config{
		Root:       filepath.Join(tmp, "objects"),
		PublicBase: "http://mirror.local",
		Secret:     []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	fport := 0
	if i := strings.LastIndexByte(up.URL, ':'); i >= 0 {
		fmt.Sscanf(up.URL[i+1:], "%d", &fport)
	}
	exec := executor.NewBuiltin(executor.BuiltinConfig{
		Policy: &ssrf.Policy{AllowLoopback: true, Ports: []int{fport}},
	})
	store, err := tasks.NewStore(filepath.Join(tmp, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := New(Config{Origin: up.URL}, nil, stor, exec, store, filepath.Join(tmp, "tmp"), time.Minute)
	return m, up, store, &hits
}

func TestImmutableFilesCached(t *testing.T) {
	zip := []byte("fake-module-zip-content")
	m, up, store, hits := newFixture(t, zip)

	mux := http.NewServeMux()
	mux.HandleFunc("/gomod/{path...}", m.ServeHTTP)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	zipURL := srv.URL + "/gomod/github.com/example/mod/@v/v1.0.0.zip"

	// 首次：入库 -> 302
	resp, err := client.Get(zipURL)
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

	// 任务 ready（family=go-module）
	canonical := up.URL + "/github.com/example/mod/@v/v1.0.0.zip"
	task, err := store.GetByCacheKey(urlcanon.CacheKey(canonical, "go-module"))
	if err != nil || task.Status != tasks.StatusReady || task.Artifact.Size != int64(len(zip)) {
		t.Fatalf("task = %+v err=%v", task, err)
	}

	// 二次不再回源
	h := hits.Load()
	resp2, _ := client.Get(zipURL)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("second: %d", resp2.StatusCode)
	}
	if hits.Load() > h {
		t.Fatalf("origin re-fetched: %d > %d", hits.Load(), h)
	}

	// .mod 同样缓存
	resp3, _ := client.Get(srv.URL + "/gomod/github.com/example/mod/@v/v1.0.0.mod")
	io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("mod: %d", resp3.StatusCode)
	}
}

func TestDynamicPathsPassthrough(t *testing.T) {
	m, _, _, _ := newFixture(t, []byte("z"))

	mux := http.NewServeMux()
	mux.HandleFunc("/gomod/{path...}", m.ServeHTTP)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/gomod/github.com/example/mod/@v/list")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "v1.0.0") {
		t.Fatalf("list passthrough: %d %s", resp.StatusCode, body)
	}

	// 转义路径保持原样（大写模块名的 ! 转义）
	resp2, _ := http.Get(srv.URL + "/gomod/github.com/Example!Mod/@v/list")
	io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("escaped module path: %d", resp2.StatusCode)
	}
}
