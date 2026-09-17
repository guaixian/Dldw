package npm

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
	reg   *httptest.Server // fake registry.npmjs.org
	stor  storage.Storage
	exec  executor.Executor
	store *tasks.Store
	hits  atomic.Int64
	tmp   string
}

func newFixture(t *testing.T, tgz []byte) *fixture {
	t.Helper()
	f := &fixture{tmp: t.TempDir()}
	f.reg = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(tgz)
			return
		}
		// 元数据（完整与 corgi 精简同构）；真实 registry 的 tarball 链接
		// 中 scope 为未编码形式（@scope/tools/-/tools-1.0.0.tgz）
		pkg := strings.TrimPrefix(r.URL.Path, "/")
		base := pkg
		if i := strings.LastIndexByte(pkg, '/'); i >= 0 {
			base = pkg[i+1:]
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name":%q,"versions":{"1.0.0":{"dist":{"tarball":"%s/%s/-/%s-1.0.0.tgz"}}}}`,
			pkg, f.reg.URL, pkg, base)
	}))
	t.Cleanup(f.reg.Close)

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
	if i := strings.LastIndexByte(f.reg.URL, ':'); i >= 0 {
		fmt.Sscanf(f.reg.URL[i+1:], "%d", &fport)
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
	return New(Config{RegistryOrigin: f.reg.URL, PublicBase: "http://127.0.0.1:18080", TmpDir: filepath.Join(f.tmp, "tmp")}, f.stor, f.exec, f.store)
}

func TestMetadataRewriteAndCache(t *testing.T) {
	f := newFixture(t, []byte("tgz-bytes"))
	m := f.mirror()

	mux := http.NewServeMux()
	mux.HandleFunc("/npm/{pkg}", func(w http.ResponseWriter, r *http.Request) {
		m.ServeMetadata(w, r, nil)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/npm/left-pad")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Dldw-Cache") != "miss" {
		t.Fatalf("first: %d %v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(string(body), "http://127.0.0.1:18080/npm/tarball/left-pad/-/left-pad-1.0.0.tgz") {
		t.Fatalf("tarball not rewritten: %s", body)
	}
	if strings.Contains(string(body), f.reg.URL) {
		t.Fatalf("origin leaked: %s", body)
	}

	// scope 包（请求 %2F 编码，Go mux 解码为 @scope/tools；元数据内为未编码）
	resp2, _ := http.Get(srv.URL + "/npm/%40scope%2Ftools")
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 || !strings.Contains(string(body2), "/npm/tarball/@scope/tools/-/tools-1.0.0.tgz") {
		t.Fatalf("scoped pkg: %d %s", resp2.StatusCode, body2)
	}
	if strings.Contains(string(body2), f.reg.URL) {
		t.Fatalf("origin leaked: %s", body2)
	}

	// 命中缓存（元数据不再回源）
	resp3, _ := http.Get(srv.URL + "/npm/left-pad")
	io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.Header.Get("X-Dldw-Cache") != "hit" {
		t.Fatalf("cache header: %v", resp3.Header.Get("X-Dldw-Cache"))
	}

	// 非法名
	resp4, _ := http.Get(srv.URL + "/npm/..%2Fetc")
	resp4.Body.Close()
	if resp4.StatusCode != 400 {
		t.Fatalf("bad name: %d", resp4.StatusCode)
	}
}

func TestTarballFlow(t *testing.T) {
	tgz := bytes.Repeat([]byte("tgz!"), 500) // 2KB
	f := newFixture(t, tgz)
	m := f.mirror()

	mux := http.NewServeMux()
	mux.HandleFunc("/npm/tarball/{path...}", m.ServeTarball)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	url := srv.URL + "/npm/tarball/left-pad/-/left-pad-1.0.0.tgz"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 首次：抓取入库 -> 302 预签名
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first: %d body=%s", resp.StatusCode, b)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "http://mirror.local/files/") {
		t.Fatalf("location: %q", resp.Header.Get("Location"))
	}
	if f.hits.Load() < 1 {
		t.Fatalf("origin hits = %d", f.hits.Load())
	}

	// 任务登记 ready（dldw get 同 URL 命中）
	canonical, _ := urlcanon.Canonicalize(f.reg.URL + "/left-pad/-/left-pad-1.0.0.tgz")
	key := urlcanon.CacheKey(canonical, urlcanon.FamilyNpmTarball)
	task, err := f.store.GetByCacheKey(key)
	if err != nil || task.Status != tasks.StatusReady || task.Artifact == nil || task.Artifact.Size != int64(len(tgz)) {
		t.Fatalf("task = %+v err=%v", task, err)
	}

	// 二次：不再回源
	hitsBefore := f.hits.Load()
	resp2, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("second: %d body=%s", resp2.StatusCode, body2)
	}
	// 元数据计数 +1 是允许的（这里没请求元数据），tgz 不应重复抓取
	time.Sleep(50 * time.Millisecond)
	if f.hits.Load() > hitsBefore {
		t.Fatalf("origin re-fetched: %d > %d", f.hits.Load(), hitsBefore)
	}
}
