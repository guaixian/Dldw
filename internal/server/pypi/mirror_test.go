package pypi

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

// fixture 起假的 pypi.org + files.pythonhosted.org + localfs 存储。
type fixture struct {
	files    *httptest.Server // files origin
	index    *httptest.Server // index origin
	stor     storage.Storage
	exec     executor.Executor
	store    *tasks.Store
	filesHit atomic.Int64
	tmpDir   string
}

func newFixture(t *testing.T, payload []byte) *fixture {
	t.Helper()
	f := &fixture{tmpDir: t.TempDir()}
	f.files = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.filesHit.Add(1)
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeContent(w, r, "w.whl", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(f.files.Close)

	f.index = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/simple/six/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<html><a href="`+f.files.URL+`/packages/b7/ce/abc/six-1.0-py3.whl#sha256=deadbeef">six-1.0-py3.whl</a></html>`)
	}))
	t.Cleanup(f.index.Close)

	stor, err := localfs.New(localfs.Config{
		Root:       filepath.Join(f.tmpDir, "objects"),
		PublicBase: "http://mirror.local",
		Secret:     []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.stor = stor
	// 允许回环 fake 源站（含其随机端口）
	fport := 0
	if i := strings.LastIndexByte(f.files.URL, ':'); i >= 0 {
		fmt.Sscanf(f.files.URL[i+1:], "%d", &fport)
	}
	f.exec = executor.NewBuiltin(executor.BuiltinConfig{
		Policy: &ssrf.Policy{AllowLoopback: true, Ports: []int{fport}},
	})
	store, err := tasks.NewStore(filepath.Join(f.tmpDir, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	return f
}

func (f *fixture) mirror(publicBase string) *Mirror {
	return New(Config{
		IndexOrigin: f.index.URL,
		FilesOrigin: f.files.URL,
		PublicBase:  publicBase,
		TmpDir:      filepath.Join(f.tmpDir, "tmp"),
	}, f.stor, f.exec, f.store)
}

func TestSimpleIndexRewriteAndCache(t *testing.T) {
	f := newFixture(t, []byte("fake-wheel-bytes"))
	m := f.mirror("http://127.0.0.1:18080")

	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/simple/{pkg}/", func(w http.ResponseWriter, r *http.Request) {
		m.ServeSimple(w, r, nil)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pypi/simple/six/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Dldw-Cache") != "miss" {
		t.Fatalf("first: %d %v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(string(body), "http://127.0.0.1:18080/pypi/packages/b7/ce/abc/six-1.0-py3.whl") {
		t.Fatalf("link not rewritten: %s", body)
	}
	if strings.Contains(string(body), f.files.URL) {
		t.Fatalf("origin leaked: %s", body)
	}
	if !strings.Contains(string(body), "#sha256=deadbeef") {
		t.Fatalf("fragment lost: %s", body)
	}

	// 第二次命中内存缓存
	resp2, _ := http.Get(srv.URL + "/pypi/simple/six/")
	io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.Header.Get("X-Dldw-Cache") != "hit" {
		t.Fatalf("index cache: %v", resp2.Header.Get("X-Dldw-Cache"))
	}

	// 未知包 -> 透传 404
	resp3, _ := http.Get(srv.URL + "/pypi/simple/nosuchpkg/")
	resp3.Body.Close()
	if resp3.StatusCode != 404 {
		t.Fatalf("unknown pkg: %d", resp3.StatusCode)
	}
}

func TestWheelFlow(t *testing.T) {
	payload := bytes.Repeat([]byte("wheel!"), 1000) // 6KB
	f := newFixture(t, payload)
	m := f.mirror("http://127.0.0.1:18080")

	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/packages/{path...}", func(w http.ResponseWriter, r *http.Request) {
		m.ServePackage(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wheelURL := srv.URL + "/pypi/packages/b7/ce/abc/six-1.0-py3.whl"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 第一次：未命中 -> 抓取入库 -> 302 到存储预签名
	resp, err := client.Get(wheelURL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first: %d body=%s", resp.StatusCode, b)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://mirror.local/files/") {
		t.Fatalf("redirect to %q", loc)
	}
	if f.filesHit.Load() != 1 {
		t.Fatalf("origin hits = %d", f.filesHit.Load())
	}

	// 任务已登记 ready（dldw get 同 URL 可直接命中）
	canonical, err := urlcanon.Canonicalize(f.files.URL + "/packages/b7/ce/abc/six-1.0-py3.whl")
	if err != nil {
		t.Fatal(err)
	}
	cacheKey := urlcanon.CacheKey(canonical, urlcanon.FamilyPyPIFile)
	task, err := f.store.GetByCacheKey(cacheKey)
	if err != nil || task.Status != tasks.StatusReady || task.Artifact == nil {
		t.Fatalf("task = %+v err=%v", task, err)
	}
	if task.Artifact.Size != int64(len(payload)) || task.Artifact.SHA256 == "" {
		t.Fatalf("artifact = %+v", task.Artifact)
	}

	// 第二次：直接预签名，源站不再被请求
	resp2, err := client.Get(wheelURL)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("second: %d", resp2.StatusCode)
	}
	if f.filesHit.Load() != 1 {
		t.Fatalf("origin re-fetched! hits = %d", f.filesHit.Load())
	}
}
