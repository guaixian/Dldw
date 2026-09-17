package mirrorcore

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"dldw/internal/policy/ssrf"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage/localfs"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

func newFetcher(t *testing.T, ports ...int) (*Fetcher, *tasks.Store) {
	t.Helper()
	tmp := t.TempDir()
	stor, err := localfs.New(localfs.Config{
		Root:       filepath.Join(tmp, "objects"),
		PublicBase: "http://mirror.local",
		Secret:     []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := tasks.NewStore(filepath.Join(tmp, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	exec := executor.NewBuiltin(executor.BuiltinConfig{
		Policy:  &ssrf.Policy{AllowLoopback: true, Ports: ports},
		Retries: 0,
	})
	return &Fetcher{Stor: stor, Exec: exec, Store: store, TmpDir: tmp, PresignTTL: time.Minute}, store
}

func portOf(s *httptest.Server) int {
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	var n int
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestMultiOriginFailover(t *testing.T) {
	payload := []byte("artifact-from-origin-b")
	var bHits atomic.Int64
	// 主源：直接拒绝连接（不可达端口）
	dead := "http://127.0.0.1:1"
	// 备源：正常服务
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits.Add(1)
		w.Write(payload)
	}))
	defer b.Close()

	f, store := newFetcher(t, portOf(b))
	canonical := dead + "/pkg/x.bin"
	candidates := []string{canonical, b.URL + "/pkg/x.bin"}

	url, err := f.PresignOrFetchMulti(context.Background(), canonical, candidates, "generic-static", "test")
	if err != nil {
		t.Fatal(err)
	}
	if url == "" || bHits.Load() != 1 {
		t.Fatalf("url=%q hits=%d err=%v", url, bHits.Load(), err)
	}
	// 缓存键取主源 canonical：任务存在且 ready
	tk, err := store.GetByCacheKey(cacheKeyOf(canonical, "generic-static"))
	if err != nil || tk.Status != tasks.StatusReady || tk.Artifact.Size != int64(len(payload)) {
		t.Fatalf("task=%+v err=%v", tk, err)
	}

	// 二次命中（不再回源）
	url2, err := f.PresignOrFetchMulti(context.Background(), canonical, candidates, "generic-static", "test")
	if err != nil || url2 == "" || bHits.Load() != 1 {
		t.Fatalf("second: hits=%d err=%v", bHits.Load(), err)
	}
}

func TestMultiOriginAllFail(t *testing.T) {
	f, _ := newFetcher(t)
	_, err := f.PresignOrFetchMulti(context.Background(),
		"http://127.0.0.1:1/a.bin", []string{"http://127.0.0.1:1/a.bin", "http://127.0.0.1:2/a.bin"},
		"generic-static", "test")
	if err == nil {
		t.Fatal("all origins down should fail")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("all 2 origins failed")) {
		t.Fatalf("error should mention all origins: %v", err)
	}
}

func cacheKeyOf(canonical, family string) string {
	return urlcanon.CacheKey(canonical, family)
}
