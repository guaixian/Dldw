package hfmirror

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
	"dldw/internal/transfer/storage/localfs"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

func newFixture(t *testing.T, file []byte) (*Mirror, *httptest.Server, *tasks.Store, *atomic.Int64) {
	t.Helper()
	tmp := t.TempDir()
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/models/"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":"test/model","sha":"%s"}`, strings.Repeat("ab", 20))
		case strings.Contains(r.URL.Path, "/resolve/"):
			if r.Method == http.MethodHead {
				w.Header().Set("X-Repo-Commit", strings.Repeat("ab", 20))
				w.Header().Set("X-Linked-Size", fmt.Sprint(len(file)))
				w.WriteHeader(200)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(file)
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

func TestSHAFileCached(t *testing.T) {
	weights := bytes.Repeat([]byte("model-weights!"), 100)
	m, up, store, hits := newFixture(t, weights)

	mux := http.NewServeMux()
	mux.Handle("/hf/", m)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sha := strings.Repeat("ab", 20)
	url := srv.URL + "/hf/test/model/resolve/" + sha + "/pytorch_model.bin"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("sha file should cache: %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "http://mirror.local/files/") {
		t.Fatalf("location: %q", resp.Header.Get("Location"))
	}

	// 任务登记（family=huggingface-file）
	canonical, _ := urlcanon.Canonicalize(up.URL + "/test/model/resolve/" + sha + "/pytorch_model.bin")
	tk, err := store.GetByCacheKey(urlcanon.CacheKey(canonical, "huggingface-file"))
	if err != nil || tk.Status != tasks.StatusReady || tk.Artifact.Size != int64(len(weights)) {
		t.Fatalf("task = %+v err=%v", tk, err)
	}

	// 二次不再回源
	h := hits.Load()
	resp2, _ := client.Get(url)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound || hits.Load() > h {
		t.Fatalf("second: %d hits=%d->%d", resp2.StatusCode, h, hits.Load())
	}
}

func TestBranchAndAPIPassthrough(t *testing.T) {
	m, _, _, _ := newFixture(t, []byte("x"))

	mux := http.NewServeMux()
	mux.Handle("/hf/", m)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 分支引用 -> 透传（非 302 本地缓存）
	resp, err := http.Get(srv.URL + "/hf/test/model/resolve/main/pytorch_model.bin")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "x" {
		t.Fatalf("branch passthrough: %d %q", resp.StatusCode, body)
	}

	// API 透传
	resp2, _ := http.Get(srv.URL + "/hf/api/models/test/model")
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 || !strings.Contains(string(body2), `"sha"`) {
		t.Fatalf("api passthrough: %d %s", resp2.StatusCode, body2)
	}

	// HEAD 元数据透传（X-Repo-Commit 头保留）
	req, _ := http.NewRequest(http.MethodHead, srv.URL+"/hf/test/model/resolve/main/config.json", nil)
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 200 || resp3.Header.Get("X-Repo-Commit") == "" {
		t.Fatalf("HEAD passthrough: %d %v", resp3.StatusCode, resp3.Header)
	}
}
