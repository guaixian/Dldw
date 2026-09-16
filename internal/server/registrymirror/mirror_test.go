package registrymirror

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/storage/localfs"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

// fixture 模拟 registry-1.docker.io + auth.docker.io。
type fixture struct {
	reg   *httptest.Server
	auth  *httptest.Server
	stor  storage.Storage
	store *tasks.Store
	blobHits  atomic.Int64
	manHits   atomic.Int64
	authUser  atomic.Value // string：收到的 Basic 用户名（校验账号透传）
}

func newFixture(t *testing.T, layer []byte) *fixture {
	t.Helper()
	f := &fixture{}
	layerSum := sha256.Sum256(layer)
	layerDigest := "sha256:" + hex.EncodeToString(layerSum[:])

	f.auth = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok {
			f.authUser.Store(u + "/" + p)
		}
		if r.URL.Query().Get("service") != "registry.docker.io" {
			http.Error(w, "bad service", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "tok-test"})
	}))
	t.Cleanup(f.auth.Close)

	f.reg = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(200)
		case strings.Contains(r.URL.Path, "/manifests/"):
			f.manHits.Add(1)
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			fmt.Fprintf(w, `{"schemaVersion":2,"layers":[{"mediaType":"application/octet-stream","size":%d,"digest":"%s"}]}`,
				len(layer), layerDigest)
		case strings.Contains(r.URL.Path, "/blobs/"):
			f.blobHits.Add(1)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(layer)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.reg.Close)

	tmp := t.TempDir()
	stor, err := localfs.New(localfs.Config{
		Root:       filepath.Join(tmp, "objects"),
		PublicBase: "http://mirror.local",
		Secret:     []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.stor = stor
	store, err := tasks.NewStore(filepath.Join(tmp, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	return f
}

func (f *fixture) mirror() *Mirror {
	return New(Config{
		Origin:  f.reg.URL,
		AuthURL: f.auth.URL + "/token",
	}, nil, f.stor, f.store)
}

func TestPing(t *testing.T) {
	f := newFixture(t, []byte("x"))
	m := f.mirror()
	srv := httptest.NewServer(m)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Fatalf("ping: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestManifestAndBlobFlow(t *testing.T) {
	layer := []byte("docker-layer-content-0123456789")
	sum := sha256.Sum256(layer)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	f := newFixture(t, layer)
	m := f.mirror()

	mux := http.NewServeMux()
	mux.Handle("/v2/", m)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1) manifest：tag 引用，内联返回 + 内存缓存
	resp, err := http.Get(srv.URL + "/v2/library/alpine/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), digest) {
		t.Fatalf("manifest: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Type") != "application/vnd.docker.distribution.manifest.v2+json" {
		t.Fatalf("ct = %v", resp.Header.Get("Content-Type"))
	}
	// 二次命中内存缓存（manifest 不再回源）
	manHits := f.manHits.Load()
	resp2, _ := http.Get(srv.URL + "/v2/library/alpine/manifests/latest")
	io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.Header.Get("X-Dldw-Cache") != "hit" || f.manHits.Load() > manHits {
		t.Fatalf("manifest cache miss: hdr=%v hits=%d->%d", resp2.Header.Get("X-Dldw-Cache"), manHits, f.manHits.Load())
	}

	// 2) blob：首抓入库（digest 校验）-> 302 预签名
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	blobURL := srv.URL + "/v2/library/alpine/blobs/" + digest
	resp3, err := client.Get(blobURL)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("blob first: %d", resp3.StatusCode)
	}
	if !strings.HasPrefix(resp3.Header.Get("Location"), "http://mirror.local/files/") {
		t.Fatalf("location: %q", resp3.Header.Get("Location"))
	}

	// 任务 ready + SHA256 与 digest 一致
	canonical := f.reg.URL + "/v2/library/alpine/blobs/" + digest
	task, err := f.store.GetByCacheKey(urlcanon.CacheKey(canonical, "docker-blob"))
	if err != nil || task.Status != tasks.StatusReady || task.Artifact.Size != int64(len(layer)) {
		t.Fatalf("task = %+v err=%v", task, err)
	}
	if task.Artifact.SHA256 != digest[7:] {
		t.Fatalf("sha mismatch: %s", task.Artifact.SHA256)
	}

	// 3) blob 二次：预签名直出（不再回源）
	hits := f.blobHits.Load()
	resp4, _ := client.Get(blobURL)
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusFound {
		t.Fatalf("blob second: %d", resp4.StatusCode)
	}
	if f.blobHits.Load() > hits {
		t.Fatalf("blob re-fetched: %d > %d", f.blobHits.Load(), hits)
	}

	// 4) HEAD blob 命中缓存
	req, _ := http.NewRequest(http.MethodHead, blobURL, nil)
	resp5, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != 200 || resp5.Header.Get("Docker-Content-Digest") != digest {
		t.Fatalf("head blob: %d %v", resp5.StatusCode, resp5.Header)
	}
}

func TestDigestMismatchRejected(t *testing.T) {
	// 上游返回的内容与请求 digest 不符 -> 必须拒绝入库
	f := newFixture(t, []byte("actual-layer"))
	m := f.mirror()
	mux := http.NewServeMux()
	mux.Handle("/v2/", m)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fakeDigest := "sha256:" + strings.Repeat("ab", 32) // 与 actual-layer 不符
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/v2/library/x/blobs/" + fakeDigest)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("mismatched digest must fail, got %d", resp.StatusCode)
	}
	// 不应留下任务
	canonical := f.reg.URL + "/v2/library/x/blobs/" + fakeDigest
	if _, err := f.store.GetByCacheKey(urlcanon.CacheKey(canonical, "docker-blob")); err == nil {
		t.Fatal("mismatched blob must not be cached")
	}
}

func TestCredentialsForwarded(t *testing.T) {
	f := newFixture(t, []byte("x"))
	m := New(Config{Origin: f.reg.URL, AuthURL: f.auth.URL + "/token", Username: "me", Password: "pat"}, nil, f.stor, f.store)
	mux := http.NewServeMux()
	mux.Handle("/v2/", m)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	http.Get(srv.URL + "/v2/library/alpine/manifests/latest") //nolint
	if u, _ := f.authUser.Load().(string); u != "me/pat" {
		t.Fatalf("credentials not forwarded: %q", u)
	}
}

func TestSplitRepoRef(t *testing.T) {
	n, r, ok := splitRepoRef("library/nginx/manifests/1.25", "manifests")
	if !ok || n != "library/nginx" || r != "1.25" {
		t.Fatalf("split = %q %q %v", n, r, ok)
	}
	n2, d, ok2 := splitRepoRef("org/app/blobs/sha256:abc", "blobs")
	if !ok2 || n2 != "org/app" || d != "sha256:abc" {
		t.Fatalf("split2 = %q %q %v", n2, d, ok2)
	}
	if _, _, ok3 := splitRepoRef("nope", "manifests"); ok3 {
		t.Fatal("bad rest should fail")
	}
}

var _ = time.Second
