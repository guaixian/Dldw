// Package registrymirror 实现 Docker Registry V2 拉穿镜像（spec 4.4）：
//
//	GET  /v2/                          ping（客户端能力探测）
//	GET  /v2/<name>/manifests/<ref>    manifest：tag 短 TTL 内存缓存 / digest
//	                                   永久缓存，内联返回（不重定向）
//	GET  /v2/<name>/blobs/<digest>     层内容：SHA256 内容寻址 -> 入 Garage
//	                                   -> 302 预签名（与全部镜像共享存储）
//	HEAD /v2/<name>/manifests|blobs/.. 存在性检查
//
// 客户端接入：Docker Desktop daemon.json
//	{ "registry-mirrors": ["http://127.0.0.1:18080"] }
//
// 上游认证：服务端统一向 auth.docker.io 取 token；配置 Docker Hub 账号
// （username/password）可绕开匿名 IP 限流（200 次/6h），否则匿名（易被限）。
// 层内容按 digest 校验 SHA256 后入库——内容寻址，天然防篡改。
package registrymirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

const familyDockerBlob = "docker-blob"

// Config 配置 registry 镜像。
type Config struct {
	Origin       string // 上游 registry，默认 https://registry-1.docker.io
	AuthURL      string // token 端点，默认 https://auth.docker.io/token
	Username     string // Docker Hub 账号（可选；绕开匿名限流）
	Password     string // 密码或 Access Token
	ManifestTTL  time.Duration // tag manifest 内存缓存 TTL，默认 60s
	TmpDir       string
	PresignTTL   time.Duration
	UpstreamTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.Origin == "" {
		c.Origin = "https://registry-1.docker.io"
	}
	if c.AuthURL == "" {
		c.AuthURL = "https://auth.docker.io/token"
	}
	c.Origin = strings.TrimRight(c.Origin, "/")
	if c.ManifestTTL <= 0 {
		c.ManifestTTL = 60 * time.Second
	}
	if c.UpstreamTimeout <= 0 {
		c.UpstreamTimeout = 5 * time.Minute
	}
	return c
}

// Mirror 是 Registry V2 拉穿镜像。
type Mirror struct {
	cfg   Config
	stor  storage.Storage
	store *tasks.Store
	client *http.Client // 上游客户端（由 app 注入：走出口代理或直连）

	tokMu sync.Mutex
	toks  map[string]tokEntry // repository -> token

	mfMu sync.Mutex
	mfs  map[string]mfEntry // name/ref -> manifest 缓存

	flightMu sync.Mutex
	flights  map[string]*flight
}

type tokEntry struct {
	token     string
	fetchedAt time.Time
}

type mfEntry struct {
	body        []byte
	contentType string
	fetchedAt   time.Time
	immutable   bool // digest 引用：永久缓存
}

type flight struct {
	wg  sync.WaitGroup
	val any
	err error
}

// New 构造镜像。client 为上游 HTTP 客户端（nil = 默认直连）。
func New(cfg Config, client *http.Client, stor storage.Storage, store *tasks.Store) *Mirror {
	return &Mirror{
		cfg:    cfg.withDefaults(),
		stor:   stor,
		store:  store,
		client: client,
		toks:   map[string]tokEntry{},
		mfs:    map[string]mfEntry{},
		flights: map[string]*flight{},
	}
}

// ServeHTTP 处理 /v2/ 下的全部请求（由 api 层挂载）。
func (m *Mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v2")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		// ping：本镜像对客户端免认证
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}\n"))
		return
	}
	switch {
	case strings.Contains(rest, "/manifests/"):
		m.serveManifest(w, r, rest)
	case strings.Contains(rest, "/blobs/"):
		m.serveBlob(w, r, rest)
	default:
		http.NotFound(w, r)
	}
}

// splitRepoRef 从 "owner/repo/manifests|blobs/xxx" 拆出 name 与 ref。
func splitRepoRef(rest, marker string) (name, ref string, ok bool) {
	i := strings.Index(rest, "/"+marker+"/")
	if i <= 0 {
		return "", "", false
	}
	return rest[:i], rest[i+len(marker)+2:], true
}

// ---- 上游 token -----------------------------------------------------------

func (m *Mirror) token(ctx context.Context, repo string) (string, error) {
	m.tokMu.Lock()
	if e, ok := m.toks[repo]; ok && time.Since(e.fetchedAt) < 4*time.Minute {
		m.tokMu.Unlock()
		return e.token, nil
	}
	m.tokMu.Unlock()

	u := m.cfg.AuthURL + "?service=registry.docker.io&scope=" + url.QueryEscape("repository:"+repo+":pull")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if m.cfg.Username != "" {
		req.SetBasicAuth(m.cfg.Username, m.cfg.Password)
	}
	resp, err := m.clientOrDefault().Do(req)
	if err != nil {
		return "", fmt.Errorf("registry auth: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry auth: HTTP %d (%s)", resp.StatusCode, truncate(body, 200))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("registry auth: bad token response")
	}
	m.tokMu.Lock()
	m.toks[repo] = tokEntry{token: out.Token, fetchedAt: time.Now()}
	m.tokMu.Unlock()
	return out.Token, nil
}

func (m *Mirror) clientOrDefault() *http.Client {
	if m.client != nil {
		return m.client
	}
	return &http.Client{Timeout: m.cfg.UpstreamTimeout}
}

// ---- manifest ---------------------------------------------------------------

func (m *Mirror) serveManifest(w http.ResponseWriter, r *http.Request, rest string) {
	name, ref, ok := splitRepoRef(rest, "manifests")
	if !ok || name == "" || ref == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodHead {
		m.proxyUpstream(w, r, name, rest, true)
		return
	}

	key := name + "/" + ref
	immutable := strings.HasPrefix(ref, "sha256:")
	if !immutable {
		if e, hit := m.cachedManifest(key); hit {
			writeManifest(w, e)
			return
		}
	}

	// 上游取 manifest（Accept 透传，兼容 OCI index/manifest list）
	upURL := m.cfg.Origin + "/v2/" + name + "/manifests/" + ref
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tok, terr := m.token(r.Context(), name)
	if terr != nil {
		http.Error(w, terr.Error(), http.StatusBadGateway)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	} else {
		req.Header.Set("Accept",
			"application/vnd.docker.distribution.manifest.v2+json, "+
				"application/vnd.docker.distribution.manifest.list.v2+json, "+
				"application/vnd.oci.image.manifest.v1+json, "+
				"application/vnd.oci.image.index.v1+json")
	}
	resp, err := m.clientOrDefault().Do(req)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		http.Error(w, "read manifest: "+err.Error(), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		for _, h := range []string{"Content-Type", "Docker-Content-Digest"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/vnd.docker.distribution.manifest.v2+json"
	}
	entry := mfEntry{body: body, contentType: ct, fetchedAt: time.Now(), immutable: immutable}
	m.mfMu.Lock()
	m.mfs[key] = entry
	m.mfMu.Unlock()
	if d := resp.Header.Get("Docker-Content-Digest"); d != "" {
		w.Header().Set("Docker-Content-Digest", d)
	}
	writeManifest(w, entry)
}

func writeManifest(w http.ResponseWriter, e mfEntry) {
	w.Header().Set("Content-Type", e.contentType)
	w.Header().Set("Content-Length", fmt.Sprint(len(e.body)))
	w.Header().Set("X-Dldw-Cache", "hit")
	w.WriteHeader(http.StatusOK)
	w.Write(e.body)
}

func (m *Mirror) cachedManifest(key string) (mfEntry, bool) {
	m.mfMu.Lock()
	defer m.mfMu.Unlock()
	e, ok := m.mfs[key]
	if !ok {
		return e, false
	}
	if !e.immutable && time.Since(e.fetchedAt) > m.cfg.ManifestTTL {
		return e, false
	}
	return e, true
}

// ---- blob -------------------------------------------------------------------

func (m *Mirror) serveBlob(w http.ResponseWriter, r *http.Request, rest string) {
	name, digest, ok := splitRepoRef(rest, "blobs")
	if !ok || name == "" || !strings.HasPrefix(digest, "sha256:") || len(digest) != 7+64 {
		http.NotFound(w, r)
		return
	}
	canonical := m.cfg.Origin + "/v2/" + name + "/blobs/" + digest

	if r.Method == http.MethodHead {
		m.serveBlobHead(w, r, name, digest, canonical)
		return
	}

	v, _ := m.doFlight(digest, func() (any, error) {
		return m.fetchOrPresignBlob(r.Context(), name, canonical, digest)
	})
	target, _ := v.(string)
	if target == "" {
		http.Error(w, "blob fetch failed", http.StatusBadGateway)
		return
	}
	// Registry 客户端遵循 blob 重定向（官方 CDN 同款行为）
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

func (m *Mirror) serveBlobHead(w http.ResponseWriter, r *http.Request, name, digest, canonical string) {
	cacheKey := urlcanon.CacheKey(canonical, familyDockerBlob)
	if t, err := m.store.GetByCacheKey(cacheKey); err == nil && t.Status == tasks.StatusReady && t.Artifact != nil {
		w.Header().Set("Content-Length", fmt.Sprint(t.Artifact.Size))
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
		return
	}
	m.proxyUpstream(w, r, name, "/v2/"+name+"/blobs/"+digest, true)
}

// fetchOrPresignBlob：命中预签名；未命中带 token 抓取 -> 校验 SHA256=digest
// -> 入库（family=docker-blob，与 urlcanon 对 production.cloudflare.docker.com
// 的分类共用键空间）-> 登记 ready 任务 -> 预签名。
func (m *Mirror) fetchOrPresignBlob(ctx context.Context, repo, canonical, digest string) (string, error) {
	cacheKey := urlcanon.CacheKey(canonical, familyDockerBlob)
	if t, err := m.store.GetByCacheKey(cacheKey); err == nil && t.Status == tasks.StatusReady && t.Artifact != nil {
		return m.stor.PresignGet(ctx, t.Artifact.StorageKey, m.cfg.PresignTTL)
	}

	tok, err := m.token(ctx, repo)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canonical, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	key := tasks.StorageKeyFor(familyDockerBlob, cacheKey)
	dir := filepath.Join(m.cfg.TmpDir, "docker-blob", digest[7:15])
	defer os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, "blob-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()

	h := sha256.New()
	var size int64
	resp, err := m.clientOrDefault().Do(req)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		tmp.Close()
		os.Remove(tmpName)
		return "", fmt.Errorf("blob HTTP %d", resp.StatusCode)
	}
	size, err = io.Copy(io.MultiWriter(tmp, h), resp.Body)
	resp.Body.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmpName)
		return "", err
	}
	gotSum := hex.EncodeToString(h.Sum(nil))
	if gotSum != digest[7:] {
		os.Remove(tmpName)
		return "", fmt.Errorf("digest mismatch: got sha256:%s want %s", gotSum, digest)
	}

	fp, err := os.Open(tmpName)
	if err != nil {
		return "", err
	}
	obj, err := m.stor.Put(ctx, key, fp, size, "application/octet-stream")
	fp.Close()
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	task := tasks.NewTask(canonical, canonical, cacheKey, familyDockerBlob, "registry-mirror", 0)
	task.Status = tasks.StatusReady
	task.Progress = 1
	task.Artifact = &tasks.Artifact{
		Size:       obj.Size,
		SHA256:     gotSum,
		ETag:       obj.ETag,
		StorageKey: key,
	}
	if err := m.store.Put(task); err != nil {
		return "", err
	}
	return m.stor.PresignGet(ctx, key, m.cfg.PresignTTL)
}

// ---- 上游透传（HEAD 等） -----------------------------------------------------

func (m *Mirror) proxyUpstream(w http.ResponseWriter, r *http.Request, repo, path string, headOnly bool) {
	tok, err := m.token(r.Context(), repo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, m.cfg.Origin+path, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := m.clientOrDefault().Do(req)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	for _, h := range []string{"Content-Type", "Content-Length", "Docker-Content-Digest", "ETag"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
}

// ---- 极简 singleflight -------------------------------------------------------

func (m *Mirror) doFlight(key string, fn func() (any, error)) (any, error) {
	m.flightMu.Lock()
	if f, ok := m.flights[key]; ok {
		m.flightMu.Unlock()
		f.wg.Wait()
		return f.val, f.err
	}
	f := &flight{}
	f.wg.Add(1)
	m.flights[key] = f
	m.flightMu.Unlock()

	f.val, f.err = fn()
	f.wg.Done()

	m.flightMu.Lock()
	delete(m.flights, key)
	m.flightMu.Unlock()
	return f.val, f.err
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}
