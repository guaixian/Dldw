// Package npm 实现 npm registry 拉穿镜像（pull-through cache），让 npm /
// pnpm / yarn 的包下载吃 dldw 服务端缓存：
//
//	GET /npm/<pkg>               代理 registry.npmjs.org 元数据（完整/精简
//	                             corgi 两种格式），把 dist.tarball 链接重写为
//	                             /npm/tarball/...（内存缓存，默认 2min）
//	GET /npm/tarball/<pkg>/-/x   tgz 请求：命中 -> 302 预签名（本地直出）；
//	                             未命中 -> 经出口代理抓取入库 -> 302
//
// 客户端接入（wrapper 自动注入，也可手动）：
//	NPM_CONFIG_REGISTRY=http://127.0.0.1:18080/npm
//
// 与 `dldw get` / PyPI 镜像共享存储与任务记录。仅支持公共 registry 匿名
// 拉取；带 _authToken 的私有源请勿指向本镜像。
package npm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"dldw/internal/server/mirrorcore"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

// Config 配置镜像行为。
type Config struct {
	RegistryOrigin  string   `json:"-"` // 兼容单源写法（等价于 RegistryOrigins[0]）
	RegistryOrigins []string // registry 源列表（顺序回退）
	PublicBase      string   // 对外基础 URL
	IndexTTL        time.Duration
	TmpDir          string
	PresignTTL      time.Duration
}

func (c Config) withDefaults() Config {
	if c.RegistryOrigins == nil {
		origins := []string{}
		for _, s := range []string{c.RegistryOrigin, "https://registry.npmjs.org"} {
			if s != "" {
				origins = append(origins, s)
			}
		}
		c.RegistryOrigins = origins
	}
	for i := range c.RegistryOrigins {
		c.RegistryOrigins[i] = strings.TrimRight(c.RegistryOrigins[i], "/")
	}
	if c.IndexTTL <= 0 {
		c.IndexTTL = 2 * time.Minute
	}
	if c.PresignTTL <= 0 {
		c.PresignTTL = 15 * time.Minute
	}
	return c
}

// Mirror 是 npm 拉穿镜像。
type Mirror struct {
	cfg   Config
	fetch *mirrorcore.Fetcher
	group *mirrorcore.Group

	idxMu sync.Mutex
	idx   map[string]idxEntry
}

type idxEntry struct {
	body        []byte
	contentType string
	fetchedAt   time.Time
}

// New 构造镜像。
func New(cfg Config, stor storage.Storage, exec executor.Executor, store *tasks.Store) *Mirror {
	return &Mirror{
		cfg:   cfg.withDefaults(),
		fetch: &mirrorcore.Fetcher{Stor: stor, Exec: exec, Store: store, TmpDir: cfg.TmpDir, PresignTTL: cfg.PresignTTL},
		group: mirrorcore.NewGroup(),
		idx:   map[string]idxEntry{},
	}
}

var pkgNameRe = func(s string) bool {
	// 包名：裸名 或 @scope/name（URL 里可能是 %2F 编码）
	s = strings.ReplaceAll(s, "%2F", "/")
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == '@', r == '/':
		default:
			return false
		}
	}
	return true
}

// ServeMetadata 处理 GET /npm/{pkg} —— 代理元数据并重写 tarball 链接。
func (m *Mirror) ServeMetadata(w http.ResponseWriter, r *http.Request, upstream *http.Client) {
	pkg := strings.Trim(r.PathValue("pkg"), "/")
	if !pkgNameRe(pkg) {
		http.Error(w, "invalid package name", http.StatusBadRequest)
		return
	}
	// 归一化编码：@scope%2Fname -> @scope/name
	pkgNorm := strings.ReplaceAll(pkg, "%2F", "/")

	if body, ctype, ok := m.cachedMeta(pkgNorm); ok {
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("X-Dldw-Cache", "hit")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		return
	}

	if upstream == nil {
		upstream = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}
	}
	// 多源顺序回退
	var body []byte
	var ctype string
	for _, origin := range m.cfg.RegistryOrigins {
		// 元数据请求路径保留原始编码形式（npm 对 scope 包用 %2F）
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
			origin+"/"+pkg, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Accept", r.Header.Get("Accept")) // 透传 corgi 精简格式协商
		resp, err := upstream.Do(req)
		if err != nil {
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if rerr != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode >= 500 || resp.StatusCode == 429 {
				continue
			}
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			w.Write(b)
			return
		}
		body, ctype = b, resp.Header.Get("Content-Type")
		break
	}
	if body == nil {
		http.Error(w, "all registry origins unreachable", http.StatusBadGateway)
		return
	}

	// 重写 tarball 链接：任一源的 origin/<pkg>/-/ 前缀都替换为本地镜像
	rewritten := string(body)
	for _, origin := range m.cfg.RegistryOrigins {
		rewritten = strings.ReplaceAll(rewritten,
			origin+"/"+pkg+"/-/", m.cfg.PublicBase+"/npm/tarball/"+pkg+"/-/")
	}
	if ctype == "" {
		ctype = "application/json"
	}

	m.idxMu.Lock()
	m.idx[pkgNorm] = idxEntry{body: []byte(rewritten), contentType: ctype, fetchedAt: time.Now()}
	m.idxMu.Unlock()

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Dldw-Cache", "miss")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(rewritten))
}

func (m *Mirror) cachedMeta(pkg string) ([]byte, string, bool) {
	m.idxMu.Lock()
	defer m.idxMu.Unlock()
	e, ok := m.idx[pkg]
	if !ok || time.Since(e.fetchedAt) > m.cfg.IndexTTL {
		return nil, "", false
	}
	return e.body, e.contentType, true
}

// ServeTarball 处理 GET /npm/tarball/{path...} —— tgz 缓存/302。
func (m *Mirror) ServeTarball(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/npm/tarball/")
	p = strings.Trim(p, "/")
	if p == "" || !strings.Contains(p, "/-/") || strings.Contains(p, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	canonical := m.cfg.RegistryOrigins[0] + "/" + p

	target, err := m.serveTarball(r.Context(), canonical)
	if err != nil {
		code := http.StatusBadGateway
		if strings.Contains(err.Error(), "HTTP 4") {
			code = http.StatusNotFound
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

// serveTarball 返回预签名 URL；未命中则抓取入库。家族固定 npm-tarball，
// 缓存键取 RegistryOrigins[0]（源站回退不影响键），与 dldw get 共享。
func (m *Mirror) serveTarball(ctx context.Context, canonicalURL string) (string, error) {
	canonical, err := urlcanon.Canonicalize(canonicalURL)
	if err != nil {
		return "", err
	}
	candidates := []string{}
	if i := strings.Index(canonicalURL, "/-/"); i >= 0 {
		pkgPath := tarballPathOf(canonicalURL)     // <pkg>/-/<file>
		suffix := canonicalURL[i:]                 // "/-/<file>"
		for _, origin := range m.cfg.RegistryOrigins {
			cand := origin + "/" + pkgPath
			if u, uerr := urlcanon.Canonicalize(cand); uerr == nil {
				candidates = append(candidates, u)
			}
			_ = suffix
		}
	}
	if len(candidates) == 0 {
		candidates = []string{canonical}
	}
	v, _ := m.group.Do(canonical, func() (any, error) {
		return m.fetch.PresignOrFetchMulti(ctx, canonical, candidates, urlcanon.FamilyNpmTarball, "npm-mirror")
	})
	url, _ := v.(string)
	if url == "" {
		return "", fmt.Errorf("cache error")
	}
	return url, nil
}

// tarballPathOf 提取 tarball URL 的 <pkg>/-/ 部分（去掉源站前缀）。
func tarballPathOf(canonicalURL string) string {
	s := canonicalURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if j := strings.IndexByte(s, '/'); j >= 0 {
		s = s[j+1:] // <pkg>/-/<file>
	}
	return s
}
