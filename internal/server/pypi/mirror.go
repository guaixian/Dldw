// Package pypi 实现 PyPI 拉穿镜像（pull-through cache），让 uv / pip 的包下载
// 全量吃 dldw 服务端缓存：
//
//	GET /pypi/simple/<pkg>/       代理 pypi.org 索引页并把 files.pythonhosted.org
//	                              链接重写为 /pypi/packages/...（索引内存缓存 10min）
//	GET /pypi/packages/<path>     wheel 请求：
//	                                命中 -> 302 到 Garage 预签名 URL（本地直出）
//	                                未命中 -> 经出口代理抓取入库 -> 302 预签名
//
// 客户端接入：
//	UV_INDEX_URL=http://127.0.0.1:18080/pypi/simple
//	pip config set global.index-url http://127.0.0.1:18080/pypi/simple
//
// 与 `dldw get <pypi-url>` 共用同一 storage key 与任务记录：任一入口缓存后，
// 其余入口（含 dldw get）直接命中。
package pypi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"dldw/internal/server/mirrorcore"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

// Config 配置镜像行为（源站可替换，便于测试与私有 devpi）。
type Config struct {
	IndexOrigin  string   `json:"-"` // 兼容单源写法（等价于 IndexOrigins[0]）
	IndexOrigins []string // 索引源列表（顺序回退）：如 [pypi.org, tuna, aliyun]
	FilesOrigin  string   `json:"-"` // 兼容单源写法
	FilesOrigins []string // wheel 源列表（顺序回退）
	PublicBase   string   // 对外基础 URL，如 http://127.0.0.1:18080
	IndexTTL     time.Duration
	TmpDir       string // 抓取临时目录
	PresignTTL   time.Duration
	FetchTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.IndexOrigins == nil {
		c.IndexOrigins = nonEmpty([]string{c.IndexOrigin, "https://pypi.org"})
	}
	if c.FilesOrigins == nil {
		c.FilesOrigins = nonEmpty([]string{c.FilesOrigin, "https://files.pythonhosted.org"})
	}
	for i := range c.IndexOrigins {
		c.IndexOrigins[i] = strings.TrimRight(c.IndexOrigins[i], "/")
	}
	for i := range c.FilesOrigins {
		c.FilesOrigins[i] = strings.TrimRight(c.FilesOrigins[i], "/")
	}
	if c.IndexTTL <= 0 {
		c.IndexTTL = 10 * time.Minute
	}
	if c.PresignTTL <= 0 {
		c.PresignTTL = 15 * time.Minute
	}
	if c.FetchTimeout <= 0 {
		c.FetchTimeout = 10 * time.Minute
	}
	return c
}

func nonEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Mirror 是 PyPI 拉穿镜像。
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

var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ServeSimple 处理 GET /pypi/simple/{pkg}/ —— 代理并重写索引页。
// upstream 用于抓取 pypi.org（应配置出口代理的 client；nil = 无代理直连）。
func (m *Mirror) ServeSimple(w http.ResponseWriter, r *http.Request, upstream *http.Client) {
	pkg := strings.Trim(strings.ToLower(r.PathValue("pkg")), "/")
	if pkg == "" || !pkgNameRe.MatchString(pkg) {
		http.Error(w, "invalid package name", http.StatusBadRequest)
		return
	}
	if body, ctype, ok := m.cachedIndex(pkg); ok {
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("X-Dldw-Cache", "hit")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		return
	}

	if upstream == nil {
		upstream = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}
	}
	// 多源顺序回退：主源失败（网络错误/5xx）时尝试下一个
	var body []byte
	var ctype string
	for _, origin := range m.cfg.IndexOrigins {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
			origin+"/simple/"+pkg+"/", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 同时接受 HTML 与 PEP 691 JSON 两种 simple 索引格式
		req.Header.Set("Accept", "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01")
		resp, err := upstream.Do(req)
		if err != nil {
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if rerr != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode >= 500 || resp.StatusCode == 429 {
				continue // 源站故障/限流 -> 下一源
			}
			// 4xx 视为确定结果（如 404），透传并停止尝试
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			w.Write(b)
			return
		}
		body, ctype = b, resp.Header.Get("Content-Type")
		break
	}
	if body == nil {
		http.Error(w, "all index origins unreachable", http.StatusBadGateway)
		return
	}

	// 重写文件链接 -> 本镜像（HTML href 与 JSON url 均为绝对地址，统一替换；
	// 任一 FilesOrigin 的前缀都重写，来源不限）
	rewritten := string(body)
	for _, fo := range m.cfg.FilesOrigins {
		rewritten = strings.ReplaceAll(rewritten,
			fo+"/packages/", m.cfg.PublicBase+"/pypi/packages/")
	}
	if ctype == "" {
		ctype = "text/html; charset=utf-8"
	}

	m.idxMu.Lock()
	m.idx[pkg] = idxEntry{body: []byte(rewritten), contentType: ctype, fetchedAt: time.Now()}
	m.idxMu.Unlock()

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Dldw-Cache", "miss")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(rewritten))
}

func (m *Mirror) cachedIndex(pkg string) ([]byte, string, bool) {
	m.idxMu.Lock()
	defer m.idxMu.Unlock()
	e, ok := m.idx[pkg]
	if !ok || time.Since(e.fetchedAt) > m.cfg.IndexTTL {
		return nil, "", false
	}
	return e.body, e.contentType, true
}

// ServePackage 处理 GET /pypi/packages/{path...} —— wheel 下载/缓存/302。
func (m *Mirror) ServePackage(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/pypi/packages/")
	p = strings.Trim(p, "/")
	if p == "" || strings.Contains(p, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	canonical := m.cfg.FilesOrigin + "/packages/" + p

	target, err := m.serveWheel(r.Context(), canonical)
	if err != nil {
		code := http.StatusBadGateway
		if strings.Contains(err.Error(), "E_UPSTREAM") || strings.Contains(err.Error(), "HTTP 4") {
			code = http.StatusNotFound
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

// serveWheel 返回预签名 URL；未命中则抓取入库（singleflight 去重并发）。
// 家族固定为 pypi-file：真实 files.pythonhosted.org URL 的分类结果一致，
// 因此与 `dldw get` 共享同一 cache key（键取 FilesOrigins[0]，源站回退不影响键）。
func (m *Mirror) serveWheel(ctx context.Context, canonicalURL string) (string, error) {
	canonical, err := urlcanon.Canonicalize(canonicalURL)
	if err != nil {
		return "", err
	}
	candidates := []string{}
	for _, fo := range m.cfg.FilesOrigins {
		if u, uerr := urlcanon.Canonicalize(fo + pathAfterPackages(canonical)); uerr == nil {
			candidates = append(candidates, u)
		}
	}
	v, _ := m.group.Do(canonical, func() (any, error) {
		return m.fetch.PresignOrFetchMulti(ctx, canonical, candidates, urlcanon.FamilyPyPIFile, "pypi-mirror")
	})
	url, _ := v.(string)
	if url == "" {
		return "", fmt.Errorf("cache error")
	}
	return url, nil
}

// pathAfterPackages 提取 /packages/ 之后的路径。
func pathAfterPackages(canonical string) string {
	if i := strings.Index(canonical, "/packages/"); i >= 0 {
		return canonical[i:]
	}
	return "/packages/" + path.Base(canonical)
}
