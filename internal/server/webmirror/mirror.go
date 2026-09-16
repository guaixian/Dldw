// Package webmirror 实现通用静态文件拉穿镜像，覆盖 apt（.deb）、yum/dnf
// （.rpm）及任何静态大文件：
//
//	GET /mirror/https/{host}/{path...}   upstream = https://{host}/{path}
//	GET /mirror/http/{host}/{path...}    upstream = http://{host}/{path}
//
// 行为：
//   - 路径可判定为静态工件（urlcanon 家族非空，如 .deb/.rpm/.tar.gz/.zip，
//     或 apt 的 /by-hash/ 路径）-> 命中 302 预签名；未命中抓取入库后 302
//   - 其余（Packages/Release/repomd.xml 等元数据）-> 流式透传，不缓存
//     （转发 Range/ETag 等，保证签名校验与增量更新正确）
//
// apt 接入（示例）：
//	deb http://127.0.0.1:18080/mirror/https/deb.debian.org/debian bookworm main
// dnf 接入（示例）：
//	baseurl=http://127.0.0.1:18080/mirror/https/mirrors.aliyun.com/centos/$releasever/BaseOS/$basearch/os/
//
// 安全：透传与抓取均受 SSRF 策略约束（端口 80/443、阻断私网/保留段）；
// 可选 allowed_hosts 白名单进一步收窄。监听 127.0.0.1 时仅本机可用。
package webmirror

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dldw/internal/server/mirrorcore"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

// Config 配置通用镜像。
type Config struct {
	AllowedHosts []string // 可选 host 白名单（小写；空 = 任意公网主机，仍受 SSRF 策略限制）
	PassTimeout time.Duration
}

// Mirror 是通用静态文件拉穿镜像。
type Mirror struct {
	cfg    Config
	fetch  *mirrorcore.Fetcher
	group  *mirrorcore.Group
	client *http.Client // 透传客户端（带出口代理或 SSRF 守卫，由 app 注入）
}

// New 构造。client 用于元数据透传（nil = 默认直连，生产应由 app 注入带
// 出口代理/SSRF 守卫的客户端）。
func New(cfg Config, client *http.Client, stor storage.Storage, exec executor.Executor, store *tasks.Store, tmpDir string, presignTTL time.Duration) *Mirror {
	if cfg.PassTimeout <= 0 {
		cfg.PassTimeout = 5 * time.Minute
	}
	for i, h := range cfg.AllowedHosts {
		cfg.AllowedHosts[i] = strings.ToLower(strings.TrimSpace(h))
	}
	return &Mirror{
		cfg:   cfg,
		fetch: &mirrorcore.Fetcher{Stor: stor, Exec: exec, Store: store, TmpDir: tmpDir, PresignTTL: presignTTL},
		group: mirrorcore.NewGroup(),
		client: client,
	}
}

// ServeHTTP 处理 GET/HEAD /mirror/{scheme}/{host}/{path...}。
func (m *Mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET/HEAD only", http.StatusMethodNotAllowed)
		return
	}
	scheme := strings.ToLower(r.PathValue("scheme"))
	host := strings.ToLower(r.PathValue("host"))
	p := r.PathValue("path")
	if (scheme != "http" && scheme != "https") || host == "" || p == "" || strings.Contains(p, "..") {
		http.Error(w, "bad mirror path", http.StatusBadRequest)
		return
	}
	if host == "127.0.0.1" || host == "localhost" || strings.Contains(host, "/") {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	if len(m.cfg.AllowedHosts) > 0 && !containsHost(m.cfg.AllowedHosts, host) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	upstream := scheme + "://" + host + "/" + p
	canonical, family := classify(upstream)
	if family != "" {
		m.serveCached(w, r, canonical, family)
		return
	}
	m.servePassthrough(w, r, upstream)
}

// classify 判定 upstream 是否静态工件：urlcanon 家族 + apt by-hash 路径。
// 注意：仓库元数据（Packages*/Sources*/Release*/InRelease/Contents*、
// yum repodata/）即使带压缩扩展名也必须透传——缓存会导致 apt/dnf 拿到
// 过期索引与签名校验失败。
func classify(upstream string) (string, string) {
	u, err := url.Parse(upstream)
	if err != nil {
		return "", ""
	}
	canonical, err := urlcanon.Canonicalize(upstream)
	if err != nil {
		return "", ""
	}
	path := u.Path
	// apt by-hash：按内容寻址，可安全永久缓存
	if strings.Contains(path, "/by-hash/") {
		return canonical, "generic-static"
	}
	if isRepoMetadata(path) {
		return canonical, ""
	}
	_, family, _, err := urlcanon.FamilyOfRaw(upstream)
	if err != nil || family == "" {
		return canonical, ""
	}
	return canonical, family
}

// isRepoMetadata 识别 apt/yum/dnf 仓库元数据路径。
func isRepoMetadata(path string) bool {
	// yum/dnf：repodata/ 下的 primary/filelists/other/repomd 等
	if strings.Contains(path, "/repodata/") {
		return true
	}
	base := path
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	// 剥压缩/签名扩展：Packages.gz/xz/bz2、Release.gpg 等
	for _, ext := range []string{".gz", ".xz", ".bz2", ".zst", ".gpg", ".sig"} {
		if strings.HasSuffix(base, ext) {
			base = strings.TrimSuffix(base, ext)
		}
	}
	switch {
	case base == "Packages" || strings.HasPrefix(base, "Packages."),
		base == "Sources" || strings.HasPrefix(base, "Sources."),
		base == "Release", base == "InRelease",
		base == "Contents" || strings.HasPrefix(base, "Contents."),
		base == "repomd", strings.HasPrefix(base, "repomd."),
		strings.HasPrefix(base, "MD5SUMS"), strings.HasPrefix(base, "SHA256SUMS"):
		return true
	}
	return false
}

// serveCached：命中 302 预签名；未命中抓取入库（singleflight）。
func (m *Mirror) serveCached(w http.ResponseWriter, r *http.Request, canonical, family string) {
	v, _ := m.group.Do(family+"\n"+canonical, func() (any, error) {
		return m.fetch.PresignOrFetch(r.Context(), canonical, family, "web-mirror")
	})
	target, _ := v.(string)
	if target == "" {
		http.Error(w, "origin fetch failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

// servePassthrough：流式透传元数据/动态内容（转发关键头与 Range）。
func (m *Mirror) servePassthrough(w http.ResponseWriter, r *http.Request, upstream string) {
	client := m.client
	if client == nil {
		client = &http.Client{Timeout: m.cfg.PassTimeout}
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, h := range []string{"Range", "If-Modified-Since", "If-None-Match", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("User-Agent", "dldw-mirror/1.0")
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range []string{"Content-Type", "Content-Length", "ETag", "Last-Modified", "Location", "Accept-Ranges", "Content-Range"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		io.Copy(w, resp.Body)
	}
}

func containsHost(list []string, h string) bool {
	for _, x := range list {
		if x == h || strings.HasSuffix(h, "."+x) {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
var _ = context.Background
