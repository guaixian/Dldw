// Package hfmirror 实现 HuggingFace Hub 代理（对标 hf-mirror.com 的用法）：
//
//	GET/HEAD /hf/api/...                      元数据 API -> 透传
//	GET/HEAD /hf/<repo>/resolve/<rev>/<file>  文件下载：
//	    <rev> 为 40 位 commit SHA -> 内容不可变，入库缓存 -> 302 预签名
//	    <rev> 为分支/tag（main 等）-> 透传（上游 302 到 CDN 的 Location 原样转发）
//
// 客户端接入（wrapper 自动注入，用户已设 HF_ENDPOINT 时尊重用户）：
//	HF_ENDPOINT=http://127.0.0.1:18080/hf
// 适用 huggingface_hub / transformers / datasets 等 python 生态。
//
// 大模型权重（GB 级）正是 dldw 分块预签名下载的主场：首次经出口抓取入库，
// 之后任何设备命中即本地直出。
package hfmirror

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dldw/internal/server/mirrorcore"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

const familyHFFile = "huggingface-file"

// Config 配置 HF 代理。
type Config struct {
	Origin      string // 默认 https://huggingface.co
	PassTimeout time.Duration
}

// Mirror 是 HuggingFace Hub 代理。
type Mirror struct {
	origin  string
	fetch   *mirrorcore.Fetcher
	group   *mirrorcore.Group
	client  *http.Client
	timeout time.Duration
}

// New 构造。client 用于透传（nil = 默认直连；生产由 app 注入带出口的客户端）。
func New(cfg Config, client *http.Client, stor storage.Storage, exec executor.Executor, store *tasks.Store, tmpDir string, presignTTL time.Duration) *Mirror {
	if cfg.Origin == "" {
		cfg.Origin = "https://huggingface.co"
	}
	cfg.Origin = strings.TrimRight(cfg.Origin, "/")
	if cfg.PassTimeout <= 0 {
		cfg.PassTimeout = 5 * time.Minute
	}
	return &Mirror{
		origin:  cfg.Origin,
		fetch:   &mirrorcore.Fetcher{Stor: stor, Exec: exec, Store: store, TmpDir: tmpDir, PresignTTL: presignTTL},
		group:   mirrorcore.NewGroup(),
		client:  client,
		timeout: cfg.PassTimeout,
	}
}

// ServeHTTP 处理 /hf/{path...}。
func (m *Mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET/HEAD only", http.StatusMethodNotAllowed)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/hf")
	p = strings.Trim(p, "/")
	if p == "" || strings.Contains(p, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	upstream := m.origin + "/" + p

	if rev, ok := resolveRevision(p); ok && isCommitSHA(rev) {
		// commit-SHA 定位的文件内容不可变 -> 缓存
		canonical, err := urlcanon.Canonicalize(upstream)
		if err == nil {
			v, _ := m.group.Do(familyHFFile+"\n"+canonical, func() (any, error) {
				return m.fetch.PresignOrFetchMulti(r.Context(), canonical, []string{canonical}, familyHFFile, "hf-mirror")
			})
			if target, _ := v.(string); target != "" {
				w.Header().Set("Location", target)
				w.WriteHeader(http.StatusFound)
				return
			}
			http.Error(w, "origin fetch failed", http.StatusBadGateway)
			return
		}
	}
	// 其余（API、分支/tag 引用、HEAD 元数据）-> 透传
	m.servePassthrough(w, r, upstream)
}

// resolveRevision 提取 "<repo>/resolve/<rev>/<file>" 中的 <rev>。
func resolveRevision(p string) (string, bool) {
	i := strings.Index(p, "/resolve/")
	if i < 0 {
		return "", false
	}
	rest := p[i+len("/resolve/"):]
	if j := strings.IndexByte(rest, '/'); j > 0 {
		return rest[:j], true
	}
	return "", false
}

// isCommitSHA 判断 40 位小写十六进制 commit SHA。
func isCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (m *Mirror) servePassthrough(w http.ResponseWriter, r *http.Request, upstream string) {
	client := m.client
	if client == nil {
		client = &http.Client{Timeout: m.timeout, Transport: &http.Transport{Proxy: nil}}
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, h := range []string{"Accept", "Range", "If-None-Match", "If-Modified-Since", "Authorization"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("User-Agent", "dldw-hf-mirror/1.0")
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// HF 特有头（hf 客户端依赖）：X-Repo-Commit / X-Linked-Etag / X-Linked-Size 等
	for k, vv := range resp.Header {
		if strings.HasPrefix(k, "X-") || k == "Content-Type" || k == "Content-Length" ||
			k == "ETag" || k == "Location" || k == "Accept-Ranges" || k == "Content-Range" {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		io.Copy(w, resp.Body)
	}
}

var _ = fmt.Sprintf
