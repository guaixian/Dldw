// Package gomod 实现 Go module proxy 拉穿镜像（GOPROXY 协议）：
//
//	GET /gomod/<module>/@v/<ver>.zip|.mod|.info   版本化文件（不可变）-> 缓存 302
//	GET /gomod/<module>/@v/list、/@latest        动态 -> 流式透传
//	GET /gomod/sumdb/...                          校验和数据库 -> 透传
//
// 客户端接入（wrapper 自动注入，用户已设 GOPROXY 时尊重用户）：
//	GOPROXY=http://127.0.0.1:18080/gomod,direct
//
// 注意：module 路径大小写与转义（%21 等）有语义，不能走 urlcanon 的
// host 小写/路径重建，缓存键直接对原始转义路径计算。
package gomod

import (
	"io"
	"net/http"
	"strings"
	"time"

	"dldw/internal/server/mirrorcore"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/tasks"
)

const familyGoMod = "go-module"

// Config 配置 gomod 镜像。
type Config struct {
	Origin      string   `json:"-"` // 兼容单源写法
	Origins     []string // 上游 GOPROXY 列表（顺序回退），如 [proxy.golang.org, goproxy.cn]
	PassTimeout time.Duration
}

// Mirror 是 Go module proxy 镜像。
type Mirror struct {
	origins []string
	fetch   *mirrorcore.Fetcher
	group   *mirrorcore.Group
	client  *http.Client
	timeout time.Duration
}

// New 构造。client 用于动态路径透传（nil = 默认直连）。
func New(cfg Config, client *http.Client, stor storage.Storage, exec executor.Executor, store *tasks.Store, tmpDir string, presignTTL time.Duration) *Mirror {
	origins := cfg.Origins
	if origins == nil {
		origins = []string{}
		for _, s := range []string{cfg.Origin, "https://proxy.golang.org"} {
			if s != "" {
				origins = append(origins, s)
			}
		}
	}
	for i := range origins {
		origins[i] = strings.TrimRight(origins[i], "/")
	}
	if cfg.PassTimeout <= 0 {
		cfg.PassTimeout = time.Minute
	}
	return &Mirror{
		origins:  origins,
		fetch:    &mirrorcore.Fetcher{Stor: stor, Exec: exec, Store: store, TmpDir: tmpDir, PresignTTL: presignTTL},
		group:    mirrorcore.NewGroup(),
		client:   client,
		timeout:  cfg.PassTimeout,
	}
}

// ServeHTTP 处理 GET /gomod/{path...}。
func (m *Mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET/HEAD only", http.StatusMethodNotAllowed)
		return
	}
	// 保留转义形式（module 路径大小写/!转义有语义）
	p := r.URL.EscapedPath()
	p = strings.TrimPrefix(p, "/gomod/")
	p = strings.Trim(p, "/")
	if p == "" || strings.Contains(p, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}

	// 版本化的不可变文件 -> 缓存；其余（list/latest/sumdb）透传
	if isImmutable(p) {
		canonical := m.origins[0] + "/" + p
		candidates := make([]string, 0, len(m.origins))
		for _, o := range m.origins {
			candidates = append(candidates, o+"/"+p)
		}
		v, _ := m.group.Do(familyGoMod+"\n"+canonical, func() (any, error) {
			return m.fetch.PresignOrFetchMulti(r.Context(), canonical, candidates, familyGoMod, "gomod-mirror")
		})
		target, _ := v.(string)
		if target == "" {
			http.Error(w, "origin fetch failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
		return
	}
	m.servePassthrough(w, r, m.origins[0]+"/"+p)
}

// isImmutable 判断 <module>/@v/<version>.{zip,mod,info}（不可变文件）。
func isImmutable(p string) bool {
	if !strings.Contains(p, "/@v/") {
		return false
	}
	for _, ext := range []string{".zip", ".mod", ".info"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func (m *Mirror) servePassthrough(w http.ResponseWriter, r *http.Request, upstream string) {
	client := m.client
	if client == nil {
		client = &http.Client{Timeout: m.timeout}
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, h := range []string{"Accept", "If-Modified-Since", "If-None-Match"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range []string{"Content-Type", "Content-Length", "ETag", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		io.Copy(w, resp.Body)
	}
}
