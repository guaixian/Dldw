// Package executor performs the actual artifact download on the server side.
// The builtin executor is a plain, SSRF-guarded HTTP fetcher; aria2ctl wraps
// an external aria2 RPC endpoint for hardened production setups (spec 4.3).
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"dldw/internal/policy/ssrf"
)

// Result of a completed fetch.
type Result struct {
	LocalPath   string
	Size        int64
	SHA256      string
	ETag        string
	ContentType string
}

// Executor downloads rawURL into destDir/hintName.
type Executor interface {
	Name() string
	Fetch(ctx context.Context, rawURL, destDir, hintName string) (*Result, error)
	Healthy(ctx context.Context) error
}

// ErrRetryable wraps transient failures.
var ErrRetryable = errors.New("executor: transient failure")

// BuiltinConfig configures the builtin fetcher.
type BuiltinConfig struct {
	Policy        *ssrf.Policy // egress policy; nil = default (80/443, block private)
	Retries       int          // per-URL attempts (default 3)
	MaxBytes      int64        // hard artifact size cap; 0 = unlimited
	Timeout       time.Duration
	UserAgent     string
	MaxRedirects  int
	// UpstreamProxy is an optional http(s):// proxy for ALL origin fetches
	// (e.g. Xray mixed inbound http://127.0.0.1:10808). When set, target
	// DNS/SSRF resolution is delegated to the proxy; the port allowlist
	// above still applies locally. Private/loopback targets bypass the
	// proxy and go direct (a VPS cannot reach your LAN).
	UpstreamProxy string
	// ProgressFunc is called with (bytesRead, totalBytes) during download.
	// totalBytes is -1 when Content-Length is unknown.
	ProgressFunc func(read, total int64)
}

// Builtin is the default zero-dependency executor.
type Builtin struct {
	cfg       BuiltinConfig
	client    *http.Client
	policy    *ssrf.Policy
	proxyURL  string
}

func NewBuiltin(cfg BuiltinConfig) *Builtin {
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "dldw-server/1.0 (+https://dldw.example.com)"
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 10
	}
	policy := cfg.Policy
	if policy == nil {
		policy = &ssrf.Policy{BlockPrivate: true}
	}
	tr := &http.Transport{
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    true, // artifacts are already compressed; avoid gzip traps
	}
	if cfg.UpstreamProxy != "" {
		// 经上游代理：私网/回环目标绕过代理直连（VPS 连不上你的局域网）。
		// 对域名做 DNS 解析后判定（host.docker.internal 解析为 192.168.x.x）。
		pu, err := url.Parse(cfg.UpstreamProxy)
		if err == nil && (pu.Scheme == "http" || pu.Scheme == "https") {
			dnsCache := &hostClassCache{}
			tr.Proxy = func(req *http.Request) (*url.URL, error) {
				if dnsCache.isPrivate(req.URL.Hostname()) {
					return nil, nil // 直连，不走代理
				}
				return pu, nil
			}
			tr.DialContext = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
		}
	} else {
		// 直连：SSRF 策略拨号（拨号时校验 IP，防 DNS rebinding）
		tr.Proxy = nil
		tr.DialContext = policy.DialContext
	}
	return &Builtin{
		cfg:    cfg,
		client: &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", len(via))
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("refused redirect to %s", req.URL.Scheme)
			}
			return nil
		}},
		policy:   policy,
		proxyURL: cfg.UpstreamProxy,
	}
}

// SetProgressFunc sets or updates the progress callback (thread-safe enough
// for our single-threaded engine usage).
func (b *Builtin) SetProgressFunc(fn func(read, total int64)) {
	b.cfg.ProgressFunc = fn
}

func (b *Builtin) Name() string { return "builtin" }

func (b *Builtin) Healthy(ctx context.Context) error { return nil }

// Fetch downloads rawURL with retries, streaming to a temp file and computing
// sha256 while writing.
func (b *Builtin) Fetch(ctx context.Context, rawURL, destDir, hintName string) (*Result, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt <= b.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		res, err := b.fetchOnce(ctx, rawURL, destDir, hintName)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !errors.Is(err, ErrRetryable) && !isRetryableNet(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("builtin: retries exhausted: %v", lastErr)
}

func isRetryableNet(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

func (b *Builtin) fetchOnce(ctx context.Context, rawURL, destDir, hintName string) (*Result, error) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// 上游代理模式下目标 DNS/SSRF 由代理负责，但端口白名单仍在本地强制
	if b.proxyURL != "" && b.policy != nil {
		port := 80
		if req.URL.Scheme == "https" {
			port = 443
		}
		if p := req.URL.Port(); p != "" {
			if n, aerr := strconv.Atoi(p); aerr == nil {
				port = n
			}
		}
		if perr := b.policy.CheckPort(port); perr != nil {
			return nil, perr
		}
	}
	req.Header.Set("User-Agent", b.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRetryable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			return nil, fmt.Errorf("%w: HTTP %d (url: %s)", ErrRetryable, resp.StatusCode, sanitizeURLForLog(req.URL.String()))
		}
		return nil, fmt.Errorf("builtin: HTTP %d (url: %s)", resp.StatusCode, sanitizeURLForLog(req.URL.String()))
	}

	name := sanitizeFilename(hintName)
	if name == "" {
		name = "artifact.bin"
	}
	tmp, err := os.CreateTemp(destDir, ".fetch-*-"+name)
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmp != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	limit := io.Reader(resp.Body)
	if b.cfg.MaxBytes > 0 {
		limit = io.LimitReader(resp.Body, b.cfg.MaxBytes+1)
	}
	// 实时进度：包装 body 追踪已读字节数
	total := resp.ContentLength // -1 if unknown
	pr := &progressReader{r: limit, total: total, fn: b.cfg.ProgressFunc}
	written, err := io.Copy(io.MultiWriter(tmp, h), pr)
	pr.close()
	if err != nil {
		tmp.Close()
		tmp = nil
		return nil, fmt.Errorf("%w: copy: %v", ErrRetryable, err)
	}
	if b.cfg.MaxBytes > 0 && written > b.cfg.MaxBytes {
		tmp.Close()
		tmp = nil
		return nil, fmt.Errorf("builtin: artifact exceeds MaxBytes=%d", b.cfg.MaxBytes)
	}
	if err := tmp.Close(); err != nil {
		tmp = nil
		return nil, err
	}
	tmp = nil

	final := filepath.Join(destDir, name)
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	return &Result{
		LocalPath:   final,
		Size:        written,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		ETag:        strings.Trim(resp.Header.Get("ETag"), `"`),
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

func sanitizeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.TrimLeft(b.String(), ".")
	if len(out) > 128 {
		out = out[len(out)-128:]
	}
	return out
}

func sanitizeURLForLog(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i] + "?..."
	}
	return u
}

// hostClassCache caches DNS lookups for proxy bypass decisions.
type hostClassCache struct {
	mu    sync.RWMutex
	known map[string]bool // host -> isPrivate
}

func (c *hostClassCache) isPrivate(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	// 常见本地主机名快速路径
	if host == "host.docker.internal" || host == "localhost" ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home") {
		return true
	}
	c.mu.RLock()
	v, ok := c.known[host]
	c.mu.RUnlock()
	if ok {
		return v
	}
	// DNS 解析后判定（失败时保守返回 false = 走代理）
	addrs, err := net.LookupHost(host)
	isPriv := false
	if err == nil {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
					isPriv = true
					break
				}
			}
		}
	}
	c.mu.Lock()
	if c.known == nil {
		c.known = map[string]bool{}
	}
	c.known[host] = isPriv
	c.mu.Unlock()
	return isPriv
}

// progressReader wraps a reader and reports bytes read to fn periodically.
type progressReader struct {
	r        io.Reader
	read     int64
	total    int64 // -1 if unknown
	fn       func(read, total int64)
	lastTick time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	// 每秒最多回调一次，避免小文件刷屏
	if p.fn != nil && time.Since(p.lastTick) > time.Second {
		p.lastTick = time.Now()
		p.fn(p.read, p.total)
	}
	return n, err
}

func (p *progressReader) close() {
	if p.fn != nil {
		p.fn(p.read, p.total) // 最终回调
	}
}
