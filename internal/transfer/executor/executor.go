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
	"os"
	"path/filepath"
	"strings"
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
	FollowRedirect bool
}

// Builtin is the default zero-dependency executor.
type Builtin struct {
	cfg    BuiltinConfig
	client *http.Client
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
		Proxy:                 nil,
		DialContext:           policy.DialContext,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    true, // artifacts are already compressed; avoid gzip traps
	}
	return &Builtin{cfg: cfg, client: &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", len(via))
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("refused redirect to %s", req.URL.Scheme)
			}
			return nil
		},
	}}
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
			return nil, fmt.Errorf("%w: HTTP %d", ErrRetryable, resp.StatusCode)
		}
		return nil, fmt.Errorf("builtin: HTTP %d for %s", resp.StatusCode, sanitizeURLForLog(rawURL))
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
	written, err := io.Copy(io.MultiWriter(tmp, h), limit)
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
