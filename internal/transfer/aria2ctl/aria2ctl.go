// Package aria2ctl drives an aria2 JSON-RPC endpoint as an alternative fetch
// executor (spec 4.3). It is optional: the builtin executor is the default.
package aria2ctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dldw/internal/transfer/executor"
)

// Config for the aria2 RPC connection.
type Config struct {
	RPCURL    string // e.g. http://127.0.0.1:6800/jsonrpc
	Secret    string // aria2 rpc-secret (without "token:" prefix)
	PollEvery time.Duration
	Timeout   time.Duration
}

type Client struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Client {
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 500 * time.Millisecond
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Minute
	}
	return &Client{cfg: cfg, client: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: "dldw", Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.RPCURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aria2: HTTP %d", resp.StatusCode)
	}
	var rr rpcResponse
	if err := json.Unmarshal(buf, &rr); err != nil {
		return err
	}
	if rr.Error != nil {
		return fmt.Errorf("aria2: %s: %s", rr.Error.Message, method)
	}
	if out != nil {
		return json.Unmarshal(rr.Result, out)
	}
	return nil
}

func (c *Client) token() []any {
	p := []any{}
	if c.cfg.Secret != "" {
		p = append(p, "token:"+c.cfg.Secret)
	}
	return p
}

// Version returns the aria2 version (used by Healthy).
func (c *Client) Version(ctx context.Context) (string, error) {
	var v string
	if err := c.call(ctx, "aria2.getVersion", c.token(), &v); err != nil {
		return "", err
	}
	return v, nil
}

type aria2Status struct {
	GID         string   `json:"gid"`
	Status      string   `json:"status"`
	ErrorCode   string   `json:"errorCode"`
	ErrorMessage string  `json:"errorMessage"`
	TotalLength string   `json:"totalLength"`
	Files       []struct {
		Path         string `json:"path"`
		Length       string `json:"length"`
		URIs         []struct {
			URI string `json:"uri"`
		} `json:"uris"`
	} `json:"files"`
}

// Executor adapts Client to the executor.Executor interface.
type Executor struct {
	client *Client
}

func NewExecutor(cfg Config) *Executor { return &Executor{client: New(cfg)} }

func (e *Executor) Name() string { return "aria2" }

func (e *Executor) Healthy(ctx context.Context) error {
	_, err := e.client.Version(ctx)
	return err
}

// Fetch adds rawURL to aria2 with dir/out pinned, polls to completion, then
// computes sha256 of the file in place.
func (e *Executor) Fetch(ctx context.Context, rawURL, destDir, hintName string) (*executor.Result, error) {
	name := sanitizeFilename(hintName)
	if name == "" {
		name = "artifact.bin"
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	var gid string
	params := append(e.client.token(), []any{[]string{rawURL}}, map[string]any{
		"dir":                    destDir,
		"out":                    name,
		"allow-overwrite":        "true",
		"auto-file-renaming":     "false",
		"max-connection-per-server": "8",
		"min-split-size":         "8M",
		"split":                  "8",
		"timeout":                "60",
		"max-tries":              "5",
		"retry-wait":             "2",
	})
	if err := e.client.call(ctx, "aria2.addUri", params, &gid); err != nil {
		return nil, fmt.Errorf("%w: %v", executor.ErrRetryable, err)
	}

	deadline := time.Now().Add(e.client.cfg.Timeout)
	for {
		if ctx.Err() != nil {
			e.client.call(context.Background(), "aria2.forceRemove", append(e.client.token(), gid), nil)
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			e.client.call(context.Background(), "aria2.forceRemove", append(e.client.token(), gid), nil)
			return nil, errors.New("aria2: timeout waiting for download")
		}
		var st aria2Status
		params := append(e.client.token(), gid, []string{"gid", "status", "errorCode", "errorMessage", "totalLength", "files"})
		if err := e.client.call(ctx, "aria2.tellStatus", params, &st); err != nil {
			return nil, fmt.Errorf("%w: %v", executor.ErrRetryable, err)
		}
		switch st.Status {
		case "complete":
			return resultFromStatus(&st, name)
		case "error":
			return nil, fmt.Errorf("aria2: download failed: %s (%s)", st.ErrorMessage, st.ErrorCode)
		}
		select {
		case <-time.After(e.client.cfg.PollEvery):
		case <-ctx.Done():
		}
	}
}

func resultFromStatus(st *aria2Status, name string) (*executor.Result, error) {
	path := ""
	for _, f := range st.Files {
		if strings.HasSuffix(filepath.ToSlash(f.Path), "/"+name) || f.Path != "" {
			path = f.Path
			if strings.HasSuffix(filepath.ToSlash(path), "/"+name) {
				break
			}
		}
	}
	if path == "" {
		return nil, errors.New("aria2: no file path in status")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return &executor.Result{
		LocalPath:   path,
		Size:        info.Size(),
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		ContentType: "application/octet-stream",
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
