// Package downloader implements `dldw get`: resolve via the control API,
// parallel ranged downloads from presigned URLs, resume via .part metadata,
// sha256 verification and explicit direct fallback (spec 3.5).
package downloader

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIError is a structured error from the control API.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("api: HTTP %d", e.Status)
	}
	return fmt.Sprintf("api: %s: %s (HTTP %d, request_id=%s)", e.Code, e.Message, e.Status, e.RequestID)
}

// IsCode reports whether err is an APIError with the given code.
func IsCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// Artifact mirrors the server artifact metadata.
type Artifact struct {
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ETag        string `json:"etag"`
	ContentType string `json:"content_type"`
}

// Download describes the presigned transfer plan.
type DownloadPlan struct {
	Mode          string    `json:"mode"`
	URLs          []string  `json:"urls"`
	ExpiresAt     time.Time `json:"expires_at"`
	SupportsRange bool      `json:"supports_range"`
}

// TaskView is the client-side view of a cache task.
type TaskView struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	Status       string    `json:"status"`
	Progress     float64   `json:"progress"`
	Error        string    `json:"error"`
	ErrorCode    string    `json:"error_code"`
	Retries      int       `json:"retries"`
	Artifact     *Artifact `json:"artifact"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ResolveResponse mirrors POST /api/v1/resolve.
type ResolveResponse struct {
	RequestID string     `json:"request_id"`
	Status    string     `json:"status"`
	CacheKey  string     `json:"cache_key"`
	Artifact  *Artifact  `json:"artifact"`
	Download  *DownloadPlan `json:"download"`
	Task      *TaskView  `json:"task"`
}

// TaskResponse mirrors GET /api/v1/tasks/:id.
type TaskResponse struct {
	RequestID string    `json:"request_id"`
	Task      *TaskView `json:"task"`
}

// WhitelistResponse mirrors GET /api/v1/whitelist.
type WhitelistResponse struct {
	RequestID string   `json:"request_id"`
	Version   string   `json:"version"`
	Entries   []string `json:"entries"`
}

// IntrospectResponse mirrors POST /api/v1/introspect.
type IntrospectResponse struct {
	RequestID       string         `json:"request_id"`
	OK              bool           `json:"ok"`
	ServerTime      time.Time      `json:"server_time"`
	Version         string         `json:"version"`
	Token           *TokenInfo     `json:"token"`
	Storage         map[string]any `json:"storage"`
	WhitelistVersion string        `json:"whitelist_version"`
}

// TokenInfo is the token section of introspect.
type TokenInfo struct {
	Valid     bool      `json:"valid"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// HealthResponse mirrors GET /healthz.
type HealthResponse struct {
	Status string    `json:"status"`
	Time   time.Time `json:"time"`
}

// TokenActionResponse mirrors POST /api/v1/token.
type TokenActionResponse struct {
	RequestID string    `json:"request_id"`
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Action    string    `json:"action"`
}

// Client talks to the dldw control API. Its HTTP transport never uses env
// proxies and is safe to use while the local proxy is running.
type Client struct {
	base     string
	token    string
	clientID string
	hc       *http.Client
}

// NewAPIClient builds a control API client. tlsSkipVerify is for dev servers.
func NewAPIClient(base, token, clientID string, tlsSkipVerify ...bool) (*Client, error) {
	if base == "" {
		return nil, errors.New("downloader: empty server URL")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("downloader: invalid server URL %q", base)
	}
	tr := &http.Transport{
		Proxy:       nil, // never route control API traffic through env proxies
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	if len(tlsSkipVerify) > 0 && tlsSkipVerify[0] {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	return &Client{
		base:     strings.TrimRight(base, "/"),
		token:    token,
		clientID: clientID,
		hc:       &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}, nil
}

// SetToken updates the bearer token.
func (c *Client) SetToken(tok string) { c.token = tok }

// Base returns the server base URL.
func (c *Client) Base() string { return c.base }

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("api unreachable: %w", err)
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		ae := &APIError{Status: resp.StatusCode, RequestID: resp.Header.Get("X-Dldw-Request-Id")}
		var errEnvelope struct {
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(buf, &errEnvelope) == nil && errEnvelope.Error != nil {
			ae.Code = errEnvelope.Error.Code
			ae.Message = errEnvelope.Error.Message
		}
		return ae
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(buf, out)
}

type resolveRequest struct {
	URL      string `json:"url"`
	ClientID string `json:"client_id"`
	Caps     struct {
		Range      bool `json:"range"`
		Concurrent bool `json:"concurrent"`
		SHA256     bool `json:"sha256"`
	} `json:"capabilities"`
}

// Resolve queries the cache for rawURL.
func (c *Client) Resolve(ctx context.Context, rawURL string) (*ResolveResponse, error) {
	req := resolveRequest{URL: rawURL, ClientID: c.clientID}
	req.Caps.Range = true
	req.Caps.Concurrent = true
	req.Caps.SHA256 = true
	var out ResolveResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/resolve", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Task fetches task status by id.
func (c *Client) Task(ctx context.Context, id string) (*TaskView, error) {
	var out TaskResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/tasks/"+id, nil, &out); err != nil {
		return nil, err
	}
	return out.Task, nil
}

// Refresh re-issues presigned URLs for a ready task.
func (c *Client) Refresh(ctx context.Context, id string) (*ResolveResponse, error) {
	var out ResolveResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/tasks/"+id+"/refresh", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Whitelist fetches the current server whitelist.
func (c *Client) Whitelist(ctx context.Context) (*WhitelistResponse, error) {
	var out WhitelistResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/whitelist", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Introspect asks the server to validate this token and probe its deps.
func (c *Client) Introspect(ctx context.Context) (*IntrospectResponse, error) {
	var out IntrospectResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/introspect", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Health checks liveness.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.do(ctx, http.MethodGet, "/healthz", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterToken obtains a fresh device token.
func (c *Client) RegisterToken(ctx context.Context, clientID string) (*TokenActionResponse, error) {
	var out TokenActionResponse
	body := map[string]string{"action": "register", "client_id": clientID}
	if err := c.do(ctx, http.MethodPost, "/api/v1/token", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Raw performs an arbitrary API request (used by doctor/bench).
func (c *Client) Raw(ctx context.Context, method, path string, body any, out any) error {
	return c.do(ctx, method, path, body, out)
}
