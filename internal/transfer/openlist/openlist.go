// Package openlist is a minimal client for OpenList (AList fork) metadata
// APIs. In v1 it is optional infrastructure: the task engine works without it
// and uses it only for supplementary metadata when configured (spec 4.3).
package openlist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config for the OpenList connection.
type Config struct {
	BaseURL string // e.g. http://openlist:5244
	Token   string // OpenList API token
}

type Client struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Client {
	return &Client{cfg: cfg, client: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}}
}

type listResponse struct {
	Code    int `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Content []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			IsDir bool  `json:"is_dir"`
			Sign string `json:"sign"`
		} `json:"content"`
	} `json:"data"`
}

// Ping verifies the API answers.
func (c *Client) Ping(ctx context.Context) error {
	var out listResponse
	if err := c.get(ctx, "/api/fs/list", url.Values{"path": {"/"}}, &out); err != nil {
		return err
	}
	if out.Code != 200 {
		return fmt.Errorf("openlist: code %d: %s", out.Code, out.Message)
	}
	return nil
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := strings.TrimRight(c.cfg.BaseURL, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", c.cfg.Token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("openlist: HTTP %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, out)
}
