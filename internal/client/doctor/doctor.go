// Package doctor runs client side diagnostics (spec 7): port availability,
// time skew, DNS, server health/readiness, token, whitelist version, object
// storage probe, tool adapter status and leftover state. --fix repairs what
// it can (token registration, whitelist pinning).
package doctor

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"dldw/internal/client/config"
	"dldw/internal/client/downloader"
	"dldw/internal/ids"
)

// Status values for a check.
const (
	OK    = "ok"
	WARN  = "warn"
	FAIL  = "fail"
	SKIP  = "skip"
	FIXED = "fixed"
)

// Check is one diagnostic result.
type Check struct {
	Name   string
	Status string
	Detail string
	Hint   string
}

// Report aggregates checks.
type Report struct {
	Checks []Check
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

// HasFail reports whether any check failed.
func (r *Report) HasFail() bool {
	for _, c := range r.Checks {
		if c.Status == FAIL {
			return true
		}
	}
	return false
}

// Options for a doctor run.
type Options struct {
	Cfg    config.Config
	Server string
	Token  string
	Fix    bool
}

// Run executes all checks, applying fixes when requested.
func Run(opts Options) *Report {
	r := &Report{}
	cfg := opts.Cfg

	// 1. config
	if opts.Server == "" {
		r.add(Check{Name: "config", Status: WARN,
			Detail: "no server configured", Hint: "dldw config set server https://dldw.example.com"})
	} else {
		r.add(Check{Name: "config", Status: OK, Detail: "server=" + opts.Server})
	}

	// 2. proxy port availability / E_PROXY_BIND
	bind := net.JoinHostPort(cfg.Proxy.Bind, fmt.Sprint(cfg.Proxy.Port))
	if ln, err := net.Listen("tcp", bind); err != nil {
		r.add(Check{Name: "proxy_bind", Status: FAIL, Detail: bind + ": " + err.Error(),
			Hint: "E_PROXY_BIND: free the port or set proxy.port=0 (ephemeral)"})
	} else {
		ln.Close()
		r.add(Check{Name: "proxy_bind", Status: OK, Detail: bind + " available"})
	}

	// 3. token presence
	token := opts.Token
	if token == "" {
		if creds, err := config.LoadCredentials(cfg.TokenFilePath()); err == nil && creds.Token != "" {
			token = creds.Token
			r.add(Check{Name: "token_file", Status: OK, Detail: cfg.TokenFilePath()})
		} else {
			r.add(Check{Name: "token_file", Status: WARN, Detail: "no token at " + cfg.TokenFilePath(),
				Hint: "run with --fix or `dldw doctor --fix` to register"})
		}
	} else {
		r.add(Check{Name: "token_file", Status: OK, Detail: "token from flag/env"})
	}

	if opts.Server == "" {
		r.add(Check{Name: "server", Status: SKIP, Detail: "server checks skipped (no server)"})
		return r
	}

	// 4. DNS
	uhost := hostOf(opts.Server)
	if addrs, err := net.LookupHost(uhost); err != nil {
		r.add(Check{Name: "dns", Status: FAIL, Detail: uhost + ": " + err.Error()})
	} else {
		r.add(Check{Name: "dns", Status: OK, Detail: uhost + " -> " + strings.Join(addrs[:min(3, len(addrs))], ", ")})
	}

	client, _ := downloader.NewAPIClient(opts.Server, token, clientID(cfg), cfg.TLSSkipVerify)

	// 5. health + time skew
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if h, err := client.Health(ctx); err != nil {
		r.add(Check{Name: "healthz", Status: FAIL, Detail: err.Error(), Hint: "check server status / URL"})
		r.add(Check{Name: "time_skew", Status: SKIP, Detail: "unavailable"})
	} else {
		r.add(Check{Name: "healthz", Status: OK, Detail: h.Status})
		skew := time.Since(h.Time)
		if skew < 0 {
			skew = -skew
		}
		if skew > 30*time.Second {
			r.add(Check{Name: "time_skew", Status: WARN, Detail: skew.Truncate(time.Second).String() + " off server clock",
				Hint: "install a time sync service (ntp/chrony/w32tm)"})
		} else {
			r.add(Check{Name: "time_skew", Status: OK, Detail: skew.Truncate(time.Millisecond).String()})
		}
	}

	// 6. readyz
	if resp, err := postJSON(client, ctx, "/readyz"); err == nil {
		if s, _ := resp["status"].(string); s == "ok" {
			r.add(Check{Name: "readyz", Status: OK, Detail: "all subsystems ok"})
		} else {
			r.add(Check{Name: "readyz", Status: WARN, Detail: fmt.Sprint(resp["checks"])})
		}
	} else {
		r.add(Check{Name: "readyz", Status: WARN, Detail: err.Error()})
	}

	// 7. introspect: token validity + storage probe
	ictx, icancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer icancel()
	if intro, err := client.Introspect(ictx); err != nil {
		r.add(Check{Name: "token", Status: FAIL, Detail: err.Error(), Hint: "E_RESOLVE_AUTH: register again with --fix"})
		if opts.Fix {
			tryRegister(opts, r)
		}
	} else {
		if intro.Token != nil && intro.Token.Valid {
			r.add(Check{Name: "token", Status: OK,
				Detail: fmt.Sprintf("client=%s expires=%s", intro.Token.ClientID, intro.Token.ExpiresAt.Format(time.RFC3339))})
		}
		if st, _ := intro.Storage["ok"].(bool); st {
			r.add(Check{Name: "storage", Status: OK, Detail: fmt.Sprint(intro.Storage["name"])})
		} else {
			r.add(Check{Name: "storage", Status: FAIL, Detail: fmt.Sprint(intro.Storage["error"]),
				Hint: "server side object storage unreachable"})
		}
		// 8. whitelist version
		wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer wcancel()
		if wl, werr := client.Whitelist(wctx); werr == nil {
			if cfg.WhitelistVersion != "" && cfg.WhitelistVersion != wl.Version {
				if opts.Fix {
					cfg.WhitelistVersion = wl.Version
					if serr := cfg.Save(""); serr == nil {
						r.add(Check{Name: "whitelist_version", Status: FIXED, Detail: "pinned " + wl.Version})
					}
				} else {
					r.add(Check{Name: "whitelist_version", Status: WARN,
						Detail: fmt.Sprintf("local=%s server=%s", cfg.WhitelistVersion, wl.Version),
						Hint: "run --fix to pin the new version"})
				}
			} else {
				r.add(Check{Name: "whitelist_version", Status: OK, Detail: wl.Version + fmt.Sprintf(" (%d entries)", len(wl.Entries))})
			}
		}
	}

	// 9. tools
	tools := []string{"curl", "wget", "git", "pip", "uv", "npm", "conda", "apt", "dnf", "docker"}
	var present, missing []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err == nil {
			present = append(present, t)
		} else {
			missing = append(missing, t)
		}
	}
	r.add(Check{Name: "tools", Status: OK,
		Detail: "installed: " + strings.Join(present, " ") + " | absent: " + strings.Join(missing, " ")})

	// 10. leftover processes: check the configured fixed port occupancy
	if cfg.Proxy.Port != 0 {
		if c, err := net.DialTimeout("tcp", bind, 300*time.Millisecond); err == nil {
			c.Close()
			r.add(Check{Name: "leftover", Status: WARN, Detail: "something already listens on " + bind,
				Hint: "a dldw proxy may be running; reuse it or stop it"})
		} else {
			r.add(Check{Name: "leftover", Status: OK, Detail: "no listener on " + bind})
		}
	}
	return r
}

func (r *Report) lastFailed() *Check {
	for i := len(r.Checks) - 1; i >= 0; i-- {
		if r.Checks[i].Status == FAIL {
			return &r.Checks[i]
		}
	}
	return nil
}

func tryRegister(opts Options, r *Report) {
	if opts.Server == "" {
		return
	}
	cid := clientID(opts.Cfg)
	client, err := downloader.NewAPIClient(opts.Server, "", cid, opts.Cfg.TLSSkipVerify)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.RegisterToken(ctx, cid)
	if err != nil {
		for i := range r.Checks {
			if r.Checks[i].Name == "token" {
				r.Checks[i].Hint = "auto-register failed: " + err.Error()
			}
		}
		return
	}
	creds := &config.Credentials{ClientID: resp.ClientID, Token: resp.Token, Server: opts.Server}
	if err := config.SaveCredentials(opts.Cfg.TokenFilePath(), creds); err != nil {
		for i := range r.Checks {
			if r.Checks[i].Name == "token" {
				r.Checks[i].Hint = "registered but could not save: " + err.Error()
			}
		}
		return
	}
	r.add(Check{Name: "token_fix", Status: FIXED,
		Detail: "registered client " + resp.ClientID + " -> " + opts.Cfg.TokenFilePath()})
	// repair the originating check so the overall verdict is not a failure
	for i := range r.Checks {
		if r.Checks[i].Name == "token" {
			r.Checks[i].Status = FIXED
			r.Checks[i].Detail = "registered " + resp.ClientID
			r.Checks[i].Hint = ""
		}
	}
}

func clientID(cfg config.Config) string {
	if creds, err := config.LoadCredentials(cfg.TokenFilePath()); err == nil && creds.ClientID != "" {
		return creds.ClientID
	}
	return ids.NewClientID()
}

func hostOf(serverURL string) string {
	s := serverURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		if !strings.Contains(s, "]") || strings.HasSuffix(s, "]") {
			s = s[:i]
		}
	}
	return strings.Trim(s, "[]")
}

// postJSON is a tiny helper hitting an endpoint and decoding the JSON object.
func postJSON(c *downloader.Client, ctx context.Context, path string) (map[string]any, error) {
	// reuse health for GET endpoints
	req := struct{}{}
	_ = req
	var out map[string]any
	if err := c.Raw(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = os.Getenv
