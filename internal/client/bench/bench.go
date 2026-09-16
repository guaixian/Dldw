// Package bench measures transfer performance per mode: direct, tunnel
// (through the local proxy + server egress) and presigned (cache fast path),
// reporting TTFB, throughput and failure (spec 7).
package bench

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"dldw/internal/client/config"
	"dldw/internal/client/downloader"
	"dldw/internal/client/proxy"
	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
)

// Mode selects the measured path.
type Mode string

const (
	ModeDirect    Mode = "direct"
	ModeTunnel    Mode = "tunnel"
	ModePresigned Mode = "presigned"
)

// Result of one benchmark run.
type Result struct {
	Mode  Mode
	TTFB  time.Duration
	Total time.Duration
	Bytes int64
	Err   error
}

func (r Result) Mbps() float64 {
	if r.Total <= 0 || r.Bytes <= 0 {
		return 0
	}
	return float64(r.Bytes) / (1024 * 1024) / r.Total.Seconds()
}

// Options for benchmarking.
type Options struct {
	Cfg    config.Config
	Server string
	Token  string
	Modes  []Mode
}

// Run measures each requested mode for rawURL.
func Run(ctx context.Context, rawURL string, opts Options) []Result {
	var out []Result
	for _, m := range opts.Modes {
		switch m {
		case ModeDirect:
			out = append(out, measure(ctx, rawURL, plainClient()))
		case ModeTunnel:
			res := benchTunnel(ctx, rawURL, opts)
			out = append(out, res)
		case ModePresigned:
			out = append(out, benchPresigned(ctx, rawURL, opts))
		}
	}
	return out
}

func plainClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   0,
	}
}

func measure(ctx context.Context, rawURL string, hc *http.Client) Result {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{Err: err}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{Err: err}
	}
	defer resp.Body.Close()
	ttfb := time.Since(start)
	if resp.StatusCode/100 != 2 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return Result{TTFB: ttfb, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	}
	n, err := io.Copy(io.Discard, resp.Body)
	total := time.Since(start)
	return Result{TTFB: ttfb, Total: total, Bytes: n, Err: err}
}

func benchTunnel(ctx context.Context, rawURL string, opts Options) Result {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Result{Err: err}
	}
	host := u.Hostname()
	port := 80
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	// bench proxy: whitelist the target host so it egresses via tunnel
	wl := whitelist.NewStore(whitelist.Parse("bench", []string{host}))
	var tunnelCfg *proxy.TunnelConfig
	if opts.Server != "" && opts.Token != "" {
		tc, terr := proxy.TunnelConfigFromServer(opts.Server, opts.Token, "dev_bench", opts.Cfg.TLSSkipVerify)
		if terr != nil {
			return Result{Err: terr}
		}
		tunnelCfg = tc
	}
	px, err := proxy.Start(proxy.Options{
		WL:      wl,
		Policy:  &ssrf.Policy{BlockPrivate: false, Ports: []int{port}},
		Tunnel:  tunnelCfg,
	})
	if err != nil {
		return Result{Err: err}
	}
	defer px.Stop(2 * time.Second)

	hc := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustURL(px.URL())),
		},
	}
	res := measure(ctx, rawURL, hc)
	res.Mode = ModeTunnel
	return res
}

func benchPresigned(ctx context.Context, rawURL string, opts Options) Result {
	if opts.Server == "" || opts.Token == "" {
		return Result{Mode: ModePresigned, Err: fmt.Errorf("presigned mode requires server+token")}
	}
	client, err := downloader.NewAPIClient(opts.Server, opts.Token, "dev_bench", opts.Cfg.TLSSkipVerify)
	if err != nil {
		return Result{Mode: ModePresigned, Err: err}
	}
	resolveCtx, cancel := context.WithTimeout(ctx, opts.Cfg.TaskTimeoutDur())
	defer cancel()
	res, err := client.Resolve(resolveCtx, rawURL)
	if err != nil {
		return Result{Mode: ModePresigned, Err: err}
	}
	url0 := ""
	if res.Download != nil && len(res.Download.URLs) > 0 {
		url0 = res.Download.URLs[0]
	}
	if url0 == "" {
		// poll task until ready
		taskID := ""
		if res.Task != nil {
			taskID = res.Task.ID
		}
		if taskID == "" {
			return Result{Mode: ModePresigned, Err: fmt.Errorf("resolve status %s without task", res.Status)}
		}
		for {
			t, terr := client.Task(ctx, taskID)
			if terr != nil {
				return Result{Mode: ModePresigned, Err: terr}
			}
			if t.Status == "ready" {
				rr, rerr := client.Refresh(ctx, taskID)
				if rerr != nil {
					return Result{Mode: ModePresigned, Err: rerr}
				}
				if rr.Download != nil && len(rr.Download.URLs) > 0 {
					url0 = rr.Download.URLs[0]
				}
				break
			}
			if t.Status == "dead" {
				return Result{Mode: ModePresigned, Err: fmt.Errorf("task dead: %s", t.Error)}
			}
			select {
			case <-ctx.Done():
				return Result{Mode: ModePresigned, Err: ctx.Err()}
			case <-time.After(opts.Cfg.TaskPollWaitDur()):
			}
		}
	}
	if url0 == "" {
		return Result{Mode: ModePresigned, Err: fmt.Errorf("no presigned url")}
	}
	out := measure(ctx, url0, plainClient())
	out.Mode = ModePresigned
	return out
}

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

// Fprint renders a result table.
func Fprint(w io.Writer, results []Result) {
	fmt.Fprintln(w, "MODE       TTFB        TOTAL       SIZE        MB/s     ERROR")
	for _, r := range results {
		err := "-"
		if r.Err != nil {
			err = r.Err.Error()
		}
		fmt.Fprintf(w, "%-10s %-11s %-11s %-11s %-8.2f %s\n",
			r.Mode, r.TTFB.Round(time.Millisecond), r.Total.Round(time.Millisecond),
			humanBytes(r.Bytes), r.Mbps(), err)
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2fKiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

var _ = os.Stdout
var _ = strings.TrimSpace
