package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dldw/internal/client/config"
	"dldw/internal/client/downloader"
	"dldw/internal/hunits"
)

// cmdGet 实现 `dldw get [flags] <url> [output]`（spec 3.5 主链路）：
//
//	有 server+token：POST /resolve -> cached(直接预签名下载)
//	                                 或 queued/downloading(轮询任务)->refresh->下载
//	无 server/token：direct 模式（源站 HEAD 探测 Range 后分块并发）
//
// 下载引擎特性：.part + bitmap 断点续传、临期 403/410 自动 refresh、
// sha256 校验、进度条（stderr）、Ctrl-C 中断后可续传。
// 退出码：0 成功；2 参数错误；4 令牌失效(E_RESOLVE_AUTH)；1 其他失败。
func cmdGet(cfg config.Config, g globals, args []string) int {
	var (
		concurrency int
		chunk       string
		output      string
		force       bool
		direct      string
	)
	fs := newFlagSet("get")
	fs.IntVar(&concurrency, "concurrency", cfg.Concurrency())
	fs.IntVar(&concurrency, "j", cfg.Concurrency())
	fs.StrVar(&chunk, "chunk", cfg.Download.ChunkSize)
	fs.StrVar(&output, "output", "")
	fs.StrVar(&output, "O", "")
	fs.BoolVar(&force, "force", false)
	fs.StrVar(&direct, "direct-fallback", "")
	urlArg, out := fs.Parse(args)
	if urlArg == "" {
		fmt.Fprintln(os.Stderr, "usage: dldw get [flags] <url> [output]")
		return 2
	}
	if len(out) > 0 && output == "" {
		output = out[0]
	}
	chunkBytes, err := hunits.ParseBytes(chunk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dldw: bad --chunk %q: %v\n", chunk, err)
		return 2
	}
	if g.directFallback != nil && direct == "" {
		if *g.directFallback {
			direct = "always"
		} else {
			direct = "never"
		}
	}
	if direct == "" {
		direct = cfg.Download.DirectFallback
	}

	server := config.EffectiveServer(g.server, cfg)
	token := resolveToken(cfg, g)
	var api *downloader.Client
	if server != "" && token != "" {
		api, err = downloader.NewAPIClient(server, token, clientIDOf(cfg), cfg.TLSSkipVerify)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 2
		}
	} else if g.verbose > 0 {
		fmt.Fprintln(os.Stderr, "dldw: no server/token configured; direct mode")
	}

	if resume, size := downloader.ResumeState(output); resume && g.verbose > 0 {
		fmt.Fprintf(os.Stderr, "dldw: resuming %s (%s done so far)\n", output+".part", hunitsFmt(size))
	}

	progress := newProgressPrinter(g.verbose)
	opts := downloader.Options{
		Concurrency:    concurrency,
		ChunkSize:      chunkBytes,
		Output:         output,
		Overwrite:      force,
		TaskTimeout:    cfg.TaskTimeoutDur(),
		PollWait:       cfg.TaskPollWaitDur(),
		DirectFallback: direct,
		Progress:       progress.tick,
		Verbose:        g.verbose > 0,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	start := time.Now()
	res, err := downloader.Download(ctx, urlArg, opts, api)
	progress.done()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
		if downloader.IsCode(err, "E_RESOLVE_AUTH") {
			fmt.Fprintln(os.Stderr, "hint: run `dldw doctor --fix` to register a token")
			return 4
		}
		return 1
	}
	if res.Size > 0 {
		elapsed := time.Since(start)
		mbps := float64(res.Size) / (1024 * 1024) / elapsed.Seconds()
		fmt.Fprintf(os.Stderr, "dldw: %s (%s, %s mode) in %s (%.2f MiB/s)\n",
			res.Path, hunitsFmt(res.Size), res.Mode, elapsed.Round(time.Millisecond), mbps)
	} else {
		fmt.Fprintf(os.Stderr, "dldw: %s (%s mode)\n", res.Path, res.Mode)
	}
	return 0
}

func hunitsFmt(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// progressPrinter renders a single-line progress on stderr.
type progressPrinter struct {
	enabled bool
	last    time.Time
	doneCh  chan struct{}
}

func newProgressPrinter(verbose int) *progressPrinter {
	return &progressPrinter{enabled: verbose >= 0, doneCh: make(chan struct{})}
}

func (p *progressPrinter) tick(done, total int64) {
	if !p.enabled || total <= 0 {
		return
	}
	now := time.Now()
	if now.Sub(p.last) < 200*time.Millisecond && done < total {
		return
	}
	p.last = now
	pct := float64(done) / float64(total) * 100
	fmt.Fprintf(os.Stderr, "\rdldw: %s / %s (%.1f%%)", hunitsFmt(done), hunitsFmt(total), pct)
	if done >= total {
		fmt.Fprint(os.Stderr, "\n")
	}
}

func (p *progressPrinter) done() {
	select {
	case <-p.doneCh:
	default:
		close(p.doneCh)
	}
}

// cmdEnv 实现 `dldw env [--shell ...]`：输出与常驻代理（dldw proxy）配套的
// 环境变量导出语句。端口取 proxy.port（为 0 时提示使用 8080 配套
// `dldw proxy --port 8080`）。支持的 shell：bash/zsh/fish/powershell/cmd。
//
//	用法：eval "$(dldw env)"                          # bash/zsh
//	      dldw env --shell powershell | Invoke-Expression
func cmdEnv(cfg config.Config, g globals, args []string) int {
	shell := ""
	fs := newFlagSet("env")
	fs.StrVar(&shell, "shell", "")
	_, rest := fs.Parse(args)
	if shell == "" && len(rest) > 0 {
		shell = rest[0]
	}
	if shell == "" {
		shell = detectShell()
	}
	port := cfg.Proxy.Port
	if port == 0 {
		port = 8080 // suggests pairing with `dldw proxy --port 8080`
	}
	proxyURL := "http://" + cfg.Proxy.Bind + ":" + strconv.Itoa(port)
	if cfg.Proxy.Bind == "" {
		proxyURL = "http://127.0.0.1:" + strconv.Itoa(port)
	}
	noProxy := "localhost,127.0.0.1,::1,*.local"
	vars := [][2]string{
		{"http_proxy", proxyURL},
		{"https_proxy", proxyURL},
		{"HTTP_PROXY", proxyURL},
		{"HTTPS_PROXY", proxyURL},
		{"no_proxy", noProxy},
		{"NO_PROXY", noProxy},
	}
	switch shell {
	case "fish":
		for _, kv := range vars {
			fmt.Printf("set -gx %s %s\n", kv[0], kv[1])
		}
	case "powershell", "pwsh":
		for _, kv := range vars {
			fmt.Printf("$env:%s = '%s'\n", kv[0], kv[1])
		}
	case "cmd":
		for _, kv := range vars {
			fmt.Printf("set %s=%s\n", kv[0], kv[1])
		}
	case "bash", "zsh", "sh", "":
		for _, kv := range vars {
			fmt.Printf("export %s=%s\n", kv[0], kv[1])
		}
	default:
		fmt.Fprintf(os.Stderr, "dldw: unsupported shell %q\n", shell)
		return 2
	}
	fmt.Fprintf(os.Stderr, "# starts a persistent proxy: dldw proxy --port %d\n", port)
	return 0
}

func detectShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		base := s[strings.LastIndexByte(s, '/')+1:]
		if base != "" {
			return base
		}
	}
	if _, ok := os.LookupEnv("PSModulePath"); ok {
		return "powershell"
	}
	if _, ok := os.LookupEnv("COMSPEC"); ok && strings.EqualFold(os.Getenv("OSTYPE"), "") {
		return "cmd"
	}
	return "bash"
}

func clientIDOf(cfg config.Config) string {
	if creds, err := config.LoadCredentials(cfg.TokenFilePath()); err == nil && creds.ClientID != "" {
		return creds.ClientID
	}
	return ""
}
