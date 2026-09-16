// Package wrapper implements the dldw command wrapper (spec 3.2): start the
// local proxy, run tool adapters, inject proxy env, exec the child with full
// stdio passthrough, forward signals and map exit codes.
package wrapper

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"dldw/internal/client/adapters"
	"dldw/internal/client/config"
	"dldw/internal/client/downloader"
	"dldw/internal/client/proxy"
	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
)

// Options for one wrapped invocation.
type Options struct {
	Tool  string
	Args  []string
	Cfg   config.Config
	Token string // device token ("" -> tunnel disabled)
	Server string // effective server base URL ("" -> tunnel disabled)

	NoProxy       bool
	Apply         bool // adapters --apply
	Verbose       int
	Stdout        io.Writer
	Stderr        io.Writer
	Stdin         io.Reader
	ForceTunnel   bool // debug: tunnel non-whitelisted too (still SSRF checked)
}

// Run executes the wrapped tool and returns its exit code.
func Run(opts Options) int {
	stdout := orWriter(opts.Stdout)
	stderr := orWriter(opts.Stderr)
	debugf := func(format string, args ...any) {
		if opts.Verbose > 0 {
			fmt.Fprintf(stderr, "dldw: "+format+"\n", args...)
		}
	}

	bin, err := exec.LookPath(opts.Tool)
	if err != nil {
		fmt.Fprintf(stderr, "dldw: command not found: %s\n", opts.Tool)
		return 127
	}
	info := adapters.Identify(opts.Tool)
	if opts.Verbose > 0 {
		fmt.Fprintf(stderr, "dldw: wrapping %s (compat=%s)\n", info.Name, info.Level)
	}

	var (
		px       *proxy.Server
		proxyURL string
	)
	if !opts.NoProxy {
		px, err = startProxy(opts, debugf)
		if err != nil {
			fmt.Fprintf(stderr, "dldw: %v\n", err)
			return 3
		}
		proxyURL = px.URL()
		defer px.Stop(5 * time.Second)
		debugf("local proxy on %s", proxyURL)
	}

	// adapter pre-step (hints or --apply)
	if !opts.NoProxy {
		adapters.PreTool(adapters.PreOptions{
			Tool: opts.Tool, ProxyURL: proxyURL, Apply: opts.Apply,
			Stderr: stderr, Verbose: opts.Verbose > 0,
		})
	}

	// child env
	env := adapters.BuildEnv(os.Environ(), proxyURL)

	// 镜像自动注入：uv/pip/npm 系工具且用户未自行配置 index/registry 时，
	// 指向服务端拉穿镜像（探测失败静默跳过）
	if opts.Server != "" {
		if extra := injectMirrors(opts, info.Name, opts.Args, env); len(extra) > 0 {
			env = append(env, extra...)
			for _, kv := range extra {
				fmt.Fprintf(stderr, "dldw: mirror %s\n", kv)
			}
		}
	}

	cmd := exec.Command(bin, opts.Args...)
	cmd.Stdin = orReader(opts.Stdin)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = env
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "dldw: failed to start %s: %v\n", opts.Tool, err)
		return 127
	}

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	var sigOnce sync.Once
	go func() {
		for sig := range sigCh {
			debugf("signal %v -> child", sig)
			sigOnce.Do(func() { forwardSignal(cmd, sig) })
			// repeated signals: escalate to kill
			go func(s os.Signal) {
				<-time.After(3 * time.Second)
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
			}(sig)
		}
	}()

	waitErr := cmd.Wait()
	if px != nil {
		px.Stop(5 * time.Second)
	}

	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code := ee.ExitCode()
			if code == -1 {
				// signaled
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					code = 128 + int(ws.Signal())
				} else {
					code = 130 // SIGINT convention
				}
			}
			return code
		}
		fmt.Fprintf(stderr, "dldw: wait: %v\n", waitErr)
		return 1
	}
	return 0
}

// injectMirrors 探测服务端镜像能力并生成注入的环境变量（失败静默）。
func injectMirrors(opts Options, tool string, args, env []string) []string {
	client, err := downloader.NewAPIClient(opts.Server, "", "")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	caps, err := client.Capabilities(ctx)
	if err != nil || caps == nil {
		return nil
	}
	return adapters.InjectMirrors(tool, args, env, opts.Server, adapters.MirrorCaps{
		PyPI:   caps.PyPI,
		NPM:    caps.NPM,
		GoMod:  caps.GoMod,
	})
}

func orWriter(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stdout
}

func orReader(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return os.Stdin
}

// startProxy builds and starts the local proxy with whitelist + tunnel.
func startProxy(opts Options, debugf func(string, ...any)) (*proxy.Server, error) {
	wl := whitelist.NewStore(whitelist.Default())

	tunnelCfg, err := BuildTunnelConfig(opts, debugf)
	if err != nil {
		return nil, err
	}

	// best-effort server whitelist fetch
	if tunnelCfg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if client, cerr := downloader.NewAPIClient(opts.Server, opts.Token, ""); cerr == nil {
			if wlr, werr := client.Whitelist(ctx); werr == nil && len(wlr.Entries) > 0 {
				wl.Swap(whitelist.Parse(wlr.Version, wlr.Entries))
				debugf("whitelist v%s (%d entries)", wlr.Version, len(wlr.Entries))
			} else if werr != nil {
				debugf("whitelist fetch failed, using builtin default: %v", werr)
			}
		}
		cancel()
	}

	blockPrivate := true
	if opts.Cfg.Security.BlockPrivate != nil {
		blockPrivate = *opts.Cfg.Security.BlockPrivate
	}
	policy := &ssrf.Policy{
		BlockPrivate: blockPrivate,
		Ports:        opts.Cfg.Security.Ports,
	}
	if len(policy.Ports) == 0 {
		policy.Ports = []int{80, 443}
	}

	m := proxy.NewMetrics()
	px, err := proxy.Start(proxy.Options{
		Bind:        opts.Cfg.Proxy.Bind,
		Port:        opts.Cfg.Proxy.Port,
		WL:          wl,
		Policy:      policy,
		Tunnel:      tunnelCfg,
		IdleTimeout: opts.Cfg.ProxyIdleTimeout(),
		Metrics:     m,
		Debugf:      debugf,
	})
	if err != nil {
		return nil, fmt.Errorf("starting local proxy: %w", err)
	}
	return px, nil
}

// BuildTunnelConfig derives the server tunnel endpoint from the server URL
// via proxy.TunnelConfigFromServer. Returns nil when not configured.
func BuildTunnelConfig(opts Options, debugf func(string, ...any)) (*proxy.TunnelConfig, error) {
	if opts.Server == "" || opts.Token == "" {
		return nil, nil
	}
	return proxy.TunnelConfigFromServer(opts.Server, opts.Token, clientIDFor(opts), opts.Cfg.TLSSkipVerify)
}

func clientIDFor(opts Options) string {
	creds, err := config.LoadCredentials(opts.Cfg.TokenFilePath())
	if err == nil && creds.ClientID != "" {
		return creds.ClientID
	}
	return "dev_anon"
}
