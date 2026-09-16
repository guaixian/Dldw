package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dldw/internal/client/bench"
	"dldw/internal/client/config"
	"dldw/internal/client/doctor"
	"dldw/internal/client/downloader"
	"dldw/internal/client/proxy"
	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
	"dldw/internal/server/app"
)

// cmdDoctor implements `dldw doctor [--fix]`.
func cmdDoctor(cfg config.Config, g globals, args []string) int {
	fix := false
	fs := newFlagSet("doctor")
	fs.BoolVar(&fix, "fix", false)
	fs.Parse(args)
	if fix {
		fix = true
	}

	server := config.EffectiveServer(g.server, cfg)
	report := doctor.Run(doctor.Options{
		Cfg:    cfg,
		Server: server,
		Token:  resolveToken(cfg, g),
		Fix:    fix,
	})
	icon := map[string]string{"ok": "[ok]  ", "warn": "[warn]", "fail": "[FAIL]", "skip": "[skip]", "fixed": "[fix] "}
	for _, c := range report.Checks {
		ic := icon[c.Status]
		fmt.Printf("%s %-18s %s\n", ic, c.Name, c.Detail)
		if c.Hint != "" {
			fmt.Printf("       %-18s hint: %s\n", "", c.Hint)
		}
	}
	if report.HasFail() {
		fmt.Println("result: FAIL (see above)")
		return 1
	}
	fmt.Println("result: ok")
	return 0
}

// cmdBenchmark implements `dldw benchmark --url URL [--mode ...]`.
func cmdBenchmark(cfg config.Config, g globals, args []string) int {
	var urlArg, mode string
	fs := newFlagSet("benchmark")
	fs.StrVar(&urlArg, "url", "")
	fs.StrVar(&mode, "mode", "direct")
	first, _ := fs.Parse(args)
	if urlArg == "" && first != "" {
		urlArg = first
	}
	if urlArg == "" {
		fmt.Fprintln(os.Stderr, "usage: dldw benchmark --url URL [--mode direct|tunnel|presigned|all]")
		return 2
	}
	var modes []bench.Mode
	switch mode {
	case "all":
		modes = []bench.Mode{bench.ModeDirect, bench.ModeTunnel, bench.ModePresigned}
	case "direct", "tunnel", "presigned":
		modes = []bench.Mode{bench.Mode(mode)}
	default:
		fmt.Fprintf(os.Stderr, "dldw: unknown mode %q\n", mode)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	results := bench.Run(ctx, urlArg, bench.Options{
		Cfg:    cfg,
		Server: config.EffectiveServer(g.server, cfg),
		Token:  resolveToken(cfg, g),
		Modes:  modes,
	})
	bench.Fprint(os.Stdout, results)
	for _, r := range results {
		if r.Err != nil {
			return 1
		}
	}
	return 0
}

// cmdConfig implements `dldw config init|show|set|unset|path`.
func cmdConfig(cfg config.Config, g globals, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "init":
		path, err := config.Init()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 1
		}
		fmt.Println("wrote", path)
		fmt.Println("edit it freely; every option is documented inline (YAML)")
		return 0
	case "show":
		printConfig(cfg)
		return 0
	case "path":
		fmt.Println(config.ActivePath()) // 当前实际生效的文件（json 优先，否则 yaml）
		return 0
	case "set":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: dldw config set <key> <value>")
			return 2
		}
		hadYAML := strings.HasSuffix(config.ActivePath(), ".yaml")
		if err := cfg.Set(args[0], strings.Join(args[1:], " ")); err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 1
		}
		if err := cfg.Save(""); err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 1
		}
		fmt.Println("set", args[0])
		if hadYAML {
			fmt.Println("note: saved to config.json which now takes precedence over config.yaml;")
			fmt.Println("      delete one of them to avoid confusion")
		}
		return 0
	case "unset":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: dldw config unset <key>")
			return 2
		}
		hadYAML := strings.HasSuffix(config.ActivePath(), ".yaml")
		if err := cfg.Unset(args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 1
		}
		if err := cfg.Save(""); err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 1
		}
		fmt.Println("unset", args[0])
		if hadYAML {
			fmt.Println("note: saved to config.json which now takes precedence over config.yaml")
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: dldw config init|show|set|unset|path")
		return 2
	}
}

func printConfig(cfg config.Config) {
	fmt.Printf("server:            %s\n", orDash(cfg.Server))
	fmt.Printf("token_file:        %s\n", cfg.TokenFilePath())
	fmt.Printf("proxy.bind:        %s\n", cfg.Proxy.Bind)
	fmt.Printf("proxy.port:        %d\n", cfg.Proxy.Port)
	fmt.Printf("proxy.mode:        %s\n", cfg.Proxy.Mode)
	fmt.Printf("proxy.fallback:    %s\n", cfg.Proxy.Fallback)
	fmt.Printf("download.chunk:    %s (%d bytes)\n", cfg.Download.ChunkSize, cfg.ChunkSizeBytes())
	fmt.Printf("download.conc:     %d\n", cfg.Concurrency())
	fmt.Printf("download.fallback: %s\n", cfg.Download.DirectFallback)
	fmt.Printf("whitelist_version: %s\n", orDash(cfg.WhitelistVersion))
	fmt.Printf("security.ports:    %v\n", cfg.Security.Ports)
	fmt.Printf("active file:       %s\n", config.ActivePath())
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// cmdProxy implements `dldw proxy [--port N]`: a long-running local proxy.
func cmdProxy(cfg config.Config, g globals, args []string) int {
	port := cfg.Proxy.Port
	fs := newFlagSet("proxy")
	fs.IntVar(&port, "port", port)
	fs.Parse(args)

	wl := whitelist.NewStore(whitelist.Default())
	var tunnelCfg *proxy.TunnelConfig
	server := config.EffectiveServer(g.server, cfg)
	token := resolveToken(cfg, g)
	if server != "" && token != "" {
		var err error
		tunnelCfg, err = proxy.TunnelConfigFromServer(server, token, clientIDOf(cfg), cfg.TLSSkipVerify)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 2
		}
	}

	blockPrivate := true
	if cfg.Security.BlockPrivate != nil {
		blockPrivate = *cfg.Security.BlockPrivate
	}
	ports := cfg.Security.Ports
	if len(ports) == 0 {
		ports = []int{80, 443}
	}

	m := proxy.NewMetrics()
	px, err := proxy.Start(proxy.Options{
		Bind:        cfg.Proxy.Bind,
		Port:        port,
		WL:          wl,
		Policy:      &ssrf.Policy{BlockPrivate: blockPrivate, Ports: ports},
		Tunnel:      tunnelCfg,
		IdleTimeout: cfg.ProxyIdleTimeout(),
		Metrics:     m,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
		return 3
	}
	fmt.Printf("dldw proxy listening on %s (whitelist=%d entries, tunnel=%v)\n",
		px.URL(), wl.Get().Len(), tunnelCfg != nil)

	// background whitelist refresh
	go func() {
		if tunnelCfg == nil {
			return
		}
		api := apiClient(server, token, cfg)
		if api == nil {
			return
		}
		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()
		for range tick.C {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if wlRes, err := api.Whitelist(ctx); err == nil && len(wlRes.Entries) > 0 {
				wl.Swap(whitelist.Parse(wlRes.Version, wlRes.Entries))
			}
			cancel()
		}
	}()

	// periodic stats
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for range tick.C {
			snap := m.Snapshot()
			fmt.Printf("dldw proxy stats: conns=%v tunnel=%v direct=%v bytes_in=%v bytes_out=%v err=%v\n",
				snap["connections"], snap["tunnel_conns"], snap["direct_conns"],
				snap["bytes_in"], snap["bytes_out"], snap["errors"])
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("shutting down proxy...")
	px.Stop(5 * time.Second)
	return 0
}

// cmdServe implements `dldw serve [--config FILE] [--no-proxy-core]`。
// --no-proxy-core 启动时禁用内嵌代理核心（覆盖 proxy.enabled）。
func cmdServe(g globals, args []string) int {
	configFile := ""
	noCore := false
	fs := newFlagSet("serve")
	fs.StrVar(&configFile, "config", "")
	fs.BoolVar(&noCore, "no-proxy-core", false)
	first, _ := fs.Parse(args)
	if configFile == "" && first != "" {
		configFile = first
	}
	cfg, err := app.LoadConfig(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dldw serve: %v\n", err)
		return 2
	}
	if noCore {
		cfg.Proxy.Enabled = false
	}
	if err := app.DefaultWhitelistFile(cfg.WhitelistFile); err != nil {
		fmt.Fprintf(os.Stderr, "dldw serve: whitelist init: %v\n", err)
	}
	a, err := app.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dldw serve: %v\n", err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "dldw serve: %v\n", err)
		return 1
	}
	return 0
}

func apiClient(server, token string, cfg config.Config) *downloader.Client {
	c, err := downloader.NewAPIClient(server, token, clientIDOf(cfg), cfg.TLSSkipVerify)
	if err != nil {
		return nil
	}
	return c
}
