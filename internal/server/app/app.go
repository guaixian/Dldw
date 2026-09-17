package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dldw/internal/hunits"
	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
	"dldw/internal/server/api"
	"dldw/internal/server/audit"
	"dldw/internal/server/auth"
	"dldw/internal/server/gomod"
	"dldw/internal/server/hfmirror"
	"dldw/internal/server/npm"
	"dldw/internal/server/proxycore"
	"dldw/internal/server/pypi"
	"dldw/internal/server/registrymirror"
	"dldw/internal/server/tunnel"
	"dldw/internal/server/webmirror"
	"dldw/internal/transfer/aria2ctl"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/storage/localfs"
	"dldw/internal/transfer/storage/openliststore"
	s3stor "dldw/internal/transfer/storage/s3"
	"dldw/internal/transfer/tasks"
	"dldw/internal/upstreamproxy"
	"dldw/internal/version"
)

// App owns the running server components.
type App struct {
	Cfg     Config
	Engine  *tasks.Engine
	Tokens  *auth.Store
	WLStore *whitelist.Store
	Storage storage.Storage
	Stor    storage.Storage
	Local   *localfs.Driver
	Audit   *audit.Logger
	Exec    executor.Executor
	PyPI    *pypi.Mirror
	NPM     *npm.Mirror
	WebMirror *webmirror.Mirror
	GoModM *gomod.Mirror
	Registry *registrymirror.Mirror
	HFM *hfmirror.Mirror

	coreLink *proxycore.ShareLink // 解析后的分享链接（proxy.enabled 时非空）
	coreMgr  *proxycore.Manager

	apiServer *http.Server
	tunnelLn  net.Listener
	tunnelSrv *tunnel.Server
	wlModTime time.Time
}

// New builds all components from cfg.
func New(cfg Config) (*App, error) {
	a := &App{Cfg: cfg}

	// 内嵌代理核心：解析分享链接；executor/隧道未显式配置 upstream 时自动接管
	coreUpstream := ""
	if cfg.Proxy.Enabled {
		sl, perr := proxycore.ParseHysteria2(cfg.Proxy.ShareLink)
		if perr != nil {
			return nil, perr
		}
		if !strings.EqualFold(cfg.Proxy.Core, "sing-box") {
			return nil, fmt.Errorf("proxy core %q not supported (want sing-box)", cfg.Proxy.Core)
		}
		coreUpstream = "http://" + net.JoinHostPort(cfg.Proxy.Listen, strconv.Itoa(cfg.Proxy.Port))
		a.coreLink = sl
		if cfg.Executor.UpstreamProxy == "" {
			cfg.Executor.UpstreamProxy = coreUpstream
			a.Cfg = cfg
		}
		if cfg.Tunnel.UpstreamProxy == "" {
			cfg.Tunnel.UpstreamProxy = coreUpstream
			a.Cfg = cfg
		}
	}

	// audit
	var w interface{ Write([]byte) (int, error) } = os.Stdout
	if cfg.AuditLog != "" {
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		w = f
	}
	a.Audit = audit.New(w)

	// whitelist
	wl, err := LoadWhitelist(cfg.WhitelistFile)
	if err != nil {
		return nil, err
	}
	if st, serr := os.Stat(cfg.WhitelistFile); serr == nil {
		a.wlModTime = st.ModTime()
	}
	a.WLStore = whitelist.NewStore(wl)

	// auth
	ttl := cfg.TokenTTL()
	a.Tokens, err = auth.NewStore(cfg.Auth.TokensFile, ttl)
	if err != nil {
		return nil, fmt.Errorf("auth store: %w", err)
	}

	// storage 驱动选择（spec 4.3）：
	//   localfs | fs          本地磁盘 + HMAC 预签名（/files/ 提供 Range 下载）
	//   s3                     任何 S3 兼容后端的 SigV4 预签名直传
	//                          （AWS S3、OSS/COS/R2 等凡暴露 S3 API 的均用此项）
	//   minio                  同 s3，但强制 path_style=true（MinIO 布局约定）
	//   openlist               OpenList/AList 挂载作为存储；下载链接用 fs/get
	//                          的 raw_url：S3 类挂载=底层直链（零中转），
	//                          本地/WebDAV 类挂载=OpenList /d/ 代理（中转）。
	//
	// 新增后端：实现 internal/transfer/storage.Storage 接口并在本 switch 注册。
	switch strings.ToLower(cfg.Storage.Driver) {
	case "", "localfs", "fs":
		d, derr := localfs.New(localfs.Config{
			Root:       cfg.Storage.Root,
			PublicBase: cfg.PublicBase,
			Secret:     []byte(cfg.Storage.Secret),
			Expires:    cfg.PresignTTLDuration(),
		})
		if derr != nil {
			return nil, fmt.Errorf("localfs: %w", derr)
		}
		a.Local = d
		a.Storage = d
	case "s3", "minio":
		sc := cfg.Storage.S3
		if strings.EqualFold(cfg.Storage.Driver, "minio") {
			sc.PathStyle = true // MinIO 用 path-style 寻址（bucket 在路径上）
		}
		d, derr := s3stor.New(s3stor.Config{
			Endpoint:        sc.Endpoint,
			Region:          sc.Region,
			Bucket:          sc.Bucket,
			AccessKeyID:     sc.AccessKeyID,
			SecretAccessKey: sc.SecretAccessKey,
			PathStyle:       sc.PathStyle,
		})
		if derr != nil {
			return nil, fmt.Errorf("s3: %w", derr)
		}
		a.Storage = d
	case "openlist":
		ol := cfg.Storage.OpenList
		d, derr := openliststore.New(openliststore.Config{
			BaseURL:     ol.BaseURL,
			Token:       ol.Token,
			Username:    ol.Username,
			Password:    ol.Password,
			RootPath:    ol.RootPath,
			DirPassword: ol.DirPassword,
		})
		if derr != nil {
			return nil, fmt.Errorf("openlist: %w", derr)
		}
		a.Storage = d
	default:
		return nil, fmt.Errorf("unknown storage driver %q (supported: localfs | s3 | minio | openlist; OSS/COS/R2 等 S3 兼容后端用 s3)", cfg.Storage.Driver)
	}
	a.Stor = a.Storage

	// executor
	blockPrivate := true
	if a.Cfg.BlockPrivate != nil {
		blockPrivate = *a.Cfg.BlockPrivate
	}
	switch strings.ToLower(cfg.Executor.Driver) {
	case "", "builtin":
		maxBytes, _ := hunits.ParseBytes(cfg.Executor.MaxBytes)
		if uerr := upstreamproxy.Validate(cfg.Executor.UpstreamProxy); uerr != nil {
			return nil, fmt.Errorf("executor upstream_proxy: %w", uerr)
		}
		a.Exec = executor.NewBuiltin(executor.BuiltinConfig{
			Policy: &ssrf.Policy{
				BlockPrivate:  blockPrivate,
				AllowLoopback: cfg.Executor.AllowLoopback,
				Ports:         cfg.Executor.Ports,
			},
			MaxBytes:      maxBytes,
			UpstreamProxy: cfg.Executor.UpstreamProxy,
		})
	case "aria2":
		if cfg.Executor.Aria2.RPCURL == "" {
			return nil, errors.New("aria2 executor requires rpc_url")
		}
		a.Exec = aria2ctl.NewExecutor(aria2ctl.Config{
			RPCURL: cfg.Executor.Aria2.RPCURL,
			Secret: cfg.Executor.Aria2.Secret,
		})
	default:
		return nil, fmt.Errorf("unknown executor driver %q", cfg.Executor.Driver)
	}

	// task engine（实时进度：executor 每秒回调字节 → 后台协程写任务 Progress）
	store, err := tasks.NewStore(cfg.TasksFile)
	if err != nil {
		return nil, fmt.Errorf("task store: %w", err)
	}
	// 进度追踪器：executor 写入，后台协程读出并更新任务
	prog := &fetchProgress{store: store}
	if b, ok := a.Exec.(*executor.Builtin); ok {
		b.SetProgressFunc(func(read, total int64) {
			prog.update(read, total)
		})
	}
	// 后台协程：每 2 秒把进度写入任务存储（客户端轮询即可看到）
	go prog.loop()
	a.Engine = tasks.NewEngine(tasks.EngineConfig{
		TmpDir:     cfg.TmpDir,
		PresignTTL: cfg.PresignTTLDuration(),
		BeginFetch: prog.Begin,
		EndFetch:   prog.End,
	}, store, a.Exec, a.Storage, a.Audit)

	// PyPI 拉穿镜像（pypi.enabled 时挂载 /pypi/*）
	if cfg.PyPI.Enabled {
		ttl, _ := hunits.ParseDuration(cfg.PyPI.IndexTTL)
		a.PyPI = pypi.New(pypi.Config{
			IndexOrigin:  cfg.PyPI.IndexOrigin,
			IndexOrigins: cfg.PyPI.IndexOrigins,
			FilesOrigin:  cfg.PyPI.FilesOrigin,
			FilesOrigins: cfg.PyPI.FilesOrigins,
			PublicBase:   cfg.PublicBase,
			IndexTTL:     ttl,
			TmpDir:       cfg.TmpDir,
			PresignTTL:   cfg.PresignTTLDuration(),
		}, a.Storage, a.Exec, a.Engine.Store())
	}

	// npm 拉穿镜像（npm.enabled 时挂载 /npm/*）
	if cfg.NPM.Enabled {
		ttl, _ := hunits.ParseDuration(cfg.NPM.IndexTTL)
		a.NPM = npm.New(npm.Config{
			RegistryOrigin:  cfg.NPM.RegistryOrigin,
			RegistryOrigins: cfg.NPM.RegistryOrigins,
			PublicBase:      cfg.PublicBase,
			IndexTTL:        ttl,
			TmpDir:          cfg.TmpDir,
			PresignTTL:      cfg.PresignTTLDuration(),
		}, a.Storage, a.Exec, a.Engine.Store())
	}

	// 通用静态文件拉穿镜像（mirror.enabled 时挂载 /mirror/*）
	// 透传客户端：优先走服务端出口（内嵌核心/upstream_proxy），否则 SSRF 守卫直连
	var passClient *http.Client
	if a.Cfg.Executor.UpstreamProxy != "" {
		if u, uerr := url.Parse(a.Cfg.Executor.UpstreamProxy); uerr == nil {
			passClient = &http.Client{Transport: &http.Transport{
				Proxy: http.ProxyURL(u),
			}}
		}
	} else {
		blockPrivate := true
		if cfg.BlockPrivate != nil {
			blockPrivate = *cfg.BlockPrivate
		}
		passClient = &http.Client{Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&ssrf.Policy{BlockPrivate: blockPrivate, Ports: []int{80, 443}}).DialContext,
		}}
	}
	if cfg.Mirror.Enabled {
		a.WebMirror = webmirror.New(webmirror.Config{
			AllowedHosts: cfg.Mirror.AllowedHosts,
		}, passClient, a.Storage, a.Exec, a.Engine.Store(), cfg.TmpDir, cfg.PresignTTLDuration())
	}

	// Go module proxy 镜像（gomod.enabled 时挂载 /gomod/*）
	if cfg.GoMod.Enabled {
		a.GoModM = gomod.New(gomod.Config{Origin: cfg.GoMod.Origin, Origins: cfg.GoMod.Origins}, passClient,
			a.Storage, a.Exec, a.Engine.Store(), cfg.TmpDir, cfg.PresignTTLDuration())
	}

	// Docker Registry V2 镜像（registry.enabled 时挂载 /v2/*）
	if cfg.Registry.Enabled {
		mttl, _ := hunits.ParseDuration(cfg.Registry.ManifestTTL)
		a.Registry = registrymirror.New(registrymirror.Config{
			Origin:       cfg.Registry.Origin,
			AuthURL:      cfg.Registry.AuthURL,
			Username:     cfg.Registry.Username,
			Password:     cfg.Registry.Password,
			ManifestTTL:  mttl,
			TmpDir:       cfg.TmpDir,
			PresignTTL:   cfg.PresignTTLDuration(),
		}, passClient, a.Storage, a.Engine.Store())
	}

	// HuggingFace Hub 代理（huggingface.enabled 时挂载 /hf/*）
	if cfg.HF.Enabled {
		a.HFM = hfmirror.New(hfmirror.Config{Origin: cfg.HF.Origin}, passClient,
			a.Storage, a.Exec, a.Engine.Store(), cfg.TmpDir, cfg.PresignTTLDuration())
	}

	return a, nil
}

// Handler returns the API HTTP handler (useful for tests).
func (a *App) Handler() http.Handler {
	// 镜像索引抓取客户端：跟随服务端出口（内嵌核心或显式 upstream_proxy）
	var mirrorClient *http.Client
	if up := a.Cfg.Executor.UpstreamProxy; up != "" {
		if u, err := url.Parse(up); err == nil {
			mirrorClient = &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					Proxy:               http.ProxyURL(u),
					TLSHandshakeTimeout: 10 * time.Second,
				},
			}
		}
	}
	return api.New(api.Config{
		Engine:            a.Engine,
		Tokens:            a.Tokens,
		WL:                a.WLStore,
		Stor:              a.Stor,
		Local:             a.Local,
		Audit:             a.Audit,
		Version:           version.Version,
		AllowRegistration: a.Cfg.Auth.AllowRegistration,
		PyPI:              a.PyPI,
		PyPIClient:        mirrorClient,
		NPM:               a.NPM,
		NPMClient:         mirrorClient,
		WebMirror:         handlerOrNil(a.WebMirror),
		GoMod:             handlerOrNil(a.GoModM),
		Registry:          handlerOrNil(a.Registry),
		HF:                handlerOrNil(a.HFM),
		MirrorAuth:        a.Cfg.Auth.MirrorAuth,
	})
}

// handlerOrNil 返回实现了 http.Handler 的镜像（或 nil）。
func handlerOrNil(h http.Handler) http.Handler {
	if h == nil {
		return nil
	}
	return h
}

// startProxyCore 生成 sing-box 配置并托管其进程。
func (a *App) startProxyCore() error {
	cfg := a.Cfg.Proxy
	if err := os.MkdirAll(cfg.ConfigDir, 0o755); err != nil {
		return err
	}
	cfgJSON, err := proxycore.GenerateSingBoxConfig(a.coreLink, cfg.Listen, cfg.Port, cfg.LogLevel)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(cfg.ConfigDir, "sing-box.json")
	if err := os.WriteFile(cfgPath, cfgJSON, 0o600); err != nil {
		return err
	}
	logPath := filepath.Join(cfg.ConfigDir, "sing-box.log")
	mgr, err := proxycore.Start(cfg.Binary, cfgPath, logPath)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port))
	if err := mgr.WaitReady(addr, 15*time.Second); err != nil {
		mgr.Stop()
		return err
	}
	a.coreMgr = mgr
	a.Audit.Log("proxy_core_start", "", "core", cfg.Core, "listen", addr,
		"server", a.coreLink.Server, "node", a.coreLink.Name)
	fmt.Fprintf(os.Stderr, "dldw proxy core (sing-box) listening on %s -> %s:%d (%s)\n",
		addr, a.coreLink.Server, a.coreLink.Port, a.coreLink.Name)
	return nil
}

// Run starts everything and blocks until ctx is done or a signal arrives.
func (a *App) Run(ctx context.Context) error {
	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	a.apiServer = &http.Server{
		Addr:              a.Cfg.Listen,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 内嵌代理核心：先于监听器启动（executor/隧道依赖其出口）
	if a.Cfg.Proxy.Enabled && a.coreLink != nil {
		if err := a.startProxyCore(); err != nil {
			return fmt.Errorf("proxy core: %w", err)
		}
		defer a.coreMgr.Stop()
	}

	errCh := make(chan error, 2)

	ln, err := net.Listen("tcp", a.Cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", a.Cfg.Listen, err)
	}
	if a.Cfg.TLS.Cert != "" && a.Cfg.TLS.Key != "" {
		ln = a.wrapTLS(ln, a.Cfg.TLS)
	}
	fmt.Fprintf(os.Stderr, "dldw %s control API listening on %s (storage=%s executor=%s)\n",
		version.Version, ln.Addr(), a.Storage.Name(), a.Exec.Name())
	go func() { errCh <- a.apiServer.Serve(ln) }()

	if a.Cfg.Tunnel.Enabled {
		tln, terr := net.Listen("tcp", a.Cfg.Tunnel.Listen)
		if terr != nil {
			return fmt.Errorf("tunnel listen %s: %w", a.Cfg.Tunnel.Listen, terr)
		}
		tln = a.wrapTLS(tln, a.Cfg.Tunnel.TLS)

		maxBytes, _ := hunits.ParseBytes(a.Cfg.Tunnel.MaxBytesPerConn)
		idle, _ := hunits.ParseDuration(a.Cfg.Tunnel.IdleTimeout)
		if uerr := upstreamproxy.Validate(a.Cfg.Tunnel.UpstreamProxy); uerr != nil {
			return fmt.Errorf("tunnel upstream_proxy: %w", uerr)
		}
		a.tunnelSrv = tunnel.New(tunnel.Config{
			Tokens:           a.Tokens,
			Nonces:           auth.NewNonceStore(10 * time.Minute),
			WL:               a.WLStore,
			Policy:           &ssrf.Policy{BlockPrivate: true, Ports: []int{80, 443}},
			Audit:            a.Audit,
			UpstreamProxy:    a.Cfg.Tunnel.UpstreamProxy,
			Mode:             a.Cfg.Tunnel.Mode,
			MaxConnsPerToken: a.Cfg.Tunnel.MaxConnsPerToken,
			MaxBytesPerConn:  maxBytes,
			IdleTimeout:      idle,
		})
		fmt.Fprintf(os.Stderr, "dldw tunnel listening on %s (whitelist v%s)\n", tln.Addr(), a.WLStore.Get().Version())
		go func() { errCh <- a.tunnelSrv.Serve(signalCtx, tln) }()
		a.tunnelLn = tln
	}

	// background: GC + whitelist reload
	gcTick := time.NewTicker(10 * time.Minute)
	defer gcTick.Stop()
	wlTick := time.NewTicker(30 * time.Second)
	defer wlTick.Stop()

	for {
		select {
		case <-signalCtx.Done():
			fmt.Fprintln(os.Stderr, "shutting down...")
			shctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer scancel()
			a.apiServer.Shutdown(shctx)
			if a.tunnelLn != nil {
				a.tunnelLn.Close()
			}
			return nil
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-gcTick.C:
			a.Engine.GC(context.Background())
		case <-wlTick.C:
			a.maybeReloadWhitelist()
		}
	}
}

func (a *App) wrapTLS(ln net.Listener, tlsCfg TLSConfig) net.Listener {
	cert, err := loadCert(tlsCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dldw: TLS config failed, serving plaintext: %v\n", err)
		return ln
	}
	return newTLSListener(ln, cert)
}

func (a *App) maybeReloadWhitelist() {
	st, err := os.Stat(a.Cfg.WhitelistFile)
	if err != nil {
		return
	}
	if st.ModTime().After(a.wlModTime) {
		if wl, lerr := LoadWhitelist(a.Cfg.WhitelistFile); lerr == nil {
			a.WLStore.Swap(wl)
			a.wlModTime = st.ModTime()
			a.Audit.Log("whitelist_reload", "", "version", wl.Version(), "entries", wl.Len())
		}
	}
}

// LoadWhitelist reads a whitelist file: one domain per line, '#' comments,
// optional "# version: <tag>" header. Missing file falls back to defaults.
func LoadWhitelist(path string) (*whitelist.List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return whitelist.Default(), nil
		}
		return nil, err
	}
	version := ""
	var entries []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			if v := strings.TrimPrefix(line, "# version:"); v != line {
				version = strings.TrimSpace(v)
			}
			continue
		}
		entries = append(entries, line)
	}
	if version == "" {
		if st, serr := os.Stat(path); serr == nil {
			version = st.ModTime().UTC().Format("2006-01-02.150405")
		} else {
			version = "unknown"
		}
	}
	return whitelist.Parse(version, entries), nil
}

// DefaultWhitelistFile writes the default whitelist for first runs.
func DefaultWhitelistFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := `# dldw tunnel whitelist
# version: 2026-09-16.1
# One domain per line. github.com also matches *.github.com.
github.com
objects.githubusercontent.com
codeload.github.com
raw.githubusercontent.com
github-releases.githubusercontent.com
api.github.com
files.pythonhosted.org
pypi.org
registry.npmjs.org
`
	return os.WriteFile(path, []byte(content), 0o644)
}
