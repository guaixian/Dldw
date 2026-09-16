package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dldw/internal/hunits"
	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
	"dldw/internal/server/api"
	"dldw/internal/server/audit"
	"dldw/internal/server/auth"
	"dldw/internal/server/tunnel"
	"dldw/internal/transfer/aria2ctl"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/storage/localfs"
	s3stor "dldw/internal/transfer/storage/s3"
	"dldw/internal/transfer/tasks"
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

	apiServer  *http.Server
	tunnelLn   net.Listener
	tunnelSrv  *tunnel.Server
	wlModTime  time.Time
}

// New builds all components from cfg.
func New(cfg Config) (*App, error) {
	a := &App{Cfg: cfg}

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

	// storage
	switch strings.ToLower(cfg.Storage.Driver) {
	case "", "localfs":
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
	case "s3":
		d, derr := s3stor.New(s3stor.Config{
			Endpoint:        cfg.Storage.S3.Endpoint,
			Region:          cfg.Storage.S3.Region,
			Bucket:          cfg.Storage.S3.Bucket,
			AccessKeyID:     cfg.Storage.S3.AccessKeyID,
			SecretAccessKey: cfg.Storage.S3.SecretAccessKey,
			PathStyle:       cfg.Storage.S3.PathStyle,
		})
		if derr != nil {
			return nil, fmt.Errorf("s3: %w", derr)
		}
		a.Storage = d
	default:
		return nil, fmt.Errorf("unknown storage driver %q", cfg.Storage.Driver)
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
		a.Exec = executor.NewBuiltin(executor.BuiltinConfig{
			Policy: &ssrf.Policy{
				BlockPrivate:  blockPrivate,
				AllowLoopback: cfg.Executor.AllowLoopback,
				Ports:         cfg.Executor.Ports,
			},
			MaxBytes: maxBytes,
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

	// task engine
	store, err := tasks.NewStore(cfg.TasksFile)
	if err != nil {
		return nil, fmt.Errorf("task store: %w", err)
	}
	a.Engine = tasks.NewEngine(tasks.EngineConfig{
		TmpDir:     cfg.TmpDir,
		PresignTTL: cfg.PresignTTLDuration(),
	}, store, a.Exec, a.Storage, a.Audit)

	return a, nil
}

// Handler returns the API HTTP handler (useful for tests).
func (a *App) Handler() http.Handler {
	return api.New(api.Config{
		Engine:           a.Engine,
		Tokens:           a.Tokens,
		WL:               a.WLStore,
		Stor:             a.Stor,
		Local:            a.Local,
		Audit:            a.Audit,
		Version:          version.Version,
		AllowRegistration: a.Cfg.Auth.AllowRegistration,
	})
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
		a.tunnelSrv = tunnel.New(tunnel.Config{
			Tokens:           a.Tokens,
			Nonces:           auth.NewNonceStore(10 * time.Minute),
			WL:               a.WLStore,
			Policy:           &ssrf.Policy{BlockPrivate: true, Ports: []int{80, 443}},
			Audit:            a.Audit,
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
