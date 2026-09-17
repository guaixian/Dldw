// Package api implements the dldw control plane HTTP API (spec 4.1).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dldw/internal/ids"
	"dldw/internal/policy/whitelist"
	"dldw/internal/server/audit"
	"dldw/internal/server/auth"
	"dldw/internal/server/npm"
	"dldw/internal/server/pypi"
	"dldw/internal/server/ratelimit"
	"dldw/internal/transfer/presign"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/storage/localfs"
	"dldw/internal/transfer/tasks"
	"dldw/internal/version"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxTokenRec
)

// Config wires the API dependencies.
type Config struct {
	Engine  *tasks.Engine
	Tokens  *auth.Store
	WL      *whitelist.Store
	Stor    storage.Storage
	Local   *localfs.Driver // non-nil only for the localfs driver
	Audit   *audit.Logger
	Version string

	AllowRegistration bool

	IPRate       *ratelimit.Limiter // generic per-IP request limit
	RegisterRate *ratelimit.Limiter // token registration per-IP
	ResolveRate  *ratelimit.Count   // resolve/task creation per token

	// PyPI 拉穿镜像（nil = 不挂载 /pypi/*）
	PyPI       *pypi.Mirror
	PyPIClient *http.Client // 索引抓取客户端（带出口代理）；nil = 直连
	// npm 拉穿镜像（nil = 不挂载 /npm/*）
	NPM        *npm.Mirror
	NPMClient  *http.Client
	// 通用静态文件拉穿镜像（apt/yum；nil = 不挂载 /mirror/*）
	WebMirror http.Handler
	// Go module proxy 镜像（nil = 不挂载 /gomod/*）
	GoMod http.Handler
	// Docker Registry V2 镜像（nil = 不挂载 /v2/*）
	// 注意：docker daemon 不会向 registry-mirror 发送凭证，/v2 不参与 MirrorAuth。
	Registry http.Handler
	// HuggingFace Hub 代理（nil = 不挂载 /hf/*）
	HF http.Handler
	// MirrorAuth 为 true 时，/pypi /npm /mirror /gomod /hf 需要设备令牌
	// （Authorization: Bearer <token> 或 Basic（用户名或密码为 token））。
	// 客户端 wrapper 自动把令牌嵌入注入的镜像 URL（userinfo 形式）。
	MirrorAuth bool
}

// New builds the HTTP handler with all routes (spec 4.1):
//
//	GET  /healthz                     存活检查（无鉴权）
//	GET  /readyz                      就绪检查：api + storage 依赖细分
//	POST /api/v1/resolve              查询/创建缓存任务（Bearer 设备令牌；幂等）
//	GET  /api/v1/tasks/{id}           任务进度与状态
//	POST /api/v1/tasks/{id}/refresh   重新签发预签名 URL
//	GET  /api/v1/whitelist            下发白名单与版本（无鉴权）
//	POST /api/v1/introspect           服务端视角诊断：token/DNS/存储/时间
//	POST /api/v1/token                设备令牌 register|refresh|revoke（IP 限流）
//	GET  /files/{key...}              localfs 预签名对象下载（验签 + Range）
//
// 所有请求经过 middleware：request_id 生成/回显、按 IP 限流、panic 恢复、
// JSON lines 审计（含状态码与字节数）。/api/v1/* 除 /token 外均要求
// Authorization: Bearer <设备令牌>。
func New(cfg Config) http.Handler {
	if cfg.Audit == nil {
		cfg.Audit = audit.New(nil)
	}
	if cfg.IPRate == nil {
		cfg.IPRate = ratelimit.New(50, 100)
	}
	if cfg.RegisterRate == nil {
		cfg.RegisterRate = ratelimit.New(0.05, 5)
	}
	if cfg.ResolveRate == nil {
		cfg.ResolveRate = ratelimit.NewCount(120, time.Hour)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC()})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		s := cfg.ready()
		code := http.StatusOK
		if s["status"] != "ok" {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, s)
	})

	mux.HandleFunc("POST /api/v1/resolve", cfg.withAuth(cfg.handleResolve))
	mux.HandleFunc("GET /api/v1/tasks/{id}", cfg.withAuth(cfg.handleTask))
	mux.HandleFunc("POST /api/v1/tasks/{id}/refresh", cfg.withAuth(cfg.handleRefresh))
	mux.HandleFunc("GET /api/v1/whitelist", cfg.handleWhitelist)
	mux.HandleFunc("POST /api/v1/introspect", cfg.withAuth(cfg.handleIntrospect))
	mux.HandleFunc("POST /api/v1/token", cfg.handleToken)
	if cfg.Local != nil {
		mux.HandleFunc("GET /files/{key...}", cfg.handleFile)
		mux.HandleFunc("HEAD /files/{key...}", cfg.handleFile)
	}
	// 镜像端点鉴权包装（MirrorAuth 开启时）
	authWrap := func(h http.Handler) http.Handler {
		if !cfg.MirrorAuth || h == nil {
			return h
		}
		return cfg.mirrorAuth(h)
	}
	if cfg.PyPI != nil {
		// GET /pypi/simple/<pkg>/   索引代理（HTML/JSON 双格式，链接重写）
		// GET /pypi/packages/<path> wheel -> 302 预签名（首次抓取入库）
		simple := func(w http.ResponseWriter, r *http.Request) {
			cfg.PyPI.ServeSimple(w, r, cfg.PyPIClient)
		}
		mux.HandleFunc("GET /pypi/simple/{pkg}", simple)
		mux.HandleFunc("GET /pypi/simple/{pkg}/", simple)
		mux.Handle("GET /pypi/packages/{path...}", authWrap(http.HandlerFunc(cfg.PyPI.ServePackage)))
	}
	if cfg.NPM != nil {
		// GET /npm/<pkg>            元数据代理（tarball 链接重写 + 内存缓存）
		// GET /npm/tarball/<path>   tarball -> 302 预签名（首次抓取入库）
		meta := func(w http.ResponseWriter, r *http.Request) {
			cfg.NPM.ServeMetadata(w, r, cfg.NPMClient)
		}
		mux.HandleFunc("GET /npm/{pkg}", meta)
		mux.Handle("GET /npm/tarball/{path...}", authWrap(http.HandlerFunc(cfg.NPM.ServeTarball)))
	}
	if cfg.WebMirror != nil {
		// GET /mirror/{scheme}/{host}/{path...}  apt(.deb)/yum(.rpm)/任意静态文件
		mux.Handle("GET /mirror/{scheme}/{host}/{path...}", authWrap(cfg.WebMirror))
		mux.Handle("HEAD /mirror/{scheme}/{host}/{path...}", authWrap(cfg.WebMirror))
	}
	if cfg.GoMod != nil {
		// GET /gomod/{path...}  Go module proxy（版本化文件缓存，其余透传）
		mux.Handle("GET /gomod/{path...}", authWrap(cfg.GoMod))
		mux.Handle("HEAD /gomod/{path...}", authWrap(cfg.GoMod))
	}
	if cfg.HF != nil {
		// GET /hf/{path...}  HuggingFace Hub 代理（SHA 版本文件缓存，API 透传）
		mux.Handle("/hf/{path...}", authWrap(cfg.HF))
	}
	if cfg.Registry != nil {
		// GET/HEAD /v2/...  Docker Registry V2 拉穿镜像（manifest 缓存 + blob 入库）
		mux.Handle("/v2/", cfg.Registry)
		mux.Handle("/v2", cfg.Registry)
	}
	// 能力探测（无鉴权）：客户端 wrapper 据此决定是否自动注入镜像地址
	mux.HandleFunc("GET /api/v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"request_id":  requestID(r),
			"pypi":        cfg.PyPI != nil,
			"npm":         cfg.NPM != nil,
			"mirror":      cfg.WebMirror != nil,
			"gomod":       cfg.GoMod != nil,
			"hf":          cfg.HF != nil,
			"registry":    cfg.Registry != nil,
			"mirror_auth": cfg.MirrorAuth,
		})
	})

	return cfg.middleware(mux)
}

func (c *Config) ready() map[string]any {
	checks := map[string]string{"api": "ok"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Stor.Ping(ctx); err != nil {
		checks["storage"] = "fail: " + err.Error()
	} else {
		checks["storage"] = "ok"
	}
	status := "ok"
	for _, v := range checks {
		if v != "ok" {
			status = "degraded"
		}
	}
	return map[string]any{"status": status, "checks": checks, "time": time.Now().UTC()}
}

// --- middleware -----------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (c *Config) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := ids.NewRequestID()
		ctx := context.WithValue(r.Context(), ctxRequestID, reqID)
		w.Header().Set("X-Dldw-Request-Id", reqID)
		w.Header().Set("Server", "dldw/"+version.Version)

		ip := clientIP(r)
		if !c.IPRate.Allow(ip) {
			writeErr(w, reqID, http.StatusTooManyRequests, "E_RATE_LIMITED", "too many requests")
			return
		}

		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				writeErr(sw, reqID, http.StatusInternalServerError, "E_INTERNAL", "internal error")
				c.Audit.Log("panic", reqID, "path", r.URL.Path, "error", fmt.Sprint(rec))
			}
			c.Audit.Log("http", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"bytes", sw.bytes,
				"ip", ip,
				"duration_ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

func (c *Config) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := auth.BearerToken(r.Header.Get("Authorization"))
		rec, err := c.Tokens.Validate(token)
		if err != nil {
			writeErr(w, requestID(r), http.StatusUnauthorized, "E_RESOLVE_AUTH", "invalid or missing token: "+err.Error())
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxTokenRec, rec)))
	}
}

// mirrorAuth 是镜像端点的令牌鉴权中间件：接受
//   - Authorization: Bearer <token>
//   - Authorization: Basic（用户名或密码任一为 token）
// 兼容 pip/uv/go 把令牌写在镜像 URL userinfo 的常见用法。
func (c *Config) mirrorAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, tok := range mirrorTokenCandidates(r) {
			if tok != "" {
				if _, err := c.Tokens.Validate(tok); err == nil {
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, requestID(r))))
					return
				}
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="dldw-mirror"`)
		writeErr(w, requestID(r), http.StatusUnauthorized, "E_MIRROR_AUTH",
			"device token required (Bearer, or Basic with token as username/password)")
	})
}

// mirrorTokenCandidates 从 Bearer 或 Basic 头提取候选令牌（用户名与密码都试）。
func mirrorTokenCandidates(r *http.Request) []string {
	var out []string
	if t := auth.BearerToken(r.Header.Get("Authorization")); t != "" {
		return []string{t}
	}
	if user, pass, ok := r.BasicAuth(); ok {
		if user != "" {
			out = append(out, user)
		}
		if pass != "" {
			out = append(out, pass)
		}
	}
	return out
}

// --- helpers --------------------------------------------------------------

func requestID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

func tokenRec(r *http.Request) *auth.Record {
	if v, ok := r.Context().Value(ctxTokenRec).(*auth.Record); ok {
		return v
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":{"code":"E_INTERNAL"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(append(buf, '\n'))
}

func writeErr(w http.ResponseWriter, reqID string, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"request_id": reqID,
		"error":      map[string]string{"code": code, "message": msg},
	})
}

func readJSON(w http.ResponseWriter, r *http.Request, reqID string, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErr(w, reqID, http.StatusBadRequest, "E_BAD_REQUEST", "cannot read body")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, reqID, http.StatusBadRequest, "E_BAD_REQUEST", "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// --- handlers -------------------------------------------------------------

type resolveRequest struct {
	URL           string `json:"url"`
	ClientID      string `json:"client_id"`
	Capabilities  struct {
		Range      bool `json:"range"`
		Concurrent bool `json:"concurrent"`
		SHA256     bool `json:"sha256"`
	} `json:"capabilities"`
}

func (c *Config) handleResolve(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	rec := tokenRec(r)
	var req resolveRequest
	if !readJSON(w, r, reqID, &req) {
		return
	}
	if len(req.URL) > 8192 {
		writeErr(w, reqID, http.StatusRequestEntityTooLarge, "E_BAD_REQUEST", "url too long")
		return
	}
	if req.ClientID == "" && rec != nil {
		req.ClientID = rec.ClientID
	}
	if !c.ResolveRate.Allow(rec.ID) {
		writeErr(w, reqID, http.StatusTooManyRequests, "E_RATE_LIMITED", "resolve budget exceeded for token")
		return
	}
	res, err := c.Engine.Resolve(r.Context(), req.URL, rec.ID)
	if err != nil {
		switch {
		case errors.Is(err, tasks.ErrNotCacheable):
			writeErr(w, reqID, http.StatusUnprocessableEntity, "E_NOT_CACHEABLE", err.Error())
		default:
			writeErr(w, reqID, http.StatusBadRequest, "E_RESOLVE_FAILED", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": reqID,
		"status":     res.Status,
		"cache_key":  res.CacheKey,
		"artifact":   res.Artifact,
		"download":   res.Download,
		"task":       res.Task,
	})
}

func (c *Config) handleTask(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	id := r.PathValue("id")
	t, err := c.Engine.Task(id)
	if err != nil {
		writeErr(w, reqID, http.StatusNotFound, "E_TASK_NOT_FOUND", "no such task")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request_id": reqID, "task": t})
}

func (c *Config) handleRefresh(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	id := r.PathValue("id")
	res, err := c.Engine.Refresh(r.Context(), id)
	if err != nil {
		writeErr(w, reqID, http.StatusConflict, "E_REFRESH_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": reqID,
		"status":     res.Status,
		"cache_key":  res.CacheKey,
		"artifact":   res.Artifact,
		"download":   res.Download,
		"task":       res.Task,
	})
}

func (c *Config) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	l := c.WL.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": reqID,
		"version":    l.Version(),
		"entries":    l.Entries(),
	})
}

func (c *Config) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	rec := tokenRec(r)
	out := map[string]any{
		"request_id": reqID,
		"ok":         true,
		"server_time": time.Now().UTC(),
		"version":    c.Version,
	}
	if rec != nil {
		out["token"] = map[string]any{
			"valid":      true,
			"client_id":  rec.ClientID,
			"expires_at": rec.ExpiresAt,
		}
	}
	if c.Stor != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		perr := c.Stor.Ping(ctx)
		st := map[string]any{"name": c.Stor.Name()}
		if perr != nil {
			st["ok"] = false
			st["error"] = perr.Error()
			out["ok"] = false
		} else {
			st["ok"] = true
		}
		out["storage"] = st
	}
	if c.WL != nil {
		out["whitelist_version"] = c.WL.Get().Version()
	}
	writeJSON(w, http.StatusOK, out)
}

type tokenRequest struct {
	Action   string `json:"action"` // register|refresh|revoke
	ClientID string `json:"client_id"`
	Token    string `json:"token"`
}

func (c *Config) handleToken(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req tokenRequest
	if !readJSON(w, r, reqID, &req) {
		return
	}
	if req.Action == "" {
		req.Action = "register"
	}
	switch req.Action {
	case "register":
		if !c.AllowRegistration {
			writeErr(w, reqID, http.StatusForbidden, "E_REGISTRATION_DISABLED", "token registration is disabled on this server")
			return
		}
		if !c.RegisterRate.Allow(clientIP(r)) {
			writeErr(w, reqID, http.StatusTooManyRequests, "E_RATE_LIMITED", "registration rate limit")
			return
		}
		rec, tok, err := c.Tokens.Register(req.ClientID)
		if err != nil {
			writeErr(w, reqID, http.StatusInternalServerError, "E_TOKEN_ISSUE", err.Error())
			return
		}
		c.Audit.Log("token_register", reqID, "token_id", rec.ID, "client_id", rec.ClientID)
		writeJSON(w, http.StatusCreated, map[string]any{
			"request_id": reqID, "token": tok, "client_id": rec.ClientID,
			"expires_at": rec.ExpiresAt, "action": "register",
		})
	case "refresh":
		if req.Token == "" {
			writeErr(w, reqID, http.StatusUnauthorized, "E_RESOLVE_AUTH", "token required")
			return
		}
		rec, tok, err := c.Tokens.Refresh(req.Token)
		if err != nil {
			writeErr(w, reqID, http.StatusUnauthorized, "E_RESOLVE_AUTH", err.Error())
			return
		}
		c.Audit.Log("token_refresh", reqID, "token_id", rec.ID)
		writeJSON(w, http.StatusOK, map[string]any{
			"request_id": reqID, "token": tok, "client_id": rec.ClientID,
			"expires_at": rec.ExpiresAt, "action": "refresh",
		})
	case "revoke":
		if req.Token == "" {
			writeErr(w, reqID, http.StatusUnauthorized, "E_RESOLVE_AUTH", "token required")
			return
		}
		if err := c.Tokens.Revoke(req.Token); err != nil {
			writeErr(w, reqID, http.StatusUnauthorized, "E_RESOLVE_AUTH", err.Error())
			return
		}
		c.Audit.Log("token_revoke", reqID)
		writeJSON(w, http.StatusOK, map[string]any{"request_id": reqID, "action": "revoke", "revoked": true})
	default:
		writeErr(w, reqID, http.StatusBadRequest, "E_BAD_REQUEST", "unknown action "+req.Action)
	}
}

// handleFile serves presigned localfs objects with Range support.
func (c *Config) handleFile(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := c.Local.VerifyRequest(r.Method, key, r.URL.RawQuery); err != nil {
		switch {
		case errors.Is(err, presign.ErrExpired):
			writeErr(w, requestID(r), http.StatusGone, "E_PRESIGN_EXPIRED", "url expired")
		case errors.Is(err, presign.ErrBadSignature):
			writeErr(w, requestID(r), http.StatusForbidden, "E_PRESIGN_INVALID", "bad signature")
		default:
			writeErr(w, requestID(r), http.StatusBadRequest, "E_BAD_REQUEST", "malformed url")
		}
		return
	}
	f, err := c.Local.Get(r.Context(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeErr(w, requestID(r), http.StatusNotFound, "E_NOT_FOUND", "no such object")
			return
		}
		writeErr(w, requestID(r), http.StatusInternalServerError, "E_INTERNAL", err.Error())
		return
	}
	defer f.Close()
	obj, err := c.Local.Head(r.Context(), key)
	if err != nil {
		writeErr(w, requestID(r), http.StatusInternalServerError, "E_INTERNAL", err.Error())
		return
	}
	if obj.ContentType != "" {
		w.Header().Set("Content-Type", obj.ContentType)
	}
	if obj.ETag != "" {
		w.Header().Set("ETag", obj.ETag)
	}
	name := key
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	http.ServeContent(w, r, name, time.Time{}, f.(io.ReadSeeker))
}
