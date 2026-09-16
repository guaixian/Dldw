// Package openliststore 把 OpenList（AList 分支）作为 dldw 的缓存存储后端。
//
// 工作方式（spec 4.3 组件定位的落地）：
//
//	Put        -> PUT  /api/fs/put     按路径上传到 OpenList 挂载的存储
//	Head       -> POST /api/fs/stat    取大小/修改时间
//	PresignGet -> POST /api/fs/get     取 raw_url 作为下载链接：
//	               - 挂载 S3/云盘类驱动：raw_url 是底层存储的直链/预签名 URL，
//	                 客户端直连下载，dldw 仍然零中转；
//	               - 挂载本地/WebDAV 类驱动：raw_url 是 OpenList 的 /d/ 代理地址，
//	                 字节经 OpenList 中转（Range 透传，功能完整，吞吐取决于
//	                 OpenList 所在机器）。是否可接受由部署者自行权衡。
//	Get        -> PresignGet 后拉取字节（服务端自用）
//	Delete     -> POST /api/fs/remove
//
// 鉴权：优先用配置的 API token；否则用用户名/密码走 /api/auth/login，
// 遇 401 自动重新登录重试一次。
//
// 限制：raw_url 的有效期由 OpenList/底层存储决定，本驱动的 expires 参数
// 仅作为参考传递（客户端临期 refresh 时会重新调用 fs/get 拿新链接）。
package openliststore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"dldw/internal/transfer/storage"
)

// Config 配置 OpenList 驱动。
type Config struct {
	BaseURL string // 如 http://openlist:5244（客户端必须能访问到它/其底层直链）
	Token   string // OpenList API token（推荐，管理员在后台生成）；留空则用账密登录
	Username string
	Password string
	RootPath string // OpenList 里的缓存根目录（建议独立目录），默认 /dldw-cache
	// DirPassword 是 OpenList 目录的签名/访问密码，一般留空。
	DirPassword string
}

type Driver struct {
	cfg Config
	hc  *http.Client // API 调用（带超时；上传用独立无总超时客户端）
	up *http.Client

	mu    sync.Mutex
	token string // 缓存的 API token
}

// New 构造驱动；不发网络请求，真实连通性由 Ping 探测。
func New(cfg Config) (*Driver, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("openlist: base_url required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.RootPath == "" {
		cfg.RootPath = "/dldw-cache"
	}
	if !strings.HasPrefix(cfg.RootPath, "/") {
		cfg.RootPath = "/" + cfg.RootPath
	}
	tr := &http.Transport{
		Proxy:               nil, // 不走环境代理
		MaxIdleConns:        8,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &Driver{
		cfg: cfg,
		hc:  &http.Client{Transport: tr, Timeout: 30 * time.Second},
		up:  &http.Client{Transport: tr}, // 上传/下载大文件只受 ctx 控制
	}, nil
}

func (d *Driver) Name() string { return "openlist" }

// fullPath 把 dldw 存储 key 映射为 OpenList 绝对路径。
// key 已由 storage.ValidateKey 约束为 [a-z0-9/._-]，路径安全。
func (d *Driver) fullPath(key string) (string, error) {
	if err := storage.ValidateKey(key); err != nil {
		return "", err
	}
	return path.Join(d.cfg.RootPath, key), nil
}

// --- API 基础设施 -----------------------------------------------------------

type envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// call 执行一次 JSON API 调用。logical 为 true 时检查业务码 code==200。
// retErr 带回 (code, message) 供上层判断 not found 等语义。
func (d *Driver) call(ctx context.Context, method, apiPath string, body any, out any) (int, string, error) {
	token, err := d.authToken(ctx)
	if err != nil {
		return 0, "", err
	}
	code, msg, rerr := d.callWith(ctx, token, method, apiPath, body, out)
	if (code == http.StatusUnauthorized || rerrIsAuth(rerr)) && d.cfg.Token == "" {
		// token 失效：重新登录再试一次
		if lerr := d.login(ctx); lerr != nil {
			return code, msg, lerr
		}
		ntok, _ := d.authToken(ctx)
		return d.callWith(ctx, ntok, method, apiPath, body, out)
	}
	return code, msg, rerr
}

func rerrIsAuth(err error) bool {
	return err != nil && strings.Contains(err.Error(), "401")
}

func (d *Driver) callWith(ctx context.Context, token, method, apiPath string, body any, out any) (int, string, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.cfg.BaseURL+apiPath, rdr)
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	var env envelope
	if jerr := json.Unmarshal(buf, &env); jerr == nil && env.Code != 0 {
		if env.Code != 200 {
			return env.Code, env.Message, fmt.Errorf("openlist: %s: %s", apiPath, env.Message)
		}
		if out != nil && len(env.Data) > 0 {
			if uerr := json.Unmarshal(env.Data, out); uerr != nil {
				return env.Code, env.Message, uerr
			}
		}
		return env.Code, env.Message, nil
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, strings.TrimSpace(string(buf)), fmt.Errorf("openlist: %s: HTTP %d", apiPath, resp.StatusCode)
	}
	return resp.StatusCode, "", nil
}

func (d *Driver) authToken(ctx context.Context) (string, error) {
	d.mu.Lock()
	tok := d.token
	d.mu.Unlock()
	if tok != "" {
		return tok, nil
	}
	if d.cfg.Token != "" {
		d.mu.Lock()
		d.token = d.cfg.Token
		d.mu.Unlock()
		return d.cfg.Token, nil
	}
	if err := d.login(ctx); err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.token, nil
}

// login 用用户名/密码换取 API token。
func (d *Driver) login(ctx context.Context) error {
	if d.cfg.Username == "" {
		return errors.New("openlist: no token and no username/password configured")
	}
	var data struct {
		Token string `json:"token"`
	}
	_, _, err := d.callWith(ctx, "", http.MethodPost, "/api/auth/login",
		map[string]string{"username": d.cfg.Username, "password": d.cfg.Password}, &data)
	if err != nil {
		return err
	}
	if data.Token == "" {
		return errors.New("openlist: login returned empty token")
	}
	d.mu.Lock()
	d.token = data.Token
	d.mu.Unlock()
	return nil
}

// --- Storage 接口实现 -------------------------------------------------------

func (d *Driver) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) (*storage.Object, error) {
	full, err := d.fullPath(key)
	if err != nil {
		return nil, err
	}
	// 确保父目录存在（best-effort，已存在不算错误）
	if parent := path.Dir(full); parent != "/" && parent != "" {
		if code, msg, merr := d.call(ctx, http.MethodPost, "/api/fs/mkdir", map[string]string{"path": parent}, nil); merr != nil {
			if !strings.Contains(strings.ToLower(msg), "exist") && code != 200 {
				return nil, fmt.Errorf("openlist: mkdir %s: %v", parent, merr)
			}
		}
	}

	token, err := d.authToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, d.cfg.BaseURL+"/api/fs/put", r)
	if err != nil {
		return nil, err
	}
	// File-Path：key 字符集受限（[a-z0-9/._-]），可直接放 header。
	req.Header.Set("File-Path", full)
	req.Header.Set("Content-Type", "application/octet-stream")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if size >= 0 {
		req.ContentLength = size
	}
	req.Header.Set("Authorization", token)
	resp, err := d.up.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env envelope
	if jerr := json.Unmarshal(body, &env); jerr == nil && env.Code != 0 && env.Code != 200 {
		return nil, fmt.Errorf("openlist: put %s: %s", key, env.Message)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("openlist: put %s: HTTP %d", key, resp.StatusCode)
	}
	return &storage.Object{Key: key, Size: size, ContentType: contentType}, nil
}

type fsStat struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	IsDir    bool      `json:"is_dir"`
	Modified time.Time `json:"modified"`
}

func (d *Driver) Head(ctx context.Context, key string) (*storage.Object, error) {
	full, err := d.fullPath(key)
	if err != nil {
		return nil, err
	}
	var st fsStat
	code, msg, err := d.call(ctx, http.MethodPost, "/api/fs/stat", map[string]string{"path": full}, &st)
	if err != nil {
		if strings.Contains(strings.ToLower(msg), "not found") || strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	if code == 200 && st.IsDir {
		return nil, storage.ErrNotFound
	}
	return &storage.Object{
		Key:  key,
		Size: st.Size,
		ETag: `"` + st.Modified.UTC().Format("20060102150405") + fmt.Sprintf("-%d", st.Size) + `"`,
	}, nil
}

type fsGet struct {
	fsStat
	Sign   string `json:"sign"`
	RawURL string `json:"raw_url"`
}

// rawURL 获取（并在必要时构造）下载直链。
func (d *Driver) rawURL(ctx context.Context, full string) (string, *fsGet, error) {
	var data fsGet
	body := map[string]string{"path": full}
	if d.cfg.DirPassword != "" {
		body["password"] = d.cfg.DirPassword
	}
	if _, _, err := d.call(ctx, http.MethodPost, "/api/fs/get", body, &data); err != nil {
		return "", nil, err
	}
	u := data.RawURL
	if u == "" {
		// 驱动未给直链时回落到 OpenList 自身的 /d/ 代理（Range 透传）
		u = d.cfg.BaseURL + "/d" + full
		if data.Sign != "" {
			u += "?sign=" + data.Sign
		}
	}
	return u, &data, nil
}

// PresignGet 返回 fs/get 的 raw_url。expires 仅作参考（实际有效期由
// OpenList/底层存储决定；客户端 refresh 会重新调用本方法拿新链接）。
func (d *Driver) PresignGet(ctx context.Context, key string, expires time.Duration) (string, error) {
	full, err := d.fullPath(key)
	if err != nil {
		return "", err
	}
	u, _, err := d.rawURL(ctx, full)
	return u, err
}

// PresignHead 与 GET 共用（OpenList 无独立 HEAD 直链语义）。
func (d *Driver) PresignHead(ctx context.Context, key string, expires time.Duration) (string, error) {
	return d.PresignGet(ctx, key, expires)
}

func (d *Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	full, err := d.fullPath(key)
	if err != nil {
		return nil, err
	}
	u, _, err := d.rawURL(ctx, full)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.up.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, storage.ErrNotFound
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("openlist: get %s: HTTP %d", key, resp.StatusCode)
	}
	return resp.Body, nil
}

func (d *Driver) Delete(ctx context.Context, key string) error {
	full, err := d.fullPath(key)
	if err != nil {
		return err
	}
	dir := path.Dir(full)
	base := path.Base(full)
	_, _, err = d.call(ctx, http.MethodPost, "/api/fs/remove",
		map[string]any{"dir": dir, "names": []string{base}}, nil)
	return err
}

func (d *Driver) Ping(ctx context.Context) error {
	_, _, err := d.call(ctx, http.MethodPost, "/api/me", nil, nil)
	return err
}

var _ storage.Storage = (*Driver)(nil)
