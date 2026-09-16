// Package config handles the dldw client configuration: precedence is
// runtime flags > tool adapter overrides > profile > defaults (spec 6).
// Files: ~/.dldw/config.json (canonical writable) or ~/.dldw/config.yaml
// (annotated template written by `dldw config init`; JSON takes precedence).
//
// 配置说明（维护者向）：
//   - `dldw config init` 生成带完整注释的 config.yaml 模板，可直接手改；
//   - `dldw config set/unset` 始终写 config.json（机器可写的规范格式），
//     一旦存在则优先于 config.yaml 生效；
//   - 环境变量：DLDW_HOME 覆盖 ~/.dldw；DLDW_CONFIG 指定配置文件路径；
//     DLDW_SERVER / DLDW_TOKEN 提供运行时覆盖。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dldw/internal/hunits"
	"dldw/internal/yamlmin"
)

// ProxyConfig 配置 wrapper 启动的临时本地代理（spec 3.3）。
type ProxyConfig struct {
	Bind                 string `json:"bind"`                   // 监听地址，默认 127.0.0.1（仅本机回环）
	Port                 int    `json:"port"`                   // 0 = 每次调用随机空闲端口；dldw env/proxy 建议固定端口
	Mode                 string `json:"mode"`                   // v1 仅支持 whitelist_only（白名单走隧道）
	Fallback             string `json:"fallback"`               // 非白名单的处理方式：direct（直连）
	AllowLargeOverTunnel bool   `json:"allow_large_over_tunnel"` // 大文件是否允许走隧道；默认 false（spec 风险表）
	IdleTimeout          string `json:"idle_timeout"`           // 连接空闲超时，如 "300s"
}

// DownloadConfig 配置 `dldw get`（spec 3.5）。
type DownloadConfig struct {
	ChunkSize      string `json:"chunk_size"`      // 分块大小，如 "16MiB"；支持 B/KB/KiB/MB/MiB/GB/GiB
	Concurrency    int    `json:"concurrency"`     // 并发分块数（1-64）
	RefreshBefore  string `json:"refresh_before"`  // 预签名 URL 临期多久前刷新（客户端侧参考）
	DirectFallback string `json:"direct_fallback"` // resolve 失败是否回退直连：ask | always | never
	TaskPollWait   string `json:"task_poll_wait"`  // 服务端任务轮询间隔
	TaskTimeout    string `json:"task_timeout"`    // 等待服务端任务就绪的总超时
}

// SecurityConfig 镜像本地代理直连路径的出口策略（与服务端策略保持一致的语义）。
type SecurityConfig struct {
	BlockPrivate *bool `json:"block_private,omitempty"` // 拒绝 loopback/私网/保留段目标；nil = true
	Ports        []int `json:"ports"`                   // 允许的目标端口，默认 [80,443]
}

// Config is the client configuration tree.
type Config struct {
	Server           string         `json:"server"`            // 控制 API 地址；同时决定隧道端口（P -> P+1）
	TokenFile        string         `json:"token_file"`        // 设备令牌文件；空 = ~/.dldw/token.json
	Proxy            ProxyConfig    `json:"proxy"`             // 本地代理
	Download         DownloadConfig `json:"download"`          // dldw get
	WhitelistVersion string         `json:"whitelist_version"` // 期望的服务端白名单版本（doctor 比对/固定）
	Security         SecurityConfig `json:"security"`          // 直连出口策略
	LogLevel         int            `json:"log_level"`         // 0=WARN 1=INFO 2=DEBUG（等同 -v/-vv）
	TLSSkipVerify    bool           `json:"tls_skip_verify"`   // 跳过 TLS 校验，仅开发自签环境使用
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		Server:    "",
		TokenFile: "",
		Proxy: ProxyConfig{
			Bind:         "127.0.0.1",
			Port:         0,
			Mode:         "whitelist_only",
			Fallback:     "direct",
			IdleTimeout:  "300s",
		},
		Download: DownloadConfig{
			ChunkSize:      "16MiB",
			Concurrency:    8,
			RefreshBefore:  "120s",
			DirectFallback: "ask",
			TaskPollWait:   "1s",
			TaskTimeout:    "600s",
		},
		WhitelistVersion: "",
		Security:         SecurityConfig{Ports: []int{80, 443}},
		LogLevel:         0,
	}
}

// Dir returns the dldw home directory (~/.dldw), honoring DLDW_HOME.
func Dir() string {
	if d := os.Getenv("DLDW_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".dldw")
}

// Path returns the active config file path (may not exist).
func Path() string {
	if p := os.Getenv("DLDW_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(Dir(), "config.json")
}

// Load reads the config file if present, applying it over defaults.
// 读取顺序：DLDW_CONFIG 指定路径（或 ~/.dldw/config.json）；不存在时尝试
// 同名的 config.yaml（`dldw config init` 生成的带注释模板）。
func Load() (Config, string, error) {
	path := Path()
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			yamlPath := yamlSibling(path)
			if ydata, yerr := os.ReadFile(yamlPath); yerr == nil {
				if uerr := yamlmin.Unmarshal(ydata, &cfg); uerr != nil {
					return cfg, yamlPath, uerr
				}
				return cfg, yamlPath, nil
			}
			return cfg, "", nil
		}
		return cfg, path, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if err := yamlmin.Unmarshal(data, &cfg); err != nil {
			return cfg, path, err
		}
	default:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, path, err
		}
	}
	return cfg, path, nil
}

// yamlSibling 把 config.json 路径映射为同目录的 config.yaml。
func yamlSibling(p string) string {
	return strings.TrimSuffix(p, filepath.Ext(p)) + ".yaml"
}

// Save writes the config as pretty JSON to path（config set/unset 使用；
// JSON 是机器可写的规范格式，写出的 config.json 优先于 config.yaml 生效）。
func (c Config) Save(path string) error {
	if path == "" {
		path = Path()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(buf, '\n'), 0o644)
}

// defaultYAMLTemplate 是 `dldw config init` 写出的带注释模板。
// 字段与 Config 的 json tag 一一对应；修改字段时同步更新此处。
const defaultYAMLTemplate = `# ============================================================================
# dldw 客户端配置（带注释模板，可直接手改）
#
# 优先级：命令行 flags (--server/--token/...) > 工具适配器 > 本文件 > 默认值
# 位置：  ~/.dldw/config.yaml（可用 DLDW_HOME / DLDW_CONFIG 覆盖）
# 注意：  ` + "`dldw config set`" + ` 写入的是 config.json，一旦存在将优先于本文件。
# ============================================================================

# ----------------------------------------------------------------------------
# 服务端
# ----------------------------------------------------------------------------
server: ""
# 控制 API 地址，如 https://dldw.example.com。
# !! 端口约定：客户端按此 URL 推导隧道地址——URL 带显式端口 P 时为 P+1，
# !! https 默认 4443，http 默认 8081（对应服务端 tunnel.listen）。

token_file: ""
# 设备令牌文件路径；留空 = ~/.dldw/token.json。
# 令牌由 ` + "`dldw doctor --fix`" + ` 自动注册生成，一般无需手改。

# ----------------------------------------------------------------------------
# 本地代理（dldw <tool> 每次调用临时启动；dldw proxy 常驻）
# ----------------------------------------------------------------------------
proxy:
  bind: 127.0.0.1            # 仅监听本机回环，不要改成 0.0.0.0
  port: 0                    # 0 = 每次调用随机空闲端口；配合 dldw env/proxy 时固定端口
  mode: whitelist_only       # v1 仅支持：白名单域名走服务端隧道
  fallback: direct           # 非白名单域名的处理：直连（不回退到隧道）
  allow_large_over_tunnel: false  # 大文件默认禁走隧道；大文件请用 dldw get
  idle_timeout: 300s         # 代理连接空闲超时

# ----------------------------------------------------------------------------
# dldw get 下载器
# ----------------------------------------------------------------------------
download:
  chunk_size: 16MiB          # 分块大小；支持 B/KB/KiB/MB/MiB/GB/GiB
  concurrency: 8             # 并发分块数（1-64）；弱网环境可调小
  refresh_before: 120s       # 预签名 URL 临期多久前刷新
  direct_fallback: ask       # resolve 失败时回退直连：ask（非交互=不回退）| always | never
  task_poll_wait: 1s         # 等待服务端缓存任务的轮询间隔
  task_timeout: 600s         # 等待服务端任务就绪的总超时

# ----------------------------------------------------------------------------
# 安全（本地代理的直连出口策略；服务端另有自己的策略）
# ----------------------------------------------------------------------------
whitelist_version: ""
# 期望的服务端白名单版本；由 doctor --fix 自动固定，用于发现配置漂移。

security:
  block_private: true        # 拒绝 loopback/私网/保留段目标（SSRF 防护，勿关）
  ports: [80, 443]           # 允许的目标端口

log_level: 0                 # 日志级别：0=WARN 1=INFO 2=DEBUG（等同 -v/-vv）
tls_skip_verify: false       # 跳过服务端 TLS 校验；仅开发自签环境使用
`

// Init writes an annotated default config if none exists, returning the path.
// 优先写 config.yaml（带注释，便于手改）；已存在任何配置文件时不覆盖。
func Init() (string, error) {
	jsonPath := Path()
	if _, err := os.Stat(jsonPath); err == nil {
		return jsonPath, nil
	}
	yamlPath := yamlSibling(jsonPath)
	if _, err := os.Stat(yamlPath); err == nil {
		return yamlPath, nil
	}
	if err := os.MkdirAll(filepath.Dir(yamlPath), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(yamlPath, []byte(defaultYAMLTemplate), 0o644); err != nil {
		return "", err
	}
	return yamlPath, nil
}

// ActivePath 返回当前实际生效的配置文件：config.json 存在则用之，
// 否则回落到同目录 config.yaml（`dldw config path` 展示用）。
func ActivePath() string {
	p := Path()
	if _, err := os.Stat(p); err == nil {
		return p
	}
	y := yamlSibling(p)
	if _, err := os.Stat(y); err == nil {
		return y
	}
	return p
}

// Set applies a dotted path assignment ("download.concurrency" "8").
func (c *Config) Set(path, value string) error {
	m, err := c.toMap()
	if err != nil {
		return err
	}
	parts := strings.Split(strings.ToLower(path), ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = coerce(value)
			break
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	buf, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, c)
}

// Unset removes a dotted path key.
func (c *Config) Unset(path string) error {
	m, err := c.toMap()
	if err != nil {
		return err
	}
	parts := strings.Split(strings.ToLower(path), ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			delete(cur, p)
			break
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			return fmt.Errorf("config: unknown key %q", path)
		}
		cur = next
	}
	buf, err := json.Marshal(m)
	if err != nil {
		return err
	}
	*c = Default()
	return json.Unmarshal(buf, c)
}

func (c Config) toMap() (map[string]any, error) {
	buf, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func coerce(v string) any {
	switch strings.ToLower(v) {
	case "true":
		return true
	case "false":
		return false
	}
	if i, err := strconv.Atoi(v); err == nil {
		return i
	}
	return v
}

// Accessors with sane fallbacks.

func (c Config) ChunkSizeBytes() int64 {
	v, err := hunits.ParseBytes(c.Download.ChunkSize)
	if err != nil || v < 1 {
		return 16 << 20
	}
	return v
}

func (c Config) Concurrency() int {
	if c.Download.Concurrency < 1 {
		return 8
	}
	if c.Download.Concurrency > 64 {
		return 64
	}
	return c.Download.Concurrency
}

func (c Config) RefreshBeforeDur() time.Duration {
	d, err := hunits.ParseDuration(c.Download.RefreshBefore)
	if err != nil || d <= 0 {
		return 120 * time.Second
	}
	return d
}

func (c Config) TaskPollWaitDur() time.Duration {
	d, err := hunits.ParseDuration(c.Download.TaskPollWait)
	if err != nil || d <= 0 {
		return time.Second
	}
	return d
}

func (c Config) TaskTimeoutDur() time.Duration {
	d, err := hunits.ParseDuration(c.Download.TaskTimeout)
	if err != nil || d <= 0 {
		return 10 * time.Minute
	}
	return d
}

func (c Config) ProxyIdleTimeout() time.Duration {
	d, err := hunits.ParseDuration(c.Proxy.IdleTimeout)
	if err != nil || d <= 0 {
		return 5 * time.Minute
	}
	return d
}

// TokenFile renders the token file path.
func (c Config) TokenFilePath() string {
	if c.TokenFile == "" {
		return filepath.Join(Dir(), "token.json")
	}
	if filepath.IsAbs(c.TokenFile) {
		return c.TokenFile
	}
	if strings.HasPrefix(c.TokenFile, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(c.TokenFile, "~/"))
	}
	return c.TokenFile
}

// Credentials stored in the token file.
type Credentials struct {
	ClientID string `json:"client_id"`
	Token    string `json:"token"`
	Server   string `json:"server,omitempty"`
}

// LoadCredentials reads the token file.
func LoadCredentials(path string) (*Credentials, error) {
	if path == "" {
		return nil, errors.New("no token file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// SaveCredentials atomically writes the token file.
func SaveCredentials(path string, c *Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EffectiveServer resolves the server URL: flag > env > config.
func EffectiveServer(flagValue string, cfg Config) string {
	if flagValue != "" {
		return strings.TrimRight(flagValue, "/")
	}
	if v := os.Getenv("DLDW_SERVER"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(cfg.Server, "/")
}
