// Package app wires and runs the dldw server: control API, tunnel, storage,
// executor and task engine (spec 4).
//
// 配置说明（维护者向）：
//   - 配置文件支持 JSON 与 YAML 子集两种格式（按扩展名 .json / .yaml 判断），
//     带注释的可读模板见 deploy/server.example.yaml。
//   - 加载顺序：Default(dataDir) 打底 → 配置文件覆盖 → normalize() 补全相对路径。
//   - 字段未配置时的默认值见 Default() 与 normalize()；duration/size 字段
//     一律为字符串（如 "15m"、"256MiB"），由 internal/hunits 解析。
package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dldw/internal/hunits"
	"dldw/internal/yamlmin"
)

// TLSConfig 为 API / 隧道可选的 TLS 终结配置。
// cert/key 为 PEM 文件路径；两者都为空表示明文监听（仅限内网/开发）。
type TLSConfig struct {
	Cert string `json:"cert"` // PEM 证书路径，如 /etc/dldw/tls/fullchain.pem
	Key  string `json:"key"`  // PEM 私钥路径
}

// TunnelConfig 配置 DLDW/1 受控出口隧道（spec 4.2）。
//
// 端口约定（重要）：客户端从 server URL 推导隧道地址——
// URL 带显式端口 P 时隧道端口为 P+1；https 默认 4443，http 默认 8081。
// 因此修改 tunnel.listen 时必须同步修改客户端侧的 server 端口约定，
// 否则客户端会连错端口。
type TunnelConfig struct {
	Enabled          bool      `json:"enabled"`             // 是否启动隧道监听
	Listen           string    `json:"listen"`              // 监听地址，如 0.0.0.0:8081
	TLS              TLSConfig `json:"tls"`                 // 可选 TLS（生产环境必须启用）
	UpstreamProxy    string    `json:"upstream_proxy"`      // 可选上游代理 http://127.0.0.1:10808（如 Xray mixed 入站）；启用后目标 DNS/SSRF 委托给代理，白名单与端口策略仍生效
	Mode             string    `json:"mode"`                // whitelist_only（默认，dldw 语义）| relay_all（dldc 语义：任意公网域名中转，SSRF/端口/限额不变）
	MaxConnsPerToken int       `json:"max_conns_per_token"` // 每 token 并发隧道连接上限
	MaxBytesPerConn  string    `json:"max_bytes_per_conn"`  // 单连接字节上限（如 "256MiB"），隧道不承载大文件
	IdleTimeout      string    `json:"idle_timeout"`        // 连接空闲超时（如 "300s"），同时作为 OK 应答的 expires_in
}

// S3Config 为 S3 兼容对象存储驱动配置（AWS S3 / MinIO / OSS / COS / R2）。
// 大文件通过预签名 URL 由客户端直连对象存储，不经过 dldw 服务器中转。
type S3Config struct {
	Endpoint        string `json:"endpoint"`   // 如 https://s3.us-east-1.amazonaws.com 或 http://minio:9000
	Region          string `json:"region"`     // 如 us-east-1；留空按 us-east-1
	Bucket          string `json:"bucket"`     // 缓存桶名
	AccessKeyID     string `json:"access_key"` // AccessKey ID
	SecretAccessKey string `json:"secret_key"` // AccessKey Secret（务必保密）
	PathStyle       bool   `json:"path_style"` // MinIO/自建 = true；AWS 虚拟主机风格 = false（driver: minio 时强制 true）
}

// OpenListConfig 为 OpenList（AList 分支）存储驱动配置。
// dldw 通过其 REST API 存取工件，下载链接用 fs/get 返回的 raw_url：
// 挂载 S3/云盘类驱动时是底层直链（零中转）；挂载本地/WebDAV 类驱动时是
// OpenList 的 /d/ 代理地址（中转模式，Range 透传）。
type OpenListConfig struct {
	BaseURL    string `json:"base_url"`    // 如 http://openlist:5244；客户端必须能访问它或其底层直链
	Token      string `json:"token"`       // OpenList API token（推荐）；留空则用账密登录
	Username   string `json:"username"`    // 登录用户名（token 为空时使用）
	Password   string `json:"password"`    // 登录密码
	RootPath   string `json:"root_path"`   // OpenList 内的缓存根目录，默认 /dldw-cache；建议独立目录
	DirPassword string `json:"dir_password"` // 目录签名/访问密码，一般留空
}

// StorageConfig 选择并配置对象存储驱动。
//   - localfs（别名 fs）：本地文件系统 + HMAC 预签名 URL，由控制 API 的
//     /files/ 提供 Range 下载（自托管/开发用，流量仍经过 API 端口）。
//   - s3：任何 S3 兼容后端的 SigV4 预签名直传，缓存命中流量零中转
//     （AWS S3、阿里云 OSS、腾讯 COS、Cloudflare R2 等凡暴露 S3 API 的都用此项）。
//   - minio：等价于 s3，但强制 path_style=true（MinIO 的寻址约定）。
//   - openlist：把 OpenList/AList 挂载当作存储；直链或中转取决于其挂载的驱动。
//
// 新增后端：实现 internal/transfer/storage.Storage 接口（PresignGet/Head/
// Put/Get/Delete/Ping），并在 app.New 的 storage switch 注册。
type StorageConfig struct {
	Driver   string        `json:"driver"`   // localfs | fs | s3 | minio | openlist
	Root     string        `json:"root"`     // localfs 对象根目录；相对路径基于 data_dir
	Secret   string        `json:"secret"`   // localfs 预签名 HMAC 密钥，必须 >=16 字节，生产环境务必更换
	S3       S3Config      `json:"s3"`       // driver=s3|minio 时生效
	OpenList OpenListConfig `json:"openlist"` // driver=openlist 时生效
}

// Aria2Config 为 aria2 RPC 执行器配置（可选；默认用 builtin 纯 Go 执行器）。
type Aria2Config struct {
	RPCURL string `json:"rpc_url"` // aria2 JSON-RPC 地址，如 http://127.0.0.1:6800/jsonrpc
	Secret string `json:"secret"`  // aria2 的 rpc-secret（不带 "token:" 前缀）
}

// ExecutorConfig 选择并配置源站抓取执行器（spec 4.3）。
type ExecutorConfig struct {
	Driver        string      `json:"driver"`         // builtin（默认，纯 Go）| aria2
	MaxBytes      string      `json:"max_bytes"`      // 单工件大小上限（如 "8GiB"；0/空 = 不限）
	Ports         []int       `json:"ports"`          // 允许访问源站的端口，默认 [80,443]
	UpstreamProxy string      `json:"upstream_proxy"` // 可选上游代理（如 Xray http://127.0.0.1:10808）；启用后源站 DNS/SSRF 委托给代理，端口白名单仍生效
	AllowLoopback bool        `json:"allow_loopback"` // 仅测试用：允许抓取回环源站；公网部署必须为 false
	Aria2         Aria2Config `json:"aria2"`          // driver=aria2 时生效
}

// AuthConfig 配置设备令牌（spec 5：设备 token 与控制面鉴权）。
type AuthConfig struct {
	TokensFile        string `json:"tokens_file"`        // 令牌存储文件（只存哈希）
	TokenTTL          string `json:"token_ttl"`          // 令牌有效期，如 "720h"；支持 refresh 轮换
	AllowRegistration bool   `json:"allow_registration"` // 是否开放 POST /api/v1/token 注册；完成设备接入后建议关闭
	// MirrorAuth 为 true 时，/pypi /npm /mirror /gomod /hf 需要设备令牌
	//（Bearer 或 Basic），用于把镜像端点暴露到局域网/公网给团队共享；
	// /v2（Docker）不参与——daemon 不会向 mirror 发凭证，需网络层限制。
	MirrorAuth bool `json:"mirror_auth"`
}

// HFConfig 配置 HuggingFace Hub 代理。
type HFConfig struct {
	Enabled bool   `json:"enabled"` // 是否挂载 /hf/* 路由
	Origin  string `json:"origin"`  // 默认 https://huggingface.co
}

// ProxyCoreConfig 内嵌代理核心（sing-box 子进程托管），让服务端自带出口，
// 不再依赖宿主机上的 v2rayN/Xray 客户端。
//
// 启用后：executor 抓源站与隧道出口的 upstream_proxy 若未显式配置，
// 会自动指向本核心的 mixed 入站（http://<listen>:<port>）。
type ProxyCoreConfig struct {
	Enabled   bool   `json:"enabled"`    // 启动时是否启用服务端代理
	Core      string `json:"core"`       // 目前支持 sing-box
	Binary    string `json:"binary"`     // sing-box 可执行文件路径
	ShareLink string `json:"share_link"` // hysteria2://... 分享链接
	Listen    string `json:"listen"`     // mixed 入站监听地址，默认 127.0.0.1
	Port      int    `json:"port"`       // mixed 入站端口，默认 1080
	ConfigDir string `json:"config_dir"` // 生成的 sing-box 配置目录，默认 data_dir/proxycore
	LogLevel  string `json:"log_level"`  // sing-box 日志级别（warn/info/debug/trace）
}

// PyPIConfig 配置 PyPI 拉穿镜像（uv/pip 吃服务端缓存）。
type PyPIConfig struct {
	Enabled      bool     `json:"enabled"`       // 是否挂载 /pypi/* 路由
	IndexOrigin  string   `json:"index_origin"`  // 兼容单源写法（等价 index_origins[0]）
	IndexOrigins []string `json:"index_origins"` // 索引源列表（顺序回退），如 [https://pypi.org, https://pypi.tuna.tsinghua.edu.cn]
	FilesOrigin  string   `json:"files_origin"`  // 兼容单源写法
	FilesOrigins []string `json:"files_origins"` // wheel 源列表（顺序回退）
	IndexTTL     string   `json:"index_ttl"`     // 索引页内存缓存 TTL，默认 10m
}

// NPMConfig 配置 npm registry 拉穿镜像（npm/pnpm/yarn 吃服务端缓存）。
type NPMConfig struct {
	Enabled         bool     `json:"enabled"`          // 是否挂载 /npm/* 路由
	RegistryOrigin  string   `json:"registry_origin"`  // 兼容单源写法
	RegistryOrigins []string `json:"registry_origins"` // registry 源列表（顺序回退）
	IndexTTL        string   `json:"index_ttl"`        // 元数据内存缓存 TTL，默认 2m
}

// WebMirrorConfig 配置通用静态文件拉穿镜像（apt .deb / yum .rpm / 任意静态
// 大文件；仓库元数据自动透传不缓存）。
type WebMirrorConfig struct {
	Enabled      bool     `json:"enabled"`       // 是否挂载 /mirror/* 路由
	AllowedHosts []string `json:"allowed_hosts"` // 可选 host 白名单；空 = 任意公网主机（仍受 SSRF 策略限制）
}

// GoModConfig 配置 Go module proxy 拉穿镜像（GOPROXY 协议）。
type GoModConfig struct {
	Enabled bool     `json:"enabled"` // 是否挂载 /gomod/* 路由
	Origin  string   `json:"origin"`  // 兼容单源写法（默认 https://proxy.golang.org）
	Origins []string `json:"origins"` // 上游列表（顺序回退），如 [https://proxy.golang.org, https://goproxy.cn]
}

// DockerRegistryConfig 配置 Docker Registry V2 拉穿镜像。
// 上游认证由服务端统一处理：配置 Docker Hub 账号可绕开匿名 IP 限流
// （免费账号 200 次/6h）；blob 按 digest 校验 SHA256 后入库（内容寻址防篡改）。
// 客户端：Docker Desktop daemon.json 加 "registry-mirrors": ["http://<listen>"]。
type DockerRegistryConfig struct {
	Enabled     bool   `json:"enabled"`      // 是否挂载 /v2/* 路由
	Username    string `json:"username"`     // Docker Hub 账号（强烈建议配置）
	Password    string `json:"password"`     // 密码或 Access Token
	Origin      string `json:"origin"`       // 默认 https://registry-1.docker.io
	AuthURL     string `json:"auth_url"`     // 默认 https://auth.docker.io/token
	ManifestTTL string `json:"manifest_ttl"` // tag manifest 缓存 TTL，默认 60s
}

// Config 是服务端完整配置。字段与 deploy/server.example.yaml 一一对应。
type Config struct {
	Listen        string         `json:"listen"`        // 控制 API 监听地址（healthz/resolve/...）
	PublicBase    string         `json:"public_base"`   // 对外可见基础 URL；localfs 预签名/pypi 重写会拼在它后面
	TLS           TLSConfig      `json:"tls"`           // 控制 API 可选 TLS
	Tunnel        TunnelConfig   `json:"tunnel"`        // DLDW/1 隧道
	Proxy         ProxyCoreConfig `json:"proxy"`        // 内嵌代理核心（sing-box 托管）
	Storage       StorageConfig  `json:"storage"`       // 对象存储驱动
	Executor      ExecutorConfig `json:"executor"`      // 源站抓取执行器
	Auth          AuthConfig     `json:"auth"`          // 设备令牌
	PyPI          PyPIConfig     `json:"pypi"`          // PyPI 拉穿镜像
	NPM           NPMConfig      `json:"npm"`           // npm 拉穿镜像
	Mirror        WebMirrorConfig `json:"mirror"`       // 通用静态文件拉穿镜像（apt/yum）
	GoMod         GoModConfig    `json:"gomod"`         // Go module proxy 镜像
	HF            HFConfig       `json:"huggingface"`   // HuggingFace Hub 代理
	Registry      DockerRegistryConfig `json:"registry"` // Docker Registry V2 镜像
	WhitelistFile string         `json:"whitelist_file"` // 隧道白名单文件（热加载，改文件即生效）
	TasksFile     string         `json:"tasks_file"`    // 任务持久化文件（JSON，重启可恢复）
	TmpDir        string         `json:"tmp_dir"`       // 任务临时下载目录（GC 自动清理）
	AuditLog      string         `json:"audit_log"`     // 审计日志文件；空 = stdout（JSON lines）
	DataDir       string         `json:"data_dir"`      // 相对路径与空缺路径的解析基准目录
	PresignTTL    string         `json:"presign_ttl"`   // 预签名 URL 有效期（如 "15m"）
	BlockPrivate  *bool          `json:"block_private"` // 执行器出口是否阻断私网；nil = true（默认）。安全下限：loopback/link-local 永远阻断
}

// Default 返回基于 dataDir 的开发友好默认配置。
// 生产环境至少需要修改：storage.secret（localfs）或切换 storage.driver=s3、
// 开启 tunnel.tls、收紧 auth.allow_registration。
func Default(dataDir string) Config {
	return Config{
		Listen: "127.0.0.1:8080",
		Tunnel: TunnelConfig{
			Enabled:          true,
			Listen:           "127.0.0.1:8081",
			MaxConnsPerToken: 16,
			MaxBytesPerConn:  "256MiB",
			IdleTimeout:      "300s",
		},
		Storage: StorageConfig{
			Driver: "localfs",
			Root:   filepath.Join(dataDir, "objects"),
			Secret: "dldw-dev-secret-change-me-32bytes",
		},
		Executor: ExecutorConfig{Driver: "builtin", MaxBytes: "8GiB", Ports: []int{80, 443}},
		Auth: AuthConfig{
			TokensFile:        filepath.Join(dataDir, "tokens.json"),
			TokenTTL:          "720h",
			AllowRegistration: true,
		},
		WhitelistFile: filepath.Join(dataDir, "whitelist.txt"),
		TasksFile:     filepath.Join(dataDir, "tasks.json"),
		TmpDir:        filepath.Join(dataDir, "tmp"),
		DataDir:       dataDir,
		PresignTTL:    "15m",
	}
}

// LoadConfig 读取配置文件（.json 或 .yaml/.yml 子集），覆盖到默认值上。
// path 为空时直接返回默认配置。文件不存在返回错误。
func LoadConfig(path string) (Config, error) {
	cfg := Default(filepath.Dir(path))
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if strings.EqualFold(filepath.Ext(path), ".yaml") || strings.EqualFold(filepath.Ext(path), ".yml") {
		if err := yamlmin.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse yaml %s: %w", path, err)
		}
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse json %s: %w", path, err)
		}
	}
	cfg.normalize(filepath.Dir(path))
	return cfg, nil
}

// normalize 填充空缺路径并应用兜底值：
//   - 未提供的路径字段：相对 data_dir 存放（见 rel）；
//   - 相对路径：一律相对于 data_dir 解析（而非进程工作目录）；
//   - 监听地址、TTL、驱动名等留空时使用内置默认。
func (c *Config) normalize(base string) {
	if c.DataDir == "" {
		c.DataDir = base
	}
	rel := func(p string, def string) string {
		if p == "" {
			return def
		}
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(c.DataDir, p)
	}
	c.Storage.Root = rel(c.Storage.Root, filepath.Join(c.DataDir, "objects"))
	if c.Storage.Secret == "" {
		c.Storage.Secret = "dldw-dev-secret-change-me-32bytes"
	}
	c.Auth.TokensFile = rel(c.Auth.TokensFile, filepath.Join(c.DataDir, "tokens.json"))
	c.WhitelistFile = rel(c.WhitelistFile, filepath.Join(c.DataDir, "whitelist.txt"))
	c.TasksFile = rel(c.TasksFile, filepath.Join(c.DataDir, "tasks.json"))
	c.TmpDir = rel(c.TmpDir, filepath.Join(c.DataDir, "tmp"))
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.Tunnel.Enabled && c.Tunnel.Listen == "" {
		c.Tunnel.Listen = "127.0.0.1:8081"
	}
	if c.Auth.TokenTTL == "" {
		c.Auth.TokenTTL = "720h"
	}
	if c.PresignTTL == "" {
		c.PresignTTL = "15m"
	}
	if c.Executor.Driver == "" {
		c.Executor.Driver = "builtin"
	}
	if len(c.Executor.Ports) == 0 {
		c.Executor.Ports = []int{80, 443}
	}

	// 内嵌代理核心路径兜底
	if c.Proxy.Enabled {
		if c.Proxy.Core == "" {
			c.Proxy.Core = "sing-box"
		}
		if c.Proxy.Listen == "" {
			c.Proxy.Listen = "127.0.0.1"
		}
		if c.Proxy.Port == 0 {
			c.Proxy.Port = 1080
		}
		c.Proxy.ConfigDir = rel(c.Proxy.ConfigDir, filepath.Join(c.DataDir, "proxycore"))
	}
}

// TokenTTL 解析 auth.token_ttl；非法值兜底 720h。
func (c *Config) TokenTTL() time.Duration {
	d, err := hunits.ParseDuration(c.Auth.TokenTTL)
	if err != nil {
		return 720 * time.Hour
	}
	return d
}

// PresignTTLDuration 解析 presign_ttl；非法值兜底 15m。
func (c *Config) PresignTTLDuration() time.Duration {
	d, err := hunits.ParseDuration(c.PresignTTL)
	if err != nil {
		return 15 * time.Minute
	}
	return d
}
