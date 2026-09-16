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
	Enabled          bool      `json:"enabled"`                // 是否启动隧道监听
	Listen           string    `json:"listen"`                 // 监听地址，如 0.0.0.0:8081
	TLS              TLSConfig `json:"tls"`                    // 可选 TLS（生产环境必须启用）
	MaxConnsPerToken int       `json:"max_conns_per_token"`    // 每 token 并发隧道连接上限
	MaxBytesPerConn  string    `json:"max_bytes_per_conn"`     // 单连接字节上限（如 "256MiB"），隧道不承载大文件
	IdleTimeout      string    `json:"idle_timeout"`           // 连接空闲超时（如 "300s"），同时作为 OK 应答的 expires_in
}

// S3Config 为 S3 兼容对象存储驱动配置（S3/MinIO/OSS/COS）。
// 大文件通过预签名 URL 由客户端直连对象存储，不经过 dldw 服务器中转。
type S3Config struct {
	Endpoint        string `json:"endpoint"`    // 如 https://s3.us-east-1.amazonaws.com 或 http://minio:9000
	Region          string `json:"region"`      // 如 us-east-1；留空按 us-east-1
	Bucket          string `json:"bucket"`      // 缓存桶名
	AccessKeyID     string `json:"access_key"`  // AccessKey ID
	SecretAccessKey string `json:"secret_key"`  // AccessKey Secret（务必保密）
	PathStyle       bool   `json:"path_style"`  // MinIO/自建为 true；AWS 虚拟主机风格为 false
}

// StorageConfig 选择并配置对象存储驱动。
//   - localfs：本地文件系统 + HMAC 预签名 URL，由控制 API 的 /files/ 提供
//     Range 下载（自托管/开发用，流量仍经过 API 端口）。
//   - s3：预签名直传，缓存命中流量零中转（生产推荐）。
type StorageConfig struct {
	Driver string   `json:"driver"` // localfs | s3
	Root   string   `json:"root"`   // localfs 对象根目录；相对路径基于 data_dir
	Secret string   `json:"secret"` // localfs 预签名 HMAC 密钥，必须 >=16 字节，生产环境务必更换
	S3     S3Config `json:"s3"`     // driver=s3 时生效
}

// Aria2Config 为 aria2 RPC 执行器配置（可选；默认用 builtin 纯 Go 执行器）。
type Aria2Config struct {
	RPCURL string `json:"rpc_url"` // aria2 JSON-RPC 地址，如 http://127.0.0.1:6800/jsonrpc
	Secret string `json:"secret"`  // aria2 的 rpc-secret（不带 "token:" 前缀）
}

// ExecutorConfig 选择并配置源站抓取执行器（spec 4.3）。
type ExecutorConfig struct {
	Driver        string      `json:"driver"`        // builtin（默认，纯 Go）| aria2
	MaxBytes      string      `json:"max_bytes"`     // 单工件大小上限（如 "8GiB"；0/空 = 不限）
	Ports         []int       `json:"ports"`         // 允许访问源站的端口，默认 [80,443]
	AllowLoopback bool        `json:"allow_loopback"` // 仅测试用：允许抓取回环源站；公网部署必须为 false
	Aria2         Aria2Config `json:"aria2"`         // driver=aria2 时生效
}

// AuthConfig 配置设备令牌（spec 5：设备 token 与控制面鉴权）。
type AuthConfig struct {
	TokensFile        string `json:"tokens_file"`        // 令牌存储文件（只存哈希）
	TokenTTL          string `json:"token_ttl"`          // 令牌有效期，如 "720h"；支持 refresh 轮换
	AllowRegistration bool   `json:"allow_registration"` // 是否开放 POST /api/v1/token 注册；完成设备接入后建议关闭
}

// Config 是服务端完整配置。字段与 deploy/server.example.yaml 一一对应。
type Config struct {
	Listen        string        `json:"listen"`        // 控制 API 监听地址（healthz/resolve/...）
	PublicBase    string        `json:"public_base"`   // 对外可见基础 URL；localfs 预签名 URL 会拼在它后面
	TLS           TLSConfig     `json:"tls"`           // 控制 API 可选 TLS
	Tunnel        TunnelConfig  `json:"tunnel"`        // DLDW/1 隧道
	Storage       StorageConfig `json:"storage"`       // 对象存储驱动
	Executor      ExecutorConfig `json:"executor"`     // 源站抓取执行器
	Auth          AuthConfig    `json:"auth"`          // 设备令牌
	WhitelistFile string        `json:"whitelist_file"` // 隧道白名单文件（热加载，改文件即生效）
	TasksFile     string        `json:"tasks_file"`    // 任务持久化文件（JSON，重启可恢复）
	TmpDir        string        `json:"tmp_dir"`       // 任务临时下载目录（GC 自动清理）
	AuditLog      string        `json:"audit_log"`     // 审计日志文件；空 = stdout（JSON lines）
	DataDir       string        `json:"data_dir"`      // 相对路径与空缺路径的解析基准目录
	PresignTTL    string        `json:"presign_ttl"`   // 预签名 URL 有效期（如 "15m"）
	BlockPrivate  *bool         `json:"block_private"` // 执行器出口是否阻断私网；nil = true（默认）。安全下限：loopback/link-local 永远阻断
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
