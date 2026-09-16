// Package proxycore 让 dldw 服务端自带翻墙出口：解析分享链接（hysteria2），
// 生成 sing-box 配置并作为子进程托管（mixed 入站 = 服务端内部 upstream_proxy）。
// 部署上不再依赖宿主机的 v2rayN；是否启用由 server.yaml 的 proxy.enabled
// 或 serve --no-proxy-core 控制。
package proxycore

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ShareLink 是从分享链接解析出的出口描述（当前支持 hysteria2）。
type ShareLink struct {
	Server     string // 服务器主机
	Port       int    // 服务器端口
	Password   string // 认证密码
	SNI        string // TLS SNI（默认同 Server）
	Insecure   bool   // 跳过证书校验
	ObfsType   string // 空 | salamander
	ObfsPass   string
	Name       string // 节点备注
}

// ParseHysteria2 解析 hysteria2://password@host:port?sni=..&insecure=..&obfs=..
// 链接（兼容 hy2:// 前缀）。
func ParseHysteria2(raw string) (*ShareLink, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("proxycore: bad share link: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "hysteria2" && scheme != "hy2" {
		return nil, fmt.Errorf("proxycore: unsupported scheme %q (want hysteria2://)", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, fmt.Errorf("proxycore: missing host/port in share link")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("proxycore: bad port %q", u.Port())
	}
	sl := &ShareLink{
		Server:   u.Hostname(),
		Port:     port,
		SNI:      u.Hostname(),
		Password: u.User.Username(),
	}
	if p, ok := u.User.Password(); ok && sl.Password == "" {
		sl.Password = p
	}
	q := u.Query()
	if v := q.Get("sni"); v != "" {
		sl.SNI = v
	}
	if v := q.Get("insecure"); v == "1" || strings.EqualFold(v, "true") {
		sl.Insecure = true
	}
	if v := q.Get("allowInsecure"); v == "1" || strings.EqualFold(v, "true") {
		sl.Insecure = true
	}
	if v := q.Get("obfs"); v != "" && v != "none" {
		sl.ObfsType = v
		sl.ObfsPass = q.Get("obfs-password")
	}
	sl.Name = strings.TrimPrefix(u.Fragment, "")
	if sl.Password == "" {
		return nil, fmt.Errorf("proxycore: missing password in share link")
	}
	return sl, nil
}

// singBoxConfig 是生成 sing-box 配置所需的最小结构。
type singBoxConfig struct {
	Log      singBoxLog      `json:"log"`
	Inbounds []singBoxIn     `json:"inbounds"`
	Outbounds []singBoxOut   `json:"outbounds"`
	Route    singBoxRoute    `json:"route"`
}

type singBoxLog struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type singBoxIn struct {
	Type       string `json:"type"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

type singBoxOut struct {
	Type       string          `json:"type"`
	Tag        string          `json:"tag,omitempty"`
	Server     string          `json:"server,omitempty"`
	ServerPort int             `json:"server_port,omitempty"`
	Password   string          `json:"password,omitempty"`
	Obfs       *singBoxObfs    `json:"obfs,omitempty"`
	TLS        *singBoxTLS     `json:"tls,omitempty"`
}

type singBoxObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type singBoxTLS struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
	Insecure   bool   `json:"insecure"`
}

type singBoxRoute struct {
	Final string `json:"final"`
}

// GenerateSingBoxConfig 生成 sing-box 配置：本地 mixed 入站 -> hysteria2 出口。
func GenerateSingBoxConfig(sl *ShareLink, listen string, port int, logLevel string) ([]byte, error) {
	if listen == "" {
		listen = "127.0.0.1"
	}
	if port <= 0 {
		port = 1080
	}
	if logLevel == "" {
		logLevel = "warn"
	}
	out := singBoxOut{
		Type:       "hysteria2",
		Tag:        "proxy",
		Server:     sl.Server,
		ServerPort: sl.Port,
		Password:   sl.Password,
		TLS: &singBoxTLS{
			Enabled:    true,
			ServerName: sl.SNI,
			Insecure:   sl.Insecure,
		},
	}
	if sl.ObfsType != "" {
		out.Obfs = &singBoxObfs{Type: sl.ObfsType, Password: sl.ObfsPass}
	}
	cfg := singBoxConfig{
		Log:      singBoxLog{Level: logLevel, Timestamp: true},
		Inbounds: []singBoxIn{{Type: "mixed", Listen: listen, ListenPort: port}},
		Outbounds: []singBoxOut{
			out,
			{Type: "direct", Tag: "direct"},
		},
		Route: singBoxRoute{Final: "proxy"},
	}
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}

// Manager 托管 sing-box 子进程的生命周期。
type Manager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	exited  chan struct{}
	LogPath string
}

// Start 启动 sing-box（run -c <cfgPath>），日志追加到 logPath（空 = 丢弃）。
func Start(binary, cfgPath, logPath string) (*Manager, error) {
	if binary == "" {
		return nil, fmt.Errorf("proxycore: binary path required")
	}
	if _, err := os.Stat(binary); err != nil {
		return nil, fmt.Errorf("proxycore: sing-box binary not found: %w", err)
	}
	cmd := exec.Command(binary, "run", "-c", cfgPath)
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("proxycore: open log: %w", err)
		}
		cmd.Stdout = f
		cmd.Stderr = f
	} else {
		cmd.Stdout = nil
		cmd.Stderr = nil
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("proxycore: start sing-box: %w", err)
	}
	m := &Manager{cmd: cmd, exited: make(chan struct{}), LogPath: logPath}
	go func() {
		cmd.Wait()
		close(m.exited)
	}()
	return m, nil
}

// WaitReady 等待 mixed 入站端口可连（探测 TCP），超时返回错误。
func (m *Manager) WaitReady(addr string, timeout time.Duration) error {
	if addr == "" {
		addr = "127.0.0.1:1080"
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-m.exited:
			return fmt.Errorf("proxycore: sing-box exited early (see %s)", m.LogPath)
		default:
		}
		conn, err := net_DialTimeout(addr, 700*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("proxycore: sing-box inbound %s not ready within %s", addr, timeout)
}

// Stop 终止子进程（幂等）。
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return
	}
	select {
	case <-m.exited:
		return
	default:
	}
	m.cmd.Process.Kill()
	<-m.exited
	m.cmd = nil
}
