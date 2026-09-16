// Package upstreamproxy 通过上游 HTTP 代理建立隧道连接（HTTP CONNECT）。
// 用于把 dldw 服务端的源站抓取/隧道出口交给既有代理（如 Xray/v2ray 的
// mixed 入站）处理——由代理负责远端 DNS 解析与路由。
//
// 安全语义：启用上游代理后，目标主机的 DNS/SSRF 校验委托给代理执行
// （本地校验无法反映代理的真实出口）；dldw 仍保留目标端口白名单。
package upstreamproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Dial 经 proxyURL（http:// 或 https://[user:pass@]host:port）与 targetAddr
// （host:port）建立 CONNECT 隧道，返回已就绪的裸 TCP 连接。
func Dial(ctx context.Context, proxyURL, targetAddr string) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy: bad url: %w", err)
	}
	host := u.Hostname()
	port := u.Port()
	var useTLS bool
	switch u.Scheme {
	case "http", "":
		if port == "" {
			port = "80"
		}
	case "https":
		useTLS = true
		if port == "" {
			port = "443"
		}
	default:
		return nil, fmt.Errorf("upstream proxy: unsupported scheme %q (want http/https)", u.Scheme)
	}

	d := net.Dialer{Timeout: 15 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("upstream proxy: dial %s: %w", proxyURL, err)
	}
	conn := raw
	if useTLS {
		tc := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("upstream proxy: TLS: %w", err)
		}
		conn = tc
	}

	// 发送 CONNECT；携带代理认证（URL userinfo -> Basic）
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: http.Header{},
	}
	if u.User != nil {
		pass, _ := u.User.Password()
		req.SetBasicAuth(url.QueryEscape(u.User.Username()), url.QueryEscape(pass))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy: write CONNECT: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy: read response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy: CONNECT %s rejected: HTTP %d", targetAddr, resp.StatusCode)
	}
	conn.SetReadDeadline(time.Time{})
	// br 中若有多读的字节属于罕见情形（CONNECT 响应后不应有数据），丢弃缓存
	// 会丢字节，因此要求代理不在 200 响应后立刻发送目标数据（标准行为）。
	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		br.Read(buf)
		go func() { conn.Write(buf) }() // 极少见：回写早到的数据
	}
	return conn, nil
}

// Validate 校验代理 URL 格式。
func Validate(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream proxy: scheme must be http/https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream proxy: missing host")
	}
	if strings.ContainsAny(u.Host, " \t") {
		return fmt.Errorf("upstream proxy: bad host")
	}
	return nil
}
