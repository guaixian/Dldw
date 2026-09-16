// Package tunnel implements the server side of the DLDW/1 controlled egress
// tunnel (spec 4.2): token auth, nonce replay protection, whitelist, DNS +
// SSRF validation, port policy, per-token concurrency and byte caps, then
// raw TCP forwarding with audit.
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"dldw/internal/ids"
	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
	"dldw/internal/protocol/dldw1"
	"dldw/internal/server/audit"
	"dldw/internal/server/auth"
	"dldw/internal/server/ratelimit"
	"dldw/internal/upstreamproxy"
)

// Config wires tunnel dependencies and limits.
type Config struct {
	Tokens *auth.Store
	Nonces *auth.NonceStore
	WL     *whitelist.Store
	Policy *ssrf.Policy
	Audit  *audit.Logger

	// UpstreamProxy is an optional http(s):// proxy for tunnel egress
	// (e.g. Xray mixed inbound http://127.0.0.1:10808). When set, target
	// DNS/SSRF resolution is delegated to the proxy; whitelist and port
	// policy still apply locally, and the OK reply reports resolved_ip "-".
	UpstreamProxy string

	HandshakeTimeout time.Duration // default 10s
	IdleTimeout      time.Duration // default 5m
	MaxConnsPerToken int           // default 16
	MaxBytesPerConn  int64         // default 256MiB (tunnels are not for large files)
	CopyBuffer       int           // default 32KiB
}

func (c *Config) defaults() {
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	if c.MaxConnsPerToken <= 0 {
		c.MaxConnsPerToken = 16
	}
	if c.MaxBytesPerConn <= 0 {
		c.MaxBytesPerConn = 256 << 20
	}
	if c.CopyBuffer <= 0 {
		c.CopyBuffer = 32 * 1024
	}
	if c.Audit == nil {
		c.Audit = audit.New(nil)
	}
	if c.Policy == nil {
		c.Policy = &ssrf.Policy{BlockPrivate: true}
	}
	if c.Nonces == nil {
		c.Nonces = auth.NewNonceStore(10 * time.Minute)
	}
}

// Server is the tunnel listener.
type Server struct {
	cfg   Config
	conns *ratelimit.Conc
}

func New(cfg Config) *Server {
	cfg.defaults()
	return &Server{cfg: cfg, conns: ratelimit.NewConc(cfg.MaxConnsPerToken)}
}

// Serve accepts connections on ln until the context is canceled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
		}
		go s.handle(conn)
	}
}

// ListenTLS wraps ln in TLS when cert/key are provided.
func ListenTLS(ln net.Listener, certFile, keyFile string) (net.Listener, error) {
	if certFile == "" || keyFile == "" {
		return ln, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tunnel: load TLS: %w", err)
	}
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

func (s *Server) reject(conn net.Conn, code, msg string) {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.Write((&dldw1.Err{Code: code, Message: msg}).Encode())
	conn.Close()
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	cfg := s.cfg

	conn.SetReadDeadline(time.Now().Add(cfg.HandshakeTimeout))
	br := bufio.NewReaderSize(conn, dldw1.MaxLine+1)
	line, err := dldw1.ReadLine(br)
	if err != nil {
		s.reject(conn, "E_PROTO", "handshake read failed")
		return
	}
	req, err := dldw1.ParseConnect(line)
	if err != nil {
		s.reject(conn, "E_PROTO", "malformed handshake")
		return
	}

	// authenticate
	rec, aerr := cfg.Tokens.Validate(req.Token)
	if aerr != nil {
		s.reject(conn, "E_AUTH", "invalid token")
		cfg.Audit.Log("tunnel_auth_fail", "", "client_id", req.ClientID, "error", aerr.Error())
		return
	}
	if !cfg.Nonces.CheckAndAdd(rec.ID, req.Nonce) {
		s.reject(conn, "E_REPLAY", "nonce already used")
		cfg.Audit.Log("tunnel_replay", "", "token_id", rec.ID, "client_id", req.ClientID)
		return
	}

	// policy checks
	if !cfg.WL.Get().Match(req.Host) {
		s.reject(conn, "E_NOT_WHITELISTED", "host not in whitelist")
		cfg.Audit.Log("tunnel_wl_deny", "", "token_id", rec.ID, "host", req.Host)
		return
	}
	if perr := cfg.Policy.CheckPort(req.Port); perr != nil {
		s.reject(conn, ssrf.ErrorCode(perr), perr.Error())
		cfg.Audit.Log("tunnel_port_deny", "", "token_id", rec.ID, "host", req.Host, "port", req.Port)
		return
	}
	if cfg.UpstreamProxy == "" {
		// 直连模式：连接前完成 DNS 解析 + 私网/保留段阻断
		ctx, cancel := context.WithTimeout(context.Background(), cfg.HandshakeTimeout)
		if herr := cfg.Policy.CheckHost(ctx, req.Host); herr != nil {
			cancel()
			s.reject(conn, ssrf.ErrorCode(herr), herr.Error())
			cfg.Audit.Log("tunnel_ssrf_deny", "", "token_id", rec.ID, "host", req.Host)
			return
		}
		cancel()
	}
	// 上游代理模式：DNS/SSRF 委托给代理；白名单与端口策略已在本地强制

	// concurrency
	release, ok := s.concs(rec.ID)
	if !ok {
		s.reject(conn, "E_BUSY", "too many tunnel connections for token")
		cfg.Audit.Log("tunnel_busy", "", "token_id", rec.ID)
		return
	}
	defer release()

	// dial: 经上游代理（CONNECT）或带 SSRF 守卫的直连
	dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dcancel()
	var target net.Conn
	resolved := "-"
	if cfg.UpstreamProxy != "" {
		target, err = upstreamproxy.Dial(dctx, cfg.UpstreamProxy, net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
		if err == nil {
			if ta, ok := target.RemoteAddr().(*net.TCPAddr); ok && !ta.IP.IsLoopback() {
				resolved = ta.IP.String() // 代理地址，仅作参考
			}
		}
	} else {
		target, err = cfg.Policy.DialContext(dctx, "tcp", net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
		if err == nil {
			if ta, ok := target.RemoteAddr().(*net.TCPAddr); ok {
				resolved = ta.IP.String()
			}
		}
	}
	if err != nil {
		s.reject(conn, "E_UPSTREAM", "connect failed")
		cfg.Audit.Log("tunnel_dial_fail", "", "token_id", rec.ID, "host", req.Host, "port", req.Port,
			"proxied", cfg.UpstreamProxy != "", "error", err.Error())
		return
	}
	defer target.Close()

	connID := ids.NewConnID()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, werr := conn.Write((&dldw1.OK{
		ConnID:     connID,
		ExpiresIn:  int(cfg.IdleTimeout.Seconds()),
		ResolvedIP: resolved,
	}).Encode()); werr != nil {
		return
	}
	conn.SetReadDeadline(time.Time{}) // managed by copy loop below

	start := time.Now()
	var total int64
	cfg.Audit.Log("tunnel_open", connID, "token_id", rec.ID, "client_id", req.ClientID,
		"host", req.Host, "port", req.Port, "resolved_ip", resolved, "proxied", cfg.UpstreamProxy != "")

	done := make(chan struct{}, 2)
	go func() { s.pump(conn, target, connID, &total, false); done <- struct{}{} }()
	go func() { s.pump(target, conn, connID, &total, true); done <- struct{}{} }()
	<-done
	// closing both sides tears down the peer pump quickly
	conn.Close()
	target.Close()
	<-done

	cfg.Audit.Log("tunnel_close", connID, "token_id", rec.ID, "host", req.Host,
		"bytes", atomic.LoadInt64(&total), "duration_ms", time.Since(start).Milliseconds())
}

func (s *Server) concs(tokenID string) (func(), bool) { return s.conns.Acquire(tokenID) }

// pump copies src to dst with idle deadline and byte cap. halfClose marks the
// direction where EOF on src implies CloseWrite on dst.
func (s *Server) pump(src, dst net.Conn, connID string, total *int64, halfClose bool) {
	buf := make([]byte, s.cfg.CopyBuffer)
	for {
		src.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				dst.SetWriteDeadline(time.Now().Add(s.cfg.IdleTimeout))
				wn, werr := dst.Write(buf[written:n])
				written += wn
				if werr != nil {
					return
				}
			}
			t := atomic.AddInt64(total, int64(n))
			if s.cfg.MaxBytesPerConn > 0 && t > s.cfg.MaxBytesPerConn {
				s.cfg.Audit.Log("tunnel_cap", connID, "bytes", t, "cap", s.cfg.MaxBytesPerConn)
				return
			}
		}
		if rerr != nil {
			if errors.Is(rerr, os.ErrDeadlineExceeded) {
				s.cfg.Audit.Log("tunnel_idle_close", connID)
			}
			if halfClose {
				if tc, ok := dst.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
			}
			return
		}
	}
}

// io.EOF explicit reference for clarity.
var _ = io.EOF
