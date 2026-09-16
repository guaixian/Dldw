// Package proxy implements the local HTTP/1.1 forward proxy used by the
// wrapper: plain HTTP requests are forwarded (absolute URI form), HTTPS uses
// CONNECT. Whitelisted hosts egress through the server tunnel, everything
// else goes direct; private/reserved targets are refused (spec 3.3).
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
)

// Options configures the local proxy server.
type Options struct {
	Bind string
	Port int // 0 = ephemeral

	// WL returns the current whitelist (hot swappable).
	WL *whitelist.Store

	// Policy guards direct egress.
	Policy *ssrf.Policy

	// Tunnel is the server tunnel config; nil disables tunneling (all direct).
	Tunnel *TunnelConfig

	IdleTimeout    time.Duration // default 5m
	MaxHeaderBytes int           // default 16KiB
	CopyBuffer     int           // default 32KiB

	Metrics *Metrics
	Debugf  func(format string, args ...any)
}

// Server is a running local proxy.
type Server struct {
	opts    Options
	ln      net.Listener
	metrics *Metrics

	mu       sync.Mutex
	closing  bool
	activeWG sync.WaitGroup
}

// Start binds and begins accepting. The listener is ready when Start returns.
func Start(opts Options) (*Server, error) {
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1"
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 5 * time.Minute
	}
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = 16 << 10
	}
	if opts.CopyBuffer <= 0 {
		opts.CopyBuffer = 32 << 10
	}
	if opts.WL == nil {
		opts.WL = whitelist.NewStore(whitelist.Default())
	}
	if opts.Policy == nil {
		opts.Policy = &ssrf.Policy{BlockPrivate: true}
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(opts.Bind, strconv.Itoa(opts.Port)))
	if err != nil {
		return nil, fmt.Errorf("E_PROXY_BIND: %w", err)
	}
	m := opts.Metrics
	if m == nil {
		m = NewMetrics()
	}
	s := &Server{opts: opts, ln: ln, metrics: m}
	go s.acceptLoop()
	return s, nil
}

// Addr returns the bound address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// URL returns the http:// proxy URL.
func (s *Server) URL() string {
	a := s.ln.Addr().(*net.TCPAddr)
	return "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(a.Port))
}

// Port returns the bound port.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Metrics exposes counters.
func (s *Server) Metrics() *Metrics { return s.metrics }

// Stop closes the listener and waits for active connections up to
// drainTimeout (spec 3.2 step 6).
func (s *Server) Stop(drainTimeout time.Duration) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	s.mu.Unlock()

	s.ln.Close()
	done := make(chan struct{})
	go func() {
		s.activeWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
	}
}

func (s *Server) debugf(format string, args ...any) {
	if s.opts.Debugf != nil {
		s.opts.Debugf(format, args...)
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.activeWG.Add(1)
		go func() {
			defer s.activeWG.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

// loopDetect reports whether addr targets our own listener (E_PROXY_LOOP).
func (s *Server) loopDetect(host string, port int) bool {
	if port != s.Port() {
		return false
	}
	if host == "127.0.0.1" || strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func (s *Server) handleConn(conn net.Conn) {
	s.metrics.Connections.Add(1)
	s.metrics.ActiveConns.Add(1)
	defer func() {
		s.metrics.ActiveConns.Add(-1)
		conn.Close()
	}()

	br := bufio.NewReaderSize(conn, s.opts.MaxHeaderBytes+4096)
	conn.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
	line, err := br.ReadBytes('\n')
	if err != nil {
		s.metrics.Errors.Add(1)
		return
	}
	if len(line) > s.opts.MaxHeaderBytes {
		s.writeSimple(conn, http.StatusRequestHeaderFieldsTooLarge, "request line too long")
		s.metrics.Errors.Add(1)
		return
	}
	fields := strings.Fields(string(line))
	if len(fields) < 3 {
		s.writeSimple(conn, http.StatusBadRequest, "malformed request line")
		s.metrics.Errors.Add(1)
		return
	}
	reqMethod, target := fields[0], fields[1]

	if len(target) > 8192 {
		s.writeSimple(conn, http.StatusRequestURITooLong, "request target too long")
		s.metrics.Errors.Add(1)
		return
	}

	if strings.EqualFold(reqMethod, http.MethodConnect) {
		s.handleConnect(conn, br, target)
		return
	}
	s.handleHTTP(conn, br, line)
}

// handleConnect proxies CONNECT host:port.
func (s *Server) handleConnect(conn net.Conn, br *bufio.Reader, target string) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host, portStr = target, "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		s.metrics.Errors.Add(1)
		s.replyConnectError(conn, http.StatusBadRequest, "E_BAD_REQUEST", "invalid port")
		return
	}

	if s.loopDetect(host, port) {
		s.metrics.Errors.Add(1)
		s.replyConnectError(conn, http.StatusLoopDetected, "E_PROXY_LOOP", "proxy loop detected")
		return
	}

	// drain remaining request headers before dialing
	if err := s.drainHeaders(br); err != nil {
		s.metrics.Errors.Add(1)
		return
	}

	upstream, mode, uerr := s.connectUpstream(host, port)
	if uerr != nil {
		s.metrics.Errors.Add(1)
		s.debugf("connect %s:%d failed: %v", host, port, uerr)
		s.replyConnectError(conn, http.StatusBadGateway, "E_UPSTREAM", uerr.Error())
		return
	}
	defer upstream.Close()

	s.metrics.HTTPSConns.Add(1)
	s.metrics.addHost(host, 1)
	if mode == "tunnel" {
		s.metrics.TunnelConns.Add(1)
	} else {
		s.metrics.DirectConns.Add(1)
	}

	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	s.pump(conn, upstream)
}

// connectUpstream dials host:port either via tunnel (whitelisted) or direct.
func (s *Server) connectUpstream(host string, port int) (net.Conn, string, error) {
	if s.loopDetect(host, port) {
		return nil, "", fmt.Errorf("E_PROXY_LOOP: refusing to proxy to self")
	}
	if s.opts.WL.Get().Match(host) && s.opts.Tunnel != nil {
		tc, _, err := TunnelDial(context.Background(), *s.opts.Tunnel, host, port, map[string]string{"v": "1"})
		if err != nil {
			return nil, "tunnel", err
		}
		return tc, "tunnel", nil
	}
	// direct: SSRF policy applies (private/reserved refused, port allowlist)
	conn, err := s.opts.Policy.DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, "direct", err
	}
	return conn, "direct", nil
}

// handleHTTP forwards a plain (absolute-form) HTTP request. firstLine is the
// raw request line (with terminator) already consumed from br.
func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader, firstLine []byte) {
	req, err := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(firstLine), br)))
	if err != nil {
		s.metrics.Errors.Add(1)
		s.writeSimple(conn, http.StatusBadRequest, "malformed request")
		return
	}
	defer req.Body.Close()

	if !req.URL.IsAbs() || req.URL.Host == "" {
		s.metrics.Errors.Add(1)
		s.writeSimple(conn, http.StatusBadRequest, "proxy requires absolute URI")
		return
	}
	host := req.URL.Hostname()
	port := 80
	if p := req.URL.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}

	upstream, mode, uerr := s.connectUpstream(host, port)
	if uerr != nil {
		s.metrics.Errors.Add(1)
		s.debugf("http %s %s failed: %v", req.Method, req.URL, uerr)
		s.writeSimple(conn, http.StatusBadGateway, "upstream unreachable: "+uerr.Error())
		return
	}
	defer upstream.Close()

	s.metrics.HTTPReqs.Add(1)
	s.metrics.addHost(host, 1)
	if mode == "tunnel" {
		s.metrics.TunnelConns.Add(1)
	} else {
		s.metrics.DirectConns.Add(1)
	}

	// clean hop-by-hop / proxy headers
	cleanProxyHeaders(req.Header)
	req.Host = req.URL.Host
	req.RequestURI = "" // required by Request.Write for client-side writes

	if err := req.Write(upstream); err != nil {
		s.metrics.Errors.Add(1)
		s.writeSimple(conn, http.StatusBadGateway, "write upstream failed")
		return
	}

	ubr := bufio.NewReaderSize(upstream, s.opts.CopyBuffer*2)
	resp, err := http.ReadResponse(ubr, req)
	if err != nil {
		s.metrics.Errors.Add(1)
		s.writeSimple(conn, http.StatusBadGateway, "read upstream failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if err := resp.Write(conn); err != nil {
		s.metrics.Errors.Add(1)
	}
}

// cleanProxyHeaders strips hop-by-hop and proxy-revealing headers (spec 3.3).
func cleanProxyHeaders(h http.Header) {
	for _, name := range []string{
		"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
		"Connection", "Keep-Alive", "Proxy-Proxy-Connection", "Te", "Trailer",
		"Transfer-Encoding", "Upgrade", "Via", "X-Forwarded-For", "X-Forwarded-Host",
		"X-Forwarded-Proto", "Forwarded",
	} {
		h.Del(name)
	}
}

func (s *Server) drainHeaders(br *bufio.Reader) error {
	total := 0
	for {
		line, err := br.ReadBytes('\n')
		total += len(line)
		if total > s.opts.MaxHeaderBytes {
			return fmt.Errorf("header overflow")
		}
		if err != nil {
			return err
		}
		trimmed := strings.TrimRight(string(line), "\r\n")
		if trimmed == "" {
			return nil
		}
	}
}

func (s *Server) replyConnectError(conn net.Conn, status int, code, msg string) {
	body := code + ": " + msg
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nX-Dldw-Error: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), code, len(body), body)
}

func (s *Server) writeSimple(conn net.Conn, status int, msg string) {
	body := msg + "\n"
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

// pump copies bytes both ways, tracking counters and honoring idle timeouts.
func (s *Server) pump(client, remote net.Conn) {
	done := make(chan struct{}, 2)
	copyDir := func(dst, src net.Conn, counter *atomic.Int64) {
		buf := make([]byte, s.opts.CopyBuffer)
		for {
			src.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
			rn, rerr := src.Read(buf)
			if rn > 0 {
				wn := 0
				for wn < rn {
					dst.SetWriteDeadline(time.Now().Add(s.opts.IdleTimeout))
					w, werr := dst.Write(buf[wn:rn])
					wn += w
					if werr != nil {
						done <- struct{}{}
						return
					}
				}
				counter.Add(int64(rn))
			}
			if rerr != nil {
				// half-close: EOF on src closes write side of dst
				if errors.Is(rerr, io.EOF) {
					if tc, ok := dst.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
				}
				done <- struct{}{}
				return
			}
		}
	}
	go copyDir(remote, client, &s.metrics.BytesIn)
	go copyDir(client, remote, &s.metrics.BytesOut)
	<-done
	client.Close()
	remote.Close()
	<-done
}
