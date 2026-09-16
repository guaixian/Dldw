package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
	"dldw/internal/protocol/dldw1"
)

func startProxy(t *testing.T, wl *whitelist.Store, tunnel *TunnelConfig, ports ...int) *Server {
	t.Helper()
	s, err := Start(Options{
		WL:          wl,
		Policy:      &ssrf.Policy{BlockPrivate: false, AllowLoopback: true, Ports: ports},
		Tunnel:      tunnel,
		IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop(2 * time.Second) })
	return s
}

func originPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	ou, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(ou.Port())
	return p
}

func TestHTTPForwardDirect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Connection") != "" || r.Header.Get("Via") != "" ||
			r.Header.Get("X-Forwarded-For") != "" {
			t.Errorf("hop-by-hop header leaked: %v", r.Header)
		}
		fmt.Fprintf(w, "path=%s ua=%s", r.URL.Path, r.Header.Get("User-Agent"))
	}))
	defer origin.Close()

	s := startProxy(t, whitelist.NewStore(whitelist.Parse("t", nil)), nil, originPort(t, origin))
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse(s.URL())
	}}}
	resp, err := client.Get(origin.URL + "/a/b?x=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "path=/a/b") {
		t.Fatalf("body = %s", body)
	}
	m := s.Metrics()
	if m.HTTPReqs.Load() != 1 || m.DirectConns.Load() != 1 || m.TunnelConns.Load() != 0 {
		t.Fatalf("metrics = %v", m.Snapshot())
	}
}

func TestHTTPPostBody(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "len=%d", len(buf))
	}))
	defer origin.Close()
	s := startProxy(t, whitelist.NewStore(whitelist.Parse("t", nil)), nil, originPort(t, origin))
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse(s.URL())
	}}}
	resp, err := client.Post(origin.URL+"/upload", "text/plain", strings.NewReader(strings.Repeat("x", 100000)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "len=100000" {
		t.Fatalf("body = %s", body)
	}
}

func TestConnectDirectLoopbackAllowed(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure-ok")
	}))
	defer origin.Close()
	ou, _ := url.Parse(origin.URL)
	port, _ := strconv.Atoi(ou.Port())

	// test-only policy permitting the loopback origin
	s, err := Start(Options{
		WL:         whitelist.NewStore(whitelist.Parse("t", nil)),
		Policy:     &ssrf.Policy{AllowLoopback: true, Ports: []int{port}},
		IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop(2 * time.Second)

	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	// speak TLS through the tunnel to the test origin
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tresp, err := http.Get("https://origin.example/") // placeholder; use manual request
	_ = tresp
	_ = err
	req, _ := http.NewRequest(http.MethodGet, "https://origin.example/", nil)
	tres, herr := (&http.Client{Transport: &http.Transport{DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return tc, nil
	}}}).Do(req)
	if herr != nil {
		t.Fatal(herr)
	}
	body, _ := io.ReadAll(tres.Body)
	tres.Body.Close()
	if string(body) != "secure-ok" {
		t.Fatalf("body = %q", body)
	}
	if s.Metrics().HTTPSConns.Load() != 1 || s.Metrics().DirectConns.Load() != 1 {
		t.Fatalf("metrics = %v", s.Metrics().Snapshot())
	}
}

func TestConnectPrivateDenied(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	ou, _ := url.Parse(origin.URL)
	port, _ := strconv.Atoi(ou.Port())

	s, err := Start(Options{
		WL:          whitelist.NewStore(whitelist.Parse("t", nil)),
		Policy:      &ssrf.Policy{BlockPrivate: true, Ports: []int{port}}, // loopback refused
		IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop(2 * time.Second)
	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("private target must be denied, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Dldw-Error") != "E_UPSTREAM" && !strings.Contains(resp.Header.Get("X-Dldw-Error"), "E_") {
		t.Fatalf("error header = %q", resp.Header.Get("X-Dldw-Error"))
	}
}

func TestConnectPortDenied(t *testing.T) {
	s := startProxy(t, whitelist.NewStore(whitelist.Parse("t", nil)), nil)
	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 1.2.3.4:22 HTTP/1.1\r\nHost: 1.2.3.4:22\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("port 22 must be denied, got %d", resp.StatusCode)
	}
}

func TestProxyLoopDetection(t *testing.T) {
	s := startProxy(t, whitelist.NewStore(whitelist.Parse("t", nil)), nil)
	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", s.Port(), s.Port())
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusLoopDetected || resp.Header.Get("X-Dldw-Error") != "E_PROXY_LOOP" {
		t.Fatalf("loop: %d %q", resp.StatusCode, resp.Header.Get("X-Dldw-Error"))
	}
}

// fake tunnel server for whitelist tunneling tests
func fakeTunnelServer(t *testing.T) (addr string, reqs chan *dldw1.Connect) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reqs = make(chan *dldw1.Connect, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				line, err := dldw1.ReadLine(bufio.NewReader(c))
				if err != nil {
					return
				}
				req, err := dldw1.ParseConnect(line)
				if err != nil {
					c.Write((&dldw1.Err{Code: "E_PROTO", Message: "bad"}).Encode())
					return
				}
				reqs <- req
				// resolve localhost targets for test purposes
				if req.Host == "testhost.local" {
					c.Write((&dldw1.OK{ConnID: "conn_test01", ExpiresIn: 60, ResolvedIP: "127.0.0.1"}).Encode())
					c.SetDeadline(time.Time{})
					io.Copy(c, c) // echo the raw bytes
					return
				}
				c.Write((&dldw1.Err{Code: "E_NOT_WHITELISTED", Message: "nope"}).Encode())
			}(conn)
		}
	}()
	return ln.Addr().String(), reqs
}

func TestConnectWhitelistedGoesTunnel(t *testing.T) {
	// Whitelisted name "testhost.local"; fake tunnel echoes bytes back
	tunnelAddr, reqs := fakeTunnelServer(t)
	wl := whitelist.Parse("t", []string{"testhost.local"})
	s := startProxy(t, whitelist.NewStore(wl), &TunnelConfig{
		Addr:          tunnelAddr,
		TokenProvider: func() string { return "dldw_testtoken123456" },
		ClientID:      "dev_test",
	})

	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT testhost.local:443 HTTP/1.1\r\nHost: testhost.local:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("tunnel connect failed: %d", resp.StatusCode)
	}
	// bytes should echo through the fake tunnel
	msg := []byte("through-the-tunnel")
	conn.Write(msg)
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q", got)
	}
	select {
	case req := <-reqs:
		if req.Host != "testhost.local" || req.Port != 443 || req.Token != "dldw_testtoken123456" {
			t.Fatalf("handshake req = %+v", req)
		}
		if len(req.Nonce) != 32 {
			t.Fatalf("nonce = %q", req.Nonce)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no tunnel handshake seen")
	}
	m := s.Metrics()
	if m.TunnelConns.Load() != 1 || m.DirectConns.Load() != 0 {
		t.Fatalf("metrics = %v", m.Snapshot())
	}
}

func TestTunnelErrorSurfaces(t *testing.T) {
	tunnelAddr, _ := fakeTunnelServer(t) // rejects non-testhost with ERR
	s, err := Start(Options{
		WL:     whitelist.NewStore(whitelist.Parse("t", []string{"otherhost.local"})),
		Policy: &ssrf.Policy{BlockPrivate: true},
		Tunnel: &TunnelConfig{Addr: tunnelAddr, TokenProvider: func() string { return "dldw_testtoken123456" }, ClientID: "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop(time.Second)
	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT otherhost.local:443 HTTP/1.1\r\nHost: otherhost.local:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestNoTokenTunnelFails(t *testing.T) {
	tunnelAddr, _ := fakeTunnelServer(t)
	s, err := Start(Options{
		WL:     whitelist.NewStore(whitelist.Parse("t", []string{"testhost.local"})),
		Policy: &ssrf.Policy{BlockPrivate: true},
		Tunnel: &TunnelConfig{Addr: tunnelAddr, ClientID: "dev"}, // no TokenProvider
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop(time.Second)
	conn, _ := net.Dial("tcp", s.Addr().String())
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT testhost.local:443 HTTP/1.1\r\nHost: testhost.local:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 without token, got %d", resp.StatusCode)
	}
}

func TestHTTPViaTunnelForWhitelistedHost(t *testing.T) {
	// plain HTTP request to whitelisted host routes through tunnel.
	// Fake tunnel speaks plain HTTP echo? Instead: fake tunnel that, after OK,
	// responds to a tiny HTTP request.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				line, err := dldw1.ReadLine(bufio.NewReader(c))
				if err != nil {
					return
				}
				if _, err := dldw1.ParseConnect(line); err != nil {
					return
				}
				c.Write((&dldw1.OK{ConnID: "conn_http01", ExpiresIn: 60, ResolvedIP: "127.0.0.1"}).Encode())
				// read one http request, respond
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ntunneled!"))
			}(c)
		}
	}()
	s, err := Start(Options{
		WL:     whitelist.NewStore(whitelist.Parse("t", []string{"testhost.local"})),
		Policy: &ssrf.Policy{BlockPrivate: true},
		Tunnel: &TunnelConfig{Addr: ln.Addr().String(), TokenProvider: func() string { return "dldw_testtoken123456" }, ClientID: "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop(time.Second)
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse(s.URL())
	}}}
	resp, err := client.Get("http://testhost.local/data")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "tunneled!" {
		t.Fatalf("body = %q", body)
	}
	if s.Metrics().TunnelConns.Load() != 1 {
		t.Fatalf("expected tunnel egress, metrics = %v", s.Metrics().Snapshot())
	}
}

func TestMetricsTopHosts(t *testing.T) {
	m := NewMetrics()
	m.addHost("a.com", 2)
	m.addHost("b.com", 5)
	m.addHost("a.com", 1)
	top := m.TopHosts(2)
	if top[0].Host != "b.com" || top[1].Host != "a.com" || top[1].Count != 3 {
		t.Fatalf("top = %v", top)
	}
}

func TestTLSTunnelDial(t *testing.T) {
	// generate ephemeral self-signed cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dldw-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				line, err := dldw1.ReadLine(bufio.NewReader(c))
				if err != nil {
					return
				}
				if _, perr := dldw1.ParseConnect(line); perr != nil {
					return
				}
				c.Write((&dldw1.OK{ConnID: "conn_tls01", ExpiresIn: 60, ResolvedIP: "127.0.0.1"}).Encode())
				c.SetDeadline(time.Time{})
				io.Copy(c, c)
			}(c)
		}
	}()

	// trust our ephemeral CA (self-signed leaf)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	conn, okRes, err := TunnelDial(t.Context(), TunnelConfig{
		Addr:          ln.Addr().String(),
		UseTLS:        true,
		TLSConfig:     &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
		TokenProvider: func() string { return "dldw_testtoken123456" },
		ClientID:      "dev",
	}, "testhost.local", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if okRes.ConnID != "conn_tls01" {
		t.Fatalf("ok = %+v", okRes)
	}
	conn.Write([]byte("hi"))
	buf := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hi" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestCurlThroughProxyIfAvailable(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not installed")
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "curl-ok")
	}))
	defer origin.Close()
	s := startProxy(t, whitelist.NewStore(whitelist.Parse("t", nil)), nil, originPort(t, origin))
	out, err := exec.Command(curl, "-s", "-x", s.URL(), origin.URL).CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "curl-ok" {
		t.Fatalf("curl output = %q", out)
	}
}
