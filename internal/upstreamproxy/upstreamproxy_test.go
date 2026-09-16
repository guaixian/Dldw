package upstreamproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newCONNECTProxy 起一个本地 HTTP CONNECT 代理（透传到目标）。
func newCONNECTProxy(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		target, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer target.Close()
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		done := make(chan struct{}, 2)
		go func() { io.Copy(target, client); done <- struct{}{} }()
		go func() { io.Copy(client, target); done <- struct{}{} }()
		<-done
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDialThroughProxy(t *testing.T) {
	// echo 目标
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	proxy := newCONNECTProxy(t)
	conn, err := Dial(context.Background(), proxy.URL, echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("via-upstream-proxy")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q", buf)
	}
}

func TestDialRejected(t *testing.T) {
	// 代理拒绝不可达目标
	proxy := newCONNECTProxy(t)
	if _, err := Dial(context.Background(), proxy.URL, "127.0.0.1:1"); err == nil {
		t.Fatal("dial to closed port should fail via proxy 502")
	}
}

func TestValidate(t *testing.T) {
	for _, ok := range []string{"", "http://127.0.0.1:10808", "https://p.example.com", "http://u:p@127.0.0.1:8080"} {
		if err := Validate(ok); err != nil {
			t.Errorf("Validate(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"socks5://127.0.0.1:1080", "http://", "://x"} {
		if err := Validate(bad); err == nil {
			t.Errorf("Validate(%q) should fail", bad)
		}
	}
}

var _ = bufio.NewReader
