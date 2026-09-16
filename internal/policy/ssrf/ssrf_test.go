package ssrf

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "0.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1",
		"198.51.100.7", "203.0.113.9", "240.0.0.1", "255.255.255.255",
		"::1", "::", "fc00::1", "fd12::1", "fe80::1", "ff02::1",
		"2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::c000:0201",
	}
	for _, s := range blocked {
		if !BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = false, want true", s)
		}
	}
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "140.82.112.3", "20.205.243.166",
		"2606:50c0:8000::153", "2a00:1450:4001:81b::200e",
	}
	for _, s := range allowed {
		if BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = true, want false", s)
		}
	}
}

func TestCheckPort(t *testing.T) {
	p := &Policy{}
	if err := p.CheckPort(443); err != nil {
		t.Errorf("443 denied: %v", err)
	}
	if err := p.CheckPort(80); err != nil {
		t.Errorf("80 denied: %v", err)
	}
	if err := p.CheckPort(22); err == nil {
		t.Error("22 should be denied by default")
	}
	if err := p.CheckPort(0); err == nil {
		t.Error("0 should be denied")
	}
	custom := &Policy{Ports: []int{80, 443, 8080}}
	if err := custom.CheckPort(8080); err != nil {
		t.Errorf("8080 denied under custom policy: %v", err)
	}
}

func TestCheckHostIPLiteral(t *testing.T) {
	p := &Policy{BlockPrivate: true}
	if err := p.CheckHost(context.Background(), "127.0.0.1"); err == nil {
		t.Error("loopback should be denied")
	}
	if err := p.CheckHost(context.Background(), "10.0.0.1"); err == nil {
		t.Error("private should be denied")
	}
	if code := ErrorCode(p.CheckHost(context.Background(), "169.254.1.1")); code != CodeIPDenied {
		t.Errorf("code = %q, want E_SSRF_DENIED", code)
	}
}

func TestDialContextDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("listen failed")
	}
	defer ln.Close()
	p := &Policy{BlockPrivate: true, DialTimeout: 2 * time.Second}
	// loopback dial must be denied even though a listener exists
	if _, err := p.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		t.Fatal("dial to loopback listener should be denied by policy")
	} else if !IsSSRFError(err) {
		t.Fatalf("expected ssrf error, got %v", err)
	}
}

func TestDialContextAllowsSpecifiedIP(t *testing.T) {
	// Use resolver-independent literal path: dial an unroutable public IP and
	// expect a dial error (not a policy error).
	p := &Policy{BlockPrivate: true, DialTimeout: 300 * time.Millisecond}
	_, err := p.DialContext(context.Background(), "tcp", "192.0.2.1:443") // TEST-NET blocked
	if err == nil || !IsSSRFError(err) {
		t.Fatalf("TEST-NET dial should be policy-denied, got %v", err)
	}
	_, err = p.DialContext(context.Background(), "tcp", "203.0.113.5:80")
	if err == nil || !IsSSRFError(err) {
		t.Fatalf("TEST-NET-3 dial should be policy-denied, got %v", err)
	}
	_, err = p.DialContext(context.Background(), "udp", "1.1.1.1:53")
	if err == nil || !IsSSRFError(err) {
		t.Fatalf("udp should be denied, got %v", err)
	}
}
