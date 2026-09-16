// Package ssrf implements shared egress policy: blocked IP ranges
// (loopback/private/link-local/reserved/multicast), target port restrictions
// and a guarded dialer that validates resolved addresses immediately before
// dialing, mitigating DNS rebinding (spec 5).
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Error codes surfaced to users (spec 7).
const (
	CodePortDenied = "E_PORT_DENIED"
	CodeIPDenied   = "E_SSRF_DENIED"
	CodeResolve    = "E_DNS_RESOLVE"
)

type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func IsSSRFError(err error) bool {
	var se *Error
	return errors.As(err, &se)
}

func ErrorCode(err error) string {
	var se *Error
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

var blockedV4 = mustCIDRs(
	"0.0.0.0/8",             // "this" network
	"10.0.0.0/8",             // private
	"100.64.0.0/10",          // CGNAT
	"127.0.0.0/8",            // loopback
	"169.254.0.0/16",         // link-local
	"172.16.0.0/12",          // private
	"192.0.0.0/24",           // IETF protocol assignments
	"192.0.2.0/24",           // TEST-NET-1
	"192.88.99.0/24",         // 6to4 relay (deprecated)
	"192.168.0.0/16",         // private
	"198.18.0.0/15",          // benchmarking
	"198.51.100.0/24",        // TEST-NET-2
	"203.0.113.0/24",         // TEST-NET-3
	"240.0.0.0/4",            // reserved (incl. 255.255.255.255 broadcast)
)

var blockedV6 = mustCIDRs(
	"::/128",          // unspecified
	"::1/128",         // loopback
	"64:ff9b::/96",    // NAT64 (may map to private v4)
	"100::/64",        // discard-only
	"2001:10::/28",    // ORCHID
	"2001:db8::/32",   // documentation
	"fc00::/7",        // unique-local
	"fe80::/10",       // link-local
	"ff00::/8",        // multicast
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("ssrf: bad cidr " + c)
		}
		out = append(out, n)
	}
	return out
}

// BlockedIP reports whether ip sits in a range that must never be dialed.
func BlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Map IPv4-in-IPv6 to plain v4 so both forms are covered by the v4 table.
	if v4 := ip.To4(); v4 != nil && !isV4Mapped(ip) {
		ip = v4
	} else if isV4Mapped(ip) {
		return BlockedIP(v4)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	var table []*net.IPNet
	if v4 := ip.To4(); v4 != nil {
		ip, table = v4, blockedV4
	} else {
		table = blockedV6
	}
	for _, n := range table {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isV4Mapped(ip net.IP) bool {
	return len(ip) == net.IPv6len && strings.HasPrefix(ip.String(), "::ffff:")
}

// Policy describes allowed egress targets.
type Policy struct {
	// Ports are the allowed destination ports. nil/empty means default {80,443}.
	Ports []int
	// BlockPrivate disables dialing private/reserved ranges. When false the
	// policy still blocks loopback and link-local (safety floor).
	BlockPrivate bool
	// AllowLoopback permits loopback targets. Intended for local testing and
	// self-referential server requests only; never enable for public servers.
	AllowLoopback bool
	// Resolver used for DNS; nil means net.DefaultResolver.
	Resolver *net.Resolver
	// DialTimeout per candidate address.
	DialTimeout time.Duration
}

func (p *Policy) allowedPorts() []int {
	if len(p.Ports) == 0 {
		return []int{80, 443}
	}
	return p.Ports
}

func (p *Policy) resolver() *net.Resolver {
	if p.Resolver == nil {
		return net.DefaultResolver
	}
	return p.Resolver
}

func (p *Policy) dialTimeout() time.Duration {
	if p.DialTimeout <= 0 {
		return 10 * time.Second
	}
	return p.DialTimeout
}

// CheckPort validates a destination port against the port policy.
func (p *Policy) CheckPort(port int) error {
	if port <= 0 || port > 65535 {
		return &Error{Code: CodePortDenied, Detail: fmt.Sprintf("invalid port %d", port)}
	}
	for _, ap := range p.allowedPorts() {
		if ap == port {
			return nil
		}
	}
	return &Error{Code: CodePortDenied, Detail: fmt.Sprintf("port %d not allowed (allowed: %v)", port, p.allowedPorts())}
}

// CheckHost validates a hostname or IP literal: IP literals are checked
// directly; names are resolved and every address must pass the IP policy.
func (p *Policy) CheckHost(ctx context.Context, host string) error {
	if host == "" {
		return &Error{Code: CodeIPDenied, Detail: "empty host"}
	}
	if ip := parseIPLiteral(host); ip != nil {
		return p.checkIP(ip)
	}
	addrs, err := p.resolver().LookupIPAddr(ctx, host)
	if err != nil {
		return &Error{Code: CodeResolve, Detail: fmt.Sprintf("resolve %s: %v", host, err)}
	}
	if len(addrs) == 0 {
		return &Error{Code: CodeResolve, Detail: "no addresses for " + host}
	}
	for _, a := range addrs {
		if err := p.checkIP(a.IP); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) checkIP(ip net.IP) error {
	if p.AllowLoopback && ip.IsLoopback() {
		return nil
	}
	blocked := BlockedIP(ip)
	if p.BlockPrivate {
		if blocked {
			return &Error{Code: CodeIPDenied, Detail: "target resolves to blocked/reserved range " + ip.String()}
		}
		return nil
	}
	// Safety floor even when BlockPrivate=false (loopback/link-local).
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return &Error{Code: CodeIPDenied, Detail: "target resolves to loopback/link-local " + ip.String()}
	}
	if blocked && (isDocumentation(ip) || ip.IsUnspecified()) {
		return &Error{Code: CodeIPDenied, Detail: "target resolves to reserved range " + ip.String()}
	}
	return nil
}

func isDocumentation(ip net.IP) bool {
	for _, n := range append(blockedV4, blockedV6...) {
		if n.Contains(ip) {
			// Only the pure documentation ranges matter for the floor.
			if n.String() == "2001:db8::/32" || n.String() == "192.0.2.0/24" ||
				n.String() == "198.51.100.0/24" || n.String() == "203.0.113.0/24" {
				return true
			}
		}
	}
	return false
}

func parseIPLiteral(host string) net.IP {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.ParseIP(host[1 : len(host)-1])
	}
	return net.ParseIP(host)
}

// candidateIPs resolves addr (host or host:port / [v6]:port) to validated IPs.
func (p *Policy) candidateIPs(ctx context.Context, addr string) (host, port string, ips []net.IP, err error) {
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		// tolerate bare host, default port 443 for tunnel usage
		h, ps = addr, "443"
	}
	if h == "" {
		return "", "", nil, &Error{Code: CodeIPDenied, Detail: "empty host in " + addr}
	}
	if err := p.CheckPort(mustAtoi(ps)); err != nil {
		return "", "", nil, err
	}
	if ip := parseIPLiteral(h); ip != nil {
		if err := p.checkIP(ip); err != nil {
			return "", "", nil, err
		}
		return h, ps, []net.IP{ip}, nil
	}
	addrs, rerr := p.resolver().LookupIPAddr(ctx, h)
	if rerr != nil {
		return "", "", nil, &Error{Code: CodeResolve, Detail: fmt.Sprintf("resolve %s: %v", h, rerr)}
	}
	for _, a := range addrs {
		if err := p.checkIP(a.IP); err != nil {
			return "", "", nil, err
		}
		ips = append(ips, a.IP)
	}
	if len(ips) == 0 {
		return "", "", nil, &Error{Code: CodeResolve, Detail: "no addresses for " + h}
	}
	return h, ps, ips, nil
}

// DialContext is a net.Dialer-compatible function that enforces the policy on
// every dial. Because resolution and dialing happen back to back against the
// same validated address list, DNS rebinding between check and connect is
// mitigated (the IP actually dialed is the IP that was checked).
func (p *Policy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "":
	default:
		return nil, &Error{Code: CodeIPDenied, Detail: "network " + network + " not allowed"}
	}
	_, port, ips, err := p.candidateIPs(ctx, addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: p.dialTimeout()}
	var lastErr error
	for _, ip := range ips {
		c, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if derr == nil {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			return c, nil
		}
		lastErr = derr
	}
	return nil, fmt.Errorf("dial %s: %w", addr, lastErr)
}

func mustAtoi(s string) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return -1
	}
	return n
}
