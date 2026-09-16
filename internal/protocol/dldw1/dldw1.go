// Package dldw1 implements the DLDW/1 tunnel handshake wire protocol shared
// by the client proxy and the server tunnel (spec 4.2).
//
//	Request:  DLDW/1 CONNECT <host> <port> <token> <nonce> <client_id> <flags>\n
//	Response: DLDW/1 OK <conn_id> <expires_in> <resolved_ip>\n
//	          DLDW/1 ERR <code> <message...>\n
//
// After OK, the connection carries raw TCP bytes in both directions.
// All fields are single tokens without whitespace; flags is a comma separated
// k=v list or "-".
package dldw1

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	Proto   = "DLDW/1"
	MaxLine = 4096
)

var (
	ErrTooLong   = errors.New("dldw1: handshake line exceeds limit")
	ErrMalformed = errors.New("dldw1: malformed handshake")
)

// Connect is a tunnel connect request.
type Connect struct {
	Host     string
	Port     int
	Token    string
	Nonce    string
	ClientID string
	Flags    map[string]string
}

// Flag returns the value of a flag or "".
func (c *Connect) Flag(k string) string {
	if c.Flags == nil {
		return ""
	}
	return c.Flags[k]
}

// Encode renders the request line including the trailing newline.
func (c *Connect) Encode() []byte {
	return []byte(fmt.Sprintf("%s CONNECT %s %d %s %s %s %s\n",
		Proto, c.Host, c.Port, c.Token, c.Nonce, c.ClientID, encodeFlags(c.Flags)))
}

func encodeFlags(flags map[string]string) string {
	if len(flags) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(flags))
	for k, v := range flags {
		parts = append(parts, k+"="+v)
	}
	for i := 1; i < len(parts); i++ {
		for j := i; j > 0 && parts[j] < parts[j-1]; j-- {
			parts[j], parts[j-1] = parts[j-1], parts[j]
		}
	}
	return strings.Join(parts, ",")
}

// ParseConnect parses a request line (newline optional).
func ParseConnect(line []byte) (*Connect, error) {
	s := strings.TrimRight(string(line), "\r\n")
	f := strings.Fields(s)
	if len(f) != 8 || f[0] != Proto || f[1] != "CONNECT" {
		return nil, ErrMalformed
	}
	c := &Connect{Host: f[2]}
	if err := validHost(c.Host); err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(f[3])
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("%w: bad port %q", ErrMalformed, f[3])
	}
	c.Port = port
	c.Token = f[4]
	if err := validToken(c.Token, 8, 512); err != nil {
		return nil, err
	}
	c.Nonce = f[5]
	if len(c.Nonce) != 32 || !isHexLower(c.Nonce) {
		return nil, fmt.Errorf("%w: nonce must be 32 lowercase hex chars", ErrMalformed)
	}
	c.ClientID = f[6]
	if err := validToken(c.ClientID, 1, 64); err != nil {
		return nil, err
	}
	flags, err := parseFlags(f[7])
	if err != nil {
		return nil, err
	}
	c.Flags = flags
	return c, nil
}

func parseFlags(s string) (map[string]string, error) {
	if s == "-" {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if kv == "" {
			return nil, fmt.Errorf("%w: empty flag", ErrMalformed)
		}
		eq := strings.IndexByte(kv, '=')
		if strings.Count(kv, "=") > 1 {
			return nil, fmt.Errorf("%w: multiple '=' in flag", ErrMalformed)
		}
		var k, v string
		if eq < 0 {
			k, v = kv, ""
		} else {
			k, v = kv[:eq], kv[eq+1:]
		}
		if err := validToken(k, 1, 32); err != nil {
			return nil, fmt.Errorf("%w: bad flag key", ErrMalformed)
		}
		if err := validToken(v, 0, 64); err != nil {
			return nil, fmt.Errorf("%w: bad flag value", ErrMalformed)
		}
		out[k] = v
	}
	return out, nil
}

// OK is a successful handshake response.
type OK struct {
	ConnID     string
	ExpiresIn  int
	ResolvedIP string
}

func (r *OK) Encode() []byte {
	ip := r.ResolvedIP
	if ip == "" {
		ip = "-"
	}
	return []byte(fmt.Sprintf("%s OK %s %d %s\n", Proto, r.ConnID, r.ExpiresIn, ip))
}

// Err is a failed handshake response.
type Err struct {
	Code    string
	Message string
}

func (e *Err) Encode() []byte {
	msg := e.Message
	if msg == "" {
		msg = "unspecified error"
	}
	return []byte(fmt.Sprintf("%s ERR %s %s\n", Proto, e.Code, msg))
}

// ParseResponse parses a response line into either *OK or *Err.
func ParseResponse(line []byte) (*OK, *Err, error) {
	s := strings.TrimRight(string(line), "\r\n")
	f := strings.Fields(s)
	if len(f) < 3 || f[0] != Proto {
		return nil, nil, ErrMalformed
	}
	switch f[1] {
	case "OK":
		if len(f) != 5 {
			return nil, nil, ErrMalformed
		}
		if err := validToken(f[2], 4, 64); err != nil {
			return nil, nil, err
		}
		exp, err := strconv.Atoi(f[3])
		if err != nil || exp < 0 {
			return nil, nil, fmt.Errorf("%w: bad expires_in", ErrMalformed)
		}
		ip := f[4]
		if ip != "-" {
			if err := validToken(ip, 3, 64); err != nil {
				return nil, nil, err
			}
		} else {
			ip = ""
		}
		return &OK{ConnID: f[2], ExpiresIn: exp, ResolvedIP: ip}, nil, nil
	case "ERR":
		code := f[2]
		if err := validErrCode(code); err != nil {
			return nil, nil, err
		}
		msg := ""
		if idx := strings.Index(s, " ERR "+code+" "); idx >= 0 {
			msg = s[idx+len(" ERR "+code+" "):]
		}
		return nil, &Err{Code: code, Message: msg}, nil
	}
	return nil, nil, ErrMalformed
}

// ReadLine reads one handshake line with the protocol length limit.
func ReadLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return nil, ErrTooLong
	}
	if err != nil {
		return nil, err
	}
	if len(line) > MaxLine {
		return nil, ErrTooLong
	}
	return line, nil
}

func validHost(h string) error {
	if h == "" || len(h) > 253 {
		return fmt.Errorf("%w: bad host", ErrMalformed)
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c <= ' ' || c >= 0x7f || c == ',' {
			return fmt.Errorf("%w: bad char in host", ErrMalformed)
		}
	}
	return nil
}

func validToken(t string, min, max int) error {
	if len(t) < min || len(t) > max {
		return fmt.Errorf("%w: token length", ErrMalformed)
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.', c == '=':
		default:
			return fmt.Errorf("%w: bad char %q in token", ErrMalformed, c)
		}
	}
	return nil
}

func validErrCode(c string) error {
	if len(c) < 3 || len(c) > 48 {
		return fmt.Errorf("%w: bad error code length", ErrMalformed)
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_') {
			return fmt.Errorf("%w: bad error code charset", ErrMalformed)
		}
	}
	return nil
}

func isHexLower(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
