package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"dldw/internal/ids"
	"dldw/internal/protocol/dldw1"
)

// TunnelConfig describes how to reach the dldw server tunnel.
type TunnelConfig struct {
	// Addr is host:port of the tunnel listener.
	Addr string
	// UseTLS enables TLS (recommended; the server URL scheme decides).
	UseTLS bool
	// TLSConfig for the connection (InsecureSkipVerify for dev only).
	TLSConfig *tls.Config
	// TokenProvider returns the current device token.
	TokenProvider func() string
	// ClientID identifies this device.
	ClientID string
	// HandshakeTimeout defaults to 10s.
	HandshakeTimeout time.Duration
}

// TunnelDial establishes a DLDW/1 tunnel connection to host:port.
func TunnelDial(ctx context.Context, cfg TunnelConfig, host string, port int, flags map[string]string) (net.Conn, *dldw1.OK, error) {
	token := ""
	if cfg.TokenProvider != nil {
		token = cfg.TokenProvider()
	}
	if token == "" {
		return nil, nil, fmt.Errorf("tunnel: no device token configured (run `dldw doctor --fix`)")
	}
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel: dial %s: %w", cfg.Addr, err)
	}
	conn := raw
	if cfg.UseTLS {
		tlsCfg := cfg.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, nil, fmt.Errorf("tunnel: TLS handshake: %w", err)
		}
		conn = tc
	}

	req := &dldw1.Connect{
		Host:     host,
		Port:     port,
		Token:    token,
		Nonce:    ids.NewNonce(),
		ClientID: cfg.ClientID,
		Flags:    flags,
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req.Encode()); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("tunnel: write handshake: %w", err)
	}
	line, err := dldw1.ReadLine(bufio.NewReaderSize(conn, dldw1.MaxLine+1))
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("tunnel: read handshake: %w", err)
	}
	okRes, errRes, perr := dldw1.ParseResponse(line)
	if perr != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("tunnel: malformed response")
	}
	if errRes != nil {
		conn.Close()
		return nil, nil, &TunnelError{Code: errRes.Code, Message: errRes.Message}
	}
	conn.SetDeadline(time.Time{})
	return conn, okRes, nil
}

// TunnelConfigFromServer derives the tunnel endpoint from the control API
// server URL: an explicit port P maps to tunnel port P+1; otherwise the
// server defaults (4443 for https, 8081 for http) apply.
func TunnelConfigFromServer(serverURL, token, clientID string, skipVerify bool) (*TunnelConfig, error) {
	if serverURL == "" || token == "" {
		return nil, fmt.Errorf("tunnel: server and token required")
	}
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("tunnel: invalid server URL %q", serverURL)
	}
	host := u.Hostname()
	port := u.Port()
	useTLS := u.Scheme == "https"

	var tunnelPort int
	if port != "" {
		p, _ := strconv.Atoi(port)
		tunnelPort = p + 1
	} else if useTLS {
		tunnelPort = 4443
	} else {
		tunnelPort = 8081
	}
	var tlsCfg *tls.Config
	if useTLS && skipVerify {
		tlsCfg = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	return &TunnelConfig{
		Addr:          net.JoinHostPort(host, strconv.Itoa(tunnelPort)),
		UseTLS:        useTLS,
		TLSConfig:     tlsCfg,
		TokenProvider: func() string { return token },
		ClientID:      clientID,
	}, nil
}

// TunnelError is a server-side rejection.
type TunnelError struct {
	Code    string
	Message string
}

func (e *TunnelError) Error() string { return "tunnel: " + e.Code + ": " + e.Message }
