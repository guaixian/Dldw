package app

import (
	"bufio"
	"net"
	"os"
	"time"

	"dldw/internal/policy/ssrf"
	"dldw/internal/protocol/dldw1"
	"dldw/internal/server/audit"
	"dldw/internal/server/auth"
	"dldw/internal/server/tunnel"
)

// newTestTunnelServer builds a tunnel server matching app wiring.
func newTestTunnelServer(a *App) *tunnel.Server {
	return tunnel.New(tunnel.Config{
		Tokens:           a.Tokens,
		Nonces:           auth.NewNonceStore(10 * time.Minute),
		WL:               a.WLStore,
		Policy:           &ssrf.Policy{BlockPrivate: true, Ports: []int{80, 443}},
		Audit:            audit.New(nil),
		MaxConnsPerToken: 8,
		MaxBytesPerConn:  4 << 20,
		IdleTimeout:      30 * time.Second,
	})
}

// bufReader wraps dldw1.ReadLine for tests.
type bufReader struct{ r *bufio.Reader }

func newBufReader(c net.Conn) *bufReader { return &bufReader{r: bufio.NewReader(c)} }

func (b *bufReader) readLine() ([]byte, error) { return dldw1.ReadLine(b.r) }

func osWriteFile(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }
