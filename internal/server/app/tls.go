package app

import (
	"crypto/tls"
	"net"
)

func loadCert(cfg TLSConfig) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
}

func newTLSListener(ln net.Listener, cert tls.Certificate) net.Listener {
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}
