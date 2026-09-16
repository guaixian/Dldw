package proxycore

import (
	"net"
	"time"
)

// net_DialTimeout 供就绪探测（隔离成变量便于测试替换）。
var net_DialTimeout = func(addr string, d time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, d)
}
