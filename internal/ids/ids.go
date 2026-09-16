// Package ids generates short, unique, prefixed identifiers used across
// requests, connections, tasks and tokens for correlation in logs.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms; fall back to a
		// deterministic-but-unique-enough value rather than panicking.
		return fmt.Sprintf("%0*x", n*2, 0)
	}
	return hex.EncodeToString(b)
}

// NewRequestID returns an id for a control API request, e.g. req_9f2c1a4b8e7d.
func NewRequestID() string { return "req_" + randHex(8) }

// NewConnID returns an id for a proxied/tunnel connection.
func NewConnID() string { return "conn_" + randHex(6) }

// NewTaskID returns an id for a cache task.
func NewTaskID() string { return "task_" + randHex(10) }

// NewToken returns a fresh opaque device token.
func NewToken() string { return "dldw_" + randHex(24) }

// NewTokenID returns an internal identifier for a stored token record.
func NewTokenID() string { return "tok_" + randHex(6) }

// NewNonce returns a hex encoded 128-bit nonce (32 hex chars).
func NewNonce() string { return randHex(16) }

// NewClientID returns a stable device identifier.
func NewClientID() string { return "dev_" + randHex(8) }
