// Package storage abstracts object storage backends for cached artifacts
// (spec 4.3). Implementations must support presigned GET/HEAD URLs with range
// requests and streaming PUT.
package storage

import (
	"context"
	"errors"
	"io"
	"regexp"
	"time"
)

var (
	ErrNotFound = errors.New("storage: object not found")
	ErrBadKey   = errors.New("storage: invalid key")
)

// Object describes a stored artifact.
type Object struct {
	Key         string `json:"key"`
	Size        int64  `json:"size"`
	ETag        string `json:"etag"`
	ContentType string `json:"content_type"`
}

// Storage is a blob backend.
type Storage interface {
	Name() string
	// PresignGet returns a URL granting GET access to key for expires.
	PresignGet(ctx context.Context, key string, expires time.Duration) (string, error)
	// PresignHead returns a URL granting HEAD access to key for expires.
	PresignHead(ctx context.Context, key string, expires time.Duration) (string, error)
	// Put stores r (size bytes) under key, returning object metadata.
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) (*Object, error)
	// Head fetches metadata for key (ErrNotFound when missing).
	Head(ctx context.Context, key string) (*Object, error)
	// Get streams the object contents.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// Delete removes the object (idempotent).
	Delete(ctx context.Context, key string) error
	// Ping verifies backend availability.
	Ping(ctx context.Context) error
}

// keyRe constrains object keys to safe, flat, lowercase-hex-ish paths so no
// backend can ever see traversal sequences.
var keyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,511}$`)

// ValidateKey enforces the storage key format.
func ValidateKey(key string) error {
	if !keyRe.MatchString(key) || key != sanitizeDots(key) {
		return ErrBadKey
	}
	return nil
}

func sanitizeDots(k string) string {
	// reject ".." segments
	for i := 0; i+1 < len(k); i++ {
		if k[i] == '.' && k[i+1] == '.' && (i == 0 || k[i-1] == '/') && (i+2 == len(k) || k[i+2] == '/') {
			return ""
		}
	}
	return k
}
