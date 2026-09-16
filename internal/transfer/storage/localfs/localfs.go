// Package localfs is a filesystem backed storage driver with HMAC presigned
// URLs served by the control API under /files/ (spec 4.3, dev/self-host mode).
package localfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dldw/internal/transfer/presign"
	"dldw/internal/transfer/storage"
)

// Config for the local filesystem driver.
type Config struct {
	// Root directory for objects.
	Root string `json:"root"`
	// PublicBase is the externally visible base URL of the control API, e.g.
	// "https://dldw.example.com". Presigned URLs become PublicBase/files/<key>?...
	PublicBase string `json:"public_base"`
	// Secret for HMAC presigning (server side only).
	Secret []byte `json:"-"`
	// Default presign lifetime.
	Expires time.Duration `json:"expires"`
}

type Driver struct {
	cfg Config
}

func New(cfg Config) (*Driver, error) {
	if cfg.Root == "" {
		return nil, errors.New("localfs: root required")
	}
	if cfg.PublicBase == "" {
		cfg.PublicBase = "http://127.0.0.1:8080"
	}
	cfg.PublicBase = strings.TrimRight(cfg.PublicBase, "/")
	if len(cfg.Secret) < 16 {
		return nil, errors.New("localfs: presign secret must be >= 16 bytes")
	}
	if cfg.Expires <= 0 {
		cfg.Expires = 15 * time.Minute
	}
	if err := os.MkdirAll(cfg.Root, 0o755); err != nil {
		return nil, err
	}
	return &Driver{cfg: cfg}, nil
}

func (d *Driver) Name() string { return "localfs" }

func (d *Driver) path(key string) (string, error) {
	if err := storage.ValidateKey(key); err != nil {
		return "", err
	}
	return filepath.Join(d.cfg.Root, filepath.FromSlash(key)), nil
}

func (d *Driver) url(ctx context.Context, method, key string, ttl time.Duration) (string, error) {
	if _, err := d.path(key); err != nil {
		return "", err
	}
	if ttl == 0 {
		ttl = d.cfg.Expires // negative TTL intentionally yields an already-expired URL (tests)
	}
	base := d.cfg.PublicBase
	if ctx != nil {
		if pb, ok := ctx.Value(publicBaseKey{}).(string); ok && pb != "" {
			base = strings.TrimRight(pb, "/") // honor request Host for dev convenience
		}
	}
	return base + "/files/" + key + "?" + presign.Query(d.cfg.Secret, method, key, time.Now().Add(ttl)), nil
}

type publicBaseKey struct{}

// WithPublicBase returns a context carrying an override base URL for presigns.
func WithPublicBase(ctx context.Context, base string) context.Context {
	return context.WithValue(ctx, publicBaseKey{}, base)
}

func (d *Driver) PresignGet(ctx context.Context, key string, expires time.Duration) (string, error) {
	return d.url(ctx, http.MethodGet, key, expires)
}

func (d *Driver) PresignHead(ctx context.Context, key string, expires time.Duration) (string, error) {
	// HEAD shares the GET signing domain: treat as GET so one URL can do both.
	return d.url(ctx, http.MethodGet, key, expires)
}

func (d *Driver) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) (*storage.Object, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".upload-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if size >= 0 && written != size {
		return nil, fmt.Errorf("localfs: short write %d != %d", written, size)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return nil, err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	meta := objectMeta{
		Size:        written,
		SHA256:      sha,
		ContentType: contentType,
		ETag:        `"` + sha + `"`,
	}
	if err := writeMeta(p, &meta); err != nil {
		return nil, err
	}
	return &storage.Object{Key: key, Size: meta.Size, ETag: meta.ETag, ContentType: contentType}, nil
}

type objectMeta struct {
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
	ETag        string `json:"etag"`
}

func metaPath(p string) string { return p + ".meta.json" }

func writeMeta(p string, m *objectMeta) error {
	buf, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath(p), buf, 0o644)
}

func readMeta(p string) (*objectMeta, error) {
	buf, err := os.ReadFile(metaPath(p))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	var m objectMeta
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (d *Driver) Head(ctx context.Context, key string) (*storage.Object, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	m, err := readMeta(p)
	if err != nil {
		return nil, err
	}
	return &storage.Object{Key: key, Size: m.Size, ETag: m.ETag, ContentType: m.ContentType}, nil
}

// SHA256 returns the recorded content hash for a stored key.
func (d *Driver) SHA256(key string) (string, error) {
	p, err := d.path(key)
	if err != nil {
		return "", err
	}
	m, err := readMeta(p)
	if err != nil {
		return "", err
	}
	return m.SHA256, nil
}

func (d *Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (d *Driver) Delete(ctx context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	os.Remove(metaPath(p))
	return nil
}

func (d *Driver) Ping(ctx context.Context) error {
	probe := filepath.Join(d.cfg.Root, ".probe")
	if err := os.WriteFile(probe, []byte("ping"), 0o644); err != nil {
		return err
	}
	os.Remove(probe)
	return nil
}

// VerifyRequest checks an incoming /files/<key> request signature. Method
// GET and HEAD are both accepted with GET signatures.
func (d *Driver) VerifyRequest(method, key, query string) error {
	q, err := url.ParseQuery(query)
	if err != nil {
		return presign.ErrMalformed
	}
	exp := q.Get("exp")
	sig := q.Get("sig")
	if exp == "" || sig == "" {
		return presign.ErrMalformed
	}
	if method == http.MethodHead {
		method = http.MethodGet
	}
	if err := presign.Verify(d.cfg.Secret, method, key, exp, sig); err != nil {
		return err
	}
	return nil
}

// ensure interface satisfaction
var _ storage.Storage = (*Driver)(nil)
