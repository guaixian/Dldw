// Package s3 is a zero-dependency S3 compatible storage driver (S3/MinIO/OSS/
// COS) using SigV4 query presigned URLs so large transfers never transit the
// control server (spec 1.2 principle 3).
package s3

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"dldw/internal/transfer/storage"
)

const (
	algorithm    = "AWS4-HMAC-SHA256"
	service      = "s3"
	unsignedBody = "UNSIGNED-PAYLOAD"
)

// Config for the S3 driver.
type Config struct {
	Endpoint        string // e.g. https://s3.amazonaws.com or http://minio:9000
	Region          string // e.g. us-east-1
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	PathStyle       bool // true for MinIO/self-hosted, false for AWS virtual-host style
	// DialContext optionally guards/controls egress (nil = plain dialer).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

type Driver struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) (*Driver, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("s3: endpoint, bucket, access key and secret are required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return nil, errors.New("s3: invalid endpoint")
	}
	transport := &http.Transport{
		Proxy:       nil, // never route storage traffic through env proxies
		MaxIdleConns: 16,
	}
	if cfg.DialContext != nil {
		transport.DialContext = cfg.DialContext
	}
	return &Driver{cfg: cfg, client: &http.Client{Transport: transport}}, nil
}

func (d *Driver) Name() string { return "s3" }

func (d *Driver) endpointHost() (string, string, bool) {
	u, _ := url.Parse(d.cfg.Endpoint)
	host := u.Host
	tls := u.Scheme == "https"
	return host, u.Scheme, tls
}

// objectHost returns the Host header value: path style keeps the endpoint
// host, virtual-host style prefixes the bucket.
func (d *Driver) objectHost() string {
	host, _, _ := d.endpointHost()
	if d.cfg.PathStyle {
		return host
	}
	// AWS virtual-host style; custom endpoints with ports use path style.
	if strings.Contains(host, ":") && !strings.HasSuffix(host, ":443") && !strings.HasSuffix(host, ":80") {
		return host
	}
	base := host
	if i := strings.LastIndex(base, ":"); i >= 0 {
		base = base[:i]
	}
	return d.cfg.Bucket + "." + base
}

// encodePath RFC3986-encodes each segment of key, preserving slashes.
func encodePath(key string) string {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = encodeSegment(s)
	}
	return strings.Join(segs, "/")
}

const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"

func encodeSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// canonicalURI returns the canonical resource path for key.
func (d *Driver) canonicalURI(key string) string {
	if err := storage.ValidateKey(key); err != nil {
		return ""
	}
	enc := encodePath(key)
	if d.cfg.PathStyle {
		return "/" + d.cfg.Bucket + "/" + enc
	}
	return "/" + enc
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func amzDate(t time.Time) string { return t.UTC().Format("20060102T150405Z") }

// Presign produces a presigned URL for method/key valid for expires.
func (d *Driver) Presign(method, key string, expires time.Duration) (string, error) {
	if expires <= 0 {
		expires = 15 * time.Minute
	}
	if expires > 7*24*time.Hour {
		expires = 7 * 24 * time.Hour // SigV4 cap
	}
	now := time.Now()
	date := now.UTC().Format("20060102")
	scope := date + "/" + d.cfg.Region + "/" + service + "/aws4_request"

	q := url.Values{}
	q.Set("X-Amz-Algorithm", algorithm)
	q.Set("X-Amz-Credential", d.cfg.AccessKeyID+"/"+scope)
	q.Set("X-Amz-Date", amzDate(now))
	q.Set("X-Amz-Expires", strconv.FormatInt(int64(expires/time.Second), 10))
	q.Set("X-Amz-SignedHeaders", "host")

	host := d.objectHost()
	canonQuery := canonicalQueryString(q)
	canonicalRequest := strings.Join([]string{
		method,
		d.canonicalURI(key),
		canonQuery,
		"host:" + host + "\n",
		"host",
		unsignedBody,
	}, "\n")

	stringToSign := strings.Join([]string{
		algorithm,
		amzDate(now),
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")

	signingKey := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+d.cfg.SecretAccessKey), date), d.cfg.Region), service), "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	_, scheme, _ := d.endpointHost()
	if scheme == "" {
		scheme = "https"
	}
	base := scheme + "://" + host
	if d.cfg.PathStyle {
		base += "/" + d.cfg.Bucket
	}
	return base + "/" + encodePath(key) + "?" + canonQuery + "&X-Amz-Signature=" + signature, nil
}

func canonicalQueryString(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, encodeSegment(k)+"="+encodeSegment(v))
		}
	}
	return strings.Join(parts, "&")
}

func (d *Driver) PresignGet(ctx context.Context, key string, expires time.Duration) (string, error) {
	return d.Presign(http.MethodGet, key, expires)
}

func (d *Driver) PresignHead(ctx context.Context, key string, expires time.Duration) (string, error) {
	return d.Presign(http.MethodHead, key, expires)
}

// do sends a presigned request with body and method, returning the response.
func (d *Driver) do(ctx context.Context, method, key string, expires time.Duration, body io.Reader, length int64) (*http.Response, error) {
	u, err := d.Presign(method, key, expires)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if length >= 0 {
		req.ContentLength = length
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (d *Driver) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) (*storage.Object, error) {
	if err := storage.ValidateKey(key); err != nil {
		return nil, err
	}
	resp, err := d.do(ctx, http.MethodPut, key, time.Hour, r, size)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("s3: put %s: HTTP %d", key, resp.StatusCode)
	}
	return &storage.Object{Key: key, Size: size, ETag: resp.Header.Get("ETag"), ContentType: contentType}, nil
}

func (d *Driver) Head(ctx context.Context, key string) (*storage.Object, error) {
	resp, err := d.do(ctx, http.MethodHead, key, time.Minute, nil, -1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, storage.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("s3: head %s: HTTP %d", key, resp.StatusCode)
	}
	size, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	return &storage.Object{
		Key:         key,
		Size:        size,
		ETag:        resp.Header.Get("ETag"),
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

func (d *Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := d.do(ctx, http.MethodGet, key, time.Hour, nil, -1)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, storage.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, fmt.Errorf("s3: get %s: HTTP %d", key, resp.StatusCode)
	}
	return resp.Body, nil
}

func (d *Driver) Delete(ctx context.Context, key string) error {
	resp, err := d.do(ctx, http.MethodDelete, key, time.Minute, nil, -1)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("s3: delete %s: HTTP %d", key, resp.StatusCode)
	}
	return nil
}

func (d *Driver) Ping(ctx context.Context) error {
	_, err := d.Head(ctx, ".probe/healthz")
	if errors.Is(err, storage.ErrNotFound) {
		return nil // reachable: bucket listing responded 404
	}
	return err
}

var _ storage.Storage = (*Driver)(nil)
