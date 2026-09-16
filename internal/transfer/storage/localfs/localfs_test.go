package localfs

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"dldw/internal/transfer/storage"
)

func newDriver(t *testing.T) *Driver {
	t.Helper()
	d, err := New(Config{
		Root:       t.TempDir(),
		PublicBase: "https://dldw.example.com",
		Secret:     []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPutHeadGet(t *testing.T) {
	d := newDriver(t)
	ctx := context.Background()
	payload := []byte("hello dldw artifact")

	obj, err := d.Put(ctx, "ab/cd/abc123.bin", bytes.NewReader(payload), int64(len(payload)), "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != int64(len(payload)) {
		t.Fatalf("size = %d", obj.Size)
	}
	sha, err := d.SHA256("ab/cd/abc123.bin")
	if err != nil || len(sha) != 64 {
		t.Fatalf("sha256 = %q err=%v", sha, err)
	}

	h, err := d.Head(ctx, "ab/cd/abc123.bin")
	if err != nil {
		t.Fatal(err)
	}
	if h.Size != int64(len(payload)) || h.ContentType != "application/octet-stream" {
		t.Fatalf("head = %+v", h)
	}

	rc, err := d.Get(ctx, "ab/cd/abc123.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("get = %q", got)
	}

	if _, err := d.Head(ctx, "missing"); err != storage.ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := d.Delete(ctx, "ab/cd/abc123.bin"); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, "ab/cd/abc123.bin"); err != nil {
		t.Fatalf("delete should be idempotent: %v", err)
	}
}

func TestPresignAndVerify(t *testing.T) {
	d := newDriver(t)
	ctx := context.Background()
	payload := []byte("xyz")
	if _, err := d.Put(ctx, "aa/bb.bin", bytes.NewReader(payload), 3, ""); err != nil {
		t.Fatal(err)
	}
	u, err := d.PresignGet(ctx, "aa/bb.bin", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "https://dldw.example.com/files/aa/bb.bin?") {
		t.Fatalf("url = %q", u)
	}
	q := u[strings.IndexByte(u, '?')+1:]
	if err := d.VerifyRequest(http.MethodGet, "aa/bb.bin", q); err != nil {
		t.Fatalf("verify GET: %v", err)
	}
	if err := d.VerifyRequest(http.MethodHead, "aa/bb.bin", q); err != nil {
		t.Fatalf("verify HEAD (shares GET sig): %v", err)
	}
	if err := d.VerifyRequest(http.MethodGet, "aa/other.bin", q); err == nil {
		t.Fatal("key swap must fail")
	}
	// expired
	u2, _ := d.PresignGet(ctx, "aa/bb.bin", -time.Minute)
	q2 := u2[strings.IndexByte(u2, '?')+1:]
	if err := d.VerifyRequest(http.MethodGet, "aa/bb.bin", q2); err == nil {
		t.Fatal("expired must fail")
	}
}

func TestKeyTraversal(t *testing.T) {
	d := newDriver(t)
	ctx := context.Background()
	for _, bad := range []string{"../../etc/passwd", "a/../../b", "", "A/B", "a b", "..", "a/../b"} {
		if _, err := d.Put(ctx, bad, bytes.NewReader([]byte("x")), 1, ""); err != storage.ErrBadKey {
			t.Errorf("Put(%q) err = %v, want ErrBadKey", bad, err)
		}
	}
}

func TestPing(t *testing.T) {
	d := newDriver(t)
	if err := d.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}
