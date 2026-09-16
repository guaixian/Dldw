package downloader

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newRangeOrigin serves payload with Range support and counts requests.
func newRangeOrigin(t *testing.T, payload []byte) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeContent(w, r, "artifact.bin", time.Time{}, newBytesReader(payload))
	}))
	t.Cleanup(srv.Close)
	return srv, &served
}

// bytesReader recreates a seekable reader view over b (ServeContent needs Seeker).
func newBytesReader(b []byte) *bytesReaderAlias { return &bytesReaderAlias{b: b} }

type bytesReaderAlias struct {
	b   []byte
	off int64
}

func (r *bytesReaderAlias) Read(p []byte) (int, error) {
	if r.off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += int64(n)
	return n, nil
}

func (r *bytesReaderAlias) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.off = off
	case io.SeekCurrent:
		r.off += off
	case io.SeekEnd:
		r.off = int64(len(r.b)) + off
	}
	return r.off, nil
}

func TestDirectChunkedDownload(t *testing.T) {
	payload := make([]byte, 5<<20)
	rand.Read(payload)
	want := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(want[:])

	srv, _ := newRangeOrigin(t, payload)
	dir := t.TempDir()
	out := filepath.Join(dir, "app.bin")

	var progressCalls int64
	res, err := Download(context.Background(), srv.URL+"/app.bin", Options{
		ChunkSize:  512 << 10,
		Concurrency: 4,
		Output:     out,
		Progress:   func(done, total int64) { progressCalls++ },
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "direct" {
		t.Fatalf("mode = %s", res.Mode)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payload) {
		t.Fatalf("size = %d", len(got))
	}
	if hex.EncodeToString(sha256Sum(got)) != wantHex {
		t.Fatal("content mismatch")
	}
	if progressCalls < 10 {
		t.Fatalf("progress calls = %d", progressCalls)
	}
	// no leftover part files
	for _, f := range []string{out + ".part", out + ".part.meta.json"} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("leftover %s", f)
		}
	}
	// sha256 sidecar written for direct mode
	if data, err := os.ReadFile(out + ".sha256"); err != nil || !strings.Contains(string(data), wantHex) {
		t.Errorf("sha256 sidecar missing: %v", err)
	}

	// refuse overwrite by default
	if _, err := Download(context.Background(), srv.URL+"/app.bin", Options{ChunkSize: 512 << 10, Output: out}, nil); err == nil || !strings.Contains(err.Error(), "E_OUTPUT_EXISTS") {
		t.Fatalf("expected E_OUTPUT_EXISTS, got %v", err)
	}
}

func TestResumeAcrossRuns(t *testing.T) {
	payload := make([]byte, 2<<20)
	rand.Read(payload)

	var failChunk atomic.Bool
	failChunk.Store(true)
	var chunk2Start = fmt.Sprintf("bytes=%d-", 2*(256<<10))

	var servedTotal atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rng := r.Header.Get("Range")
		servedTotal.Add(1)
		if failChunk.Load() && strings.HasPrefix(rng, chunk2Start) {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeContent(w, r, "a.bin", time.Time{}, newBytesReader(payload))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	out := filepath.Join(dir, "resume.bin")
	opts := Options{ChunkSize: 256 << 10, Concurrency: 2, Output: out}

	// first run: fails after retries, leaves .part + meta with most chunks done
	_, err := Download(context.Background(), srv.URL+"/a.bin", opts, nil)
	if err == nil {
		t.Fatal("expected failure while chunk 2 is broken")
	}
	if _, err := os.Stat(out + ".part"); err != nil {
		t.Fatalf("no .part left: %v", err)
	}
	meta := loadPartMeta(out + ".part.meta.json")
	if meta == nil {
		t.Fatal("no meta left")
	}
	doneCount := 0
	for _, d := range meta.Done {
		if d {
			doneCount++
		}
	}
	if doneCount == 0 {
		t.Fatal("no chunks completed in first run")
	}

	// heal the origin; second run resumes without refetching completed chunks
	before := servedTotal.Load()
	failChunk.Store(false)
	if _, err := Download(context.Background(), srv.URL+"/a.bin", opts, nil); err != nil {
		t.Fatal(err)
	}
	after := servedTotal.Load()
	newRequests := after - before
	if newRequests > int64(doneCount+4) { // undone chunks + retries margin
		t.Fatalf("resume refetched too much: %d new requests for %d done chunks", newRequests, doneCount)
	}
	got, _ := os.ReadFile(out)
	if hex.EncodeToString(sha256Sum(got)) != hex.EncodeToString(sha256Sum(payload)) {
		t.Fatal("resumed content mismatch")
	}
}

func TestPresignedViaFakeAPI(t *testing.T) {
	payload := make([]byte, 3<<20)
	rand.Read(payload)
	wantHex := hex.EncodeToString(sha256Sum(payload))

	srv, _ := newRangeOrigin(t, payload)
	dir := t.TempDir()
	out := filepath.Join(dir, "presigned.bin")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/resolve":
			json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req_t1",
				"status":     "cached",
				"cache_key":  "kk",
				"artifact": map[string]any{
					"size":   len(payload),
					"sha256": wantHex,
				},
				"download": map[string]any{
					"mode":           "presigned",
					"urls":           []string{srv.URL + "/obj.bin"},
					"expires_at":     time.Now().Add(time.Hour),
					"supports_range": true,
				},
				"task": map[string]any{"id": "task_t1", "status": "ready"},
			})
		case "/api/v1/tasks/task_t1/refresh":
			json.NewEncoder(w).Encode(map[string]any{
				"status": "cached",
				"download": map[string]any{
					"mode":           "presigned",
					"urls":           []string{srv.URL + "/obj.bin"},
					"expires_at":     time.Now().Add(time.Hour),
					"supports_range": true,
				},
				"artifact": map[string]any{"size": len(payload), "sha256": wantHex},
				"task":     map[string]any{"id": "task_t1"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)

	client, err := NewAPIClient(api.URL, "dldw_token_for_tests", "dev_t")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Download(context.Background(), "https://github.com/org/repo/releases/download/v1/obj.bin", Options{
		ChunkSize:  256 << 10,
		Concurrency: 3,
		Output:     out,
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached || res.Mode != "presigned" {
		t.Fatalf("res = %+v", res)
	}
	got, _ := os.ReadFile(out)
	if hex.EncodeToString(sha256Sum(got)) != wantHex {
		t.Fatal("presigned content mismatch")
	}
}

func TestChecksumMismatchDetected(t *testing.T) {
	payload := make([]byte, 1<<20)
	rand.Read(payload)
	srv, _ := newRangeOrigin(t, payload)
	dir := t.TempDir()
	out := filepath.Join(dir, "bad.bin")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/resolve" {
			json.NewEncoder(w).Encode(map[string]any{
				"status": "cached",
				"artifact": map[string]any{
					"size":   len(payload),
					"sha256": strings.Repeat("f", 64), // wrong on purpose
				},
				"download": map[string]any{
					"mode": "presigned", "urls": []string{srv.URL + "/x.bin"},
					"expires_at": time.Now().Add(time.Hour), "supports_range": true,
				},
				"task": map[string]any{"id": "task_x", "status": "ready"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(api.Close)
	client, _ := NewAPIClient(api.URL, "tok", "dev")
	_, err := Download(context.Background(), srv.URL+"/x.bin", Options{ChunkSize: 256 << 10, Output: out}, client)
	if err == nil || !strings.Contains(err.Error(), "E_CHECKSUM_MISMATCH") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Fatal("output must not exist on mismatch")
	}
}

func TestPollTaskUntilReady(t *testing.T) {
	payload := []byte("tiny-but-fine-0123456789")
	srv, _ := newRangeOrigin(t, payload)
	dir := t.TempDir()
	out := filepath.Join(dir, "polled.bin")

	var polls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/resolve":
			json.NewEncoder(w).Encode(map[string]any{
				"status": "queued",
				"task":   map[string]any{"id": "task_p", "status": "queued"},
			})
		case r.URL.Path == "/api/v1/tasks/task_p":
			n := polls.Add(1)
			st := "downloading"
			if n >= 3 {
				st = "ready"
			}
			json.NewEncoder(w).Encode(map[string]any{
				"task": map[string]any{"id": "task_p", "status": st, "progress": float64(n) / 3},
			})
		case r.URL.Path == "/api/v1/tasks/task_p/refresh":
			json.NewEncoder(w).Encode(map[string]any{
				"status": "cached",
				"artifact": map[string]any{
					"size": len(payload), "sha256": hex.EncodeToString(sha256Sum(payload)),
				},
				"download": map[string]any{
					"mode": "presigned", "urls": []string{srv.URL + "/p.bin"},
					"expires_at": time.Now().Add(time.Hour), "supports_range": true,
				},
				"task": map[string]any{"id": "task_p"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	client, _ := NewAPIClient(api.URL, "tok", "dev")
	res, err := Download(context.Background(), srv.URL+"/p.bin", Options{
		Output: out, PollWait: 20 * time.Millisecond, TaskTimeout: 5 * time.Second,
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached {
		t.Fatalf("res = %+v", res)
	}
	if polls.Load() < 3 {
		t.Fatalf("polls = %d", polls.Load())
	}
}

func TestOutputName(t *testing.T) {
	cases := map[string]string{
		"https://github.com/o/r/releases/download/v1/app.tar.gz": "app.tar.gz",
		"https://x/y/a%20b.zip?token=1":                          "a_b.zip", // decoded space sanitized
		"https://x/":                                             "download.bin",
		"https://x":                                              "download.bin",
	}
	for in, want := range cases {
		if got := outputName(in, ""); got != want {
			t.Errorf("outputName(%q) = %q, want %q", in, got, want)
		}
	}
	if outputName("https://x/a.zip", "custom.bin") != "custom.bin" {
		t.Fatal("explicit name ignored")
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
