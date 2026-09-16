package downloader

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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// partMeta is the resume state persisted next to the .part file (spec 3.5).
type partMeta struct {
	Version   int     `json:"version"`
	URL       string  `json:"url"`
	Size      int64   `json:"size"`
	ChunkSize int64   `json:"chunk_size"`
	SHA256    string  `json:"sha256"`
	ETag      string  `json:"etag"`
	Done      []bool  `json:"done"`
}

const partMetaVersion = 1

var (
	// ErrChecksumMismatch indicates sha256 verification failure.
	ErrChecksumMismatch = errors.New("E_CHECKSUM_MISMATCH: downloaded content hash differs from expected")
	// ErrPresignExpired indicates an expired presigned URL (refreshable).
	ErrPresignExpired = errors.New("E_PRESIGN_EXPIRED")
)

func chunkCount(size, chunk int64) int {
	if size <= 0 || chunk <= 0 {
		return 0
	}
	n := size / chunk
	if size%chunk != 0 {
		n++
	}
	return int(n)
}

// offsetWriter writes at a moving file offset via WriteAt (concurrency safe
// for disjoint regions).
type offsetWriter struct {
	f   *os.File
	off int64
}

func (w *offsetWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.off)
	w.off += int64(n)
	return n, err
}

// loadPartMeta reads persisted resume state if compatible.
func loadPartMeta(metaPath string) *partMeta {
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil
	}
	var m partMeta
	if err := json.Unmarshal(data, &m); err != nil || m.Version != partMetaVersion {
		return nil
	}
	return &m
}

func savePartMeta(metaPath string, m *partMeta) error {
	buf, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := metaPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, metaPath)
}

// chunkPlan describes how to fetch a file in ranges.
type chunkPlan struct {
	url       string
	size      int64
	chunkSize int64
	chunks    int
	sha256    string
	etag      string
}

// runChunked performs (or resumes) a ranged parallel download into partPath.
// refresh is called when the URL expires (HTTP 401/403/410); it must return
// a fresh URL for the same content.
func runChunked(ctx context.Context, hc *http.Client, plan chunkPlan, partPath, metaPath string,
	refresh func(ctx context.Context) (string, error), concurrency int, onProgress func(done, total int64)) error {

	if plan.size <= 0 || plan.chunkSize <= 0 || plan.chunks <= 0 {
		return fmt.Errorf("invalid chunk plan (size=%d chunk=%d)", plan.size, plan.chunkSize)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	meta := loadPartMeta(metaPath)
	if meta == nil || meta.Size != plan.size || meta.ChunkSize != plan.chunkSize || len(meta.Done) != plan.chunks {
		meta = &partMeta{
			Version: partMetaVersion, URL: plan.url, Size: plan.size,
			ChunkSize: plan.chunkSize, SHA256: plan.sha256, ETag: plan.etag,
			Done: make([]bool, plan.chunks),
		}
	}
	meta.URL = plan.url
	meta.SHA256 = plan.sha256
	meta.ETag = plan.etag

	var doneBytes int64
	var doneCount int
	for i, ok := range meta.Done {
		if ok {
			doneBytes += chunkLen(int64(i), plan)
			doneCount++
		}
	}
	if doneCount == plan.chunks {
		return nil // fully resumed already
	}

	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(plan.size); err != nil {
		return err
	}

	var (
		mu       sync.Mutex
		curURL   = meta.URL
		jobs     = make(chan int)
		wg       sync.WaitGroup
		progress atomic.Int64
	)
	progress.Store(doneBytes)
	if onProgress != nil {
		onProgress(doneBytes, plan.size)
	}

	// URL refresher guarded so only one refresh happens at a time
	var refreshMu sync.Mutex
	getURL := func(ctx context.Context) (string, error) {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		mu.Lock()
		u := curURL
		mu.Unlock()
		return u, nil
	}
	doRefresh := func(ctx context.Context) (string, error) {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		if refresh == nil {
			return "", ErrPresignExpired
		}
		u, err := refresh(ctx)
		if err != nil {
			return "", err
		}
		mu.Lock()
		curURL = u
		meta.URL = u
		mu.Unlock()
		return u, nil
	}

	workerErr := make(chan error, concurrency+1)
	abort := make(chan struct{})

	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			select {
			case <-abort:
				return
			default:
			}
			start := int64(idx) * plan.chunkSize
			end := start + chunkLen(int64(idx), plan) - 1
			var lastErr error
			for attempt := 0; attempt < 4; attempt++ {
				select {
				case <-ctx.Done():
					workerErr <- ctx.Err()
					closeOnce(abort)
					return
				default:
				}
				if attempt > 0 {
					sleepBackoff(ctx, attempt)
				}
				u, err := getURL(ctx)
				if err != nil {
					lastErr = err
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					workerErr <- err
					closeOnce(abort)
					return
				}
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
				resp, err := hc.Do(req)
				if err != nil {
					lastErr = err
					continue
				}
				if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized ||
					resp.StatusCode == http.StatusGone {
					io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
					resp.Body.Close()
					if _, rerr := doRefresh(ctx); rerr != nil {
						lastErr = fmt.Errorf("%w: %v", ErrPresignExpired, rerr)
						continue
					}
					lastErr = ErrPresignExpired
					continue
				}
				if resp.StatusCode != http.StatusPartialContent {
					io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
					resp.Body.Close()
					if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
						lastErr = fmt.Errorf("chunk %d: HTTP %d", idx, resp.StatusCode)
						continue
					}
					workerErr <- fmt.Errorf("chunk %d: HTTP %d", idx, resp.StatusCode)
					closeOnce(abort)
					return
				}
				want := end - start + 1
				w := &offsetWriter{f: f, off: start}
				n, cerr := io.Copy(w, resp.Body)
				resp.Body.Close()
				if cerr != nil || n != want {
					lastErr = fmt.Errorf("chunk %d: copy %d/%d (%v)", idx, n, want, cerr)
					continue
				}
				// success
				mu.Lock()
				meta.Done[idx] = true
				done2 := progress.Add(want)
				saveErr := savePartMeta(metaPath, meta)
				mu.Unlock()
				if saveErr != nil {
					workerErr <- saveErr
					closeOnce(abort)
					return
				}
				if onProgress != nil {
					onProgress(done2, plan.size)
				}
				lastErr = nil
				break
			}
			if lastErr != nil {
				select {
				case workerErr <- lastErr:
				case <-abort:
				}
				closeOnce(abort)
				return
			}
		}
	}

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go worker()
	}

	// publisher feeds undone chunk indexes
	go func() {
		for idx := 0; idx < plan.chunks; idx++ {
			if meta.Done[idx] {
				continue
			}
			select {
			case <-abort:
				return
			case jobs <- idx:
			}
		}
		close(jobs)
	}()

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()

	var runErr error
loop:
	for {
		select {
		case err := <-workerErr:
			if err != nil {
				runErr = err
				closeOnce(abort)
				break loop
			}
		case <-ctx.Done():
			runErr = ctx.Err()
			closeOnce(abort)
			break loop
		case <-finished:
			break loop
		}
	}
	<-finished

	if runErr != nil {
		return runErr
	}
	// final meta save
	if err := savePartMeta(metaPath, meta); err != nil {
		return err
	}
	return nil
}

func chunkLen(idx int64, plan chunkPlan) int64 {
	start := idx * plan.chunkSize
	if plan.size-start >= plan.chunkSize {
		return plan.chunkSize
	}
	return plan.size - start
}

func closeOnce(c chan struct{}) {
	select {
	case <-c:
	default:
		close(c)
	}
}

func sleepBackoff(ctx context.Context, attempt int) {
	d := time.Duration(attempt*attempt) * 250 * time.Millisecond
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// verifySHA256 streams partPath and compares against want (hex, optional).
func verifySHA256(partPath, want string) error {
	if want == "" {
		return nil
	}
	f, err := os.Open(partPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%w (want %s got %s)", ErrChecksumMismatch, want, got)
	}
	return nil
}

// outputName derives a safe local filename from a URL.
func outputName(rawURL, explicit string) string {
	if explicit != "" {
		return explicit
	}
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = u.Path
	} else if i := strings.IndexByte(rawURL, '?'); i >= 0 {
		path = rawURL[:i]
	}
	segs := strings.Split(strings.ReplaceAll(path, "\\", "/"), "/")
	base := ""
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "" {
			base = segs[i]
			break
		}
	}
	base = strings.TrimLeft(base, ".")
	if len(base) == 0 || len(base) > 128 {
		return "download.bin"
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == '%', r == '+':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" || out == "." {
		return "download.bin"
	}
	return out
}

func splitQuery(rawURL string) (string, error) {
	if i := strings.IndexByte(rawURL, '?'); i >= 0 {
		return rawURL[:i], nil
	}
	return rawURL, nil
}

// computeAndStoreSHA streams path and persists its hash as path+".sha256".
func computeAndStoreSHA(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	return os.WriteFile(path+".sha256", []byte(hex.EncodeToString(h.Sum(nil))), 0o644)
}
