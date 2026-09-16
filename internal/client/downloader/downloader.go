package downloader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options configures a download run.
type Options struct {
	Concurrency   int
	ChunkSize     int64
	Output        string // explicit output path ("" = derive from URL)
	Overwrite     bool
	TaskTimeout   time.Duration
	PollWait      time.Duration
	DirectFallback string // always | never | ask (ask resolved by CLI)
	Progress      func(done, total int64)
	Verbose       bool
	HTTPClient    *http.Client // for presigned/direct transfers (no env proxy)
}

// Result describes a finished download.
type Result struct {
	Path     string
	Size     int64
	SHA256   string
	Mode     string // presigned | direct
	Cached   bool
}

// httpClient builds the transfer client (no env proxy).
func (o Options) httpClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			MaxIdleConns:        16,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 0, // governed by ctx; range GETs can be long
	}
}

// Download fetches rawURL following the fast path: resolve -> presigned range
// download; falls back to direct when the API is unusable and fallback policy
// allows it. Returns the local file path.
func Download(ctx context.Context, rawURL string, opts Options, api *Client) (*Result, error) {
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = 16 << 20
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	hc := opts.httpClient()

	if api != nil {
		res, err := api.Resolve(ctx, rawURL)
		if err != nil {
			if IsCode(err, "E_RESOLVE_AUTH") {
				return nil, err // fatal: token invalid; do not silently bypass
			}
			if !fallbackAllowed(opts.DirectFallback) {
				return nil, fmt.Errorf("E_RESOLVE_FAILED: %w", err)
			}
			fmt.Fprintf(os.Stderr, "dldw: resolve failed (%v); falling back to direct\n", err)
			return downloadDirect(ctx, hc, rawURL, opts)
		}
		switch res.Status {
		case "cached":
			if res.Download == nil || len(res.Download.URLs) == 0 {
				return nil, errors.New("E_RESOLVE_FAILED: cached response without download URLs")
			}
			return fetchPresigned(ctx, hc, api, res, rawURL, opts)
		default:
			// queued/downloading: poll the task, then refresh presigned URLs
			taskID := ""
			if res.Task != nil {
				taskID = res.Task.ID
			}
			if taskID == "" {
				return nil, errors.New("E_RESOLVE_FAILED: task status without task id")
			}
			res2, perr := pollTask(ctx, api, taskID, opts)
			if perr != nil {
				if !fallbackAllowed(opts.DirectFallback) {
					return nil, perr
				}
				fmt.Fprintf(os.Stderr, "dldw: task did not complete (%v); falling back to direct\n", perr)
				return downloadDirect(ctx, hc, rawURL, opts)
			}
			return fetchPresigned(ctx, hc, api, res2, rawURL, opts)
		}
	}
	return downloadDirect(ctx, hc, rawURL, opts)
}

func fallbackAllowed(policy string) bool {
	return policy == "always"
}

// pollTask waits for a server-side cache task to become ready.
func pollTask(ctx context.Context, api *Client, taskID string, opts Options) (*ResolveResponse, error) {
	deadline := time.Now().Add(opts.TaskTimeout)
	if deadline.IsZero() || opts.TaskTimeout <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	wait := opts.PollWait
	if wait <= 0 {
		wait = time.Second
	}
	var last *TaskView
	for {
		t, err := api.Task(ctx, taskID)
		if err != nil {
			return nil, err
		}
		last = t
		switch t.Status {
		case "ready":
			return api.Refresh(ctx, taskID)
		case "dead":
			return nil, fmt.Errorf("E_TASK_DEAD: server could not fetch artifact: %s", t.Error)
		case "failed":
			if t.Retries > 8 {
				return nil, fmt.Errorf("E_TASK_FAILED: retries exhausted: %s", t.Error)
			}
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	status := ""
	if last != nil {
		status = last.Status
	}
	return nil, fmt.Errorf("E_RESOLVE_TIMEOUT: task still %s after %s", status, opts.TaskTimeout)
}

// fetchPresigned downloads a resolved artifact via its presigned URL(s).
func fetchPresigned(ctx context.Context, hc *http.Client, api *Client, res *ResolveResponse, rawURL string, opts Options) (*Result, error) {
	size := int64(-1)
	sha := ""
	if res.Artifact != nil {
		size = res.Artifact.Size
		sha = res.Artifact.SHA256
	}
	taskID := ""
	if res.Task != nil {
		taskID = res.Task.ID
	}
	url0 := res.Download.URLs[0]
	refresh := func(ctx context.Context) (string, error) {
		if api == nil || taskID == "" {
			return "", errors.New("cannot refresh without task id")
		}
		r, err := api.Refresh(ctx, taskID)
		if err != nil {
			return "", err
		}
		if r.Download == nil || len(r.Download.URLs) == 0 {
			return "", errors.New("refresh returned no URLs")
		}
		return r.Download.URLs[0], nil
	}

	// probe with HEAD when size unknown
	if size < 0 {
		if h, err := head(ctx, hc, url0); err == nil && h.ContentLength > 0 {
			size = h.ContentLength
		}
	}

	out := outputName(rawURL, opts.Output)
	partPath := out + ".part"
	metaPath := out + ".part.meta.json"

	var err error
	useRange := res.Download.SupportsRange && size > 2*opts.ChunkSize && size > 0
	if useRange {
		plan := chunkPlan{
			url: url0, size: size, chunkSize: opts.ChunkSize,
			chunks: chunkCount(size, opts.ChunkSize), sha256: sha, etag: res.Artifact.ETag,
		}
		err = runChunked(ctx, hc, plan, partPath, metaPath, refresh, opts.Concurrency, opts.Progress)
	} else {
		err = downloadStream(ctx, hc, url0, refresh, partPath, size, opts.Progress)
	}
	if err != nil {
		return nil, err
	}
	if err := finishFile(partPath, out, metaPath, sha, opts.Overwrite); err != nil {
		return nil, err
	}
	gotSHA := ""
	if sha != "" {
		gotSHA = sha
	}
	return &Result{Path: out, Size: size, SHA256: gotSHA, Mode: "presigned", Cached: true}, nil
}

// downloadDirect fetches from the origin without server assistance.
func downloadDirect(ctx context.Context, hc *http.Client, rawURL string, opts Options) (*Result, error) {
	head, err := head(ctx, hc, rawURL)
	size := int64(-1)
	ranges := false
	etag := ""
	if err == nil {
		size = head.ContentLength
		ranges = strings.EqualFold(head.AcceptRanges, "bytes")
		etag = head.ETag
	}
	out := outputName(rawURL, opts.Output)
	partPath := out + ".part"
	metaPath := out + ".part.meta.json"

	refresh := func(ctx context.Context) (string, error) { return rawURL, nil }
	if ranges && size > 2*opts.ChunkSize && size > 0 {
		plan := chunkPlan{
			url: rawURL, size: size, chunkSize: opts.ChunkSize,
			chunks: chunkCount(size, opts.ChunkSize), sha256: "", etag: etag,
		}
		if err := runChunked(ctx, hc, plan, partPath, metaPath, refresh, opts.Concurrency, opts.Progress); err != nil {
			return nil, err
		}
		if err := computeAndStoreSHA(partPath); err != nil {
			return nil, err
		}
		if err := finishFile(partPath, out, metaPath, "", opts.Overwrite); err != nil {
			return nil, err
		}
		return &Result{Path: out, Size: size, Mode: "direct"}, nil
	}
	if err := downloadStream(ctx, hc, rawURL, refresh, partPath, size, opts.Progress); err != nil {
		return nil, err
	}
	if err := finishFile(partPath, out, metaPath, "", opts.Overwrite); err != nil {
		return nil, err
	}
	return &Result{Path: out, Size: size, Mode: "direct"}, nil
}

type headInfo struct {
	ContentLength int64
	AcceptRanges  string
	ETag          string
}

func head(ctx context.Context, hc *http.Client, u string) (*headInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HEAD: HTTP %d", resp.StatusCode)
	}
	return &headInfo{
		ContentLength: resp.ContentLength,
		AcceptRanges:  resp.Header.Get("Accept-Ranges"),
		ETag:          resp.Header.Get("ETag"),
	}, nil
}

// downloadStream performs a single GET into partPath, computing sha256 while
// writing.
func downloadStream(ctx context.Context, hc *http.Client, u string, refresh func(context.Context) (string, error), partPath string, size int64, onProgress func(done, total int64)) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusGone {
			resp.Body.Close()
			if refresh != nil {
				if nu, rerr := refresh(ctx); rerr == nil {
					u = nu
					lastErr = ErrPresignExpired
					continue
				}
			}
			lastErr = ErrPresignExpired
			continue
		}
		if resp.StatusCode/100 != 2 {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return lastErr
			}
			continue
		}
		f, err := os.Create(partPath)
		if err != nil {
			resp.Body.Close()
			return err
		}
		h := sha256.New()
		total := size
		if total <= 0 {
			total = resp.ContentLength
		}
		var done int64
		buf := make([]byte, 64<<10)
		var rerr error
		for {
			n, re := resp.Body.Read(buf)
			if n > 0 {
				if _, we := f.Write(buf[:n]); we != nil {
					rerr = we
					break
				}
				h.Write(buf[:n])
				done += int64(n)
				if onProgress != nil {
					onProgress(done, total)
				}
			}
			if re != nil {
				if errors.Is(re, io.EOF) {
					rerr = nil
				} else {
					rerr = re
				}
				break
			}
		}
		f.Close()
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			os.Remove(partPath)
			continue
		}
		// record hash as sidecar for finishFile
		if err := os.WriteFile(partPath+".sha256", []byte(hex.EncodeToString(h.Sum(nil))), 0o644); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("direct download failed: %w", lastErr)
}

// finishFile verifies (when wanted hash known), moves .part into place and
// cleans the resume metadata.
func finishFile(partPath, out, metaPath, wantSHA string, overwrite bool) error {
	gotSHA := ""
	if data, err := os.ReadFile(partPath + ".sha256"); err == nil {
		gotSHA = strings.TrimSpace(string(data))
		os.Remove(partPath + ".sha256")
	}
	if wantSHA != "" {
		if err := verifySHA256(partPath, wantSHA); err != nil {
			os.Remove(partPath)
			os.Remove(metaPath)
			return err
		}
	} else if gotSHA != "" {
		// self-consistent hash recorded; expose via sidecar .sha256 file
		if err := os.WriteFile(out+".sha256", []byte("sha256:"+gotSHA), 0o644); err == nil {
			_ = err
		}
	}
	if !overwrite {
		if _, err := os.Stat(out); err == nil {
			os.Remove(partPath)
			os.Remove(metaPath)
			return fmt.Errorf("E_OUTPUT_EXISTS: %s already exists (use --force to overwrite)", out)
		}
	}
	if err := os.Rename(partPath, out); err != nil {
		return err
	}
	os.Remove(metaPath)
	return nil
}

// ResumeState reports whether a .part resume file exists for output.
func ResumeState(output string) (bool, int64) {
	fi, err := os.Stat(output + ".part")
	if err != nil {
		return false, 0
	}
	return true, fi.Size()
}

// DefaultOutputName exposes naming for the CLI.
func DefaultOutputName(rawURL, explicit string) string { return outputName(rawURL, explicit) }

// AbsOutput resolves the output relative to cwd.
func AbsOutput(output string) string {
	if output == "" || filepath.IsAbs(output) {
		return output
	}
	abs, err := filepath.Abs(output)
	if err != nil {
		return output
	}
	return abs
}
