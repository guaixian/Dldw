package tasks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dldw/internal/policy/ssrf"
	"dldw/internal/server/audit"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/storage/localfs"
)

func testEngine(t *testing.T, origin http.HandlerFunc) (*Engine, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(origin)
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	exec := executor.NewBuiltin(executor.BuiltinConfig{
		Policy:  &ssrf.Policy{AllowLoopback: true, Ports: []int{port}},
		Retries: 1,
	})
	stor, err := localfs.New(localfs.Config{
		Root:       t.TempDir(),
		PublicBase: srv.URL, // presigned URLs point back at test server; only used as strings
		Secret:     []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(EngineConfig{
		TmpDir:       t.TempDir(),
		MaxRetries:   2,
		RetryBackoff: 10 * time.Millisecond,
	}, store, exec, stor, audit.New(nil))
	return eng, srv
}

const artifactPath = "/org/repo/releases/download/v1/app.tar.gz"

func artifactURLFor(srv *httptest.Server) string { return srv.URL + artifactPath }

func waitReady(t *testing.T, eng *Engine, id string, timeout time.Duration) *Task {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		task, err := eng.Task(id)
		if err == nil && task.Status == StatusReady {
			return task
		}
		if err == nil && task.Status == StatusDead {
			t.Fatalf("task died: %+v", task)
		}
		time.Sleep(10 * time.Millisecond)
	}
	task, _ := eng.Task(id)
	t.Fatalf("timeout waiting ready; task=%+v", task)
	return nil
}

func TestResolveHappyPath(t *testing.T) {
	var hits int32
	eng, srv := testEngine(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "artifact-content-0123456789")
	})

	res, err := eng.Resolve(context.Background(), artifactURLFor(srv), "tok_test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != string(StatusQueued) && res.Status != string(StatusDownloading) {
		t.Fatalf("initial status = %s", res.Status)
	}
	task := waitReady(t, eng, res.Task.ID, 5*time.Second)

	if task.Artifact == nil || task.Artifact.Size != 27 {
		t.Fatalf("artifact = %+v", task.Artifact)
	}
	if task.Artifact.StorageKey == "" || task.Artifact.SHA256 == "" {
		t.Fatalf("artifact incomplete: %+v", task.Artifact)
	}
	if hits != 1 {
		t.Fatalf("origin hits = %d, want 1", hits)
	}

	// second resolve is a cache hit: no new origin hit
	res2, err := eng.Resolve(context.Background(), artifactURLFor(srv)+"#frag", "tok_test2")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status != "cached" || res2.Download == nil || len(res2.Download.URLs) != 1 {
		t.Fatalf("cached resolve = %+v", res2)
	}
	if !res2.Download.SupportsRange || res2.Download.Mode != "presigned" {
		t.Fatalf("download = %+v", res2.Download)
	}
	if res2.Artifact.SHA256 != task.Artifact.SHA256 {
		t.Fatal("artifact drift")
	}
	if hits != 1 {
		t.Fatalf("cache miss! origin hits = %d", hits)
	}

	// object actually stored
	if _, err := eng.stor.Head(context.Background(), task.Artifact.StorageKey); err != nil {
		t.Fatalf("stored object missing: %v", err)
	}
	_ = srv
}

func TestResolveNotCacheable(t *testing.T) {
	eng, _ := testEngine(t, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := eng.Resolve(context.Background(), "https://example.com/api/items", ""); !errors.Is(err, ErrNotCacheable) {
		t.Fatalf("want ErrNotCacheable, got %v", err)
	}
	if _, err := eng.Resolve(context.Background(), "not a url", ""); err == nil {
		t.Fatal("invalid url should fail")
	}
}

func TestResolveSingleflight(t *testing.T) {
	release := make(chan struct{})
	var hits int32
	eng, srv := testEngine(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release
		fmt.Fprint(w, "data-1234567890")
	})
	const n = 8
	var wg sync.WaitGroup
	var ready, pending int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := eng.Resolve(context.Background(), artifactURLFor(srv), "tok_t")
			if err != nil {
				t.Error(err)
				return
			}
			if res.Status == "cached" {
				atomic.AddInt32(&ready, 1)
			} else {
				atomic.AddInt32(&pending, 1)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond) // let all resolve calls pile into singleflight
	close(release)
	wg.Wait()

	if hits != 1 {
		t.Fatalf("origin hits = %d, want 1 (singleflight)", hits)
	}
	if ready+pending != n {
		t.Fatalf("ready=%d pending=%d", ready, pending)
	}
}

func TestTaskRetryThenDead(t *testing.T) {
	var attempts int32
	eng, srv := testEngine(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	res, err := eng.Resolve(context.Background(), artifactURLFor(srv), "tok_t")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		task, err := eng.Task(res.Task.ID)
		if err == nil && task.Status == StatusDead {
			if task.Retries < 2 {
				t.Fatalf("retries = %d, want >= 2", task.Retries)
			}
			if task.Error == "" || task.ErrorCode == "" {
				t.Fatalf("error not recorded: %+v", task)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	task, _ := eng.Task(res.Task.ID)
	t.Fatalf("expected dead, got %+v (attempts=%d)", task, attempts)
}

func TestStorePersistenceAndTransitions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tasks.json")
	s1, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	tk := NewTask("https://github.com/x", "https://github.com/x", "kk", "github-release", "tok", 3)
	if err := s1.Put(tk); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Update(tk.ID, func(x *Task) { x.Status = StatusDownloading }); err != nil {
		t.Fatal(err)
	}
	// illegal transition must be rejected
	if _, err := s1.Update(tk.ID, func(x *Task) { x.Status = StatusReady }); err == nil {
		t.Fatal("illegal transition accepted")
	}
	// stale update ignored
	old, _ := s1.Get(tk.ID)
	old.Status = StatusDownloaded
	old.UpdatedAt = time.Now().Add(-time.Hour)
	if err := s1.Put(old); err != nil {
		t.Fatal(err)
	}
	got, _ := s1.Get(tk.ID)
	if got.Status != StatusDownloading {
		t.Fatalf("stale update applied: %s", got.Status)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := s2.Get(tk.ID)
	if err != nil || got2.Status != StatusDownloading {
		t.Fatalf("persistence lost: %+v %v", got2, err)
	}
	if _, err := s2.GetByCacheKey("kk"); err != nil {
		t.Fatal(err)
	}
	if err := s2.Delete(tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Get(tk.ID); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestRefreshNotReady(t *testing.T) {
	eng, srv := testEngine(t, func(w http.ResponseWriter, r *http.Request) {})
	res, _ := eng.Resolve(context.Background(), artifactURLFor(srv), "tok")
	if _, err := eng.Refresh(context.Background(), res.Task.ID); err == nil {
		t.Fatal("refresh before ready should fail")
	}
	waitReady(t, eng, res.Task.ID, 5*time.Second)
	rr, err := eng.Refresh(context.Background(), res.Task.ID)
	if err != nil || rr.Download == nil {
		t.Fatalf("refresh: %+v %v", rr, err)
	}
	if rr.Download.URLs[0] == "" {
		t.Fatal("empty presigned url")
	}
}

func TestGC(t *testing.T) {
	eng, srv := testEngine(t, func(w http.ResponseWriter, r *http.Request) {})
	res, _ := eng.Resolve(context.Background(), artifactURLFor(srv), "tok")
	waitReady(t, eng, res.Task.ID, 5*time.Second)
	// GC right away: tmp dir should already be empty (cleaned after ready)
	eng.GC(context.Background())
	if tasks := eng.Store().List(); len(tasks) != 1 {
		t.Fatalf("gc removed live task: %d left", len(tasks))
	}
}

var _ = storage.ErrNotFound
