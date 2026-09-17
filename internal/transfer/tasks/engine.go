package tasks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dldw/internal/server/audit"
	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/urlcanon"
)

// ErrNotCacheable is returned when a URL does not map to a cacheable
// static artifact family (spec 4.3).
var ErrNotCacheable = errors.New("resolve: url is not a recognized cacheable static artifact")

// Download describes how the client should fetch a ready artifact.
type Download struct {
	Mode           string    `json:"mode"`
	URLs           []string  `json:"urls"`
	ExpiresAt      time.Time `json:"expires_at"`
	SupportsRange  bool      `json:"supports_range"`
}

// ResolveResult is the payload of POST /api/v1/resolve (spec 4.1).
type ResolveResult struct {
	RequestID string     `json:"-"` // set by API layer
	Status    string     `json:"status"`
	CacheKey  string     `json:"cache_key"`
	Artifact  *Artifact  `json:"artifact,omitempty"`
	Download  *Download  `json:"download,omitempty"`
	Task      *Task      `json:"task,omitempty"`
}

// EngineConfig tunes the resolve engine.
type EngineConfig struct {
	TmpDir       string
	PresignTTL   time.Duration // default 15m
	MaxRetries   int           // default 3
	RetryBackoff time.Duration // default 2s
	GCAge        time.Duration // tmp file age before GC, default 1h
	// FetchFunc allows the app layer to hook around the executor's Fetch
	// call (e.g. to set/clear progress tracking). Called as:
	//   begin(taskID) → exec.Fetch(...) → end()
	BeginFetch func(taskID string)
	EndFetch   func()
}

func (c EngineConfig) withDefaults() EngineConfig {
	if c.PresignTTL <= 0 {
		c.PresignTTL = 15 * time.Minute
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 3
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = 2 * time.Second
	}
	if c.GCAge <= 0 {
		c.GCAge = time.Hour
	}
	if c.TmpDir == "" {
		c.TmpDir = filepath.Join(os.TempDir(), "dldw-tasks")
	}
	return c
}

// Engine coordinates resolve/fetch/upload/register with singleflight
// deduplication per cache key.
type Engine struct {
	cfg   EngineConfig
	store *Store
	exec  executor.Executor
	stor  storage.Storage
	sf    *singleflight
	log   *audit.Logger

	mu         chan struct{} // semaphore
	processing map[string]bool
	pmu        chan struct{}
}

func NewEngine(cfg EngineConfig, store *Store, exec executor.Executor, stor storage.Storage, log *audit.Logger) *Engine {
	if store == nil {
		store, _ = NewStore("")
	}
	return &Engine{
		cfg:        cfg.withDefaults(),
		store:      store,
		exec:       exec,
		stor:       stor,
		sf:         newSingleflight(),
		log:        log,
		mu:         make(chan struct{}, 1),
		processing: map[string]bool{},
		pmu:        make(chan struct{}, 1),
	}
}

func (e *Engine) Store() *Store { return e.store }

// objectKey maps a cache key to a storage object path.
func objectKey(family, cacheKey string) string {
	return StorageKeyFor(family, cacheKey)
}

// StorageKeyFor 计算 cache key 的存储对象路径（client/server/pypi 镜像共用，
// 保证不同入口写入/读取同一对象）。
func StorageKeyFor(family, cacheKey string) string {
	if len(cacheKey) < 4 {
		return fmt.Sprintf("cache/%s/%s.bin", family, cacheKey)
	}
	return fmt.Sprintf("cache/%s/%s/%s/%s.bin", family, cacheKey[:2], cacheKey[2:4], cacheKey)
}

// StorageKeyForObject is the inverse lookup helper for API refresh.
func (e *Engine) StorageKey(t *Task) string { return objectKey(t.Family, t.CacheKey) }

func hintName(canonicalURL string) string {
	path := canonicalURL
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	base := filepath.Base(strings.ReplaceAll(path, "\\", "/"))
	if base == "" || base == "/" || base == "." {
		return "artifact.bin"
	}
	return base
}

// Resolve looks up or creates a cache task for rawURL. Concurrent calls with
// the same cache key are deduplicated (singleflight).
func (e *Engine) Resolve(ctx context.Context, rawURL, createdBy string) (*ResolveResult, error) {
	canonical, family, cacheKey, err := urlcanon.FamilyOfRaw(rawURL)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	if family == "" {
		return nil, ErrNotCacheable
	}
	v, err := e.sf.Do(cacheKey, func() (any, error) {
		if t, gerr := e.store.GetByCacheKey(cacheKey); gerr == nil {
			switch t.Status {
			case StatusReady:
				return e.readyResult(ctx, t)
			case StatusQueued, StatusDownloading, StatusDownloaded, StatusUploading, StatusRegistering:
				return &ResolveResult{Status: string(t.Status), CacheKey: cacheKey, Task: t}, nil
			case StatusFailed:
				if t.Retries < t.MaxRetries {
					nt, uerr := e.store.Update(t.ID, func(x *Task) {
						x.Status = StatusDownloading
						x.Error = ""
						x.Progress = 0.02
					})
					if uerr == nil {
						go e.process(nt.ID)
						return &ResolveResult{Status: string(StatusDownloading), CacheKey: cacheKey, Task: nt}, nil
					}
				}
				// fall through: create a fresh task
			case StatusDead:
				// create a fresh task
			}
		}
		t := NewTask(rawURL, canonical, cacheKey, family, createdBy, e.cfg.MaxRetries)
		if perr := e.store.Put(t); perr != nil {
			return nil, perr
		}
		go e.process(t.ID)
		return &ResolveResult{Status: string(StatusQueued), CacheKey: cacheKey, Task: t}, nil
	})
	if err != nil {
		return nil, err
	}
	res, ok := v.(*ResolveResult)
	if !ok {
		return nil, errors.New("resolve: internal type error")
	}
	return res, nil
}

// Task fetches a task by ID.
func (e *Engine) Task(id string) (*Task, error) { return e.store.Get(id) }

// Refresh re-presigns the download URL of a ready task.
func (e *Engine) Refresh(ctx context.Context, id string) (*ResolveResult, error) {
	t, err := e.store.Get(id)
	if err != nil {
		return nil, err
	}
	if t.Status != StatusReady || t.Artifact == nil {
		return nil, fmt.Errorf("refresh: task %s not ready", id)
	}
	return e.readyResult(ctx, t)
}

func (e *Engine) readyResult(ctx context.Context, t *Task) (*ResolveResult, error) {
	key := objectKey(t.Family, t.CacheKey)
	urls := make([]string, 0, 1)
	u, err := e.stor.PresignGet(ctx, key, e.cfg.PresignTTL)
	if err != nil {
		return nil, fmt.Errorf("presign: %w", err)
	}
	urls = append(urls, u)
	if t.Artifact.StorageKey != "" {
		key = t.Artifact.StorageKey
	}
	return &ResolveResult{
		Status:   "cached",
		CacheKey: t.CacheKey,
		Artifact: t.Artifact,
		Download: &Download{
			Mode:          "presigned",
			URLs:          urls,
			ExpiresAt:     time.Now().Add(e.cfg.PresignTTL),
			SupportsRange: true,
		},
		Task: t,
	}, nil
}

// process drives one task through the state machine, retrying internally
// until ready or dead.
func (e *Engine) process(taskID string) {
	e.pmu <- struct{}{}
	if e.processing[taskID] {
		<-e.pmu
		return
	}
	e.processing[taskID] = true
	<-e.pmu
	defer func() {
		e.pmu <- struct{}{}
		delete(e.processing, taskID)
		<-e.pmu
	}()

	t, err := e.store.Get(taskID)
	if err != nil {
		return
	}
	dir := filepath.Join(e.cfg.TmpDir, t.ID)
	defer func() {
		if t != nil && (t.Status == StatusReady || t.Status == StatusDead) {
			os.RemoveAll(dir)
		}
	}()

	e.log.Log("task_start", t.ID, "cache_key", t.CacheKey, "family", t.Family, "url", audit.RedactURL(t.URL))

	// 进度钩子：让 app 层知道当前在抓哪个任务
	if e.cfg.BeginFetch != nil {
		e.cfg.BeginFetch(t.ID)
	}

	for {
		// queued|failed -> downloading
		if t.Status == StatusQueued || t.Status == StatusFailed {
			if t, err = e.store.Update(t.ID, func(x *Task) {
				x.Status = StatusDownloading
				x.Error = ""
				x.Progress = 0.05
			}); err != nil {
				return
			}
		} else if t.Status != StatusDownloading {
			return
		}

		res, ferr := e.exec.Fetch(context.Background(), t.URL, dir, hintName(t.CanonicalURL))
		if ferr != nil {
			if t, err = e.fail(t, ferr); err != nil || t.Status == StatusDead {
				return
			}
			time.Sleep(time.Duration(t.Retries) * e.cfg.RetryBackoff)
			continue
		}

		// downloading -> downloaded -> uploading
		if t, err = e.store.Update(t.ID, func(x *Task) { x.Status = StatusDownloaded; x.Progress = 0.5 }); err != nil {
			return
		}
		if t, err = e.store.Update(t.ID, func(x *Task) { x.Status = StatusUploading; x.Progress = 0.6 }); err != nil {
			return
		}

		key := objectKey(t.Family, t.CacheKey)
		f, oerr := os.Open(res.LocalPath)
		if oerr != nil {
			if t, err = e.fail(t, oerr); err != nil || t.Status == StatusDead {
				return
			}
			time.Sleep(time.Duration(t.Retries) * e.cfg.RetryBackoff)
			continue
		}
		obj, uerr := e.stor.Put(context.Background(), key, f, res.Size, res.ContentType)
		f.Close()
		if uerr != nil {
			if t, err = e.fail(t, fmt.Errorf("upload: %w", uerr)); err != nil || t.Status == StatusDead {
				return
			}
			time.Sleep(time.Duration(t.Retries) * e.cfg.RetryBackoff)
			continue
		}

		// uploading -> registering -> ready
		if t, err = e.store.Update(t.ID, func(x *Task) { x.Status = StatusRegistering; x.Progress = 0.9 }); err != nil {
			return
		}
		art := &Artifact{
			Size:        obj.Size,
			SHA256:      res.SHA256,
			ETag:        obj.ETag,
			ContentType: res.ContentType,
			StorageKey:  key,
		}
		if t, err = e.store.Update(t.ID, func(x *Task) { x.Artifact = art; x.Status = StatusReady; x.Progress = 1.0 }); err != nil {
			return
		}
		e.log.Log("task_ready", t.ID, "cache_key", t.CacheKey, "size", art.Size, "sha256", art.SHA256)
		if e.cfg.EndFetch != nil {
			e.cfg.EndFetch()
		}
		return
	}
}

// fail records a failure via the legal two-step path (active -> failed,
// optionally failed -> dead) and returns the updated task.
func (e *Engine) fail(t *Task, err error) (*Task, error) {
	retries := t.Retries + 1
	e.log.Log("task_fail", t.ID, "cache_key", t.CacheKey, "retries", retries, "error", err.Error())

	nt, uerr := e.store.Update(t.ID, func(x *Task) {
		x.Status = StatusFailed
		x.Error = err.Error()
		x.ErrorCode = "E_TASK_FAILED"
		x.Retries = retries
	})
	if uerr != nil {
		return nil, uerr
	}
	if retries > t.MaxRetries {
		return e.store.Update(t.ID, func(x *Task) { x.Status = StatusDead })
	}
	return nt, nil
}

// GC removes orphan temp directories and long dead tasks.
func (e *Engine) GC(ctx context.Context) (files, tasks int) {
	entries, err := os.ReadDir(e.cfg.TmpDir)
	if err == nil {
		cut := time.Now().Add(-e.cfg.GCAge)
		for _, en := range entries {
			if info, ierr := en.Info(); ierr == nil && info.ModTime().Before(cut) {
				if rerr := os.RemoveAll(filepath.Join(e.cfg.TmpDir, en.Name())); rerr == nil {
					files++
				}
			}
		}
	}
	for _, t := range e.store.List() {
		if (t.Status == StatusDead || t.Status == StatusFailed) && time.Since(t.UpdatedAt) > 24*time.Hour {
			if e.store.Delete(t.ID) == nil {
				tasks++
			}
		}
	}
	e.log.Log("gc", "", "files_removed", files, "tasks_removed", tasks)
	return files, tasks
}
