// Package mirrorcore 抽取拉穿镜像的公共核心：命中预签名 / 未命中抓取入库
// 并登记 ready 任务 / singleflight 并发去重。pypi、npm、webmirror、gomod
// 四个镜像共用，保证行为一致且与 `dldw get` 共享存储键。
package mirrorcore

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"dldw/internal/transfer/executor"
	"dldw/internal/transfer/storage"
	"dldw/internal/transfer/tasks"
	"dldw/internal/urlcanon"
)

// Fetcher 封装“预签名或抓取入库”流程。
type Fetcher struct {
	Stor       storage.Storage
	Exec       executor.Executor
	Store      *tasks.Store
	TmpDir     string
	PresignTTL time.Duration
}

// PresignOrFetch 返回 canonical 的预签名 URL：
// 已有 ready 任务 -> 直接预签名；未命中 -> 抓取入库 + 登记 ready 任务。
// createdBy 用于审计区分镜像入口（pypi-mirror/npm-mirror/web-mirror/gomod-mirror）。
func (f *Fetcher) PresignOrFetch(ctx context.Context, canonical, family, createdBy string) (string, error) {
	cacheKey := urlcanon.CacheKey(canonical, family)
	if t, err := f.Store.GetByCacheKey(cacheKey); err == nil && t.Status == tasks.StatusReady && t.Artifact != nil {
		return f.Stor.PresignGet(ctx, t.Artifact.StorageKey, f.PresignTTL)
	}
	key := tasks.StorageKeyFor(family, cacheKey)
	dir := filepath.Join(f.TmpDir, family, cacheKey[:8])
	defer os.RemoveAll(dir)
	res, err := f.Exec.Fetch(ctx, canonical, dir, path.Base(canonical))
	if err != nil {
		return "", fmt.Errorf("origin fetch: %w", err)
	}
	fp, err := os.Open(res.LocalPath)
	if err != nil {
		return "", err
	}
	obj, err := f.Stor.Put(ctx, key, fp, res.Size, res.ContentType)
	fp.Close()
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	task := tasks.NewTask(canonical, canonical, cacheKey, family, createdBy, 0)
	task.Status = tasks.StatusReady
	task.Progress = 1
	task.Artifact = &tasks.Artifact{
		Size:        obj.Size,
		SHA256:      res.SHA256,
		ETag:        obj.ETag,
		ContentType: res.ContentType,
		StorageKey:  key,
	}
	if err := f.Store.Put(task); err != nil {
		return "", err
	}
	return f.Stor.PresignGet(ctx, key, f.PresignTTL)
}

// Group 是极简 singleflight（并发同 key 只执行一次）。
type Group struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	wg  sync.WaitGroup
	val any
	err error
}

// NewGroup 构造。
func NewGroup() *Group { return &Group{m: map[string]*call{}} }

// Do 执行 fn（同 key 并发共享首个结果）。
func (g *Group) Do(key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &call{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.val, c.err
}
