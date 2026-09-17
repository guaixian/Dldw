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
	"strings"
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
	return f.PresignOrFetchMulti(ctx, canonical, []string{canonical}, family, createdBy)
}

// PresignOrFetchMulti 多上游故障转移版：按顺序尝试 candidates（学 verdaccio
// 的 uplinks 语义），第一个成功者胜出；缓存键始终取 canonical（主源地址，
// 保证多实例/多入口命中同一对象）。全部失败时返回最后一个错误。
func (f *Fetcher) PresignOrFetchMulti(ctx context.Context, canonical string, candidates []string, family, createdBy string) (string, error) {
	if len(candidates) == 0 {
		candidates = []string{canonical}
	}
	cacheKey := urlcanon.CacheKey(canonical, family)
	if t, err := f.Store.GetByCacheKey(cacheKey); err == nil && t.Status == tasks.StatusReady && t.Artifact != nil {
		return f.Stor.PresignGet(ctx, t.Artifact.StorageKey, f.PresignTTL)
	}
	key := tasks.StorageKeyFor(family, cacheKey)
	dir := filepath.Join(f.TmpDir, family, cacheKey[:8])
	defer os.RemoveAll(dir)

	var lastErr error
	for _, candidate := range candidates {
		res, err := f.Exec.Fetch(ctx, candidate, dir, path.Base(candidate))
		if err != nil {
			lastErr = fmt.Errorf("[%s]: %w", originLabel(candidate), err)
			continue // 尝试下一个源
		}
		fp, err := os.Open(res.LocalPath)
		if err != nil {
			lastErr = err
			continue
		}
		obj, err := f.Stor.Put(ctx, key, fp, res.Size, res.ContentType)
		fp.Close()
		if err != nil {
			lastErr = fmt.Errorf("store: %w", err)
			continue
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
	return "", fmt.Errorf("all %d origins failed; last: %v", len(candidates), lastErr)
}

// originLabel 提取候选源的主机名用于报错（脱敏 query）。
func originLabel(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return u
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
