package app

import (
	"sync"
	"time"

	"dldw/internal/transfer/tasks"
)

// fetchProgress 把 executor 的字节级进度实时写入任务存储。
// 设计：executor 每秒回调 update(read,total) → 后台协程每 2 秒写 store →
// 客户端轮询 GET /tasks/:id 读到 Progress 字段。
type fetchProgress struct {
	store *tasks.Store

	mu     sync.RWMutex
	taskID string // 当前活跃任务（由 Begin/End 设置）
	read   int64
	total  int64
}

// update 由 executor 的 ProgressFunc 每秒调用。
func (p *fetchProgress) update(read, total int64) {
	p.mu.Lock()
	p.read = read
	p.total = total
	p.mu.Unlock()
}

// Begin 标记开始抓取某任务（由引擎在 Fetch 前调用）。
func (p *fetchProgress) Begin(taskID string) {
	p.mu.Lock()
	p.taskID = taskID
	p.read = 0
	p.total = 0
	p.mu.Unlock()
}

// End 标记抓取结束。
func (p *fetchProgress) End() {
	p.mu.Lock()
	p.taskID = ""
	p.mu.Unlock()
}

// loop 后台协程：把进度写入任务存储。
func (p *fetchProgress) loop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for range tick.C {
		p.mu.RLock()
		id := p.taskID
		read := p.read
		total := p.total
		p.mu.RUnlock()
		if id == "" || total <= 0 {
			continue
		}
		pct := float64(read) / float64(total)
		if pct > 0.99 {
			pct = 0.99
		}
		if pct <= 0 {
			continue
		}
		p.store.Update(id, func(t *tasks.Task) {
			if t.Status == tasks.StatusDownloading && pct > t.Progress {
				t.Progress = pct
			}
		})
	}
}
