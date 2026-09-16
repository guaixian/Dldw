package tasks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"dldw/internal/ids"
)

var (
	ErrNotFound = errors.New("tasks: not found")
	ErrConflict = errors.New("tasks: state conflict")
)

// Artifact describes the immutable cached object of a ready task.
type Artifact struct {
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256,omitempty"`
	ETag        string `json:"etag,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	StorageKey  string `json:"storage_key,omitempty"`
}

// Task is a cache job persisted across restarts.
type Task struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`          // original request URL
	CanonicalURL string    `json:"canonical_url"`
	CacheKey     string    `json:"cache_key"`
	Family       string    `json:"family"`
	Status       Status    `json:"status"`
	Progress     float64   `json:"progress"` // 0..1 coarse grained
	Error        string    `json:"error,omitempty"`
	ErrorCode    string    `json:"error_code,omitempty"`
	Retries      int       `json:"retries"`
	MaxRetries   int       `json:"max_retries"`
	Artifact     *Artifact `json:"artifact,omitempty"`
	CreatedBy    string    `json:"created_by,omitempty"` // token id
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Clone returns a deep copy safe for concurrent readers.
func (t *Task) Clone() *Task {
	cp := *t
	if t.Artifact != nil {
		a := *t.Artifact
		cp.Artifact = &a
	}
	return &cp
}

// Store persists tasks. It is safe for concurrent use. File persistence is
// atomic (write temp + rename) and reloads on start.
type Store struct {
	mu      sync.Mutex
	path    string
	byID    map[string]*Task
	byKey   map[string]*Task // cache_key -> latest task
	persist bool
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, byID: map[string]*Task{}, byKey: map[string]*Task{}}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var list []*Task
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("tasks: parse %s: %w", path, err)
	}
	for _, t := range list {
		cp := t.Clone()
		s.byID[cp.ID] = cp
		if prev, ok := s.byKey[cp.CacheKey]; !ok || cp.UpdatedAt.After(prev.UpdatedAt) {
			s.byKey[cp.CacheKey] = cp
		}
	}
	return s, nil
}

// Put inserts or replaces a task by ID (transition legality enforced).
func (s *Store) Put(t *Task) error {
	if t.ID == "" || t.CacheKey == "" {
		return fmt.Errorf("tasks: id and cache_key required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byID[t.ID]; ok {
		if err := ValidateTransition(old.Status, t.Status); err != nil && old.Status != t.Status {
			return err
		}
		if t.UpdatedAt.Before(old.UpdatedAt) {
			return nil // stale update, ignore
		}
	}
	cp := t.Clone()
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = time.Now()
	s.byID[cp.ID] = cp
	s.byKey[cp.CacheKey] = cp
	return s.persistLocked()
}

// Update applies fn to a stored task and saves it. fn operates on a copy; an
// illegal transition aborts with no partial mutation.
func (s *Store) Update(id string, fn func(*Task)) (*Task, error) {
	s.mu.Lock()
	t, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	cp := t.Clone()
	fn(cp)
	if err := ValidateTransition(t.Status, cp.Status); err != nil && t.Status != cp.Status {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	cp.UpdatedAt = time.Now()
	s.byID[cp.ID] = cp
	s.byKey[cp.CacheKey] = cp
	err := s.persistLocked()
	s.mu.Unlock()
	return cp.Clone(), err
}

// Get returns a copy of the task by ID.
func (s *Store) Get(id string) (*Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return t.Clone(), nil
}

// GetByCacheKey returns the newest task for cacheKey.
func (s *Store) GetByCacheKey(cacheKey string) (*Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byKey[cacheKey]
	if !ok {
		return nil, ErrNotFound
	}
	return t.Clone(), nil
}

// List returns all tasks sorted by creation time (newest first).
func (s *Store) List() []*Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Task, 0, len(s.byID))
	for _, t := range s.byID {
		out = append(out, t.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Delete removes a task by ID.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.byID, id)
	if s.byKey[t.CacheKey] != nil && s.byKey[t.CacheKey].ID == id {
		delete(s.byKey, t.CacheKey)
	}
	return s.persistLocked()
}

// NewTask constructs a queued task.
func NewTask(rawURL, canonicalURL, cacheKey, family, createdBy string, maxRetries int) *Task {
	now := time.Now()
	return &Task{
		ID:           ids.NewTaskID(),
		URL:          rawURL,
		CanonicalURL: canonicalURL,
		CacheKey:     cacheKey,
		Family:       family,
		Status:       StatusQueued,
		MaxRetries:   maxRetries,
		CreatedBy:    createdBy,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]*Task, 0, len(s.byID))
	for _, t := range s.byID {
		list = append(list, t)
	}
	buf, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
