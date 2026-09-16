// Package auth manages device tokens (register/validate/refresh/revoke) and
// tunnel nonce replay protection (spec 4.1, 5).
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dldw/internal/ids"
)

var (
	ErrInvalidToken = errors.New("auth: invalid token")
	ErrRevoked      = errors.New("auth: token revoked")
	ErrExpired      = errors.New("auth: token expired")
)

// Record is a persisted device token. Only the hash is stored, never the
// secret itself.
type Record struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

func (r *Record) Active() bool {
	return r.RevokedAt.IsZero() && (r.ExpiresAt.IsZero() || time.Now().Before(r.ExpiresAt))
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// Store is a file backed token store.
type Store struct {
	mu       sync.RWMutex
	path     string
	records  map[string]*Record // by ID
	byHash   map[string]*Record // by token hash
	ttl      time.Duration
	nowFunc  func() time.Time
	saveBack bool
}

func NewStore(path string, ttl time.Duration) (*Store, error) {
	s := &Store{
		path:    path,
		records: map[string]*Record{},
		byHash:  map[string]*Record{},
		ttl:     ttl,
		nowFunc: time.Now,
	}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return s, nil // degrade to memory-only if dir cannot be made
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var recs []*Record
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	for _, r := range recs {
		cp := r
		s.records[cp.ID] = cp
		s.byHash[cp.TokenHash] = cp
	}
	return s, nil
}

// Register issues a new token for clientID and returns the secret once.
func (s *Store) Register(clientID string) (*Record, string, error) {
	if clientID == "" {
		clientID = ids.NewClientID()
	}
	tok := ids.NewToken()
	now := s.nowFunc()
	rec := &Record{
		ID:        ids.NewTokenID(),
		ClientID:  clientID,
		TokenHash: hashToken(tok),
		CreatedAt: now,
	}
	if s.ttl > 0 {
		rec.ExpiresAt = now.Add(s.ttl)
	}
	s.mu.Lock()
	s.records[rec.ID] = rec
	s.byHash[rec.TokenHash] = rec
	err := s.saveLocked()
	s.mu.Unlock()
	return rec, tok, err
}

// Validate checks a token and returns its record, updating last seen.
func (s *Store) Validate(token string) (*Record, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}
	h := hashToken(token)
	s.mu.Lock()
	rec, ok := s.byHash[h]
	if !ok {
		s.mu.Unlock()
		return nil, ErrInvalidToken
	}
	if !rec.RevokedAt.IsZero() {
		s.mu.Unlock()
		return rec, ErrRevoked
	}
	if !rec.ExpiresAt.IsZero() && s.nowFunc().After(rec.ExpiresAt) {
		s.mu.Unlock()
		return rec, ErrExpired
	}
	rec.LastSeen = s.nowFunc()
	needSave := s.saveBack
	var err error
	if needSave {
		err = s.saveLocked()
	}
	s.mu.Unlock()
	return rec, err
}

// Refresh rotates the secret of a valid token, returning the new secret.
func (s *Store) Refresh(token string) (*Record, string, error) {
	rec, err := s.Validate(token)
	if err != nil {
		return nil, "", err
	}
	newTok := ids.NewToken()
	s.mu.Lock()
	delete(s.byHash, rec.TokenHash)
	rec.TokenHash = hashToken(newTok)
	rec.ExpiresAt = time.Time{}
	if s.ttl > 0 {
		rec.ExpiresAt = time.Now().Add(s.ttl)
	}
	s.byHash[rec.TokenHash] = rec
	err = s.saveLocked()
	s.mu.Unlock()
	return rec, newTok, err
}

// Revoke invalidates a token.
func (s *Store) Revoke(token string) error {
	h := hashToken(token)
	s.mu.Lock()
	rec, ok := s.byHash[h]
	if !ok {
		s.mu.Unlock()
		return ErrInvalidToken
	}
	rec.RevokedAt = time.Now()
	err := s.saveLocked()
	s.mu.Unlock()
	return err
}

// Count returns the number of stored records.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// KeepDirtyPersistence enables last-seen persistence (off by default to avoid
// write amplification on every request).
func (s *Store) KeepDirtyPersistence() { s.saveBack = true }

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	recs := make([]*Record, 0, len(s.records))
	for _, r := range s.records {
		recs = append(recs, r)
	}
	buf, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// NonceStore provides replay protection for tunnel handshakes keyed by
// (token_id, nonce) with TTL eviction.
type NonceStore struct {
	mu     sync.Mutex
	ttl    time.Duration
	seen   map[string]time.Time
	maxMem int
}

func NewNonceStore(ttl time.Duration) *NonceStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &NonceStore{ttl: ttl, seen: map[string]time.Time{}, maxMem: 1 << 20}
}

// CheckAndAdd returns false when nonce was already seen for tokenID.
func (n *NonceStore) CheckAndAdd(tokenID, nonce string) bool {
	key := tokenID + "/" + nonce
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.seen) >= n.maxMem {
		for k, t := range n.seen {
			if now.Sub(t) > n.ttl {
				delete(n.seen, k)
			}
		}
		if len(n.seen) >= n.maxMem {
			n.seen = map[string]time.Time{} // hard reset over unbounded growth
		}
	}
	if _, dup := n.seen[key]; dup {
		return false
	}
	n.seen[key] = now
	return true
}

// BearerToken extracts a token from an Authorization header value.
func BearerToken(header string) string {
	header = strings.TrimSpace(header)
	for _, prefix := range []string{"Bearer ", "bearer ", "token "} {
		if strings.HasPrefix(header, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(header, prefix))
		}
	}
	return ""
}
