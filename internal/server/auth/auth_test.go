package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTokenLifecycle(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "tokens.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec, tok, err := s.Register("dev_test")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ClientID != "dev_test" || tok == "" {
		t.Fatalf("bad register: %+v %q", rec, tok)
	}
	got, err := s.Validate(tok)
	if err != nil || got.ID != rec.ID {
		t.Fatalf("validate: %+v %v", got, err)
	}
	if _, err := s.Validate(tok + "x"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	// refresh
	_, tok2, err := s.Refresh(tok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("old token must die after refresh")
	}
	if _, err := s.Validate(tok2); err != nil {
		t.Fatalf("new token invalid: %v", err)
	}
	// revoke
	if err := s.Revoke(tok2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(tok2); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("count = %d, want 1", s.Count())
	}
}

func TestTokenPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "tokens.json")
	s, err := NewStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, tok, _ := s.Register("dev_a")
	// reopen
	s2, err := NewStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Validate(tok); err != nil {
		t.Fatalf("token should survive restart: %v", err)
	}
}

func TestTokenExpiry(t *testing.T) {
	s, _ := NewStore("", 50*time.Millisecond)
	_, tok, _ := s.Register("dev_b")
	if _, err := s.Validate(tok); err != nil {
		t.Fatal(err)
	}
	time.Sleep(70 * time.Millisecond)
	if _, err := s.Validate(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestNonceStore(t *testing.T) {
	n := NewNonceStore(time.Minute)
	if !n.CheckAndAdd("tok1", "abc") {
		t.Fatal("first use denied")
	}
	if n.CheckAndAdd("tok1", "abc") {
		t.Fatal("replay accepted")
	}
	if !n.CheckAndAdd("tok2", "abc") {
		t.Fatal("other token same nonce denied")
	}
}

func TestBearerToken(t *testing.T) {
	if BearerToken("Bearer abc") != "abc" {
		t.Fatal("bearer parse failed")
	}
	if BearerToken("bearer abc") != "abc" {
		t.Fatal("lowercase bearer")
	}
	if BearerToken("Basic xyz") != "" {
		t.Fatal("non-bearer should be empty")
	}
	if BearerToken("") != "" {
		t.Fatal("empty should be empty")
	}
}
