package presign

import (
	"strconv"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	exp := time.Now().Add(time.Minute)
	sig := Sign(secret, "GET", "ab/cd.bin", exp)

	cases := []struct {
		method, key, exp, sig string
		want                  error
	}{
		{"GET", "ab/cd.bin", strconv.FormatInt(exp.Unix(), 10), sig, nil},
		{"GET", "ab/cd.bin", strconv.FormatInt(exp.Unix(), 10), "deadbeef", ErrBadSignature},
		{"PUT", "ab/cd.bin", strconv.FormatInt(exp.Unix(), 10), sig, ErrBadSignature},
		{"GET", "other", strconv.FormatInt(exp.Unix(), 10), sig, ErrBadSignature},
		{"GET", "ab/cd.bin", "notanumber", sig, ErrMalformed},
		{"GET", "ab/cd.bin", "", sig, ErrMalformed},
	}
	for i, c := range cases {
		if got := Verify(secret, c.method, c.key, c.exp, c.sig); got != c.want {
			t.Errorf("case %d: Verify = %v, want %v", i, got, c.want)
		}
	}

	past := time.Now().Add(-2 * time.Second)
	oldSig := Sign(secret, "GET", "ab/cd.bin", past)
	if got := Verify(secret, "GET", "ab/cd.bin", strconv.FormatInt(past.Unix(), 10), oldSig); got != ErrExpired {
		t.Errorf("expired: Verify = %v, want %v", got, ErrExpired)
	}

	// different secret must fail
	if got := Verify([]byte("another-secret!!"), "GET", "ab/cd.bin", strconv.FormatInt(exp.Unix(), 10), sig); got != ErrBadSignature {
		t.Errorf("wrong secret: Verify = %v, want %v", got, ErrBadSignature)
	}
}
