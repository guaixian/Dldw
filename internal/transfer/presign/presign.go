// Package presign implements HMAC based URL signing for the local filesystem
// storage driver, mirroring the short-lived presigned URL semantics of S3.
package presign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var ErrExpired = errors.New("presign: url expired")
var ErrBadSignature = errors.New("presign: bad signature")
var ErrMalformed = errors.New("presign: malformed url")

// Sign computes the hex HMAC signature over method/key/expiry.
func Sign(secret []byte, method, key string, expires time.Time) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%s\n%s\n%d", method, key, expires.Unix())
	return hex.EncodeToString(mac.Sum(nil))
}

// Query returns the query string "exp=...&sig=..." to append to an object URL.
func Query(secret []byte, method, key string, expires time.Time) string {
	return "exp=" + strconv.FormatInt(expires.Unix(), 10) + "&sig=" + Sign(secret, method, key, expires)
}

// Verify checks exp/sig query values for method/key.
func Verify(secret []byte, method, key, exp, sig string) error {
	unix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return ErrMalformed
	}
	if time.Now().Unix() > unix {
		return ErrExpired
	}
	if !hmac.Equal([]byte(sig), []byte(Sign(secret, method, key, time.Unix(unix, 0)))) {
		return ErrBadSignature
	}
	return nil
}
