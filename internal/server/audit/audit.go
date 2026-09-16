// Package audit writes structured JSON lines for observability: every event
// carries request_id or conn_id, status codes, byte counts and durations.
// URL query values are redacted by default (spec 5).
package audit

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Time string `json:"ts"`
	Kind string `json:"kind"`
	// RequestID or ConnID depending on event source.
	ID      string         `json:"id,omitempty"`
	TokenID string         `json:"token_id,omitempty"`
	Detail  map[string]any `json:"-"`
}

// Logger serializes events to a writer.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

func New(w io.Writer) *Logger {
	if w == nil {
		w = io.Discard
	}
	return &Logger{w: w}
}

func NewFile(path string) (*Logger, io.Closer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return New(f), f, nil
}

// Log emits one event. kv is a flat list of key/value pairs.
func (l *Logger) Log(kind, id string, kv ...any) {
	if l == nil {
		return
	}
	if len(kv)%2 != 0 {
		kv = append(kv, "")
	}
	detail := make(map[string]any, len(kv)/2+1)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			k = "field"
		}
		detail[k] = kv[i+1]
	}
	line := map[string]any{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"kind": kind,
	}
	if id != "" {
		line["id"] = id
	}
	for k, v := range detail {
		line[k] = v
	}
	buf, err := json.Marshal(line)
	if err != nil {
		buf = []byte(`{"kind":"audit_marshal_error"}`)
	}
	l.mu.Lock()
	l.w.Write(append(buf, '\n'))
	l.mu.Unlock()
}

// RedactURL removes query parameter values, keeping parameter names, and
// truncates very long URLs.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable>"
	}
	q := u.Query()
	if len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		for i := 1; i < len(keys); i++ {
			for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
				keys[j], keys[j-1] = keys[j-1], keys[j]
			}
		}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"=<redacted>")
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	s := u.String()
	if len(s) > 512 {
		s = s[:509] + "..."
	}
	return s
}
