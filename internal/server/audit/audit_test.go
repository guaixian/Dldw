package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogJSON(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log("tunnel_open", "conn_abc123", "host", "github.com", "bytes_out", 1024)
	line := strings.TrimSpace(buf.String())
	if !strings.Contains(line, `"kind":"tunnel_open"`) ||
		!strings.Contains(line, `"id":"conn_abc123"`) ||
		!strings.Contains(line, `"host":"github.com"`) ||
		!strings.Contains(line, `"bytes_out":1024`) {
		t.Fatalf("bad line: %s", line)
	}
	if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
		t.Fatalf("not json: %s", line)
	}
}

func TestRedactURL(t *testing.T) {
	got := RedactURL("https://objects.githubusercontent.com/x.zip?token=SECRET&sig=other")
	if strings.Contains(got, "SECRET") || strings.Contains(got, "other") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !strings.Contains(got, "token=<redacted>") || !strings.Contains(got, "sig=<redacted>") {
		t.Fatalf("keys lost: %s", got)
	}
	if RedactURL("https://example.com/plain") != "https://example.com/plain" {
		t.Fatal("plain URL should pass through")
	}
}
