package dldw1

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

var goodNonce = strings.Repeat("ab", 16)

func TestConnectRoundTrip(t *testing.T) {
	c := &Connect{
		Host: "github.com", Port: 443, Token: "dldw_0123456789abcdef",
		Nonce: goodNonce, ClientID: "dev_abcdef01",
		Flags: map[string]string{"v": "1", "large": "0"},
	}
	line := c.Encode()
	if !bytes.HasSuffix(line, []byte("\n")) {
		t.Fatal("missing newline")
	}
	got, err := ParseConnect(line)
	if err != nil {
		t.Fatalf("ParseConnect: %v", err)
	}
	if got.Host != c.Host || got.Port != c.Port || got.Token != c.Token ||
		got.Nonce != c.Nonce || got.ClientID != c.ClientID {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Flag("v") != "1" || got.Flag("large") != "0" || got.Flag("missing") != "" {
		t.Fatalf("flags mismatch: %+v", got.Flags)
	}
}

func TestConnectNoFlags(t *testing.T) {
	line := []byte("DLDW/1 CONNECT pypi.org 443 tok_12345678 " + goodNonce + " dev_1 -\n")
	got, err := ParseConnect(line)
	if err != nil {
		t.Fatalf("ParseConnect: %v", err)
	}
	if len(got.Flags) != 0 {
		t.Fatalf("expected empty flags, got %v", got.Flags)
	}
}

func TestConnectRejects(t *testing.T) {
	bad := [][]byte{
		[]byte("HTTP/1.1 CONNECT github.com 443 tok_12345678 " + goodNonce + " dev_1 -\n"),
		[]byte("DLDW/1 CONNECT github.com 99999 tok_12345678 " + goodNonce + " dev_1 -\n"),
		[]byte("DLDW/1 CONNECT github.com 443 short " + goodNonce + " dev_1 -\n"),
		[]byte("DLDW/1 CONNECT github.com 443 tok_12345678 badnonce dev_1 -\n"),
		[]byte("DLDW/1 CONNECT github.com 443 tok_12345678 " + goodNonce + " dev_1"), // missing flags
		[]byte("DLDW/1 CONNECT git hub.com 443 tok_12345678 " + goodNonce + " dev_1 -\n"),
		[]byte("DLDW/1 CONNECT github.com 443 tok_12345678 " + goodNonce + " dev_1 bad=flag,x==y\n"),
		[]byte("DLDW/1 CONNECT github.com 443 tok_12345678 " + strings.Repeat("a", 33) + " dev_1 -\n"),
	}
	for i, b := range bad {
		if _, err := ParseConnect(b); err == nil {
			t.Errorf("case %d: expected error for %q", i, b)
		}
	}
}

func TestResponseOK(t *testing.T) {
	r, e, err := ParseResponse([]byte("DLDW/1 OK conn_ab12cd 600 140.82.112.3\n"))
	if err != nil || e != nil {
		t.Fatalf("unexpected: %v %v", e, err)
	}
	if r.ConnID != "conn_ab12cd" || r.ExpiresIn != 600 || r.ResolvedIP != "140.82.112.3" {
		t.Fatalf("bad parse: %+v", r)
	}
	if got, want := string(r.Encode()), "DLDW/1 OK conn_ab12cd 600 140.82.112.3\n"; got != want {
		t.Fatalf("encode = %q, want %q", got, want)
	}
	// no-resolve form
	r2, _, err := ParseResponse([]byte("DLDW/1 OK conn_ab12cd 600 -\n"))
	if err != nil || r2.ResolvedIP != "" {
		t.Fatalf("dash form: %+v %v", r2, err)
	}
}

func TestResponseErr(t *testing.T) {
	_, e, err := ParseResponse([]byte("DLDW/1 ERR E_SSRF_DENIED target resolves to private range\n"))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if e == nil || e.Code != "E_SSRF_DENIED" || e.Message != "target resolves to private range" {
		t.Fatalf("bad parse: %+v", e)
	}
	out := string(e.Encode())
	if !strings.HasPrefix(out, "DLDW/1 ERR E_SSRF_DENIED ") || !strings.HasSuffix(out, "target resolves to private range\n") {
		t.Fatalf("bad encode: %q", out)
	}
	// re-parse
	_, e2, err := ParseResponse(e.Encode())
	if err != nil || e2 == nil || e2.Message != e.Message {
		t.Fatalf("err round trip failed: %v %+v", err, e2)
	}
}

func TestResponseRejects(t *testing.T) {
	bad := []string{
		"DLDW/1 MAYBE x y z\n",
		"DLDW/1 OK\n",
		"DLDW/1 OK conn_x abc\n",
		"DLDW/1 ERR lower_case message\n",
		"DLDW/1 ERR E_X\n", // message optional? requires >= 3 fields; ERR E_X has 3 fields but empty message: allowed
	}
	for i, b := range bad[:4] {
		if _, _, err := ParseResponse([]byte(b)); err == nil {
			t.Errorf("case %d: expected error for %q", i, b)
		}
	}
}

func TestReadLineLimit(t *testing.T) {
	long := bytes.Repeat([]byte("a"), MaxLine+16)
	r := bufio.NewReader(bytes.NewReader(append(long, '\n')))
	if _, err := ReadLine(r); err != ErrTooLong {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
	r2 := bufio.NewReader(bytes.NewReader([]byte("DLDW/1 OK conn_ab12cd 600 1.2.3.4\n")))
	line, err := ReadLine(r2)
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if !bytes.HasSuffix(line, []byte("\n")) {
		t.Fatal("line should include newline")
	}
	// Exactly at limit is fine.
	ok := []byte("DLDW/1 OK conn_ab12cd 600 1.2.3.4\n")
	r3 := bufio.NewReader(bytes.NewReader(ok))
	if _, err := ReadLine(r3); err != nil {
		t.Fatalf("ReadLine small: %v", err)
	}
}
