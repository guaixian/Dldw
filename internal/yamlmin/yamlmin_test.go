package yamlmin

import (
	"reflect"
	"testing"
)

func TestParseSpecConfig(t *testing.T) {
	in := []byte(`
# dldw config (spec 6)
server: https://dldw.example.com
token_file: ~/.dldw/token
proxy:
  bind: 127.0.0.1
  port: 0
  mode: whitelist_only
  fallback: direct
  allow_large_over_tunnel: false
download:
  chunk_size: 16MiB
  concurrency: 8
  refresh_before: 120s
  direct_fallback: ask
whitelist_version: "2026-09-16.1"
security:
  block_private: true
  ports: [80, 443]
`)
	var out map[string]any
	if err := Unmarshal(in, &out); err != nil {
		t.Fatal(err)
	}
	if out["server"] != "https://dldw.example.com" {
		t.Fatalf("server = %v", out["server"])
	}
	proxy, ok := out["proxy"].(map[string]any)
	if !ok {
		t.Fatalf("proxy = %#v", out["proxy"])
	}
	if proxy["bind"] != "127.0.0.1" || proxy["port"] != float64(0) || proxy["mode"] != "whitelist_only" {
		t.Fatalf("proxy = %#v", proxy)
	}
	if proxy["allow_large_over_tunnel"] != false {
		t.Fatalf("bool: %#v", proxy["allow_large_over_tunnel"])
	}
	dl := out["download"].(map[string]any)
	if dl["chunk_size"] != "16MiB" || dl["concurrency"] != float64(8) || dl["direct_fallback"] != "ask" {
		t.Fatalf("download = %#v", dl)
	}
	sec := out["security"].(map[string]any)
	ports := sec["ports"].([]any)
	if !reflect.DeepEqual(ports, []any{float64(80), float64(443)}) {
		t.Fatalf("ports = %#v", ports)
	}
	if out["whitelist_version"] != "2026-09-16.1" {
		t.Fatalf("quoted string: %v", out["whitelist_version"])
	}
}

func TestParseBlockListAndNested(t *testing.T) {
	in := []byte(`
a:
  b:
    c: 1
  list:
    - one
    - two
empty:
str: hello world # trailing comment
url: http://x.example.com/path#frag
`)
	var out map[string]any
	if err := Unmarshal(in, &out); err != nil {
		t.Fatal(err)
	}
	a := out["a"].(map[string]any)
	if a["b"].(map[string]any)["c"] != float64(1) {
		t.Fatal("deep nesting failed")
	}
	lst := a["list"].([]any)
	if !reflect.DeepEqual(lst, []any{"one", "two"}) {
		t.Fatalf("list = %#v", lst)
	}
	if v, ok := out["empty"]; !ok || v != nil {
		t.Fatalf("empty = %#v", out["empty"])
	}
	if out["str"] != "hello world" {
		t.Fatalf("str = %v", out["str"])
	}
	if out["url"] != "http://x.example.com/path#frag" {
		t.Fatalf("url with # mangled: %v", out["url"])
	}
}

func TestParseToStruct(t *testing.T) {
	type Inner struct {
		Ports []int  `json:"ports"`
		Mode  string `json:"mode"`
	}
	type Cfg struct {
		Server string `json:"server"`
		Inner  Inner  `json:"inner"`
		On     bool   `json:"on"`
	}
	in := []byte("server: s1\ninner:\n  ports: [80, 443]\n  mode: strict\non: true\n")
	var c Cfg
	if err := Unmarshal(in, &c); err != nil {
		t.Fatal(err)
	}
	if c.Server != "s1" || len(c.Inner.Ports) != 2 || c.Inner.Ports[1] != 443 || c.Inner.Mode != "strict" || !c.On {
		t.Fatalf("cfg = %+v", c)
	}
}

func TestParseErrors(t *testing.T) {
	bad := [][]byte{
		[]byte("no colon line"),
		[]byte("a:\n\tb: 1\n"),
	}
	for i, b := range bad {
		var out map[string]any
		if err := Unmarshal(b, &out); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	var out map[string]any
	if err := Unmarshal([]byte(""), &out); err != nil || out != nil {
		t.Errorf("empty: %v %v", out, err)
	}
}
