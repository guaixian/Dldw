package proxycore

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleLink = "hysteria2://pass123@hy.example.com:32319?sni=hy.example.com&insecure=0&obfs=salamander&obfs-password=obfspass#mynode"

func TestParseHysteria2(t *testing.T) {
	sl, err := ParseHysteria2(sampleLink)
	if err != nil {
		t.Fatal(err)
	}
	if sl.Server != "hy.example.com" || sl.Port != 32319 || sl.Password != "pass123" {
		t.Fatalf("sl = %+v", sl)
	}
	if sl.SNI != "hy.example.com" || sl.Insecure {
		t.Fatalf("tls = %+v", sl)
	}
	if sl.ObfsType != "salamander" || sl.ObfsPass != "obfspass" {
		t.Fatalf("obfs = %+v", sl)
	}

	// hy2:// 前缀 + insecure=1 + 无 obfs
	sl2, err := ParseHysteria2("hy2://p@h2.example.com:443?insecure=1")
	if err != nil {
		t.Fatal(err)
	}
	if sl2.Server != "h2.example.com" || !sl2.Insecure || sl2.ObfsType != "" {
		t.Fatalf("sl2 = %+v", sl2)
	}
	if sl2.SNI != "h2.example.com" {
		t.Fatalf("default sni = %q", sl2.SNI)
	}

	for _, bad := range []string{
		"vmess://xxx",
		"hysteria2://nopath",
		"hysteria2://:443",
		"hysteria2://p@h:99999",
		"hysteria2://@h:443",
		"   ",
	} {
		if _, err := ParseHysteria2(bad); err == nil {
			t.Errorf("ParseHysteria2(%q) should fail", bad)
		}
	}
}

func TestGenerateSingBoxConfig(t *testing.T) {
	sl, _ := ParseHysteria2(sampleLink)
	buf, err := GenerateSingBoxConfig(sl, "127.0.0.1", 1080, "warn")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(buf, &cfg); err != nil {
		t.Fatalf("generated config is not valid JSON: %v\n%s", err, buf)
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "mixed" || in["listen"] != "127.0.0.1" || in["listen_port"].(float64) != 1080 {
		t.Fatalf("inbound = %v", in)
	}
	outs := cfg["outbounds"].([]any)
	hy := outs[0].(map[string]any)
	if hy["type"] != "hysteria2" || hy["server"] != "hy.example.com" || hy["server_port"].(float64) != 32319 || hy["password"] != "pass123" {
		t.Fatalf("hysteria2 outbound = %v", hy)
	}
	obfs := hy["obfs"].(map[string]any)
	if obfs["type"] != "salamander" || obfs["password"] != "obfspass" {
		t.Fatalf("obfs = %v", obfs)
	}
	tls := hy["tls"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "hy.example.com" || tls["insecure"] != false {
		t.Fatalf("tls = %v", tls)
	}
	if outs[1].(map[string]any)["type"] != "direct" {
		t.Fatalf("second outbound = %v", outs[1])
	}
	if cfg["route"].(map[string]any)["final"] != "proxy" {
		t.Fatalf("route = %v", cfg["route"])
	}

	// 无 obfs 时不应有 obfs 字段
	sl2, _ := ParseHysteria2("hysteria2://p@h.io:443")
	buf2, _ := GenerateSingBoxConfig(sl2, "", 0, "")
	s := string(buf2)
	if !strings.Contains(s, "127.0.0.1") || !strings.Contains(s, "1080") {
		t.Fatalf("defaults missing: %s", s)
	}
	if strings.Contains(s, "obfs") && strings.Contains(s, "salamander") {
		t.Fatal("obfs should be absent when not configured")
	}
}
