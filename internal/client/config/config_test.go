package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaultsWhenMissing(t *testing.T) {
	t.Setenv("DLDW_HOME", t.TempDir())
	cfg, path, err := Load()
	if err != nil || path != "" {
		t.Fatalf("load: %v %q", err, path)
	}
	if cfg.Proxy.Bind != "127.0.0.1" || cfg.ChunkSizeBytes() != 16<<20 || cfg.Concurrency() != 8 {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.Download.DirectFallback != "ask" {
		t.Fatalf("fallback = %q", cfg.Download.DirectFallback)
	}
}

func TestInitSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("DLDW_HOME", t.TempDir())
	p, err := Init()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, ".yaml") {
		t.Fatalf("init should write the annotated yaml template, got %q", p)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	// annotated template must parse and land on defaults
	cfg, got, err := Load()
	if err != nil || got != p {
		t.Fatalf("load: %v %q", err, got)
	}
	if cfg.Proxy.Bind != "127.0.0.1" || cfg.Proxy.Port != 0 {
		t.Fatalf("template proxy = %+v", cfg.Proxy)
	}
	if cfg.ChunkSizeBytes() != 16<<20 || cfg.Concurrency() != 8 || cfg.Download.DirectFallback != "ask" {
		t.Fatalf("template download = %+v", cfg.Download)
	}
	if cfg.Server != "" || cfg.TLSSkipVerify {
		t.Fatalf("template unexpected server/tls: %+v", cfg)
	}
	// init is idempotent and does not clobber existing files
	p2, err := Init()
	if err != nil || p2 != p {
		t.Fatalf("second init: %q %v", p2, err)
	}
}

func TestActivePathJSONTakesPrecedence(t *testing.T) {
	t.Setenv("DLDW_HOME", t.TempDir())
	if _, err := Init(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(ActivePath(), ".yaml") {
		t.Fatalf("active = %q, want yaml", ActivePath())
	}
	// writing json (config set) makes it take precedence
	if err := Default().Save(""); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(ActivePath(), ".json") {
		t.Fatalf("active = %q, want json after Save", ActivePath())
	}
	// and Load picks it up
	cfg, path, err := Load()
	if err != nil || !strings.HasSuffix(path, ".json") {
		t.Fatalf("load: %v %q", err, path)
	}
	if cfg.Proxy.Bind != "127.0.0.1" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestSetUnset(t *testing.T) {
	cfg := Default()
	if err := cfg.Set("server", "https://dldw.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("download.concurrency", "16"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("security.block_private", "true"); err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "https://dldw.example.com" || cfg.Download.Concurrency != 16 ||
		cfg.Security.BlockPrivate == nil || *cfg.Security.BlockPrivate != true {
		t.Fatalf("cfg = %+v", cfg)
	}
	if err := cfg.Unset("server"); err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "" {
		t.Fatalf("unset failed: %q", cfg.Server)
	}
}

func TestYAMLConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DLDW_CONFIG", filepath.Join(dir, "nope.json"))
	os.WriteFile(filepath.Join(dir, "nope.yaml"), []byte(`
server: https://s.example.com
download:
  chunk_size: 32MiB
  concurrency: 4
security:
  ports: [80, 443, 8080]
`), 0o644)
	cfg, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "https://s.example.com" || cfg.Download.Concurrency != 4 {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.ChunkSizeBytes() != 32<<20 {
		t.Fatalf("chunk = %d", cfg.ChunkSizeBytes())
	}
	if len(cfg.Security.Ports) != 3 {
		t.Fatalf("ports = %v", cfg.Security.Ports)
	}
}

func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token.json")
	if err := SaveCredentials(p, &Credentials{ClientID: "dev_x", Token: "dldw_abc"}); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCredentials(p)
	if err != nil || c.ClientID != "dev_x" || c.Token != "dldw_abc" {
		t.Fatalf("creds = %+v %v", c, err)
	}
	if _, err := LoadCredentials(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing should fail")
	}
}

func TestDurations(t *testing.T) {
	cfg := Default()
	if cfg.RefreshBeforeDur() != 120*time.Second {
		t.Fatalf("refresh = %v", cfg.RefreshBeforeDur())
	}
	if cfg.TaskPollWaitDur() != time.Second {
		t.Fatalf("poll = %v", cfg.TaskPollWaitDur())
	}
	if cfg.ProxyIdleTimeout() != 5*time.Minute {
		t.Fatalf("idle = %v", cfg.ProxyIdleTimeout())
	}
	cfg.Download.RefreshBefore = "garbage"
	if cfg.RefreshBeforeDur() != 120*time.Second {
		t.Fatal("fallback duration failed")
	}
}

func TestTokenFilePath(t *testing.T) {
	t.Setenv("DLDW_HOME", filepath.Join("X:", "dldw-home"))
	cfg := Default()
	if cfg.TokenFilePath() != filepath.Join("X:", "dldw-home", "token.json") {
		t.Fatalf("path = %q", cfg.TokenFilePath())
	}
	cfg.TokenFile = "~/custom/token.json"
	p := cfg.TokenFilePath()
	if !filepath.IsAbs(p) {
		t.Fatalf("not abs: %q", p)
	}
}

func TestJSONRoundTripStable(t *testing.T) {
	cfg := Default()
	cfg.Server = "https://x"
	buf, _ := json.Marshal(cfg)
	var cfg2 Config
	json.Unmarshal(buf, &cfg2)
	if cfg2.Server != "https://x" || cfg2.Proxy.Bind != "127.0.0.1" {
		t.Fatal("json round trip broken")
	}
}
