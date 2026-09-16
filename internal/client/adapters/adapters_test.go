package adapters

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentify(t *testing.T) {
	cases := map[string]Level{
		"curl":   LevelHigh,
		"wget":   LevelHigh,
		"git":    LevelHigh,
		"pip":    LevelHigh,
		"uv":     LevelHigh,
		"npm":    LevelMid,
		"conda":  LevelMid,
		"apt":    LevelMid,
		"dnf":    LevelMid,
		"yum":    LevelMid,
		"docker": LevelLow,
		"weird-tool-x": LevelUnknown,
	}
	for tool, want := range cases {
		if got := Identify(tool).Level; got != want {
			t.Errorf("Identify(%q).Level = %v, want %v", tool, got, want)
		}
	}
	if !Identify("git").EnvOnly {
		t.Error("git should be env-only")
	}
	if Identify("apt").EnvOnly {
		t.Error("apt should not be env-only")
	}
}

func TestBuildEnv(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"http_proxy=http://evil:1",
		"HTTPS_PROXY=http://evil:2",
		"all_proxy=socks5://evil:3",
		"NO_PROXY=internal",
		"HOME=/root",
	}
	got := BuildEnv(base, "http://127.0.0.1:3128")
	m := map[string]string{}
	for _, kv := range got {
		parts := strings.SplitN(kv, "=", 2)
		m[parts[0]] = parts[1]
	}
	for _, bad := range []string{"all_proxy", "ALL_PROXY"} {
		if _, ok := m[bad]; ok {
			t.Errorf("%s leaked from base env", bad)
		}
	}
	if m["http_proxy"] != "http://127.0.0.1:3128" || m["HTTPS_PROXY"] != "http://127.0.0.1:3128" ||
		m["HTTP_PROXY"] != "http://127.0.0.1:3128" || m["https_proxy"] != "http://127.0.0.1:3128" {
		t.Errorf("proxy vars = %v", m)
	}
	if want := "localhost,127.0.0.1,::1,*.local"; m["no_proxy"] != want || m["NO_PROXY"] != want {
		t.Errorf("no_proxy = %v", m)
	}
	if m["PATH"] != "/usr/bin" || m["HOME"] != "/root" {
		t.Errorf("base env clobbered: %v", m)
	}
	if _, ok := m["ALL_PROXY"]; ok {
		t.Error("all_proxy should not be set")
	}
}

func TestBuildEnvNoProxy(t *testing.T) {
	got := BuildEnv([]string{"A=1"}, "")
	if len(got) != 1 || got[0] != "A=1" {
		t.Fatalf("empty proxy must not inject: %v", got)
	}
}

func TestPreToolAptHintOnly(t *testing.T) {
	var buf bytes.Buffer
	notes := PreTool(PreOptions{
		Tool: "apt", ProxyURL: "http://127.0.0.1:3128", Apply: false, Stderr: &buf,
	})
	if len(notes) == 0 || !strings.Contains(buf.String(), "99dldw") {
		t.Fatalf("notes = %v, buf = %s", notes, buf.String())
	}
	if strings.Contains(buf.String(), "wrote") {
		t.Fatal("must not write without --apply")
	}
}

func TestPreToolDockerHint(t *testing.T) {
	var buf bytes.Buffer
	notes := PreTool(PreOptions{
		Tool: "docker", ProxyURL: "http://127.0.0.1:3128", Stderr: &buf,
	})
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "E_DOCKER_DAEMON") || !strings.Contains(joined, "registry-mirrors") {
		t.Fatalf("notes = %v", notes)
	}
}

func TestPreToolUnknown(t *testing.T) {
	var buf bytes.Buffer
	notes := PreTool(PreOptions{Tool: "mytool", ProxyURL: "http://127.0.0.1:3128", Stderr: &buf})
	if len(notes) == 0 || !strings.Contains(notes[0], "unknown tool") {
		t.Fatalf("notes = %v", notes)
	}
}

func TestPreToolNoProxy(t *testing.T) {
	notes := PreTool(PreOptions{Tool: "apt", ProxyURL: ""})
	if len(notes) != 1 || !strings.Contains(notes[0], "--no-proxy") {
		t.Fatalf("notes = %v", notes)
	}
}

func TestCondaApply(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	condarc := filepath.Join(home, ".condarc")
	os.WriteFile(condarc, []byte("channels:\n  - conda-forge\n"), 0o644)

	var buf bytes.Buffer
	notes := PreTool(PreOptions{Tool: "conda", ProxyURL: "http://127.0.0.1:3128", Apply: true, Stderr: &buf})
	data, err := os.ReadFile(condarc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "proxy_servers:") || !strings.Contains(s, "http://127.0.0.1:3128") {
		t.Fatalf("condarc = %s", s)
	}
	if !strings.Contains(s, "conda-forge") {
		t.Fatal("existing settings clobbered")
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "merged proxy_servers") {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes = %v", notes)
	}
}

func TestValidateProxyURL(t *testing.T) {
	if err := ValidateProxyURL("http://127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProxyURL("socks5://x:1"); err == nil {
		t.Fatal("socks should be rejected")
	}
	if err := ValidateProxyURL("http://"); err == nil {
		t.Fatal("hostless should be rejected")
	}
}
