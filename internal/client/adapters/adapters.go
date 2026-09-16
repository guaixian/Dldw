// Package adapters implements per-tool compatibility handling (spec 3.4):
// env-injected tools run directly; special tools (apt/yum/dnf/docker/conda/
// npm) get detection, hints and explicit --apply configuration.
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"dldw/internal/yamlmin"
)

// Level describes how well a tool cooperates with an HTTP proxy env.
type Level string

const (
	LevelHigh    Level = "high"
	LevelMid     Level = "mid"
	LevelLow     Level = "low"
	LevelUnknown Level = "unknown"
)

// Info describes adapter knowledge about a tool.
type Info struct {
	Name    string
	Level   Level
	EnvOnly bool // true when env injection is sufficient
}

// Identify classifies a tool name.
func Identify(tool string) Info {
	base := filepath.Base(strings.ReplaceAll(tool, "\\", "/"))
	switch base {
	case "curl", "wget", "git", "pip", "pip3", "uv", "python", "python3",
		"go", "cargo", "rustup", "gem", "bundle", "gradle", "mvn":
		return Info{Name: base, Level: LevelHigh, EnvOnly: true}
	case "npm", "yarn", "pnpm", "bun":
		return Info{Name: base, Level: LevelMid, EnvOnly: false}
	case "conda", "mamba", "micromamba":
		return Info{Name: base, Level: LevelMid, EnvOnly: false}
	case "apt", "apt-get":
		return Info{Name: base, Level: LevelMid, EnvOnly: false}
	case "yum", "dnf", "microdnf":
		return Info{Name: base, Level: LevelMid, EnvOnly: false}
	case "docker", "podman", "nerdctl":
		return Info{Name: base, Level: LevelLow, EnvOnly: false}
	case "docker-compose", "compose":
		return Info{Name: base, Level: LevelLow, EnvOnly: false}
	default:
		return Info{Name: base, Level: LevelUnknown, EnvOnly: true}
	}
}

// PreOptions configure the pre-exec adapter step.
type PreOptions struct {
	Tool     string
	ProxyURL string // local proxy URL; empty when --no-proxy
	Apply    bool   // explicit --apply: write configs (may require root)
	Stderr   io.Writer
	Verbose  bool
}

// PreTool runs tool specific preparation, printing hints to Stderr. It never
// fails the wrapped command; config application errors are reported as notes.
func PreTool(opts PreOptions) []string {
	var notes []string
	note := func(format string, args ...any) {
		s := "dldw: " + fmt.Sprintf(format, args...)
		notes = append(notes, s)
		if opts.Stderr != nil {
			fmt.Fprintln(opts.Stderr, s)
		}
	}
	info := Identify(opts.Tool)
	if opts.ProxyURL == "" {
		if !info.EnvOnly {
			note("%s: proxy disabled (--no-proxy); skipping adapter configuration", info.Name)
		}
		return notes
	}

	switch info.Name {
	case "npm", "yarn", "pnpm", "bun":
		if info.Name == "npm" {
			notes = append(notes, npmAdapt(opts, note)...)
		} else {
			note("%s: reads http(s)_proxy env; for strict setups also set proxy via config", info.Name)
		}
	case "conda", "mamba", "micromamba":
		notes = append(notes, condaAdapt(opts, note)...)
	case "apt", "apt-get":
		notes = append(notes, aptAdapt(opts, note)...)
	case "yum", "dnf", "microdnf":
		notes = append(notes, dnfAdapt(opts, note)...)
	case "docker", "podman", "nerdctl", "docker-compose", "compose":
		notes = append(notes, dockerAdapt(opts, note)...)
	default:
		if info.Level == LevelUnknown {
			note("unknown tool %q: injecting proxy env and executing as-is", info.Name)
		}
	}
	return notes
}

func npmAdapt(opts PreOptions, note func(string, ...any)) []string {
	var notes []string
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		return notes
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, npmPath, "config", "get", "proxy").Output()
	if err != nil {
		if opts.Verbose {
			note("npm: could not query npm config (%v)", err)
		}
		return notes
	}
	cur := strings.TrimSpace(string(out))
	if cur != "" && cur != "null" && cur != opts.ProxyURL {
		note("npm config proxy=%q differs from dldw proxy %q (use --apply to fix, or unset it)", cur, opts.ProxyURL)
	}
	if opts.Apply {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		for _, kv := range [][2]string{{"proxy", opts.ProxyURL}, {"https-proxy", opts.ProxyURL}} {
			if out, err := exec.CommandContext(ctx2, npmPath, "config", "set", kv[0], kv[1]).CombinedOutput(); err != nil {
				note("npm config set %s failed: %v (%s)", kv[0], err, strings.TrimSpace(string(out)))
			} else {
				note("npm config set %s %s", kv[0], kv[1])
			}
		}
	}
	return notes
}

func condaAdapt(opts PreOptions, note func(string, ...any)) []string {
	var notes []string
	home, _ := os.UserHomeDir()
	condarc := filepath.Join(home, ".condarc")
	snippet := fmt.Sprintf(
		"proxy_servers:\n  http: %s\n  https: %s\n", opts.ProxyURL, opts.ProxyURL)
	if !opts.Apply {
		note("conda: env alone is unreliable; add to %s (use --apply to merge):\n%s", condarc, strings.TrimRight(snippet, "\n"))
		return notes
	}
	existing, err := os.ReadFile(condarc)
	if err != nil && !os.IsNotExist(err) {
		note("conda: cannot read %s: %v", condarc, err)
		return notes
	}
	cfg := map[string]any{}
	if len(existing) > 0 {
		if err := yamlmin.Unmarshal(existing, &cfg); err != nil {
			note("conda: cannot parse %s: %v", condarc, err)
			return notes
		}
	}
	ps, _ := cfg["proxy_servers"].(map[string]any)
	if ps == nil {
		ps = map[string]any{}
	}
	ps["http"] = opts.ProxyURL
	ps["https"] = opts.ProxyURL
	cfg["proxy_servers"] = ps
	if err := writeCondarc(condarc, cfg); err != nil {
		note("conda: cannot write %s: %v", condarc, err)
		return notes
	}
	note("conda: merged proxy_servers into %s", condarc)
	return notes
}

// writeCondarc writes a simple flat yaml sufficient for condarc proxy settings.
func writeCondarc(path string, cfg map[string]any) error {
	var b strings.Builder
	for k, v := range cfg {
		if m, ok := v.(map[string]any); ok {
			fmt.Fprintf(&b, "%s:\n", k)
			for k2, v2 := range m {
				fmt.Fprintf(&b, "  %s: %v\n", k2, v2)
			}
		} else {
			fmt.Fprintf(&b, "%s: %v\n", k, v)
		}
	}
	tmp := path + ".dldw.tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func aptAdapt(opts PreOptions, note func(string, ...any)) []string {
	var notes []string
	target := "/etc/apt/apt.conf.d/99dldw"
	content := fmt.Sprintf(`// written by dldw (remove to disable)
Acquire::http::Proxy "%s";
Acquire::https::Proxy "%s";
`, opts.ProxyURL, opts.ProxyURL)
	if !opts.Apply {
		note("apt: env is unreliable for apt methods; write %s as root (dldw %s ... --apply):\n%s",
			target, opts.Tool, strings.TrimRight(content, "\n"))
		return notes
	}
	if runtime.GOOS == "windows" {
		note("apt: not applicable on windows")
		return notes
	}
	if os.Geteuid() != 0 {
		note("apt: --apply requires root (rerun with sudo)")
		return notes
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		note("apt: cannot write %s: %v", target, err)
		return notes
	}
	note("apt: wrote %s (next `apt update` will use it)", target)
	return notes
}

func dnfAdapt(opts PreOptions, note func(string, ...any)) []string {
	var notes []string
	candidates := []string{"/etc/dnf/dnf.conf", "/etc/yum.conf", "/etc/yum/yum.conf"}
	line := fmt.Sprintf("proxy=%s", opts.ProxyURL)
	if !opts.Apply {
		note("%s: env is unreliable; set `proxy=%s` under [main] in %s (or rerun with --apply)",
			opts.Tool, opts.ProxyURL, candidates[0])
		return notes
	}
	if runtime.GOOS == "windows" {
		note("%s: not applicable on windows", opts.Tool)
		return notes
	}
	if os.Geteuid() != 0 {
		note("%s: --apply requires root (rerun with sudo)", opts.Tool)
		return notes
	}
	target := candidates[0]
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			target = c
			break
		}
	}
	data, err := os.ReadFile(target)
	if err == nil && strings.Contains(string(data), "proxy=") {
		note("%s: %s already sets proxy=; leaving untouched (edit manually)", opts.Tool, target)
		return notes
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		note("%s: cannot write %s: %v", opts.Tool, target, err)
		return notes
	}
	defer f.Close()
	if !strings.HasSuffix(string(data), "\n") && len(data) > 0 {
		f.WriteString("\n")
	}
	f.WriteString(line + "\n")
	note("%s: appended `%s` to %s", opts.Tool, line, target)
	return notes
}

func dockerAdapt(opts PreOptions, note func(string, ...any)) []string {
	var notes []string
	note("%s: CLI proxy env does NOT affect the daemon; pulls use dockerd settings (E_DOCKER_DAEMON)", opts.Tool)
	path := dockerDaemonJSON()
	if path == "" {
		note("docker: no daemon.json found; see docs to configure registry-mirrors manually")
		return notes
	}
	data, err := os.ReadFile(path)
	if err != nil {
		note("docker: cannot read %s: %v", path, err)
		return notes
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		note("docker: %s is not valid JSON: %v", path, err)
		return notes
	}
	if mirrors, ok := cfg["registry-mirrors"].([]any); ok && len(mirrors) > 0 {
		note("docker: registry-mirrors already configured: %v", mirrors)
	} else {
		note("docker: add a registry mirror to %s manually, e.g.\n  {\"registry-mirrors\": [\"https://<your-dldw-mirror>\"]}", path)
	}
	note("docker: dldw does not restart dockerd; apply changes yourself")
	return notes
}

func dockerDaemonJSON() string {
	if runtime.GOOS == "windows" {
		home, _ := os.UserHomeDir()
		p := filepath.Join(home, ".docker", "daemon.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return filepath.Join(os.Getenv("ProgramData"), "docker", "config", "daemon.json")
	}
	p := "/etc/docker/daemon.json"
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// ProxyEnvVars returns the env pairs injected for a local proxy URL.
func ProxyEnvVars(proxyURL, noProxy string) []string {
	if noProxy == "" {
		noProxy = "localhost,127.0.0.1,::1,*.local"
	}
	return []string{
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"no_proxy=" + noProxy,
		"NO_PROXY=" + noProxy,
	}
}

// BuildEnv prepares the child environment: existing proxy vars are removed so
// our local proxy is the single source of truth (spec 3.3). all_proxy is not
// set by dldw; an inherited all_proxy is removed to avoid bypassing us.
func BuildEnv(base []string, proxyURL string) []string {
	drop := map[string]bool{
		"http_proxy": true, "https_proxy": true, "HTTP_PROXY": true, "HTTPS_PROXY": true,
		"all_proxy": true, "ALL_PROXY": true, "no_proxy": true, "NO_PROXY": true,
	}
	out := make([]string, 0, len(base)+8)
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 && drop[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	if proxyURL != "" {
		out = append(out, ProxyEnvVars(proxyURL, "")...)
	}
	return out
}

// ValidateProxyURL sanity checks the local proxy URL.
func ValidateProxyURL(u string) error {
	p, err := url.Parse(u)
	if err != nil {
		return err
	}
	if p.Scheme != "http" || p.Host == "" {
		return fmt.Errorf("proxy URL must be http://host:port, got %q", u)
	}
	return nil
}
