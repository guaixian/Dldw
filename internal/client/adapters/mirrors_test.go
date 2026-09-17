package adapters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseEnv() []string {
	return []string{"PATH=/usr/bin", "HOME=" + tHome(), "APPDATA=" + filepath.Join(tHome(), "AppData", "Roaming")}
}

func tHome() string { return os.TempDir() }

func TestInjectUV(t *testing.T) {
	caps := MirrorCaps{PyPI: true, NPM: true}
	base := "http://127.0.0.1:18080"

	// 无任何用户配置 -> 注入
	got := InjectMirrors("uv", []string{"sync"}, baseEnv(), base, "", caps)
	if len(got) != 1 || got[0] != "UV_INDEX_URL=http://127.0.0.1:18080/pypi/simple" {
		t.Fatalf("uv inject = %v", got)
	}

	// 用户 flag -> 不注入
	for _, flag := range []string{"--index", "--index-url", "--default-index", "--extra-index-url"} {
		if InjectMirrors("uv", []string{"pip", flag, "https://x/simple"}, baseEnv(), base, "", caps) != nil {
			t.Errorf("uv flag %s should disable injection", flag)
		}
	}

	// 用户 env -> 不注入
	env := append(baseEnv(), "UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple")
	if InjectMirrors("uv", []string{"sync"}, env, base, "", caps) != nil {
		t.Fatal("user env should win")
	}
	env2 := append(baseEnv(), "UV_DEFAULT_INDEX=https://x")
	if InjectMirrors("uv", []string{"sync"}, env2, base, "", caps) != nil {
		t.Fatal("UV_DEFAULT_INDEX should win")
	}

	// 服务端未开 pypi -> 不注入
	if InjectMirrors("uv", []string{"sync"}, baseEnv(), base, "", MirrorCaps{NPM: true}) != nil {
		t.Fatal("no pypi capability -> no injection")
	}
}

func TestInjectPip(t *testing.T) {
	caps := MirrorCaps{PyPI: true}
	base := "http://127.0.0.1:18080"

	// 只有 install/download/wheel 注入
	got := InjectMirrors("pip", []string{"install", "six"}, baseEnv(), base, "", caps)
	if len(got) != 1 || got[0] != "PIP_INDEX_URL=http://127.0.0.1:18080/pypi/simple" {
		t.Fatalf("pip inject = %v", got)
	}
	if InjectMirrors("pip", []string{"--version"}, baseEnv(), base, "", caps) != nil {
		t.Fatal("pip --version should not inject")
	}

	// -i / --index-url / PIP_INDEX_URL
	if InjectMirrors("pip", []string{"install", "-i", "https://x"}, baseEnv(), base, "", caps) != nil {
		t.Fatal("-i should disable")
	}
	env := append(baseEnv(), "PIP_INDEX_URL=https://x/simple")
	if InjectMirrors("pip", []string{"install", "six"}, env, base, "", caps) != nil {
		t.Fatal("user PIP_INDEX_URL should win")
	}

	// python -m pip
	got2 := InjectMirrors("python", []string{"-m", "pip", "install", "six"}, baseEnv(), base, "", caps)
	if len(got2) != 1 {
		t.Fatalf("python -m pip = %v", got2)
	}

	// 用户 pip 配置文件（APPDATA/pip/pip.ini 含 index-url）
	home := t.TempDir()
	appdata := filepath.Join(home, "AppData", "Roaming")
	os.MkdirAll(filepath.Join(appdata, "pip"), 0o755)
	os.WriteFile(filepath.Join(appdata, "pip", "pip.ini"), []byte("[global]\nindex-url = https://x/simple\n"), 0o644)
	t.Setenv("APPDATA", appdata)
	t.Setenv("PIP_CONFIG_FILE", "")
	defer func() { os.Unsetenv("APPDATA") }()
	if InjectMirrors("pip", []string{"install", "six"}, baseEnv(), base, "", caps) != nil {
		t.Fatal("user pip.ini index-url should win")
	}
}

func TestInjectNPM(t *testing.T) {
	caps := MirrorCaps{NPM: true}
	base := "http://127.0.0.1:18080"

	got := InjectMirrors("npm", []string{"install", "left-pad"}, baseEnv(), base, "", caps)
	if len(got) != 2 || got[0] != "NPM_CONFIG_REGISTRY=http://127.0.0.1:18080/npm" {
		t.Fatalf("npm inject = %v", got)
	}

	// 写操作不注入
	for _, sub := range []string{"publish", "adduser", "login", "logout", "owner", "token"} {
		if InjectMirrors("npm", []string{sub}, baseEnv(), base, "", caps) != nil {
			t.Errorf("npm %s should not inject", sub)
		}
	}
	// --registry / 环境变量
	if InjectMirrors("npm", []string{"install", "--registry", "https://x"}, baseEnv(), base, "", caps) != nil {
		t.Fatal("--registry should disable")
	}
	env := append(baseEnv(), "npm_config_registry=https://x")
	if InjectMirrors("npm", []string{"install"}, env, base, "", caps) != nil {
		t.Fatal("user npm_config_registry (case-insensitive) should win")
	}

	// pnpm/yarn/bun 同样注入（在写 .npmrc 之前测，避免目录污染）
	if InjectMirrors("pnpm", []string{"install"}, baseEnv(), base, "", caps) == nil {
		t.Fatal("pnpm should inject")
	}
	if InjectMirrors("yarn", []string{"install"}, baseEnv(), base, "", caps) == nil {
		t.Fatal("yarn should inject")
	}

	// 项目 .npmrc 声明 registry -> 不注入
	dir := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)
	os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry=https://my-registry\n"), 0o644)
	if InjectMirrors("npm", []string{"install"}, baseEnv(), base, "", caps) != nil {
		t.Fatal("project .npmrc registry should win")
	}
}

func TestInjectMirrorAuthEmbedsToken(t *testing.T) {
	caps := MirrorCaps{PyPI: true, NPM: true, GoMod: true, HF: true, MirrorAuth: true}
	base := "http://127.0.0.1:18080"
	tok := "dldw_abcdef0123456789"

	// 隔离本机真实 go env（UserConfigDir/go/env 可能配置了 GOPROXY）
	clean := t.TempDir()
	t.Setenv("AppData", clean)
	t.Setenv("GOPROXY", "")

	got := InjectMirrors("uv", []string{"sync"}, baseEnv(), base, tok, caps)
	if len(got) != 2 || got[0] != "UV_INDEX_URL=http://"+tok+"@127.0.0.1:18080/pypi/simple" {
		t.Fatalf("uv with auth = %v", got)
	}
	if got[1] != "HF_ENDPOINT=http://"+tok+"@127.0.0.1:18080/hf" {
		t.Fatalf("hf with auth = %v", got)
	}

	gotGo := InjectMirrors("go", []string{"mod", "tidy"}, baseEnv(), base, tok, caps)
	if len(gotGo) != 2 || gotGo[0] != "GOPROXY=http://"+tok+"@127.0.0.1:18080/gomod,direct" {
		t.Fatalf("go with auth = %v", gotGo)
	}
}

func TestInjectHFEndpoint(t *testing.T) {
	caps := MirrorCaps{HF: true}
	base := "http://127.0.0.1:18080"

	// 任意工具都注入 HF_ENDPOINT（python/hf 工具链会读取）
	got := InjectMirrors("git", []string{"status"}, baseEnv(), base, "", caps)
	if len(got) != 1 || got[0] != "HF_ENDPOINT=http://127.0.0.1:18080/hf" {
		t.Fatalf("hf inject = %v", got)
	}
	// 用户已设置 -> 尊重
	env := append(baseEnv(), "HF_ENDPOINT=https://hf-mirror.com")
	if InjectMirrors("git", []string{"status"}, env, base, "", caps) != nil {
		t.Fatal("user HF_ENDPOINT should win")
	}
	// 能力未开 -> 不注入
	if InjectMirrors("git", []string{"status"}, baseEnv(), base, "", MirrorCaps{}) != nil {
		t.Fatal("no hf capability -> no injection")
	}
}

func TestInjectNoServer(t *testing.T) {
	if InjectMirrors("uv", []string{"sync"}, baseEnv(), "", "", MirrorCaps{PyPI: true}) != nil {
		t.Fatal("no server -> no injection")
	}
}

func TestInjectGo(t *testing.T) {
	caps := MirrorCaps{GoMod: true}
	base := "http://127.0.0.1:18080"

	// 隔离本机真实 go env（UserConfigDir/go/env 可能配置了 GOPROXY）
	clean := t.TempDir()
	t.Setenv("AppData", clean) // os.UserConfigDir on Windows
	t.Setenv("GOPROXY", "")

	// 未配置 -> 注入
	got := InjectMirrors("go", []string{"mod", "download"}, baseEnv(), base, "", caps)
	if len(got) != 1 || got[0] != "GOPROXY=http://127.0.0.1:18080/gomod,direct" {
		t.Fatalf("go inject = %v", got)
	}

	// 用户环境变量 GOPROXY -> 尊重
	env := append(baseEnv(), "GOPROXY=https://goproxy.cn")
	if InjectMirrors("go", []string{"mod", "download"}, env, base, "", caps) != nil {
		t.Fatal("user GOPROXY env should win")
	}

	// `go env -w GOPROXY=...` 写入的配置文件 -> 尊重
	os.MkdirAll(filepath.Join(clean, "go"), 0o755)
	os.WriteFile(filepath.Join(clean, "go", "env"), []byte("GOPROXY=https://goproxy.cn,direct\n"), 0o644)
	if InjectMirrors("go", []string{"mod", "download"}, baseEnv(), base, "", caps) != nil {
		t.Fatal("go env -w GOPROXY should win")
	}

	// 服务端未开 gomod -> 不注入
	if InjectMirrors("go", []string{"mod", "download"}, baseEnv(), base, "", MirrorCaps{}) != nil {
		t.Fatal("no gomod capability -> no injection")
	}
}

func TestInjectUVProjectConfig(t *testing.T) {
	caps := MirrorCaps{PyPI: true}
	base := "http://127.0.0.1:18080"
	dir := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)

	// 无 pyproject -> 注入
	if InjectMirrors("uv", []string{"sync"}, baseEnv(), base, "", caps) == nil {
		t.Fatal("should inject without pyproject")
	}
	// pyproject 声明自定义 index -> 不注入
	os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\nname='x'\n\n[[tool.uv.index]]\nurl='https://x'\n"), 0o644)
	if InjectMirrors("uv", []string{"sync"}, baseEnv(), base, "", caps) != nil {
		t.Fatal("project [[tool.uv.index]] should win")
	}
}

var _ = strings.TrimSpace
