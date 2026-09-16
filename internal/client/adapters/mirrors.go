package adapters

import (
	"os"
	"path/filepath"
	"strings"
)

// MirrorCaps 是服务端镜像能力（来自 /api/v1/capabilities）。
type MirrorCaps struct {
	PyPI   bool
	NPM    bool
	Mirror bool
	GoMod  bool
}

// InjectMirrors 在用户未自行配置 index/registry 时，为 uv/pip/npm 系工具
// 返回自动注入的镜像环境变量。
//
// 优先级（高 -> 低）：用户命令行 flag > 用户环境变量 > 用户项目/用户级配置文件
// > dldw 自动注入。只要检测到用户自己的配置，一律不注入。
func InjectMirrors(tool string, args []string, env []string, serverBase string, caps MirrorCaps) []string {
	if serverBase == "" {
		return nil
	}
	serverBase = strings.TrimRight(serverBase, "/")
	pypiEnv := [2]string{"UV_INDEX_URL", serverBase + "/pypi/simple"}
	npmVal := serverBase + "/npm"

	switch tool {
	case "uv":
		if !caps.PyPI || userSpecifiesIndex(args, env, uvIndexFlags, uvIndexEnv, uvProjectConfig) {
			return nil
		}
		return []string{pypiEnv[0] + "=" + pypiEnv[1]}
	case "pip", "pip3":
		if !caps.PyPI || !isReadSubcommand(args, pipReadSubcommands) {
			return nil
		}
		if userSpecifiesIndex(args, env, pipIndexFlags, pipIndexEnv, pipConfigFiles) {
			return nil
		}
		return []string{"PIP_INDEX_URL=" + pypiEnv[1]}
	case "python", "python3":
		// python -m pip ...：定位 pip 子命令参数
		if len(args) >= 2 && args[0] == "-m" && (args[1] == "pip" || args[1] == "pip3") {
			return InjectMirrors(args[1], args[2:], env, serverBase, caps)
		}
		return nil
	case "go":
		// Go modules：GOPROXY 协议镜像；用户已设 GOPROXY（env 或 go env -w）时尊重
		if !caps.GoMod {
			return nil
		}
		if goProxyConfigured(env) {
			return nil
		}
		return []string{"GOPROXY=" + serverBase + "/gomod,direct"}
	case "npm", "pnpm", "yarn", "bun":
		if !caps.NPM {
			return nil
		}
		if !isReadSubcommand(args, npmReadSubcommands) {
			return nil
		}
		if userSpecifiesIndex(args, env, npmIndexFlags, npmIndexEnv, npmConfigFiles) {
			return nil
		}
		// 大小写各一份（npm/pnpm 在不同平台读取的 env 大小写不同）
		return []string{
			"NPM_CONFIG_REGISTRY=" + npmVal,
			"npm_config_registry=" + npmVal,
		}
	}
	return nil
}

var (
	uvIndexFlags  = []string{"--index", "--index-url", "--default-index", "--extra-index-url", "--uv-index"}
	uvIndexEnv    = []string{"UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX", "PIP_INDEX_URL"}
	pipIndexFlags = []string{"-i", "--index-url", "--extra-index-url"}
	pipIndexEnv   = []string{"PIP_INDEX_URL"}
	npmIndexFlags = []string{"--registry"}
	npmIndexEnv   = []string{"NPM_CONFIG_REGISTRY", "npm_config_registry"}

	pipReadSubcommands = map[string]bool{"install": true, "download": true, "wheel": true}
	// npm 写操作不走镜像（publish/login 等）
	npmReadSubcommands = map[string]bool{
		"install": true, "i": true, "ci": true, "add": true,
		"install-clean": true, "update": true, "outdated": true, "view": true,
		"info": true, "show": true, "pack": true, "cache": true, "ls": true,
		"list": true, "why": true, "diff": true, "audit": true, "rebuild": true,
	}

	// uvProjectConfig 返回可能声明自定义 index 的项目文件。
	uvProjectConfig = func() []string {
		var files []string
		for _, f := range []string{"uv.toml", "pyproject.toml"} {
			if p := filepath.Join(cwd(), f); fileExists(p) {
				files = append(files, p)
			}
		}
		return files
	}
	// pipConfigFiles 返回 pip 配置文件候选。
	pipConfigFiles = func() []string {
		var files []string
		if p := os.Getenv("PIP_CONFIG_FILE"); p != "" {
			files = append(files, p)
		}
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			files = append(files, filepath.Join(appdata, "pip", "pip.ini"))
		}
		if home, err := os.UserHomeDir(); err == nil {
			files = append(files, filepath.Join(home, ".config", "pip", "pip.conf"))
		}
		return files
	}
	// npmConfigFiles 返回 npm registry 配置候选。
	npmConfigFiles = func() []string {
		var files []string
		for _, f := range []string{".npmrc"} {
			if p := filepath.Join(cwd(), f); fileExists(p) {
				files = append(files, p)
			}
		}
		if home, err := os.UserHomeDir(); err == nil {
			p := filepath.Join(home, ".npmrc")
			if fileExists(p) {
				files = append(files, p)
			}
		}
		return files
	}
)

// goProxyConfigured 判断用户是否已配置 GOPROXY：环境变量或 `go env -w`
// 写入的配置文件（os.UserConfigDir()/go/env）。
func goProxyConfigured(env []string) bool {
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 && strings.EqualFold(kv[:eq], "GOPROXY") && strings.TrimSpace(kv[eq+1:]) != "" {
			return true
		}
	}
	if os.Getenv("GOPROXY") != "" {
		return true
	}
	if dir, err := os.UserConfigDir(); err == nil {
		if data, err := os.ReadFile(filepath.Join(dir, "go", "env")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "GOPROXY=") && strings.TrimSpace(line[len("GOPROXY="):]) != "" {
					return true
				}
			}
		}
	}
	return false
}

// userSpecifiesIndex 判断用户是否自行指定了 index/registry：
// 命令行 flag、环境变量、或配置文件中出现相关键。
func userSpecifiesIndex(args, env []string, flags, envKeys []string, configFiles func() []string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key := kv[:eq]
		for _, k := range envKeys {
			if strings.EqualFold(key, k) && strings.TrimSpace(kv[eq+1:]) != "" {
				return true
			}
		}
	}
	for _, f := range configFiles() {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := string(data)
		if strings.Contains(s, "index-url") || strings.Contains(s, "registry") ||
			strings.Contains(s, "[[tool.uv.index]]") || strings.Contains(s, "tool.uv.index") ||
			strings.Contains(s, "default-index") {
			return true
		}
	}
	return false
}

// isReadSubcommand 判断首个位置参数是否属于读类子命令。
func isReadSubcommand(args []string, allowed map[string]bool) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return allowed[a]
	}
	return false
}

func cwd() string {
	d, err := os.Getwd()
	if err != nil {
		return "."
	}
	return d
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
