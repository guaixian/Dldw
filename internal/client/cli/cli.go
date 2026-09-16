// Package cli implements the dldw command line: subcommand dispatch, global
// flag parsing and the individual commands (spec 3.1).
package cli

import (
	"fmt"
	"os"
	"strings"

	"dldw/internal/client/config"
	"dldw/internal/client/wrapper"
	"dldw/internal/version"
)

// Global options parsed before the subcommand/tool name.
type globals struct {
	server         string
	token          string
	profile        string
	noProxy        bool
	apply          bool
	directFallback *bool
	forceTunnel    bool
	verbose        int
}

// Main is the CLI entry point; it returns the process exit code.
func Main(args []string) int {
	g := globals{}
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			fatalf("flag %s requires a value", a)
			return ""
		}
		switch {
		case a == "--" :
			i++
			goto dispatch
		case a == "-v" || a == "-verbose" || a == "--verbose":
			g.verbose = 1
		case a == "-vv":
			g.verbose = 2
		case a == "--version":
			fmt.Println(version.String())
			return 0
		case a == "--server":
			g.server = next()
		case a == "--token":
			g.token = next()
		case a == "--profile":
			g.profile = next()
		case a == "--no-proxy":
			g.noProxy = true
		case a == "--apply":
			g.apply = true
		case a == "--direct-fallback":
			v := true
			g.directFallback = &v
		case a == "--no-direct-fallback":
			v := false
			g.directFallback = &v
		case a == "--force-tunnel":
			g.forceTunnel = true
		case strings.HasPrefix(a, "-"):
			fatalf("unknown dldw flag %q (place tool args after the tool name; see dldw help)", a)
		default:
			goto dispatch
		}
	}
dispatch:
	rest := args[i:]
	if len(rest) == 0 {
		return cmdHelp()
	}

	if g.profile != "" {
		os.Setenv("DLDW_CONFIG", profilePath(g.profile))
	}
	cfg, _, err := config.Load()
	if err != nil {
		fatalf("config: %v", err)
	}
	cfg.LogLevel = g.verbose

	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "get":
		return cmdGet(cfg, g, cmdArgs)
	case "repo":
		return cmdRepo(cfg, g, cmdArgs)
	case "env":
		return cmdEnv(cfg, g, cmdArgs)
	case "doctor":
		return cmdDoctor(cfg, g, cmdArgs)
	case "benchmark", "bench":
		return cmdBenchmark(cfg, g, cmdArgs)
	case "config":
		return cmdConfig(cfg, g, cmdArgs)
	case "proxy":
		return cmdProxy(cfg, g, cmdArgs)
	case "serve":
		return cmdServe(g, cmdArgs)
	case "version":
		fmt.Println(version.String())
		return 0
	case "help", "-h", "--help":
		return cmdHelp()
	}

	// default: wrap the tool
	return wrapper.Run(wrapper.Options{
		Tool:  cmd,
		Args:  cmdArgs,
		Cfg:   cfg,
		Token: resolveToken(cfg, g),
		Server: config.EffectiveServer(g.server, cfg),
		NoProxy:       g.noProxy,
		Apply:         g.apply,
		ForceTunnel:   g.forceTunnel,
		Verbose:       g.verbose,
	})
}

func profilePath(name string) string {
	return config.Dir() + "-profile-" + name + ".json"
}

// resolveToken: flag > env > creds file.
func resolveToken(cfg config.Config, g globals) string {
	if g.token != "" {
		return g.token
	}
	if t := os.Getenv("DLDW_TOKEN"); t != "" {
		return t
	}
	if creds, err := config.LoadCredentials(cfg.TokenFilePath()); err == nil {
		return creds.Token
	}
	return ""
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "dldw: "+format+"\n", args...)
	os.Exit(2)
}

func cmdHelp() int {
	fmt.Print(`dldw - command line download accelerator and controlled proxy

Usage:
  dldw [flags] <tool> [args...]       wrap a tool with the local proxy
  dldw get [flags] <url> [output]     accelerated download (cache fast path)
  dldw env [--shell bash|zsh|fish|powershell|cmd]
  dldw doctor [--fix]
  dldw benchmark --url URL [--mode direct|tunnel|presigned]
  dldw config init|show|set|unset|path
  dldw proxy [--port N]               long-running local proxy
  dldw serve [--config FILE]          run the server (control API + tunnel)
  dldw version

Global flags (before the command/tool):
  --server URL        control API server
  --token TOKEN       device token (else DLDW_TOKEN / token file)
  --profile NAME      alternate config profile
  --no-proxy          run the wrapped tool without the local proxy
  --apply             let adapters write tool configs (apt/dnf/conda/npm)
  --direct-fallback / --no-direct-fallback
  --force-tunnel      debug: tunnel everything whitelisted-or-not (SSRF still applies)
  -v / -vv            verbose logging

Configuration:
  dldw config init writes an ANNOTATED ~/.dldw/config.yaml template -
  every option is documented inline; edit it freely. "dldw config set"
  writes ~/.dldw/config.json which then takes precedence over the yaml.
  Server config: see deploy/server.example.yaml (annotated).

Examples:
  dldw git clone https://github.com/org/repo.git
  dldw curl -L -O https://github.com/org/repo/releases/download/v1/app.tar.gz
  dldw get https://github.com/org/repo/releases/download/v1/app.tar.gz
  dldw get --concurrency 16 --chunk 32MiB URL
  eval $(dldw env)
`)
	return 0
}
