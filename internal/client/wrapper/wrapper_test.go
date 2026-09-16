package wrapper

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"dldw/internal/client/config"
)

// TestWrapEnvInjection runs this very test binary as the wrapped child
// (helper process pattern) and verifies the child sees the proxy env.
func TestWrapEnvInjection(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DLDW_TEST_HELPER", "1")

	var out bytes.Buffer
	code := Run(Options{
		Tool:   exe,
		Args:   []string{"-test.run=TestHelperChild", "-test.v=false"},
		Cfg:    config.Default(),
		Stdout: &out,
		Stderr: io.Discard,
	})
	if code != 0 {
		t.Fatalf("exit code = %d, output = %q", code, out.String())
	}
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PROXY http://127.0.0.1:") {
			return // ok
		}
	}
	t.Fatalf("child did not report proxy env; output = %q", out.String())
}

// TestHelperChild is not a real test: it is spawned by TestWrapEnvInjection.
func TestHelperChild(t *testing.T) {
	if os.Getenv("DLDW_TEST_HELPER") == "" {
		t.Skip("helper only")
	}
	fmt.Printf("PROXY %s\n", os.Getenv("HTTP_PROXY"))
	fmt.Printf("NOPROXY %s\n", os.Getenv("NO_PROXY"))
	os.Exit(0)
}

// TestWrapNoProxy passes through without starting the local proxy.
func TestWrapNoProxy(t *testing.T) {
	if _, lookErr := lookGo(); lookErr != nil {
		t.Skip("go binary not on PATH")
	}
	var out bytes.Buffer
	code := Run(Options{
		Tool:    "go",
		Args:    []string{"version"},
		Cfg:     config.Default(),
		NoProxy: true,
		Stdout:  &out,
		Stderr:  io.Discard,
	})
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, out.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "go version") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestWrapToolNotFound(t *testing.T) {
	code := Run(Options{
		Tool:   "definitely-not-a-real-tool-xyz",
		Args:   nil,
		Cfg:    config.Default(),
		Stderr: io.Discard,
		Stdout: io.Discard,
	})
	if code != 127 {
		t.Fatalf("exit code = %d, want 127", code)
	}
}

// TestWrapExitCodePropagation checks a failing child maps to its code.
func TestWrapExitCodePropagation(t *testing.T) {
	if _, lookErr := lookGo(); lookErr != nil {
		t.Skip("go binary not on PATH")
	}
	code := Run(Options{
		Tool:    "go",
		Args:    []string{"env", "-w", "INVALID__KEY=x"}, // fails
		Cfg:     config.Default(),
		NoProxy: true,
		Stderr:  io.Discard,
		Stdout:  io.Discard,
	})
	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
}

func lookGo() (string, error) {
	return execLook("go")
}
