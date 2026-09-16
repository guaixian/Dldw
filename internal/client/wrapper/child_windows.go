//go:build windows

package wrapper

import (
	"os/exec"
)

// setSysProcAttr: on Windows children share the console; Ctrl+C events reach
// them automatically, so no special attributes are needed.
func setSysProcAttr(cmd *exec.Cmd) {}

// forwardSignal: sending arbitrary signals to unrelated processes is not
// supported on Windows. os.Interrupt (Ctrl+C) is delivered by the console to
// the whole process group already; a hard kill is the only direct option and
// is intentionally NOT done here to preserve normal Ctrl+C semantics.
func forwardSignal(cmd *exec.Cmd, sig any) {}
