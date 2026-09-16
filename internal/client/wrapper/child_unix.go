//go:build !windows

package wrapper

import (
	"os"
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the child in its own process group so signals can be
// delivered to the whole tree.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// forwardSignal delivers sig to the child process group.
func forwardSignal(cmd *exec.Cmd, sig os.Signal) {
	if cmd.Process == nil {
		return
	}
	s, ok := sig.(syscall.Signal)
	if !ok {
		s = syscall.SIGTERM
	}
	syscall.Kill(-cmd.Process.Pid, s)
}
