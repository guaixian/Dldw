package wrapper

import "os/exec"

func execLook(name string) (string, error) { return exec.LookPath(name) }
