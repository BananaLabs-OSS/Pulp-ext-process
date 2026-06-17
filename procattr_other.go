//go:build !windows && !linux

package processext

import (
	"os"
	"os/exec"
	"syscall"
)

// childSysProcAttr puts the child in its own process group so killProcessTree can signal
// the whole tree. (macOS/BSD have no Pdeathsig; graceful teardown does the reaping, and
// git no longer hangs, so a hard-crash orphan is a rare, low-harm edge.)
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// superviseProcess is a no-op off Windows (Setpgid already grouped the child).
func superviseProcess(proc *os.Process) {}

// killProcessTree SIGKILLs the child's whole process group (negative pid).
func killProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}

// releaseJob is a no-op off Windows.
func releaseJob(proc *os.Process) {}
