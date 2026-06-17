//go:build linux

package processext

import (
	"os"
	"os/exec"
	"syscall"
)

// childSysProcAttr puts the child in its own process group (Setpgid) so we can signal
// the WHOLE tree later, and asks the kernel to SIGKILL it if THIS host dies (Pdeathsig)
// — so a crash/hard-exit of the host never leaves orphans holding files open.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// superviseProcess is a no-op on Unix: Setpgid already made the child a group leader,
// so killProcessTree can reach the whole group. (Windows uses a Job Object instead.)
func superviseProcess(proc *os.Process) {}

// killProcessTree SIGKILLs the child's entire process group (negative pid), so
// grandchildren — git-remote-https, a shell's children — die too, not just the leader.
func killProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill() // group gone already / single-process fallback
	}
	return nil
}

// releaseJob is a no-op on Unix (no handle to release).
func releaseJob(proc *os.Process) {}
