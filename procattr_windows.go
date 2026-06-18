//go:build windows

package processext

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// childSysProcAttr makes a spawned child create NO console window. The host bundle is
// linked GUI-subsystem (-H windowsgui) and has no console of its own; without this, each
// console child (go build, git, `ctl reload`, the desktop helper) would FLASH its own
// console window. CREATE_NO_WINDOW + HideWindow suppress that.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// jobs maps a child PID to the Job Object it was assigned to, so an explicit kill
// (timeout / cancel / teardown) can terminate the whole tree, and normal completion
// can release the handle.
var (
	jobsMu sync.Mutex
	jobs   = map[int]windows.Handle{}
)

// superviseProcess puts the freshly-started child in its OWN Job Object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The host process holds the only handle, so:
//   - explicit kill → TerminateJobObject reaps the child AND its descendants
//     (git's git-remote-https grandchild, a shell's children, …);
//   - host exit — even a bare os.Exit(0) or a crash — closes the handle, and the OS
//     terminates the job, so NOTHING is left orphaned holding the toolchain dir open.
//
// (There is a microscopic race: a grandchild spawned between Start and assignment isn't
// captured. In practice nothing spawns that fast; assignment lands within microseconds.)
func superviseProcess(proc *os.Process) {
	if proc == nil {
		return
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			// KILL_ON_JOB_CLOSE reaps normal children when the host dies. BREAKAWAY_OK
			// lets a child that EXPLICITLY asks (CREATE_BREAKAWAY_FROM_JOB) escape the
			// job — used ONLY by the self-replace helper, which must outlive the host it
			// is replacing. Ordinary children (no breakaway flag) are unaffected.
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(proc.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		windows.CloseHandle(job)
		return
	}
	jobsMu.Lock()
	jobs[proc.Pid] = job
	jobsMu.Unlock()
}

// killProcessTree terminates the child and every descendant via its Job Object. Called
// from cmd.Cancel on timeout/cancel/teardown. Falls back to a single-process kill if the
// job wasn't recorded (assignment failed).
func killProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	jobsMu.Lock()
	job, ok := jobs[cmd.Process.Pid]
	if ok {
		delete(jobs, cmd.Process.Pid)
	}
	jobsMu.Unlock()
	if ok {
		_ = windows.TerminateJobObject(job, 1)
		windows.CloseHandle(job)
		return nil
	}
	return cmd.Process.Kill()
}

// releaseJob closes a job handle after the child exited normally, so a long-running host
// doesn't leak handles. No-op if killProcessTree already consumed it.
func releaseJob(proc *os.Process) {
	if proc == nil {
		return
	}
	jobsMu.Lock()
	job, ok := jobs[proc.Pid]
	if ok {
		delete(jobs, proc.Pid)
	}
	jobsMu.Unlock()
	if ok {
		windows.CloseHandle(job)
	}
}
