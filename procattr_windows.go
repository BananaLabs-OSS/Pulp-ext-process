//go:build windows

package processext

import "syscall"

// noWindowAttr makes a spawned child create NO console window. The host bundle is linked
// GUI-subsystem (-H windowsgui) and has no console of its own; without this, each console
// child (go build, git, `ctl reload`, the desktop helper) would FLASH its own console
// window. CREATE_NO_WINDOW (0x08000000) + HideWindow suppress that.
func noWindowAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
