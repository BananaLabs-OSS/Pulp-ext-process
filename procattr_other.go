//go:build !windows

package processext

import "syscall"

// noWindowAttr is a no-op off Windows (no console-window concept).
func noWindowAttr() *syscall.SysProcAttr { return nil }
