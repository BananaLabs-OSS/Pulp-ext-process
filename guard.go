package processext

// Security guard for spawn.process. Running an arbitrary host command is the
// single most dangerous capability a cell can hold, so the guard is the heart
// of this extension. Two independent, fail-closed allowlists:
//
//   1. WHICH binary may run  — PROCESS_ALLOW_BINS (the toolchain a cell needs:
//      "go,git,claude"). Empty/unset => deny every command.
//   2. WHERE it may run      — PROCESS_RUN_ROOTS (dirs the command's working
//      directory must sit under). Empty/unset => a command may only run with no
//      explicit dir (the host cwd); any requested dir is rejected.
//
// There is deliberately NO shell: argv is exec'd directly (argv[0] + args),
// never "sh -c <string>", which removes the entire shell-injection surface.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	errNoArgv        = errors.New("process guard: argv is empty")
	errBinNotAllowed = errors.New("process guard: argv[0] is not in the allowed-binaries set")
	errDirNotAllowed = errors.New("process guard: working dir is not under an allowed run root")
)

// allowedBins returns the set of permitted command names from
// PROCESS_ALLOW_BINS (comma-separated). An entry may be a bare base name
// ("go", "git") matched against the command's base name, or an absolute path
// matched exactly against the resolved executable. Empty/unset => nil =>
// deny-all (fail closed).
func allowedBins() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv("PROCESS_ALLOW_BINS"))
	if raw == "" {
		return nil
	}
	set := map[string]struct{}{}
	for _, e := range strings.Split(raw, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		set[e] = struct{}{}
	}
	return set
}

// binBase normalizes a command name to the base used for allowlist matching:
// the file name without a Windows .exe/.bat/.cmd extension, lowercased. So
// "go", "go.exe", and an absolute "C:\\...\\go.exe" all match an allow entry
// of "go".
func binBase(name string) string {
	b := strings.ToLower(filepath.Base(name))
	for _, ext := range []string{".exe", ".bat", ".cmd", ".com"} {
		if strings.HasSuffix(b, ext) {
			return strings.TrimSuffix(b, ext)
		}
	}
	return b
}

// validateBin reports whether arg0 (the requested command) and resolved (its
// exec.LookPath result, or "" if not yet resolved) are permitted by the
// allow-set. An absolute allow entry must match the resolved path exactly; a
// bare entry matches the base name of either arg0 or the resolved path.
func validateBin(arg0, resolved string, allow map[string]struct{}) error {
	if len(allow) == 0 {
		return fmt.Errorf("%w: %q (PROCESS_ALLOW_BINS is empty)", errBinNotAllowed, arg0)
	}
	// Exact absolute-path allow.
	if resolved != "" {
		if _, ok := allow[resolved]; ok {
			return nil
		}
	}
	if _, ok := allow[arg0]; ok {
		return nil
	}
	// Bare base-name allow.
	base := binBase(arg0)
	if _, ok := allow[base]; ok {
		return nil
	}
	if resolved != "" {
		if _, ok := allow[binBase(resolved)]; ok {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", errBinNotAllowed, arg0)
}

// allowedRoots returns the configured run roots from PROCESS_RUN_ROOTS
// (OS-path-list separated), each made absolute + symlink-resolved + cleaned.
// Empty/unset => nil.
func allowedRoots() []string {
	raw := strings.TrimSpace(os.Getenv("PROCESS_RUN_ROOTS"))
	if raw == "" {
		return nil
	}
	var roots []string
	for _, e := range filepath.SplitList(raw) {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		abs, err := filepath.Abs(e)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		roots = append(roots, filepath.Clean(abs))
	}
	return roots
}

// pathContains reports whether target == base or target is nested under base.
// Both are cleaned absolute paths. The separator check prevents the
// sibling-prefix bypass (/srcfoo is NOT under /src). Mirrors ext-docker.
func pathContains(base, target string) bool {
	if base == target {
		return true
	}
	sep := string(filepath.Separator)
	if strings.HasSuffix(base, sep) {
		return strings.HasPrefix(target, base)
	}
	return strings.HasPrefix(target, base+sep)
}

// validateDir reports whether dir is a permitted working directory. An empty
// dir means "run in the host cwd" and is always allowed. A non-empty dir must
// resolve (symlink-eval'd) to a path under one of roots; if roots is empty,
// any explicit dir is rejected (fail closed).
func validateDir(dir string, roots []string) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errDirNotAllowed, err)
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = filepath.Clean(resolved)
	}
	for _, root := range roots {
		if pathContains(root, abs) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", errDirNotAllowed, abs)
}
