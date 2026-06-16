package processext

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateBin_FailsClosedWhenAllowEmpty(t *testing.T) {
	if err := validateBin("go", "/usr/bin/go", nil); err == nil {
		t.Fatal("validateBin with empty allow-set = nil; want deny (fail closed)")
	}
	if err := validateBin("go", "/usr/bin/go", map[string]struct{}{}); err == nil {
		t.Fatal("validateBin with zero-len allow-set = nil; want deny")
	}
}

func TestValidateBin_BareNameMatch(t *testing.T) {
	allow := map[string]struct{}{"go": {}, "git": {}}
	cases := []struct {
		arg0, resolved string
		want           bool // true = allowed
	}{
		{"go", "/usr/local/go/bin/go", true},
		{"go.exe", `C:\tools\go\bin\go.exe`, true}, // .exe stripped, base matches
		{"git", "/usr/bin/git", true},
		{"claude", "/usr/bin/claude", false}, // not in allow-set
		{"rm", "/bin/rm", false},
		{"node", "", false},
	}
	for _, c := range cases {
		err := validateBin(c.arg0, c.resolved, allow)
		if (err == nil) != c.want {
			t.Errorf("validateBin(%q,%q) allowed=%v; want %v (err=%v)", c.arg0, c.resolved, err == nil, c.want, err)
		}
	}
}

func TestValidateBin_AbsolutePathExactMatch(t *testing.T) {
	abs := filepath.Join(string(filepath.Separator)+"opt", "toolchain", "go")
	allow := map[string]struct{}{abs: {}}
	if err := validateBin(abs, abs, allow); err != nil {
		t.Errorf("absolute allow entry should match resolved path exactly: %v", err)
	}
	// A different binary that happens to share the base name "go" but is NOT
	// the allowlisted absolute path is still allowed only if its base matches —
	// here the allow-set has no bare "go", so a different path is denied.
	other := filepath.Join(string(filepath.Separator)+"tmp", "evil", "go")
	if err := validateBin(other, other, allow); err == nil {
		t.Error("non-allowlisted absolute path matched; want deny")
	}
}

func TestValidateDir_EmptyDirAllowed(t *testing.T) {
	if err := validateDir("", nil); err != nil {
		t.Errorf("empty dir should always be allowed (host cwd): %v", err)
	}
}

func TestValidateDir_FailsClosedWhenRootsEmpty(t *testing.T) {
	if err := validateDir(t.TempDir(), nil); err == nil {
		t.Error("explicit dir with no run-roots configured = nil; want deny (fail closed)")
	}
}

func TestValidateDir_UnderRootAllowed_OutsideDenied(t *testing.T) {
	root := t.TempDir()
	// Resolve symlinks on the root so the comparison base matches validateDir's
	// symlink-eval'd target (macOS /var -> /private/var, etc.).
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	sub := filepath.Join(root, "proj", "a")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	roots := []string{root}

	if err := validateDir(sub, roots); err != nil {
		t.Errorf("dir under configured root should be allowed: %v", err)
	}
	// A sibling that shares a path prefix but is NOT nested must be denied.
	sibling := root + "_evil"
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateDir(sibling, roots); err == nil {
		t.Errorf("sibling-prefix dir %q matched; want deny", sibling)
	}
}

func TestBinBase(t *testing.T) {
	cases := map[string]string{
		"go":                  "go",
		"go.exe":              "go",
		"GO.EXE":              "go",
		`C:\x\y\git.exe`:      "git",
		"/usr/local/bin/node": "node",
		"claude.cmd":          "claude",
	}
	for in, want := range cases {
		if got := binBase(in); got != want {
			t.Errorf("binBase(%q) = %q; want %q", in, got, want)
		}
	}
}
