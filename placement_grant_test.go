package processext

import (
	"github.com/BananaLabs-OSS/Pulp/ext"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestScopedGrantOverridesDenyAllLegacyAndMapsDotToRoot(t *testing.T) {
	t.Setenv("PROCESS_ALLOW_BINS", "")
	t.Setenv("PROCESS_RUN_ROOTS", "")
	s := procScope(t, "projx", "one")
	p, root := policyFixture(t, s)
	if out, err := exec.Command("git", "init", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	pool := newProcPool(slog.Default(), 1, 4, 1, defaultMaxOutputBytes)
	defer pool.teardownAll()
	id, code := pool.submitPolicy(s.RoutingID(), runRequest{Argv: []string{"git", "status", "--porcelain=v1"}, Dir: "."}, p)
	if code != codeOK || id < firstTaskID {
		t.Fatalf("submit id=%d code=%d", id, code)
	}
	if _, status := pollUntilDone(t, pool, s.RoutingID(), id); status != statusComplete {
		t.Fatalf("status=%d", status)
	}
}

func TestFixedVerificationPolicyIsExactAndBounded(t *testing.T) {
	s := procScope(t, "projx", "one")
	exe, err := exec.LookPath("go")
	if err != nil {
		t.Skip(err)
	}
	exe, _ = filepath.Abs(exe)
	root := t.TempDir()
	r, err := ext.NewStaticPlacementGrants([]ext.PlacementGrant{{Scope: s, Capability: "spawn.process", Resource: "fixed-verification", Rights: []string{"execute"}, Attributes: map[string]string{"executable": exe, "root": root, "argv_json": `["go","test","./..."]`, "env_json": `{"GOWORK":"off"}`, "max_timeout_ms": "5000", "max_output_bytes": "4096"}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := resolveScopedProcessPolicy(r, s)
	if err != nil {
		t.Fatal(err)
	}
	good := runRequest{Argv: []string{"go", "test", "./..."}, Dir: root, Env: map[string]string{"GOWORK": "off"}, TimeoutMs: 5000}
	resolved, _ := exec.LookPath("go")
	if err = p.validate(good, resolved); err != nil {
		t.Fatal(err)
	}
	bad := []runRequest{good, good, good, good}
	bad[0].Argv = []string{"go", "test", "../..."}
	bad[1].Dir = t.TempDir()
	bad[2].Env = map[string]string{"GOWORK": "on"}
	bad[3].TimeoutMs = 5001
	for _, q := range bad {
		if p.validate(q, resolved) == nil {
			t.Fatalf("accepted %#v", q)
		}
	}
	if p.maxOutputBytes != 4096 {
		t.Fatal("output bound lost")
	}
}

func procScope(t *testing.T, app, instance string) ext.Scope {
	t.Helper()
	s, e := ext.NewScope(app, instance, "git", "primary")
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func policyFixture(t *testing.T, s ext.Scope) (*scopedProcessPolicy, string) {
	t.Helper()
	git, e := exec.LookPath("git")
	if e != nil {
		t.Skip("git unavailable")
	}
	git, e = filepath.Abs(git)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	r, e := ext.NewStaticPlacementGrants([]ext.PlacementGrant{{Scope: s, Capability: "spawn.process", Resource: "git-inspect", Rights: []string{"execute"}, Attributes: map[string]string{"executable": git, "root": root}}})
	if e != nil {
		t.Fatal(e)
	}
	p, e := resolveScopedProcessPolicy(r, s)
	if e != nil {
		t.Fatal(e)
	}
	return p, root
}
func TestScopedGitPolicyAllowsInspectionOnly(t *testing.T) {
	s := procScope(t, "projx", "one")
	p, root := policyFixture(t, s)
	git, _ := exec.LookPath("git")
	good := []runRequest{{Argv: []string{"git", "status", "--porcelain=v1"}, Dir: root}, {Argv: []string{"git", "log", "-n", "2", "--", "file"}, Dir: root, Env: map[string]string{"GIT_TERMINAL_PROMPT": "0"}}}
	for _, q := range good {
		if e := p.validate(q, git); e != nil {
			t.Fatalf("denied %#v: %v", q, e)
		}
	}
	bad := []runRequest{{Argv: []string{"git", "commit"}, Dir: root}, {Argv: []string{"git", "-C", "/tmp", "status"}, Dir: root}, {Argv: []string{"git", "status", "--git-dir=/tmp"}, Dir: root}, {Argv: []string{"git", "diff", "--no-index", "/etc/passwd", "/etc/hosts"}, Dir: root}, {Argv: []string{"git", "diff", "--", "../outside"}, Dir: root}, {Argv: []string{"git", "-c", "core.pager=cat", "status"}, Dir: root}, {Argv: []string{"git", "status"}, Dir: t.TempDir()}, {Argv: []string{"git", "status"}, Dir: root, Env: map[string]string{"GIT_CONFIG": "/tmp/x"}}}
	for _, q := range bad {
		if e := p.validate(q, git); e == nil {
			t.Fatalf("allowed %#v", q)
		}
	}
}
func TestScopedGitPolicyCanonicalizesSymlinkRoot(t *testing.T) {
	s := procScope(t, "projx", "one")
	git, _ := exec.LookPath("git")
	git, _ = filepath.Abs(git)
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "repo")
	if e := os.Symlink(real, link); e != nil {
		t.Skip(e)
	}
	r, _ := ext.NewStaticPlacementGrants([]ext.PlacementGrant{{Scope: s, Capability: "spawn.process", Resource: "git-inspect", Rights: []string{"execute"}, Attributes: map[string]string{"executable": git, "root": link}}})
	p, e := resolveScopedProcessPolicy(r, s)
	if e != nil {
		t.Fatal(e)
	}
	if p.root != real {
		t.Fatalf("root=%q want %q", p.root, real)
	}
}
func TestScopedGitPolicyExactScopeAndRights(t *testing.T) {
	s := procScope(t, "projx", "one")
	other := procScope(t, "projx", "two")
	git, _ := exec.LookPath("git")
	git, _ = filepath.Abs(git)
	r, _ := ext.NewStaticPlacementGrants([]ext.PlacementGrant{{Scope: s, Capability: "spawn.process", Resource: "git-inspect", Rights: []string{"execute"}, Attributes: map[string]string{"executable": git, "root": t.TempDir()}}})
	if p, e := resolveScopedProcessPolicy(r, other); e != nil || p != nil {
		t.Fatal("grant crossed scope", p, e)
	}
	noExec, _ := ext.NewStaticPlacementGrants([]ext.PlacementGrant{{Scope: s, Capability: "spawn.process", Resource: "git-inspect", Rights: []string{"observe"}, Attributes: map[string]string{"executable": git, "root": t.TempDir()}}})
	if _, e := resolveScopedProcessPolicy(noExec, s); e == nil {
		t.Fatal("missing execute accepted")
	}
}
