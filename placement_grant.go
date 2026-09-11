package processext

import (
	"encoding/json"
	"errors"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type scopedProcessPolicy struct {
	executable, root, kind string
	argv                   []string
	env                    map[string]string
	maxTimeout             uint32
	maxOutputBytes         int
}

func resolveScopedProcessPolicy(r ext.PlacementGrantResolver, s ext.Scope) (*scopedProcessPolicy, error) {
	g, ok := r.ResolvePlacementGrant(s, "spawn.process")
	if !ok {
		return nil, nil
	}
	if (g.Resource != "git-inspect" && g.Resource != "fixed-verification") || !g.Allows("execute") {
		return nil, errors.New("spawn.process: supported execute grant required")
	}
	exe := strings.TrimSpace(g.Attributes["executable"])
	root := strings.TrimSpace(g.Attributes["root"])
	if !filepath.IsAbs(exe) || !filepath.IsAbs(root) {
		return nil, errors.New("spawn.process: scoped executable and root must be absolute")
	}
	resolvedExe, err := exec.LookPath(exe)
	if err != nil {
		return nil, err
	}
	resolvedExe, err = filepath.EvalSymlinks(resolvedExe)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("spawn.process: scoped root must be directory")
	}
	p := &scopedProcessPolicy{executable: filepath.Clean(resolvedExe), root: filepath.Clean(root), kind: g.Resource}
	if g.Resource == "fixed-verification" {
		if err := json.Unmarshal([]byte(g.Attributes["argv_json"]), &p.argv); err != nil || len(p.argv) == 0 {
			return nil, errors.New("spawn.process: fixed argv_json required")
		}
		if err := json.Unmarshal([]byte(g.Attributes["env_json"]), &p.env); err != nil {
			return nil, errors.New("spawn.process: fixed env_json required")
		}
		n, err := strconv.ParseUint(g.Attributes["max_timeout_ms"], 10, 32)
		if err != nil || n == 0 || n > uint64(maxTimeout/time.Millisecond) {
			return nil, errors.New("spawn.process: invalid fixed timeout")
		}
		p.maxTimeout = uint32(n)
		out, err := strconv.Atoi(g.Attributes["max_output_bytes"])
		if err != nil || out < 1 || out > defaultMaxOutputBytes {
			return nil, errors.New("spawn.process: invalid output bound")
		}
		p.maxOutputBytes = out
	}
	return p, nil
}
func (p *scopedProcessPolicy) validate(q runRequest, resolved string) error {
	if p.kind == "fixed-verification" {
		if !reflect.DeepEqual(q.Argv, p.argv) {
			return errors.New("verification argv denied")
		}
		if !reflect.DeepEqual(q.Env, p.env) {
			return errors.New("verification environment denied")
		}
		if q.TimeoutMs == 0 || q.TimeoutMs > p.maxTimeout || q.TimeoutMs == noTimeoutSentinel {
			return errors.New("verification timeout denied")
		}
		return p.validateExecutableRoot(q, resolved)
	}
	if len(q.Argv) < 2 {
		return errors.New("git subcommand required")
	}
	if err := p.validateExecutableRoot(q, resolved); err != nil {
		return err
	}
	for k := range q.Env {
		if k != "GIT_TERMINAL_PROMPT" && k != "GCM_INTERACTIVE" {
			return errors.New("environment denied")
		}
	}
	allowed := map[string]bool{"rev-parse": true, "status": true, "symbolic-ref": true, "remote": true, "log": true, "diff": true}
	sub := q.Argv[1]
	if !allowed[sub] {
		return errors.New("git mutation denied")
	}
	if sub == "remote" && (len(q.Argv) != 4 || q.Argv[2] != "get-url") {
		return errors.New("git remote mutation denied")
	}
	if sub == "symbolic-ref" && !(len(q.Argv) == 5 && q.Argv[2] == "--quiet" && q.Argv[3] == "--short" && q.Argv[4] == "HEAD") {
		return errors.New("git symbolic-ref mutation denied")
	}
	for _, a := range q.Argv[1:] {
		if strings.HasPrefix(a, "-C") || strings.HasPrefix(a, "--git-dir") || strings.HasPrefix(a, "--work-tree") || strings.HasPrefix(a, "--config") || strings.HasPrefix(a, "-c") {
			return errors.New("git root/config option denied")
		}
		if a == "--no-index" || a == "--output" || strings.HasPrefix(a, "--output=") || filepath.IsAbs(a) || a == ".." || strings.HasPrefix(a, "../") || strings.Contains(a, "/../") {
			return errors.New("git path escape denied")
		}
	}
	return nil
}

func (p *scopedProcessPolicy) validateExecutableRoot(q runRequest, resolved string) error {
	r, err := filepath.EvalSymlinks(resolved)
	if err != nil || filepath.Clean(r) != p.executable {
		return errors.New("executable denied")
	}
	dir, err := filepath.EvalSymlinks(q.Dir)
	if err != nil || filepath.Clean(dir) != p.root {
		return errors.New("working root denied")
	}
	return nil
}
