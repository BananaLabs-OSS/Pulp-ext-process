package processext

import (
	"context"
	"log/slog"
	"os/exec"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// TestPool_RunsAllowedCommand drives the real exec path (not just the guard):
// submit an allowlisted command, poll to completion, decode the result. Uses
// `go version` because the Go toolchain is guaranteed present in this module's
// build/test environment and exits 0 deterministically.
func TestPool_RunsAllowedCommand(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	t.Setenv("PROCESS_ALLOW_BINS", "go")

	p := newProcPool(slog.Default(), 4, 16, 4, defaultMaxOutputBytes)
	defer p.teardownAll()

	id, code := p.submit("cellA", runRequest{Argv: []string{"go", "version"}})
	if code != codeOK {
		t.Fatalf("submit returned code %d; want OK", code)
	}
	if id < firstTaskID {
		t.Fatalf("submit returned id %d; want >= %d", id, firstTaskID)
	}

	data, status := pollUntilDone(t, p, "cellA", id)
	if status != statusComplete {
		t.Fatalf("status = %d; want complete (%d)", status, statusComplete)
	}
	var res runResult
	if err := msgpack.Unmarshal(data, &res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit_code = %d; want 0 (stderr=%q)", res.ExitCode, res.Stderr)
	}
	if len(res.Stdout) == 0 {
		t.Error("stdout empty; expected `go version` output")
	}
}

// TestPool_DeniedBinaryNeverRuns confirms the guard blocks at submit time: an
// un-allowlisted binary returns codeBinDenied and is never executed.
func TestPool_DeniedBinaryNeverRuns(t *testing.T) {
	t.Setenv("PROCESS_ALLOW_BINS", "go") // git/anything-else NOT allowed
	p := newProcPool(slog.Default(), 4, 16, 4, defaultMaxOutputBytes)
	defer p.teardownAll()

	_, code := p.submit("cellA", runRequest{Argv: []string{"git", "status"}})
	if code != codeBinDenied {
		t.Fatalf("submit(git) returned code %d; want codeBinDenied (%d)", code, codeBinDenied)
	}
}

// TestPool_CrossCellResultIsolation confirms a cell cannot poll another cell's
// task result — the per-cell ownership check returns statusUnknown.
func TestPool_CrossCellResultIsolation(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	t.Setenv("PROCESS_ALLOW_BINS", "go")
	p := newProcPool(slog.Default(), 4, 16, 4, defaultMaxOutputBytes)
	defer p.teardownAll()

	id, code := p.submit("owner", runRequest{Argv: []string{"go", "version"}})
	if code != codeOK {
		t.Fatalf("submit code %d", code)
	}
	// A different cell polling the same id must get statusUnknown, never the data.
	if _, status := p.result("intruder", id); status != statusUnknown {
		t.Fatalf("cross-cell poll status = %d; want statusUnknown (%d)", status, statusUnknown)
	}
	// The owner still gets its result.
	if _, status := pollUntilDoneCtx(t, p, "owner", id); status != statusComplete {
		t.Fatalf("owner poll status = %d; want complete", status)
	}
}

func pollUntilDone(t *testing.T, p *procPool, cellID string, id uint32) ([]byte, uint32) {
	t.Helper()
	return pollUntilDoneCtx(t, p, cellID, id)
}

func pollUntilDoneCtx(t *testing.T, p *procPool, cellID string, id uint32) ([]byte, uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		data, status := p.result(cellID, id)
		if status != statusPending {
			return data, status
		}
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for task")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
