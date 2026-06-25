// Package processext provides the spawn.process capability for Pulp cells:
// the ability to run a host command (e.g. `go build`, `git`, `claude`) as an
// ordinary OS process — NO Docker, NO shell, NO per-OS scripts. plain
// exec.Command, so it is cross-platform by construction.
//
// This is the missing harness primitive that lets a cell build, version, and
// self-rebuild itself: combined with Pulp's live-reload control op, a cell can
// `spawn.process` a `go build -o cell.wasm`, then `pulp ctl reload <cell>` and
// swap in the new code while the host stays up.
//
// Deployment:
//
//	import _ "github.com/BananaLabs-OSS/Pulp-ext-process"
//
// Host imports exposed (all msgpack request/response over linear memory):
//
//	process_run(req_ptr, req_len) -> task_id_or_code   # submit; id>=100 on success
//	process_result(task_id, out_ptr_out, out_len_out) -> status  # consume-once: returns statusUnknown on repeat read
//	process_cancel(task_id) -> code
//	process_pending() -> count  # per-cell inflight count for the calling cell
//
// The run model is async (submit → poll → cancel), mirroring Pulp-ext-workers,
// because a build can take seconds and the cell-side host import must not block
// the step loop. Security is enforced by the guard (guard.go): a fail-closed
// binary allowlist (PROCESS_ALLOW_BINS) and working-dir allowlist
// (PROCESS_RUN_ROOTS), plus per-cell task ownership and a per-cell concurrency
// cap so one cell cannot starve the host.
package processext

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

// Host return codes for process_run. Kept stable; the Fiber/cell-side wrapper
// maps these to typed errors. Task IDs start at firstTaskID so a returned
// uint32 unambiguously distinguishes an id from an error code.
const (
	codeOK             = 0
	codeEmptyReq       = 1
	codeMemRead        = 2
	codeMsgpackDecode  = 3
	codeInvalidRequest = 4
	codeBinDenied      = 5
	codeDirDenied      = 6
	codeQueueFull      = 15
	codeCellFull       = 16
	codeSaturated      = 17
	codeAllocFailed    = 7
	codeMemWrite       = 8
	codeCapAbsent      = 99
)

// process_result status codes.
const (
	statusPending  = 0
	statusComplete = 1
	statusError    = 2 // failed to start / guard rejected after submit / internal error
	statusUnknown  = 4
)

const (
	defaultMaxConcurrency = 16
	defaultMaxQueued      = 256
	defaultMaxPerCell     = 4
	defaultTimeout        = 5 * time.Minute
	maxTimeout            = 60 * time.Minute
	resultTTL             = 10 * time.Minute
	noTimeoutSentinel     = 0xFFFFFFFF // TimeoutMs value meaning "long-lived, no deadline"
	firstTaskID           = 100
	// defaultMaxOutputBytes caps stdout+stderr buffered per task so a runaway
	// command (a build dumping unbounded logs) cannot OOM the host. Override
	// via PROCESS_MAX_OUTPUT_BYTES.
	defaultMaxOutputBytes = 32 * 1024 * 1024 // 32 MiB
)

var pool *procPool

func init() {
	ext.Register(ext.Capability{
		Name:         "spawn.process",
		Setup:        setup,
		Teardown:     teardown,
		TeardownCell: teardownCell,
		Register:     bindActive,
		Stub:         bindStub,
	})
}

// ---- request / result types ----------------------------------------------

type runRequest struct {
	Argv      []string          `msgpack:"argv"`
	Dir       string            `msgpack:"dir,omitempty"`
	Env       map[string]string `msgpack:"env,omitempty"`
	TimeoutMs uint32            `msgpack:"timeout_ms,omitempty"`
}

type runResult struct {
	ExitCode int    `msgpack:"exit_code"`
	Stdout   []byte `msgpack:"stdout"`
	Stderr   []byte `msgpack:"stderr"`
	Error    string `msgpack:"error,omitempty"`
}

// ---- pool ----------------------------------------------------------------

type taskResult struct {
	data      []byte // msgpack runResult
	status    uint32
	completed time.Time
	cellID    string
}

type inflightTask struct {
	cancel context.CancelFunc
	done   chan struct{}
	cellID string
}

type procPool struct {
	logger         *slog.Logger
	maxOutputBytes int

	allowBins  map[string]struct{}
	allowRoots []string

	sem       chan struct{}
	maxQueued int

	cellsMu    sync.Mutex
	cellCount  map[string]int
	maxPerCell int

	nextID atomic.Uint32

	mu       sync.Mutex
	inflight map[uint32]*inflightTask
	results  map[uint32]*taskResult

	cleanupStop context.CancelFunc
	cleanupDone chan struct{}
}

func newProcPool(logger *slog.Logger, maxConcurrency, maxQueued, maxPerCell, maxOutputBytes int) *procPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &procPool{
		logger:         logger,
		maxOutputBytes: maxOutputBytes,
		allowBins:      allowedBins(),
		allowRoots:     allowedRoots(),
		sem:            make(chan struct{}, maxConcurrency),
		maxQueued:      maxQueued,
		cellCount:      map[string]int{},
		maxPerCell:     maxPerCell,
		inflight:       map[uint32]*inflightTask{},
		results:        map[uint32]*taskResult{},
		cleanupStop:    cancel,
		cleanupDone:    make(chan struct{}),
	}
	go p.cleanupLoop(ctx)
	return p
}

func (p *procPool) acquireCell(cellID string) bool {
	if cellID == "" {
		return true
	}
	p.cellsMu.Lock()
	defer p.cellsMu.Unlock()
	if p.cellCount[cellID] >= p.maxPerCell {
		return false
	}
	p.cellCount[cellID]++
	return true
}

func (p *procPool) releaseCell(cellID string) {
	if cellID == "" {
		return
	}
	p.cellsMu.Lock()
	defer p.cellsMu.Unlock()
	if p.cellCount[cellID] > 0 {
		p.cellCount[cellID]--
	}
	if p.cellCount[cellID] == 0 {
		delete(p.cellCount, cellID)
	}
}

func (p *procPool) inflightCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.inflight)
}

// submit validates the request, reserves slots, and launches the command in a
// goroutine. Returns (id, codeOK) or (0, errorCode).
func (p *procPool) submit(cellID string, req runRequest) (uint32, uint32) {
	if len(req.Argv) == 0 || strings.TrimSpace(req.Argv[0]) == "" {
		return 0, codeInvalidRequest
	}
	// Guard BEFORE reserving any slot — a denied command never consumes quota.
	resolved, _ := exec.LookPath(req.Argv[0])
	if err := validateBin(req.Argv[0], resolved, p.allowBins); err != nil {
		p.logger.Warn("spawn.process: binary denied", "cell", cellID, "argv0", req.Argv[0], "err", err)
		return 0, codeBinDenied
	}
	if err := validateDir(req.Dir, p.allowRoots); err != nil {
		p.logger.Warn("spawn.process: dir denied", "cell", cellID, "dir", req.Dir, "err", err)
		return 0, codeDirDenied
	}

	if p.inflightCount() >= p.maxQueued {
		return 0, codeQueueFull
	}
	// Long-lived helpers (TimeoutMs == noTimeoutSentinel: the screen-stream helper, a
	// port-forward listener) must NOT consume the per-cell cap or the concurrency
	// semaphore — those bound CPU-heavy short jobs (go build, git). Otherwise a few
	// long-lived helpers would lock the cell out of building/self-rebuilding. They're
	// still tracked in `inflight` (so Cancel works) and bound by the total maxQueued.
	longLived := req.TimeoutMs == noTimeoutSentinel
	if !longLived {
		if !p.acquireCell(cellID) {
			return 0, codeCellFull
		}
	}

	var id uint32
	for {
		id = p.nextID.Add(1)
		if id >= firstTaskID {
			break
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	task := &inflightTask{cancel: cancel, done: make(chan struct{}), cellID: cellID}

	p.mu.Lock()
	p.inflight[id] = task
	p.mu.Unlock()

	if !longLived {
		select {
		case p.sem <- struct{}{}:
		default:
			p.mu.Lock()
			delete(p.inflight, id)
			p.mu.Unlock()
			cancel()
			p.releaseCell(cellID)
			return 0, codeSaturated
		}
	}

	go func() {
		defer func() {
			if !longLived {
				<-p.sem
				p.releaseCell(cellID)
			}
			close(task.done)
		}()
		res := p.runCommand(ctx, req)
		data, err := msgpack.Marshal(res)
		status := uint32(statusComplete)
		if err != nil {
			data = []byte(err.Error())
			status = statusError
		} else if res.Error != "" {
			status = statusError
		}
		p.mu.Lock()
		delete(p.inflight, id)
		p.results[id] = &taskResult{data: data, status: status, completed: time.Now(), cellID: cellID}
		p.mu.Unlock()
	}()

	return id, codeOK
}

// runCommand executes argv directly (no shell) with the request's dir/env/
// timeout and returns a runResult. Output is capped at maxOutputBytes.
func (p *procPool) runCommand(parent context.Context, req runRequest) runResult {
	// TimeoutMs == noTimeoutSentinel (max uint32) means a LONG-LIVED process (a
	// screen-stream helper, a port-forward listener): no deadline, but still bound
	// to the parent ctx and cancellable via Cancel. Otherwise apply default/cap.
	var ctx context.Context
	var cancel context.CancelFunc
	if req.TimeoutMs == noTimeoutSentinel {
		ctx, cancel = context.WithCancel(parent)
	} else {
		timeout := defaultTimeout
		if req.TimeoutMs > 0 {
			timeout = time.Duration(req.TimeoutMs) * time.Millisecond
			if timeout > maxTimeout {
				timeout = maxTimeout
			}
		}
		ctx, cancel = context.WithTimeout(parent, timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	// Per-OS spawn attributes: suppress a console window (Windows GUI bundle would else
	// FLASH one per child), and group the child so its WHOLE tree is killable — a Windows
	// Job Object / a Unix process group. Without this, ctx-cancel kills only the direct
	// child and grandchildren (git's git-remote-https, a shell's children) orphan and lock
	// the toolchain dir.
	cmd.SysProcAttr = childSysProcAttr()
	// On timeout/cancel/teardown, kill the whole tree, not just the leader; cap the wait so
	// a wedged process can't block Wait() forever after we've signalled it.
	cmd.Cancel = func() error { return killProcessTree(cmd) }
	cmd.WaitDelay = 5 * time.Second
	if req.Dir != "" {
		cmd.Dir = req.Dir
	}
	// Overlay the requested env onto the host env so PATH/GOROOT/etc. survive.
	if len(req.Env) > 0 {
		env := os.Environ()
		for k, v := range req.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	var stdout, stderr cappedBuffer
	stdout.limit = p.maxOutputBytes
	stderr.limit = p.maxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start/Wait (not Run) so we can enroll the child in its kill-group between the two —
	// on Windows the Job Object is assigned to the live process before it can spawn much.
	if err := cmd.Start(); err != nil {
		return runResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Error: err.Error(), ExitCode: -1}
	}
	superviseProcess(cmd.Process)
	err := cmd.Wait()
	releaseJob(cmd.Process) // free the job handle now the child has exited (no-op off Windows)
	res := runResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Non-zero exit is a normal result, not a transport error: the
			// command ran. Surface the exit code; leave Error empty so the
			// cell branches on exit_code.
			return res
		}
		// Failed to start / timeout / killed: a real error.
		res.Error = err.Error()
		if res.ExitCode == 0 {
			res.ExitCode = -1
		}
	}
	return res
}

func (p *procPool) result(cellID string, id uint32) ([]byte, uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.results[id]; ok {
		if r.cellID != cellID {
			return nil, statusUnknown
		}
		delete(p.results, id)
		return r.data, r.status
	}
	if t, ok := p.inflight[id]; ok {
		if t.cellID != cellID {
			return nil, statusUnknown
		}
		return nil, statusPending
	}
	return nil, statusUnknown
}

func (p *procPool) cancel(cellID string, id uint32) uint32 {
	p.mu.Lock()
	task, ok := p.inflight[id]
	if ok && task.cellID != cellID {
		ok = false
	}
	p.mu.Unlock()
	if !ok {
		return 1
	}
	task.cancel()
	return 0
}

func (p *procPool) pendingCell(cellID string) uint32 {
	p.cellsMu.Lock()
	defer p.cellsMu.Unlock()
	return uint32(p.cellCount[cellID])
}

func (p *procPool) cleanupLoop(ctx context.Context) {
	defer close(p.cleanupDone)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			p.mu.Lock()
			for id, r := range p.results {
				if now.Sub(r.completed) > resultTTL {
					delete(p.results, id)
				}
			}
			p.mu.Unlock()
		}
	}
}

// teardownAll cancels every in-flight task and waits briefly for exit.
func (p *procPool) teardownAll() {
	p.cleanupStop()
	<-p.cleanupDone
	p.mu.Lock()
	tasks := make([]*inflightTask, 0, len(p.inflight))
	for _, t := range p.inflight {
		tasks = append(tasks, t)
	}
	p.mu.Unlock()
	for _, t := range tasks {
		t.cancel()
	}
	deadline := time.After(5 * time.Second)
	for _, t := range tasks {
		select {
		case <-t.done:
		case <-deadline:
			return
		}
	}
}

func (p *procPool) teardownCell(cellID string) int {
	p.mu.Lock()
	tasks := make([]*inflightTask, 0)
	for _, t := range p.inflight {
		if t.cellID == cellID {
			tasks = append(tasks, t)
		}
	}
	for id, r := range p.results {
		if r.cellID == cellID {
			delete(p.results, id)
		}
	}
	p.mu.Unlock()
	for _, t := range tasks {
		t.cancel()
	}
	return len(tasks)
}

// ---- capped buffer -------------------------------------------------------

// cappedBuffer is an io.Writer that buffers up to limit bytes and silently
// drops the rest, so unbounded command output cannot OOM the host. The
// overflow flag is set when bytes are dropped; it is not currently surfaced
// in runResult (no truncation indicator reaches the cell).
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.limit > 0 && c.buf.Len() >= c.limit {
		c.overflow = true
		return len(p), nil // pretend success so the command keeps running
	}
	if c.limit > 0 && c.buf.Len()+len(p) > c.limit {
		c.overflow = true
		n := c.limit - c.buf.Len()
		c.buf.Write(p[:n])
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// ---- lifecycle -----------------------------------------------------------

func setup(env ext.SetupEnv) error {
	logger := env.Logger
	if logger == nil {
		logger = slog.Default()
	}
	pool = newProcPool(logger,
		readIntEnv("PROCESS_MAX_CONCURRENCY", defaultMaxConcurrency),
		readIntEnv("PROCESS_MAX_QUEUED", defaultMaxQueued),
		readIntEnv("PROCESS_MAX_PER_CELL", defaultMaxPerCell),
		readIntEnv("PROCESS_MAX_OUTPUT_BYTES", defaultMaxOutputBytes),
	)
	if len(pool.allowBins) == 0 {
		logger.Error("spawn.process: PROCESS_ALLOW_BINS is empty — all commands will be denied")
	}
	logger.Info("spawn.process ready",
		"allow_bins", os.Getenv("PROCESS_ALLOW_BINS"),
		"run_roots", os.Getenv("PROCESS_RUN_ROOTS"))
	return nil
}

func teardown(_ context.Context) error {
	if pool != nil {
		pool.teardownAll()
	}
	return nil
}

func teardownCell(_ context.Context, cellID string) error {
	if pool != nil {
		pool.teardownCell(cellID)
	}
	return nil
}

func readIntEnv(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// ---- bindings ------------------------------------------------------------

func bindActive(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ""
	if cell != nil {
		cellID = cell.Name()
	}

	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
		if reqLen == 0 {
			return codeEmptyReq
		}
		data, ok := m.Memory().Read(reqPtr, reqLen)
		if !ok {
			return codeMemRead
		}
		var req runRequest
		if err := msgpack.Unmarshal(data, &req); err != nil {
			return codeMsgpackDecode
		}
		id, code := pool.submit(cellID, req)
		if code != codeOK {
			return code
		}
		return id
	}).Export("process_run")

	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, taskID, outPtrOut, outLenOut uint32) uint32 {
		data, status := pool.result(cellID, taskID)
		if status == statusPending || status == statusUnknown {
			return status
		}
		if len(data) == 0 {
			m.Memory().WriteUint32Le(outPtrOut, 0)
			m.Memory().WriteUint32Le(outLenOut, 0)
			return status
		}
		allocFn := m.ExportedFunction("pulp_alloc")
		if allocFn == nil {
			return status
		}
		res, err := allocFn.Call(ctx, uint64(len(data)))
		if err != nil || len(res) == 0 {
			return status
		}
		ptr := uint32(res[0])
		if ptr == 0 || !m.Memory().Write(ptr, data) {
			return status
		}
		m.Memory().WriteUint32Le(outPtrOut, ptr)
		m.Memory().WriteUint32Le(outLenOut, uint32(len(data)))
		return status
	}).Export("process_result")

	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, taskID uint32) uint32 {
		return pool.cancel(cellID, taskID)
	}).Export("process_cancel")

	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module) uint32 {
		return pool.pendingCell(cellID)
	}).Export("process_pending")

	return nil
}

func bindStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return codeCapAbsent }).Export("process_run")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _ uint32) uint32 { return statusUnknown }).Export("process_result")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _ uint32) uint32 { return 1 }).Export("process_cancel")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module) uint32 { return 0 }).Export("process_pending")
	return nil
}
