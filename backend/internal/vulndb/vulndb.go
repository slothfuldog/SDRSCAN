// Package vulndb manages the local vulnerability (CVE) database used by the scan
// engines: it reports the state of the database (by asking `sdrscan-vuln status`)
// and runs `sdrscan-vuln update` as a single background job (one at a time, with
// log, timeout and cancellation). The backend never downloads advisory data
// itself and never starts a shell: the tool is run with an argument array and a
// clean environment.
package vulndb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// Job states.
const (
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

// Error codes of a failed job.
const (
	CodeTimeout      = "timeout"
	CodeUpdateFailed = "update_failed"
	CodeToolNotFound = "tool_not_found"
	CodeCancelled    = "cancelled"
)

// Triggers.
const (
	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
)

// Audit actions.
const (
	AuditStarted   = "vulndb_update_started"
	AuditFinished  = "vulndb_update_finished"
	AuditCancelled = "vulndb_update_cancelled"
)

// AllowedEcosystems is the allow list of `update --ecosystems` values (OSV names,
// one per supported lockfile family: composer.lock, npm/yarn, go.sum, Cargo.lock).
var AllowedEcosystems = []string{"Packagist", "npm", "Go", "crates.io"}

// Errors returned by Start and Cancel.
var (
	ErrNotConfigured   = errors.New("vulnerability database is not configured")
	ErrToolUnavailable = errors.New("sdrscan-vuln is not available")
	ErrInProgress      = errors.New("an update is already running")
	ErrNoneRunning     = errors.New("no update is running")
)

var errCancelled = errors.New("update cancelled")

// lockKey is the PostgreSQL advisory lock that keeps two backend instances from updating at once.
const lockKey int64 = 0x5344525643564c

const (
	maxLogTail   = 16 * 1024
	maxLogLine   = 1000
	slotTol      = 90 * time.Second
	statusTTL    = 5 * time.Second
	defaultStale = 7 * 24 * time.Hour
)

// Config configures the manager. A zero Dir means the feature is not configured.
type Config struct {
	Dir        string        // SDRSCAN_VULN_DB (absolute)
	Bin        string        // SDRSCAN_VULN_BIN
	Timeout    time.Duration // update timeout (default 60m)
	Workdir    string        // parent of the per-update temporary directory
	ScaEnabled bool          // SDRSCAN_SCA_ENABLED, reported to the UI
	Cron       string        // SDRSCAN_VULN_UPDATE_CRON (UTC), "" = no scheduled update
	CACert     string        // SDRSCAN_VULN_CA_CERT: PEM of the CAs trusted by the updater (--ca-cert), "" = system store
	// KillGrace is the time between SIGTERM and SIGKILL (default 5s).
	KillGrace time.Duration
	// StatusTimeout bounds `sdrscan-vuln status` (default 15s).
	StatusTimeout time.Duration
	// StaleAfter is the data age after which the UI warns (default 7 days).
	StaleAfter time.Duration
}

func (c Config) withDefaults() Config {
	if c.Bin == "" {
		c.Bin = "sdrscan-vuln"
	}
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Minute
	}
	if c.KillGrace <= 0 {
		c.KillGrace = 5 * time.Second
	}
	if c.StatusTimeout <= 0 {
		c.StatusTimeout = 15 * time.Second
	}
	if c.StaleAfter <= 0 {
		c.StaleAfter = defaultStale
	}
	return c
}

// Job is a snapshot of one update run.
type Job struct {
	ID          int64
	State       string
	Trigger     string
	RequestedBy string // username, "" for the scheduler
	Ecosystems  []string
	NVD         bool
	StartedAt   time.Time
	FinishedAt  *time.Time
	ExitCode    *int
	ErrorCode   string
	LogTail     string
}

// Manager runs the database update job and reports the database state.
type Manager struct {
	cfg  Config
	st   *store.Store
	log  *slog.Logger
	base context.Context

	mu       sync.Mutex
	job      *Job
	cancel   context.CancelCauseFunc
	nextID   int64
	lastSlot time.Time
	wg       sync.WaitGroup

	cacheMu  sync.Mutex
	cached   *Status
	cachedEr error
	cachedAt time.Time
}

// New builds a Manager. base ends running updates when cancelled (shutdown).
func New(base context.Context, cfg Config, st *store.Store, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	if base == nil {
		base = context.Background()
	}
	return &Manager{cfg: cfg.withDefaults(), st: st, log: log, base: base}
}

// Config returns the effective configuration.
func (m *Manager) Config() Config { return m.cfg }

// Configured reports whether a database directory is set.
func (m *Manager) Configured() bool { return m.cfg.Dir != "" }

// Wait blocks until a running update has ended (after the base context was cancelled).
func (m *Manager) Wait() { m.wg.Wait() }

// Current returns a copy of the latest job (running or finished), or nil.
func (m *Manager) Current() *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.copyJob()
}

func (m *Manager) copyJob() *Job {
	if m.job == nil {
		return nil
	}
	j := *m.job
	j.Ecosystems = append([]string(nil), m.job.Ecosystems...)
	return &j
}

// ToolAvailable reports whether the sdrscan-vuln executable can be found.
func (m *Manager) ToolAvailable() bool {
	_, err := exec.LookPath(m.cfg.Bin)
	return err == nil
}

// DirPresent reports whether the database directory exists.
func (m *Manager) DirPresent() bool {
	if m.cfg.Dir == "" {
		return false
	}
	st, err := os.Stat(m.cfg.Dir)
	return err == nil && st.IsDir()
}

// StartOptions describe one update.
type StartOptions struct {
	Trigger    string
	Actor      *store.User // nil for the scheduler
	Ecosystems []string    // already validated against AllowedEcosystems; empty = all
	NVD        bool
}

// Start launches an update in the background. It returns ErrNotConfigured,
// ErrToolUnavailable or ErrInProgress without starting anything.
func (m *Manager) Start(opt StartOptions) (Job, error) {
	if m.cfg.Dir == "" {
		return Job{}, ErrNotConfigured
	}
	if !m.ToolAvailable() {
		return Job{}, ErrToolUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job != nil && m.job.State == StateRunning {
		return Job{}, ErrInProgress
	}
	// Another backend instance on the same database may be updating: one update at a time overall.
	var conn *pgxpool.Conn
	var unlock func()
	var release func() // idempotent: frees the advisory lock and the connection
	if m.st != nil {
		c, err := m.st.Pool.Acquire(m.base)
		if err != nil {
			return Job{}, err
		}
		var got bool
		if err := c.QueryRow(m.base, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil {
			c.Release()
			return Job{}, err
		}
		if !got {
			c.Release()
			return Job{}, ErrInProgress
		}
		conn = c
		unlock = func() { _, _ = c.Exec(context.WithoutCancel(m.base), `SELECT pg_advisory_unlock($1)`, lockKey) }
	}
	if err := os.MkdirAll(m.cfg.Dir, 0o750); err != nil {
		if unlock != nil {
			unlock()
			conn.Release()
		}
		return Job{}, fmt.Errorf("cannot create the database directory: %w", err)
	}
	m.nextID++
	j := &Job{ID: m.nextID, State: StateRunning, Trigger: opt.Trigger, Ecosystems: append([]string(nil), opt.Ecosystems...),
		NVD: opt.NVD, StartedAt: time.Now().UTC()}
	if j.Trigger == "" {
		j.Trigger = TriggerManual
	}
	var actorID *int64
	actorName := "scheduler"
	if opt.Actor != nil {
		j.RequestedBy, actorName = opt.Actor.Username, opt.Actor.Username
		id := opt.Actor.ID
		actorID = &id
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			if unlock != nil {
				unlock()
				conn.Release()
			}
		})
	}
	m.job = j
	ctx, cancel := context.WithCancelCause(m.base)
	m.cancel = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel(nil)
		defer release()
		m.run(ctx, j.ID, actorID, actorName, release)
	}()
	m.audit(actorID, actorName, AuditStarted, describe(j))
	return *m.snapshotLocked(j), nil
}

func (m *Manager) snapshotLocked(j *Job) *Job {
	c := *j
	c.Ecosystems = append([]string(nil), j.Ecosystems...)
	return &c
}

func describe(j *Job) string {
	eco := "all ecosystems"
	if len(j.Ecosystems) > 0 {
		eco = strings.Join(j.Ecosystems, ",")
	}
	s := fmt.Sprintf("#%d (%s)", j.ID, eco)
	if j.NVD {
		s += " +nvd"
	}
	return s
}

// Cancel asks the running update to stop. It returns ErrNoneRunning when none runs.
func (m *Manager) Cancel(actor *store.User) (Job, error) {
	m.mu.Lock()
	if m.job == nil || m.job.State != StateRunning || m.cancel == nil {
		m.mu.Unlock()
		return Job{}, ErrNoneRunning
	}
	cancel, j := m.cancel, *m.snapshotLocked(m.job)
	m.mu.Unlock()
	cancel(errCancelled)
	var id *int64
	name := "scheduler"
	if actor != nil {
		i := actor.ID
		id, name = &i, actor.Username
	}
	m.audit(id, name, AuditCancelled, fmt.Sprintf("#%d", j.ID))
	return j, nil
}

func (m *Manager) audit(actorID *int64, actorName, action, target string) {
	if m.st != nil {
		m.st.Audit(context.WithoutCancel(m.base), nil, actorID, actorName, action, target)
	}
}

// ScheduledTick starts a scheduled update when a slot of SDRSCAN_VULN_UPDATE_CRON is due. Each
// slot is used once. It is called once a minute by the scheduler leader.
func (m *Manager) ScheduledTick(now time.Time) {
	if m.cfg.Cron == "" || m.cfg.Dir == "" {
		return
	}
	slot, ok := scanner.LatestSlot(m.cfg.Cron, now, slotTol)
	if !ok {
		return
	}
	m.mu.Lock()
	if slot.Equal(m.lastSlot) {
		m.mu.Unlock()
		return
	}
	m.lastSlot = slot
	m.mu.Unlock()
	if _, err := m.Start(StartOptions{Trigger: TriggerSchedule}); err != nil {
		m.log.Warn("scheduled vulnerability database update not started", "err", err)
	}
}

// run executes the job. release frees the cross-instance lock; it is called before the final state is
// published, so a client that sees "finished" can start the next update at once.
func (m *Manager) run(ctx context.Context, id int64, actorID *int64, actorName string, release func()) {
	tctx, tcancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer tcancel()

	m.mu.Lock()
	j := m.job
	args := []string{"update", "--db", m.cfg.Dir}
	if len(j.Ecosystems) > 0 {
		args = append(args, "--ecosystems", strings.Join(j.Ecosystems, ","))
	}
	if j.NVD {
		args = append(args, "--nvd")
	}
	if m.cfg.CACert != "" {
		args = append(args, "--ca-cert", m.cfg.CACert)
	}
	m.mu.Unlock()

	tmpParent := m.cfg.Workdir
	if tmpParent != "" {
		_ = os.MkdirAll(tmpParent, 0o700)
	}
	tmp, terr := os.MkdirTemp(tmpParent, "vulnupdate-")
	if terr != nil {
		release()
		m.finish(id, StateFailed, CodeUpdateFailed, nil, "cannot create a temporary directory")
		return
	}
	defer os.RemoveAll(tmp)

	m.appendLog(id, "starting sdrscan-vuln update")
	lw := &lineWriter{emit: func(line string) { m.appendLog(id, line) }}
	cmd := exec.CommandContext(tctx, m.cfg.Bin, args...)
	cmd.Env = m.env(tmp)
	cmd.Dir = tmp
	cmd.Stdout, cmd.Stderr = lw, lw
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var killTimer *time.Timer
	cmd.Cancel = func() error {
		pid := cmd.Process.Pid
		err := syscall.Kill(-pid, syscall.SIGTERM)
		killTimer = time.AfterFunc(m.cfg.KillGrace, func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
		return err
	}
	cmd.WaitDelay = m.cfg.KillGrace + time.Second
	err := cmd.Run()
	if killTimer != nil {
		killTimer.Stop()
	}
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // no stray children
	}
	lw.flush()
	release()

	exit := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		exit = ee.ExitCode()
	default:
		exit = -1
	}
	switch {
	case ctx.Err() != nil: // cancelled by an Admin or by shutdown
		m.finish(id, StateCancelled, CodeCancelled, &exit, "update cancelled")
	case tctx.Err() == context.DeadlineExceeded:
		m.finish(id, StateFailed, CodeTimeout, &exit, fmt.Sprintf("update exceeded the time limit of %s", m.cfg.Timeout))
	case err == nil:
		m.finish(id, StateSucceeded, "", &exit, "update finished")
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EACCES):
		m.finish(id, StateFailed, CodeToolNotFound, nil, "the sdrscan-vuln executable was not found")
	default:
		m.finish(id, StateFailed, CodeUpdateFailed, &exit, fmt.Sprintf("update failed (exit code %d)", exit))
	}
	m.invalidateStatus()
	m.mu.Lock()
	done := m.snapshotLocked(m.job)
	m.mu.Unlock()
	m.audit(actorID, actorName, AuditFinished, fmt.Sprintf("#%d %s", done.ID, outcome(done)))
	m.log.Info("vulnerability database update finished", "id", done.ID, "state", done.State, "error_code", done.ErrorCode,
		"duration", done.FinishedAt.Sub(done.StartedAt).Round(time.Second))
}

func outcome(j *Job) string {
	if j.ErrorCode != "" {
		return j.State + " (" + j.ErrorCode + ")"
	}
	return j.State
}

func (m *Manager) finish(id int64, state, code string, exit *int, msg string) {
	m.appendLog(id, msg)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job == nil || m.job.ID != id {
		return
	}
	now := time.Now().UTC()
	m.job.State, m.job.ErrorCode, m.job.FinishedAt = state, code, &now
	if exit != nil {
		e := *exit
		m.job.ExitCode = &e
	}
	m.cancel = nil
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func cleanLine(s string) string {
	s = ansi.ReplaceAllString(s, "")
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	s = strings.TrimSpace(scanner.Sanitize(s))
	if utf8.RuneCountInString(s) > maxLogLine {
		s = string([]rune(s)[:maxLogLine]) + "…"
	}
	return s
}

func (m *Manager) appendLog(id int64, line string) {
	line = cleanLine(line)
	if line == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job == nil || m.job.ID != id {
		return
	}
	t := m.job.LogTail + line + "\n"
	if len(t) > maxLogTail {
		t = t[len(t)-maxLogTail:]
		if i := strings.IndexByte(t, '\n'); i >= 0 {
			t = t[i+1:]
		}
		t = strings.ToValidUTF8(t, "")
	}
	m.job.LogTail = t
}

// env is the clean environment of sdrscan-vuln: no database URL, no secret key, no tokens. Only
// what an updater needs to reach the public feeds is passed on (proxy and CA settings, and the
// optional NVD API key that sdrscan-vuln reads from NVD_API_KEY for a higher rate limit).
func (m *Manager) env(home string) []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=" + home, "TMPDIR=" + home, "LANG=C.UTF-8", "SDRSCAN_VULN_DB=" + m.cfg.Dir}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "NVD_API_KEY"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// lineWriter splits process output into lines.
type lineWriter struct {
	mu   sync.Mutex
	buf  []byte
	emit func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexAny(w.buf, "\r\n")
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		w.emit(line)
	}
	if len(w.buf) > 8*maxLogLine { // a line without a newline: do not grow without bound
		w.emit(string(w.buf))
		w.buf = nil
	}
	return len(p), nil
}

func (w *lineWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.emit(string(w.buf))
		w.buf = nil
	}
}

// capture runs the tool and returns its output (bounded).
func (m *Manager) capture(ctx context.Context, args ...string) (stdout, stderr string, exit int, notFound bool) {
	tmp := os.TempDir()
	cmd := exec.CommandContext(ctx, m.cfg.Bin, args...)
	cmd.Env = m.env(tmp)
	cmd.Dir = tmp
	var out, errb limited
	out.max, errb.max = 256<<10, 16<<10
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		exit = ee.ExitCode()
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.EACCES):
		exit, notFound = -1, true
	default:
		exit = -1
	}
	return out.String(), errb.String(), exit, notFound
}

type limited struct {
	max int
	b   []byte
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.max - len(l.b); room > 0 {
		if len(p) > room {
			l.b = append(l.b, p[:room]...)
		} else {
			l.b = append(l.b, p...)
		}
	}
	return len(p), nil
}

func (l *limited) String() string { return string(l.b) }

var _ io.Writer = (*limited)(nil)
