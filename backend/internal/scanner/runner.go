// Package scanner is the scan runner: a job queue in the scans table, a bounded
// worker pool, safe git clone, engine subprocesses and the DAST guardrails.
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/crypt"
	"github.com/sdrscan/sdrscan/backend/internal/dastauth"
	"github.com/sdrscan/sdrscan/backend/internal/ingest"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// Config tunes the runner.
type Config struct {
	SastBin, DastBin, Templates, Workdir string
	GitBin                               string // default: git from PATH
	Workers                              int
	SastTimeout, DastTimeout             time.Duration
	CloneTimeout                         time.Duration
	GitKnownHosts                        string
	PollInterval                         time.Duration
	LeaseDuration                        time.Duration
	LeaseRenew                           time.Duration
	CancelPoll                           time.Duration
	KillGrace                            time.Duration
	MaxRepoBytes                         int64
	MaxOutputBytes                       int
	MaxSarifBytes                        int64
	WorkdirMaxAge                        time.Duration
	// DastAllowPrivate passes --allow-private-networks-for-tests to sdrscan-dast.
	// Test/demo only (SDRSCAN_TEST_ALLOW_PRIVATE_NETWORKS); default false.
	DastAllowPrivate bool
	// DastBlockPrivateNetworks passes --block-private-networks to sdrscan-dast
	// (SDRSCAN_ALLOW_PRIVATE_NETWORKS=false). By default the engine accepts private networks.
	DastBlockPrivateNetworks bool
	// DastCACert is a PEM file with the CA(s) trusted for HTTPS DAST targets (internal CAs);
	// passed as --ca-cert. Empty means the system trust store.
	DastCACert string
	// DastInsecureTLS passes --insecure: DAST does not verify target certificates.
	// Unsafe, explicit opt-in (SDRSCAN_DAST_INSECURE_TLS); the engine records a warning.
	DastInsecureTLS bool
	// VulnDB is the vulnerability database directory (SDRSCAN_VULN_DB). Empty = CVE checks off.
	// It is passed as --vuln-db to both engines when the directory exists and the engine supports
	// the flag. ScaDisabled (SDRSCAN_SCA_ENABLED=false) switches the CVE checks off even then.
	VulnDB      string
	ScaDisabled bool
}

// WithDefaults fills zero values with the TRD defaults.
func (c Config) WithDefaults() Config {
	def := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	if c.Workers == 0 {
		c.Workers = 2
	}
	def(&c.SastTimeout, 30*time.Minute)
	def(&c.DastTimeout, 60*time.Minute)
	def(&c.CloneTimeout, 5*time.Minute)
	def(&c.PollInterval, 2*time.Second)
	def(&c.LeaseDuration, 2*time.Minute)
	def(&c.LeaseRenew, 30*time.Second)
	def(&c.CancelPoll, time.Second)
	def(&c.KillGrace, 5*time.Second)
	def(&c.WorkdirMaxAge, 24*time.Hour)
	if c.MaxRepoBytes == 0 {
		c.MaxRepoBytes = 1 << 30
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = 1 << 20
	}
	if c.MaxSarifBytes == 0 {
		c.MaxSarifBytes = 50 << 20
	}
	if c.Workdir == "" {
		c.Workdir = filepath.Join(os.TempDir(), "sdrscan")
	}
	return c
}

// Runner executes scan jobs.
type Runner struct {
	Store  *store.Store
	Ingest *ingest.Ingester
	Guard  *netguard.Guard
	Box    *crypt.Box
	Cfg    Config
	Log    *slog.Logger

	gitPath string
	wg      sync.WaitGroup

	probeOnce sync.Once
	dastFlags map[string]bool
	sastFlags map[string]bool
}

// New builds a runner.
func New(st *store.Store, ing *ingest.Ingester, guard *netguard.Guard, box *crypt.Box, cfg Config, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	r := &Runner{Store: st, Ingest: ing, Guard: guard, Box: box, Cfg: cfg.WithDefaults(), Log: log}
	bin := r.Cfg.GitBin
	if bin == "" {
		bin = "git"
	}
	if p, err := exec.LookPath(bin); err == nil {
		r.gitPath = p
	} else if r.Cfg.GitBin != "" {
		r.gitPath = r.Cfg.GitBin // explicitly configured but unusable: fail, do not fall back
	}
	return r
}

// Start launches the worker pool and the sweeper; stop with the context and Wait.
func (r *Runner) Start(ctx context.Context) {
	if err := os.MkdirAll(r.Cfg.Workdir, 0o700); err != nil {
		r.Log.Error("cannot create work directory", "err", err)
	}
	r.sweep(ctx)
	for i := 0; i < r.Cfg.Workers; i++ {
		id := fmt.Sprintf("%s-%d-%d", hostname(), os.Getpid(), i)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.workerLoop(ctx, id)
		}()
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.sweep(ctx)
			}
		}
	}()
}

// Wait blocks until all workers have stopped.
func (r *Runner) Wait() { r.wg.Wait() }

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "host"
	}
	return h
}

func (r *Runner) sweep(ctx context.Context) {
	if n, err := r.Store.SweepLostJobs(ctx); err != nil {
		r.Log.Warn("sweep lost jobs", "err", err)
	} else if n > 0 {
		r.Log.Warn("marked lost jobs as failed", "count", n)
	}
	r.cleanOldWorkdirs()
}

func (r *Runner) cleanOldWorkdirs() {
	entries, err := os.ReadDir(r.Cfg.Workdir)
	if err != nil {
		return
	}
	// A crash can leave an auth file behind: remove those long after any engine could still run.
	authMaxAge := r.Cfg.DastTimeout + r.Cfg.KillGrace + 5*time.Minute
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "scan-") {
			continue
		}
		if files, _ := filepath.Glob(filepath.Join(r.Cfg.Workdir, e.Name(), authFilePrefix+"*")); len(files) > 0 {
			for _, f := range files {
				if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) > authMaxAge {
					_ = os.Remove(f)
				}
			}
		}
		info, err := e.Info()
		if err == nil && time.Since(info.ModTime()) > r.Cfg.WorkdirMaxAge {
			_ = os.RemoveAll(filepath.Join(r.Cfg.Workdir, e.Name()))
		}
	}
}

func (r *Runner) workerLoop(ctx context.Context, workerID string) {
	for ctx.Err() == nil {
		ok, err := r.runNext(ctx, workerID)
		if err != nil {
			r.Log.Error("worker error", "err", err)
		}
		if ok {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.Cfg.PollInterval):
		}
	}
}

// RunOnce claims and processes at most one job synchronously (used by tests).
func (r *Runner) RunOnce(ctx context.Context) (bool, error) {
	return r.runNext(ctx, "runonce-"+hostname())
}

func (r *Runner) runNext(ctx context.Context, workerID string) (bool, error) {
	job, err := r.Store.ClaimJob(ctx, workerID, r.Cfg.LeaseDuration)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	r.process(ctx, workerID, job)
	return true, nil
}

var (
	errCancelRequested = errors.New("cancel requested")
	errLeaseLost       = errors.New("lease lost")
)

// jobFailure is an error with a stable error_code.
type jobFailure struct {
	code string
	msg  string
}

func (e *jobFailure) Error() string { return e.code + ": " + e.msg }

func fail(code, format string, a ...any) *jobFailure {
	return &jobFailure{code: code, msg: fmt.Sprintf(format, a...)}
}

func (r *Runner) process(root context.Context, workerID string, job store.Scan) {
	started := time.Now()
	jctx, jcancel := context.WithCancelCause(root)
	defer jcancel(nil)

	// Watcher: lease renewal and cancel polling.
	done := make(chan struct{})
	var wwg sync.WaitGroup
	wwg.Add(1)
	go func() {
		defer wwg.Done()
		renew := time.NewTicker(r.Cfg.LeaseRenew)
		poll := time.NewTicker(r.Cfg.CancelPoll)
		defer renew.Stop()
		defer poll.Stop()
		for {
			select {
			case <-done:
				return
			case <-jctx.Done():
				return
			case <-renew.C:
				cancel, err := r.Store.RenewLease(context.WithoutCancel(jctx), job.ID, workerID, r.Cfg.LeaseDuration)
				if err == nil && cancel {
					jcancel(errCancelRequested)
					return
				}
			case <-poll.C:
				cancel, err := r.Store.CancelRequested(context.WithoutCancel(jctx), job.ID)
				if err == nil && cancel {
					jcancel(errCancelRequested)
					return
				}
			}
		}
	}()

	err := r.execute(jctx, job)
	close(done)
	wwg.Wait()

	// Outcome.
	fctx := context.WithoutCancel(root)
	cause := context.Cause(jctx)
	switch {
	case err == nil:
		r.Store.AppendLog(fctx, job.ID, "done")
		r.Log.Info("scan finished", "scan_id", job.ID, "codebase_id", job.CodebaseID, "type", job.Type,
			"trigger", job.Trigger, "status", "succeeded", "duration", time.Since(started).Round(time.Millisecond))
	case errors.Is(err, ingest.ErrCancelled), errors.Is(cause, errCancelRequested), root.Err() != nil:
		r.Store.AppendLog(fctx, job.ID, "cancelled")
		r.Store.CancelJob(fctx, job.ID)
		r.Log.Info("scan cancelled", "scan_id", job.ID, "codebase_id", job.CodebaseID)
	default:
		var jf *jobFailure
		if !errors.As(err, &jf) {
			if ae, ok := apierr.As(err); ok && ae.Status == 422 {
				jf = fail("invalid_sarif", "%s", ae.Message)
			} else {
				jf = fail("ingest_failed", "internal error while saving results")
				r.Log.Error("job failed", "scan_id", job.ID, "err", err)
			}
		}
		r.Store.FailJob(fctx, job.ID, jf.code, Sanitize(jf.msg))
		r.Log.Warn("scan failed", "scan_id", job.ID, "codebase_id", job.CodebaseID, "type", job.Type,
			"trigger", job.Trigger, "error_code", jf.code, "duration", time.Since(started).Round(time.Millisecond))
	}
}

func (r *Runner) logf(ctx context.Context, id int64, secrets []string, format string, a ...any) {
	r.Store.AppendLog(ctx, id, Sanitize(fmt.Sprintf(format, a...), secrets...))
}

func (r *Runner) execute(ctx context.Context, job store.Scan) (err error) {
	cb, err := r.Store.GetCodebase(ctx, job.CodebaseID)
	if err != nil {
		return fail("clone_failed", "codebase no longer exists")
	}
	if err := os.MkdirAll(r.Cfg.Workdir, 0o700); err != nil {
		return fail("clone_failed", "cannot create the work directory")
	}
	workdir, err := os.MkdirTemp(r.Cfg.Workdir, fmt.Sprintf("scan-%d-", job.ID))
	if err != nil {
		return fail("clone_failed", "cannot create the work directory")
	}
	defer os.RemoveAll(workdir)
	if err := os.Chmod(workdir, 0o700); err != nil {
		return fail("clone_failed", "cannot secure the work directory")
	}
	sarifPath := filepath.Join(workdir, "result.sarif")
	var secrets []string
	var ref string
	// Whatever happens, no credential value may leave this function inside an error message.
	defer func() {
		var jf *jobFailure
		if err != nil && len(secrets) > 0 && errors.As(err, &jf) {
			err = &jobFailure{code: jf.code, msg: dastauth.Redact(jf.msg, secrets)}
		}
	}()

	timeout := r.Cfg.SastTimeout
	if job.Type == "dast" {
		timeout = r.Cfg.DastTimeout
	}
	tctx, tcancel := context.WithTimeout(ctx, timeout)
	defer tcancel()
	// On failure caused by the timeout, report it as such.
	defer func() {
		if err != nil && tctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			err = fail("timeout", "scan exceeded the time limit of %s", timeout)
		}
	}()

	var res procResult
	switch job.Type {
	case "sast":
		if cb.RepoURL == nil {
			return fail("clone_failed", "codebase has no repository URL")
		}
		branch := "main"
		if cb.Branch != nil && *cb.Branch != "" {
			branch = *cb.Branch
		}
		creds := GitCreds{Kind: cb.GitAuthKind}
		if cb.GitUsername != nil {
			creds.Username = *cb.GitUsername
		}
		if cb.GitAuthKind != "none" {
			if len(cb.GitSecretEnc) == 0 {
				return fail("clone_failed", "the codebase has no stored git credential")
			}
			plain, derr := r.Box.Open(cb.GitSecretEnc)
			if derr != nil {
				return fail("clone_failed", "the stored git credential cannot be decrypted (check SDRSCAN_SECRET_KEY)")
			}
			creds.Secret = string(plain)
			secrets = append(secrets, creds.Secret)
		}
		r.logf(ctx, job.ID, secrets, "cloning %s (branch %s)", *cb.RepoURL, branch)
		cloneDir := filepath.Join(workdir, "repo")
		ref, err = r.clone(tctx, cloneRequest{url: *cb.RepoURL, branch: branch, dir: cloneDir, workdir: workdir, creds: creds}, nil)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if tctx.Err() != nil {
				return tctx.Err()
			}
			if errors.Is(err, errRepoTooLarge) {
				return fail("repo_too_large", "%s", err.Error())
			}
			if errors.Is(err, netguard.ErrAddressNotAllowed) {
				return fail("address_not_allowed", "%s", netguard.ErrBlocked)
			}
			return fail("clone_failed", "%s", Sanitize(err.Error(), secrets...))
		}
		short := ref
		if len(short) > 7 {
			short = short[:7]
		}
		r.logf(ctx, job.ID, secrets, "cloned %s (depth 1)", short)
		root, rerr := resolveRoot(cloneDir, cb.Subdirectory)
		if rerr != nil {
			return fail("clone_failed", "%s", rerr.Error())
		}
		if cancel, _ := r.Store.CancelRequested(context.WithoutCancel(ctx), job.ID); cancel {
			return errCancelRequested
		}
		args := []string{"scan", root, "--format", "sarif", "--output", sarifPath}
		if r.Cfg.Templates != "" {
			args = append(args, "--templates", r.Cfg.Templates)
		}
		args = append(args, r.vulnArgs(ctx, job.ID, "sast")...)
		r.logf(ctx, job.ID, secrets, "running sdrscan-sast")
		res = runProc(tctx, procSpec{bin: r.Cfg.SastBin, args: args, env: r.engineEnv(workdir), dir: workdir,
			grace: r.Cfg.KillGrace, maxOut: r.Cfg.MaxOutputBytes})
	case "dast":
		if cb.BaseURL == nil || cb.DastStatus == nil || *cb.DastStatus != "confirmed" {
			return fail("target_not_confirmed", "the target is not confirmed by an Admin")
		}
		// Scheduled runs re-check the schedule owner's permission at run time.
		if job.Trigger == "schedule" {
			var owner *store.User
			if cb.ScheduleOwnerID != nil {
				if u, uerr := r.Store.GetUser(ctx, *cb.ScheduleOwnerID); uerr == nil {
					owner = &u
				}
			}
			if why := SuspensionFor(cb, owner); why != "" {
				return fail("schedule_suspended", "the schedule owner no longer qualifies (%s)", why)
			}
		}
		u := *cb.BaseURL
		host := hostFromURL(u)
		if herr := r.Guard.CheckResolved(tctx, host); herr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(herr, netguard.ErrAddressNotAllowed) {
				return fail("address_not_allowed", "%s", netguard.ErrBlocked)
			}
			return fail("target_unreachable", "%s", herr.Error())
		}
		args := append([]string{"scan"}, r.dastNetArgs()...)
		args = append(args, u, "--format", "sarif", "--output", sarifPath)
		fl := r.engineFlags("dast")
		if fl["--max-rps"] {
			args = append(args, "--max-rps", fmt.Sprint(cb.DastMaxRPS))
		}
		if fl["--templates"] && r.Cfg.Templates != "" {
			args = append(args, "--templates", r.Cfg.Templates)
		}
		args = append(args, r.vulnArgs(ctx, job.ID, "dast")...)

		// Authenticated scan: the credentials travel in a 0600 file inside the job directory that
		// is deleted as soon as the engine exits (never in argv or the environment).
		authPath := ""
		if cb.HasDastAuth() {
			cfg, jf := r.openAuth(cb)
			if jf != nil {
				return jf
			}
			secrets = append(secrets, dastauth.Secrets(cfg)...)
			if !fl["--auth-file"] {
				return fail("engine_unsupported", "this sdrscan-dast engine does not support authenticated scans (--auth-file); the scan was not run")
			}
			authPath, jf = writeAuthFile(workdir, cfg)
			if jf != nil {
				return jf
			}
			defer os.Remove(authPath)
			args = append(args, "--auth-file", authPath)
			r.logf(ctx, job.ID, secrets, "authenticated scan (%s)", cb.DastAuthType)
		}
		if cb.DastCrawlEnabled {
			cargs, jf := crawlArgs(cb, fl)
			if jf != nil {
				return jf
			}
			if cargs == nil {
				r.logf(ctx, job.ID, secrets, "this sdrscan-dast engine does not support --crawl; crawling skipped")
			} else {
				args = append(args, cargs...)
				r.logf(ctx, job.ID, secrets, "crawl enabled (max depth %d, max pages %d, %d excluded patterns)",
					cb.DastCrawlMaxDepth, cb.DastCrawlMaxPages, len(cb.DastCrawlExclude))
			}
		}
		// Active (payload-sending) scanning: only ever added when the job was explicitly queued with it
		// (a separate, stricter authorization layer checked by the API before the job was created). An
		// engine that does not support it fails the job rather than silently running passive-only.
		if job.Active {
			if !fl["--active"] {
				return fail("engine_unsupported", "this sdrscan-dast engine does not support active scanning (--active); the scan was not run")
			}
			args = append(args, "--active")
			kind := "boolean/error-based/XSS/open-redirect/header-injection"
			if job.ActiveTiming {
				if !fl["--active-timing"] {
					return fail("engine_unsupported", "this sdrscan-dast engine does not support time-based active scanning (--active-timing); the scan was not run")
				}
				args = append(args, "--active-timing")
				kind += "/time-based"
			}
			authorizedBy := "unknown"
			if cb.DastActiveAuthorizedBy != nil {
				if u, uerr := r.Store.GetUser(ctx, *cb.DastActiveAuthorizedBy); uerr == nil {
					authorizedBy = u.Username
				}
			}
			authorizedAt := "unknown date"
			if cb.DastActiveAuthorizedAt != nil {
				authorizedAt = cb.DastActiveAuthorizedAt.UTC().Format("2006-01-02")
			}
			r.logf(ctx, job.ID, secrets, "active scanning authorized by %s on %s, type: %s", authorizedBy, authorizedAt, kind)
			// Optional OpenAPI/Swagger spec: on top of whatever the crawl auto-discovers, this lets
			// active scanning also exercise the API operations the spec describes. Best-effort: an
			// engine without the flag just runs without it (like --templates or --vuln-db).
			if cb.DastOpenAPISpecURL != nil && *cb.DastOpenAPISpecURL != "" {
				if fl["--openapi-spec"] {
					args = append(args, "--openapi-spec", *cb.DastOpenAPISpecURL)
					r.logf(ctx, job.ID, secrets, "OpenAPI/Swagger spec: %s", *cb.DastOpenAPISpecURL)
				} else {
					r.logf(ctx, job.ID, secrets, "this sdrscan-dast engine does not support --openapi-spec; the configured spec was not used")
				}
			}
		}
		r.logf(ctx, job.ID, secrets, "running sdrscan-dast against %s", u)
		res = func() procResult {
			if authPath != "" {
				defer os.Remove(authPath) // also on panic; right after the engine exits
			}
			return runProc(tctx, procSpec{bin: r.Cfg.DastBin, args: args, env: r.engineEnv(workdir), dir: workdir,
				grace: r.Cfg.KillGrace, maxOut: r.Cfg.MaxOutputBytes})
		}()
		if res.exitCode == 0 || res.exitCode == 1 {
			if n, ok := pagesScanned(res.stderr); ok {
				r.logf(ctx, job.ID, secrets, "scan summary: %d pages scanned", n)
			}
			if job.Active {
				if n, ok := activeRequestsSent(res.stderr); ok {
					r.logf(ctx, job.ID, secrets, "%d active requests sent", n)
				}
			}
		}
	default:
		return fail("engine_failed", "unknown scan type")
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if tctx.Err() != nil {
		return tctx.Err()
	}
	if res.notFound {
		return fail("engine_not_found", "the %s engine executable was not found", job.Type)
	}
	if res.exitCode != 0 && res.exitCode != 1 {
		return fail("engine_failed", "engine exited with code %d: %s", res.exitCode, Sanitize(lastLines(res.stderr, 20), secrets...))
	}
	r.logf(ctx, job.ID, secrets, "engine finished with exit code %d", res.exitCode)
	r.logEngineWarnings(ctx, job.ID, res.stderr, secrets)
	if cancel, _ := r.Store.CancelRequested(context.WithoutCancel(ctx), job.ID); cancel {
		return errCancelRequested
	}

	st, serr := os.Stat(sarifPath)
	if serr != nil {
		return fail("invalid_sarif", "the engine produced no SARIF file")
	}
	if st.Size() > r.Cfg.MaxSarifBytes {
		return fail("invalid_sarif", "the SARIF file exceeds the size limit")
	}
	body, rerr := os.ReadFile(sarifPath)
	if rerr != nil {
		return fail("invalid_sarif", "cannot read the SARIF file")
	}
	if len(secrets) > 0 {
		clean := body
		for _, sec := range secrets {
			clean = bytes.ReplaceAll(clean, []byte(sec), []byte("[REDACTED]"))
		}
		if !bytes.Equal(clean, body) {
			body = clean
			r.logf(ctx, job.ID, secrets, "warning: the engine output contained credential values; they were redacted")
		}
	}
	r.logf(ctx, job.ID, secrets, "ingesting results")
	result, ierr := r.Ingest.Ingest(ctx, ingest.Params{Codebase: cb, Body: body, Ref: ref, Trigger: job.Trigger, JobScanID: &job.ID})
	if ierr != nil {
		return ierr
	}
	if result.Duplicate {
		r.logf(ctx, job.ID, secrets, "results identical to scan #%d; no new scan recorded", result.Scan.ID)
	}
	return nil
}

// vulnArgs returns `--vuln-db <dir>` when CVE checks are configured, the directory exists and the
// engine supports the flag (an older engine is simply run without it). It logs the reason when a
// configured database is not used; the path itself is not written to the job log.
func (r *Runner) vulnArgs(ctx context.Context, jobID int64, kind string) []string {
	if r.Cfg.VulnDB == "" {
		return nil
	}
	if r.Cfg.ScaDisabled {
		r.logf(ctx, jobID, nil, "CVE checks are disabled (SDRSCAN_SCA_ENABLED=false)")
		return nil
	}
	if st, err := os.Stat(r.Cfg.VulnDB); err != nil || !st.IsDir() {
		r.logf(ctx, jobID, nil, "vulnerability database directory not found; CVE checks skipped (install it in Admin > Vulnerability database)")
		return nil
	}
	if !r.engineFlags(kind)["--vuln-db"] {
		r.logf(ctx, jobID, nil, "this sdrscan-%s engine does not support --vuln-db; CVE checks skipped", kind)
		return nil
	}
	r.logf(ctx, jobID, nil, "CVE checks enabled (vulnerability database)")
	return []string{"--vuln-db", r.Cfg.VulnDB}
}

// logEngineWarnings copies the engine's warning lines ("peringatan: ...", e.g. a vulnerability
// database older than 30 days, or SCA skipped) into the job log. They never fail the scan. The
// database directory is replaced by a placeholder, and at most five lines are kept.
func (r *Runner) logEngineWarnings(ctx context.Context, jobID int64, stderr string, secrets []string) {
	n := 0
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "peringatan:") {
			continue
		}
		if r.Cfg.VulnDB != "" {
			line = strings.ReplaceAll(line, r.Cfg.VulnDB, "<vulnerability database>")
		}
		if len(line) > 300 {
			line = strings.ToValidUTF8(line[:300], "") + "..."
		}
		r.logf(ctx, jobID, secrets, "engine warning: %s", strings.TrimSpace(line[len("peringatan:"):]))
		if n++; n >= 5 {
			return
		}
	}
}

func hostFromURL(u string) string {
	h, err := netguard.HostOf(u)
	if err != nil {
		return ""
	}
	// HostOf may append :port; strip for resolution.
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}

// engineEnv is the clean environment of engine subprocesses: no DATABASE_URL,
// no secret key, no tokens.
func (r *Runner) engineEnv(workdir string) []string {
	return []string{"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=" + workdir, "LANG=C.UTF-8", "TMPDIR=" + workdir}
}

// engineFlags probes (once) which optional flags the engines support.
func (r *Runner) engineFlags(kind string) map[string]bool {
	r.probeOnce.Do(func() {
		probe := func(bin string, flags ...string) map[string]bool {
			out := map[string]bool{}
			res := runProc(context.Background(), procSpec{bin: bin, args: []string{"scan", "--help"}, env: r.engineEnv(os.TempDir()),
				grace: time.Second, maxOut: 64 << 10})
			for _, f := range flags {
				out[f] = strings.Contains(res.stdout, f)
			}
			return out
		}
		r.dastFlags = probe(r.Cfg.DastBin, "--max-rps", "--templates", "--max-requests", "--max-pages", "--vuln-db",
			"--auth-file", "--login-check", "--crawl", "--max-depth", "--exclude-path", "--active", "--active-timing", "--openapi-spec")
		r.sastFlags = probe(r.Cfg.SastBin, "--templates", "--files-from", "--vuln-db")
	})
	if kind == "dast" {
		return r.dastFlags
	}
	return r.sastFlags
}

// EngineVersion returns the output of `<bin> --version`.
func (r *Runner) EngineVersion(ctx context.Context, kind string) (string, error) {
	bin := r.Cfg.SastBin
	if kind == "dast" {
		bin = r.Cfg.DastBin
	}
	res := runProc(ctx, procSpec{bin: bin, args: []string{"--version"}, env: r.engineEnv(os.TempDir()), grace: time.Second, maxOut: 4096})
	if res.notFound || res.exitCode != 0 {
		return "", fmt.Errorf("%s --version failed", filepath.Base(bin))
	}
	return strings.TrimSpace(res.stdout), nil
}
