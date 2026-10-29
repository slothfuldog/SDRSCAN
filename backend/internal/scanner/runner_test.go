package scanner_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func realRig(t *testing.T, guard *netguard.Guard) (*rig, testutil.Engines) {
	e := testutil.RealEngines(t)
	r := newRig(t, rigOpts{guard: guard, runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates}})
	return r, e
}

func TestE2ESastWithRealEngineOnFixture(t *testing.T) {
	r, e := realRig(t, local())
	repo := makeRepo(t, copyFixture(t, e.Root, "php-sql-injection"))
	head := git(t, repo, "rev-parse", "HEAD")
	cb := r.repoCB("sqli", repo)
	sc := r.run(func() store.Scan { return r.enqueue(cb) }())
	if sc.Status != "succeeded" || sc.Coverage != "full" || sc.Trigger != "manual" {
		t.Fatalf("scan: %s %s / %s", sc.Status, codeOf(sc), logOf(sc))
	}
	if sc.Ref != head || sc.Engine == nil || *sc.Engine != "sdrscan-sast" || sc.EngineVersion == nil || *sc.EngineVersion != "0.1.0" {
		t.Fatalf("ref/engine: %q %v %v", sc.Ref, sc.Engine, sc.EngineVersion)
	}
	fs, total, err := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID}, store.Page{Page: 1, Size: 50})
	if err != nil || total != 3 {
		t.Fatalf("expected 3 sql-injection findings, got %d (%v)", total, err)
	}
	for _, f := range fs {
		if f.RuleID != "php-sql-injection" || *f.Path != "vulnerable.php" || f.Severity != "high" || len(f.CWE) == 0 || f.CWE[0] != "CWE-89" {
			t.Fatalf("finding: %+v", f)
		}
	}
	if sc.NHigh != 3 {
		t.Fatalf("summary: %+v", sc.Counts())
	}
	for _, want := range []string{"cloning", "cloned " + head[:7], "running sdrscan-sast", "engine finished with exit code 1", "ingesting results", "done"} {
		if !strings.Contains(logOf(sc), want) {
			t.Errorf("log_tail lacks %q:\n%s", want, logOf(sc))
		}
	}
	r.assertWorkdirClean()
	// Same commit again: identical SARIF -> the job finishes without a new scan.
	sc2 := r.run(r.enqueue(cb))
	if sc2.Status != "succeeded" || sc2.DuplicateOfScanID == nil || *sc2.DuplicateOfScanID != sc.ID {
		t.Fatalf("second run: %s dup=%v", sc2.Status, sc2.DuplicateOfScanID)
	}
	hist, n, _ := r.env.Store.ListScans(context.Background(), cb.ID, "", store.Page{Page: 1, Size: 10})
	if n != 1 || hist[0].ID != sc.ID {
		t.Fatalf("history must hold one scan, got %d", n)
	}
	// A new commit with a fix: a new full scan replaces the current state.
	if err := os.WriteFile(filepath.Join(repo, "vulnerable.php"), []byte("<?php echo 'clean';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "commit", "-aqm", "fix")
	sc3 := r.run(r.enqueue(cb))
	if sc3.Status != "succeeded" || sc3.DuplicateOfScanID != nil || sc3.Ref == head {
		t.Fatalf("third run: %+v", sc3)
	}
	if r.countFindings(cb.ID) != 0 {
		t.Fatal("current state must be clean after the fix")
	}
	cbRow, _ := r.env.Store.GetCodebase(context.Background(), cb.ID)
	if !cbRow.Scanned() || cbRow.Counts() != (store.Counts{}) {
		t.Fatalf("codebase after the fix: %+v", cbRow.Counts())
	}
	r.assertWorkdirClean()
}

func TestE2ESubdirectoryRoot(t *testing.T) {
	r, e := realRig(t, local())
	files := map[string]string{}
	for k, v := range copyFixture(t, e.Root, "php-sql-injection") {
		files["apps/shop/"+k] = v
	}
	files["other/x.php"] = "<?php echo 1;\n"
	repo := makeRepo(t, files)
	cb := r.repoCB("shop", repo)
	if _, err := r.env.Store.UpdateCodebase(context.Background(), cb.ID, map[string]any{"subdirectory": "apps/shop"}); err != nil {
		t.Fatal(err)
	}
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s %s", sc.Status, codeOf(sc), logOf(sc))
	}
	fs, total, _ := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID}, store.Page{Page: 1, Size: 50})
	if total != 3 || *fs[0].Path != "vulnerable.php" {
		t.Fatalf("paths must be relative to the sub-directory: %d %v", total, *fs[0].Path)
	}
	// A missing sub-directory fails cleanly.
	_, _ = r.env.Store.UpdateCodebase(context.Background(), cb.ID, map[string]any{"subdirectory": "nope"})
	sc = r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "clone_failed" {
		t.Fatalf("missing subdirectory: %s %s", sc.Status, codeOf(sc))
	}
	r.assertWorkdirClean()
}

func TestE2ESecretIsRedactedFromRealEngineOutput(t *testing.T) {
	r, e := realRig(t, local())
	files := copyFixture(t, e.Root, "php-hardcoded-secret")
	repo := makeRepo(t, files)
	cb := r.repoCB("secrets", repo)
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s %s", sc.Status, codeOf(sc), logOf(sc))
	}
	fs, total, _ := r.env.Store.ListFindings(context.Background(), store.FindingFilter{CodebaseID: cb.ID}, store.Page{Page: 1, Size: 50})
	if total == 0 {
		t.Fatal("expected hard-coded secret findings from the fixture")
	}
	for _, f := range fs {
		if f.RuleID == "php-hardcoded-secret" && (!f.Redacted || !strings.Contains(f.Snippet, "[REDACTED]")) {
			t.Fatalf("secret finding not redacted: %+v", f)
		}
	}
}

func TestEngineFailureModes(t *testing.T) {
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n"})
	valid := writeSarif(t, testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{
		{Rule: "php-xss-echo", URI: "a.php", Line: 1, Snippet: "x", Level: "error"}}})
	cases := []struct {
		name   string
		engine func(t *testing.T) string
		status string
		code   string
		logHas string
	}{
		{"exit 1 with findings is success", func(t *testing.T) string { return fakeEngine(t, "cp '"+valid+"' \"$out\"\nexit 1\n") }, "succeeded", "", ""},
		{"exit 0 is success", func(t *testing.T) string { return fakeEngine(t, "cp '"+valid+"' \"$out\"\nexit 0\n") }, "succeeded", "", ""},
		{"exit 2 fails with stderr", func(t *testing.T) string { return fakeEngine(t, "echo 'bad templates dir' >&2\nexit 2\n") }, "failed", "engine_failed", "bad templates dir"},
		{"killed by signal", func(t *testing.T) string { return fakeEngine(t, "kill -9 $$\n") }, "failed", "engine_failed", ""},
		{"no sarif written", func(t *testing.T) string { return fakeEngine(t, "exit 0\n") }, "failed", "invalid_sarif", ""},
		{"broken sarif", func(t *testing.T) string { return fakeEngine(t, "echo '{nope' > \"$out\"\nexit 0\n") }, "failed", "invalid_sarif", ""},
		{"old fingerprint key", func(t *testing.T) string {
			p := writeSarif(t, testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a.php", Line: 1, FPKey: "old"}}})
			return fakeEngine(t, "cp '"+p+"' \"$out\"\nexit 0\n")
		}, "failed", "invalid_sarif", "fingerprint"},
		{"engine missing", func(t *testing.T) string { return "/nonexistent/sdrscan-sast" }, "failed", "engine_not_found", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, rigOpts{guard: local(), runner: scanner.Config{}})
			r.env.Runner.Cfg.SastBin = c.engine(t)
			cb := r.repoCB("c", repo)
			// A prior good state must survive every failure.
			good := r.env.Runner.Cfg.SastBin
			if c.status == "failed" {
				r.env.Runner.Cfg.SastBin = fakeEngine(t, "cp '"+valid+"' \"$out\"\nexit 1\n")
				if s := r.run(r.enqueue(cb)); s.Status != "succeeded" {
					t.Fatalf("seed scan: %s", s.Status)
				}
				r.env.Runner.Cfg.SastBin = good
			}
			before := r.countFindings(cb.ID)
			sc := r.run(r.enqueue(cb))
			if sc.Status != c.status || codeOf(sc) != c.code {
				t.Fatalf("got %s/%s want %s/%s\n%s", sc.Status, codeOf(sc), c.status, c.code, logOf(sc))
			}
			if c.logHas != "" && !strings.Contains(logOf(sc), c.logHas) {
				t.Fatalf("log_tail lacks %q: %s", c.logHas, logOf(sc))
			}
			if c.status == "failed" {
				cbRow, _ := r.env.Store.GetCodebase(context.Background(), cb.ID)
				if r.countFindings(cb.ID) != before || cbRow.Counts().High != 1 {
					t.Fatal("a failed scan changed the current state")
				}
			}
			r.assertWorkdirClean()
		})
	}
}

func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n"})
	r := newRig(t, rigOpts{guard: local(), runner: scanner.Config{SastTimeout: 3 * time.Second}})
	pidFile := filepath.Join(t.TempDir(), "pid")
	r.env.Runner.Cfg.SastBin = fakeEngine(t, "echo $$ > '"+pidFile+"'\nsleep 60 &\nwait\n")
	cb := r.repoCB("slow", repo)
	start := time.Now()
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "timeout" {
		t.Fatalf("%s %s %s", sc.Status, codeOf(sc), logOf(sc))
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("timeout took too long")
	}
	pid := readPid(t, pidFile)
	waitDead(t, pid)
	r.assertWorkdirClean()
}

func readPid(t *testing.T, p string) int {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("pid file: %v", err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("process %d is still alive", pid)
}

func TestCancelRunningJobKillsEngineAndCleansUp(t *testing.T) {
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n"})
	r := newRig(t, rigOpts{guard: local()})
	pidFile := filepath.Join(t.TempDir(), "pid")
	r.env.Runner.Cfg.SastBin = fakeEngine(t, "echo $$ > '"+pidFile+"'\nsleep 60 &\nwait\n")
	cb := r.repoCB("slow", repo)
	sc := r.enqueue(cb)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.env.Runner.RunOnce(context.Background())
	}()
	// Wait until the engine runs.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("engine never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	pid := readPid(t, pidFile)
	adminClient := r.env.Login(r.adm)
	resp := adminClient.Do("POST", fmt.Sprintf("/api/v1/scans/%d/cancel", sc.ID), nil)
	if resp.Status != 202 {
		t.Fatalf("cancel: %d %s", resp.Status, resp.Body)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("runner did not stop after the cancel request")
	}
	got, _ := r.env.Store.GetScan(context.Background(), sc.ID)
	if got.Status != "cancelled" || got.FinishedAt == nil {
		t.Fatalf("status %s", got.Status)
	}
	waitDead(t, pid)
	r.assertWorkdirClean()
	if r.countFindings(cb.ID) != 0 {
		t.Fatal("a cancelled scan must never be ingested")
	}
	cbRow, _ := r.env.Store.GetCodebase(context.Background(), cb.ID)
	if cbRow.Scanned() {
		t.Fatal("a cancelled scan must not create a current state")
	}
}

func TestEngineArgumentsAndEnvironment(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:supersecretdbpw@db/x")
	t.Setenv("SDRSCAN_SECRET_KEY", "c2VjcmV0LWtleS1zZWNyZXQta2V5LXNlY3JldC1rZXk=")
	t.Setenv("SDRSCAN_BOOTSTRAP_ADMIN_PASSWORD", "bootstrappw")
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n"})
	r := newRig(t, rigOpts{guard: local(), runner: scanner.Config{Templates: "/opt/sdrscan/templates"}})
	rec := filepath.Join(t.TempDir(), "rec")
	valid := writeSarif(t, testutil.Doc{})
	// Record the argv separately: wrap by re-reading $@ before parsing.
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + rec + ".args'\nenv > '" + rec + ".env'\ncp '" + valid + "' \"$(printf '%s\\n' \"$@\" | sed -n '/^--output$/{n;p;}')\"\nexit 0\n"
	p := filepath.Join(t.TempDir(), "rec-engine.sh")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.env.Runner.Cfg.SastBin = p
	cb := r.repoCB("c", repo)
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s %s", sc.Status, codeOf(sc), logOf(sc))
	}
	args, _ := os.ReadFile(rec + ".args")
	as := string(args)
	if strings.Contains(as, "--files-from") {
		t.Fatalf("web scans must never use --files-from:\n%s", as)
	}
	for _, want := range []string{"scan\n", "--format\nsarif", "--output\n", "--templates\n/opt/sdrscan/templates"} {
		if !strings.Contains(as, want) {
			t.Errorf("args lack %q:\n%s", want, as)
		}
	}
	if strings.Contains(as, "--fail-on") {
		t.Fatalf("backend must not use --fail-on as a gate:\n%s", as)
	}
	env, _ := os.ReadFile(rec + ".env")
	for _, bad := range []string{"DATABASE_URL", "SDRSCAN_SECRET_KEY", "supersecretdbpw", "bootstrappw", "SDRSCAN_"} {
		if strings.Contains(string(env), bad) {
			t.Errorf("engine environment leaks %q:\n%s", bad, env)
		}
	}
	if !strings.Contains(string(env), "HOME="+r.work) {
		t.Errorf("HOME must point to the work directory:\n%s", env)
	}
}

func TestQueueSkipLockedNeverDoubleClaims(t *testing.T) {
	r := newRig(t, rigOpts{guard: local()})
	ctx := context.Background()
	const n = 24
	for i := 0; i < n; i++ {
		cb := r.repoCB(fmt.Sprintf("c%02d", i), "https://git.example.com/x.git")
		r.enqueue(cb)
	}
	var mu sync.Mutex
	claimed := map[int64]int{}
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for {
				job, err := r.env.Store.ClaimJob(ctx, fmt.Sprintf("w%d", w), time.Minute)
				if err != nil {
					return
				}
				mu.Lock()
				claimed[job.ID]++
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	if len(claimed) != n {
		t.Fatalf("claimed %d distinct jobs, want %d", len(claimed), n)
	}
	for id, c := range claimed {
		if c != 1 {
			t.Fatalf("job %d claimed %d times", id, c)
		}
	}
	q, run, _ := r.env.Store.QueueStats(ctx, true)
	if q != 0 || run != n {
		t.Fatalf("stats: queued=%d running=%d", q, run)
	}
}

func TestOldestJobFirst(t *testing.T) {
	r := newRig(t, rigOpts{guard: local()})
	a := r.enqueue(r.repoCB("a", "https://git.example.com/a.git"))
	b := r.enqueue(r.repoCB("b", "https://git.example.com/b.git"))
	job, err := r.env.Store.ClaimJob(context.Background(), "w", time.Minute)
	if err != nil || job.ID != a.ID {
		t.Fatalf("first claim: %v %v (want %d, queue has %d)", job.ID, err, a.ID, b.ID)
	}
	if job.Status != "running" || job.StartedAt == nil || job.WorkerID == nil || job.LeaseExpiresAt == nil {
		t.Fatalf("claimed job: %+v", job)
	}
}

func TestLostWorkerJobsAreFailed(t *testing.T) {
	r := newRig(t, rigOpts{guard: local()})
	ctx := context.Background()
	cb := r.repoCB("a", "https://git.example.com/a.git")
	sc := r.enqueue(cb)
	if _, err := r.env.Store.ClaimJob(ctx, "dead-worker", time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.env.Store.SweepLostJobs(ctx); n != 0 {
		t.Fatal("a job with a live lease must not be swept")
	}
	_, _ = r.env.Pool.Exec(ctx, `UPDATE scans SET lease_expires_at = now() - interval '1 second' WHERE id = $1`, sc.ID)
	// Starting the runner sweeps once at start-up.
	rctx, cancel := context.WithCancel(ctx)
	r.env.Runner.Start(rctx)
	cancel()
	r.env.Runner.Wait()
	got, _ := r.env.Store.GetScan(ctx, sc.ID)
	if got.Status != "failed" || codeOf(got) != "worker_lost" {
		t.Fatalf("%s %s", got.Status, codeOf(got))
	}
	// The codebase can queue a new job again.
	if _, err := r.env.Store.CreateJob(ctx, cb.ID, "sast", "manual", nil); err != nil {
		t.Fatalf("queue after worker_lost: %v", err)
	}
}

func TestOldWorkDirsAreSwept(t *testing.T) {
	r := newRig(t, rigOpts{guard: local()})
	old := filepath.Join(r.work, "scan-1-old")
	fresh := filepath.Join(r.work, "scan-2-fresh")
	other := filepath.Join(r.work, "keep-me")
	for _, d := range []string{old, fresh, other} {
		_ = os.MkdirAll(d, 0o700)
	}
	past := time.Now().Add(-25 * time.Hour)
	_ = os.Chtimes(old, past, past)
	_ = os.Chtimes(other, past, past)
	ctx, cancel := context.WithCancel(context.Background())
	r.env.Runner.Start(ctx)
	cancel()
	r.env.Runner.Wait()
	if _, err := os.Stat(old); err == nil {
		t.Fatal("old work directory survived")
	}
	for _, d := range []string{fresh, other} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("%s must be kept", d)
		}
	}
}

func TestGracefulShutdownCancelsRunningJobs(t *testing.T) {
	repo := makeRepo(t, map[string]string{"a.php": "<?php\n"})
	r := newRig(t, rigOpts{guard: local()})
	pidFile := filepath.Join(t.TempDir(), "pid")
	r.env.Runner.Cfg.SastBin = fakeEngine(t, "echo $$ > '"+pidFile+"'\nsleep 60 &\nwait\n")
	cb := r.repoCB("slow", repo)
	sc := r.enqueue(cb)
	ctx, cancel := context.WithCancel(context.Background())
	r.env.Runner.Start(ctx)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("engine never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	waited := make(chan struct{})
	go func() { r.env.Runner.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(20 * time.Second):
		t.Fatal("Wait did not return after shutdown")
	}
	got, _ := r.env.Store.GetScan(context.Background(), sc.ID)
	if got.Status != "cancelled" {
		t.Fatalf("status %s", got.Status)
	}
	waitDead(t, readPid(t, pidFile))
	r.assertWorkdirClean()
}
