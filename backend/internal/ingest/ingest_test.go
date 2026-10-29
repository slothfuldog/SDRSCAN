package ingest_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/ingest"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

type fx struct {
	t    *testing.T
	env  *testutil.Env
	ctx  context.Context
	proj store.Project
	cb   store.Codebase
	base time.Time
	n    int
}

func newFx(t *testing.T) *fx {
	env := testutil.NewEnv(t, testutil.EnvOptions{})
	ctx := context.Background()
	p, err := env.Store.CreateProject(ctx, "Shop", "")
	if err != nil {
		t.Fatal(err)
	}
	repo, branch := "https://git.example.com/shop.git", "main"
	cb, err := env.Store.CreateCodebase(ctx, store.NewCodebase{ProjectID: p.ID, Name: "storefront", TargetType: "repo", RepoURL: &repo, Branch: &branch, GitAuthKind: "none"})
	if err != nil {
		t.Fatal(err)
	}
	return &fx{t: t, env: env, ctx: ctx, proj: p, cb: cb, base: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// ingest runs a CI ingest with an increasing started_at (unless at is given).
func (f *fx) ingest(d testutil.Doc, ref string, at *time.Time) (ingest.Result, error) {
	f.t.Helper()
	cb, err := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	if at == nil {
		f.n++
		v := f.base.Add(time.Duration(f.n) * time.Hour)
		at = &v
	}
	return f.env.Ingest.Run(f.ctx, ingest.Params{Codebase: cb, Body: d.Build(), Ref: ref, StartedAt: at, Trigger: "ci"})
}

func (f *fx) must(d testutil.Doc, ref string) ingest.Result {
	f.t.Helper()
	r, err := f.ingest(d, ref, nil)
	if err != nil {
		f.t.Fatalf("ingest: %v", err)
	}
	f.check()
	return r
}

func res(rule, file string, line int, snippet string) testutil.SResult {
	return testutil.SResult{Rule: rule, URI: file, Line: line, Snippet: snippet, Level: "error", Message: "msg " + rule}
}

func full(rs ...testutil.SResult) testutil.Doc {
	return testutil.Doc{Rules: testutil.StdRules, Results: rs}
}

func partial(files []string, rs ...testutil.SResult) testutil.Doc {
	return testutil.Doc{Rules: testutil.StdRules, Partial: true, Scanned: files, Results: rs}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.env.Pool.QueryRow(f.ctx, sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// currentPaths lists "path:line" of the is_current findings.
func (f *fx) currentPaths() []string {
	rows, err := f.env.Pool.Query(f.ctx, `SELECT path || ':' || start_line FROM findings WHERE codebase_id = $1 AND is_current ORDER BY 1`, f.cb.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

// check verifies the four invariants of the TRD (summaries and canonical state).
func (f *fx) check() {
	f.t.Helper()
	cb, err := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	// (1) scans.n_* = GROUP BY severity of the scan.
	rows, err := f.env.Pool.Query(f.ctx, `SELECT s.id, s.n_critical, s.n_high, s.n_medium, s.n_low, s.n_info, s.n_low_confidence,
		(SELECT count(*) FILTER (WHERE severity='critical' AND confidence='normal') FROM findings WHERE scan_id = s.id),
		(SELECT count(*) FILTER (WHERE severity='high' AND confidence='normal') FROM findings WHERE scan_id = s.id),
		(SELECT count(*) FILTER (WHERE severity='medium' AND confidence='normal') FROM findings WHERE scan_id = s.id),
		(SELECT count(*) FILTER (WHERE severity='low' AND confidence='normal') FROM findings WHERE scan_id = s.id),
		(SELECT count(*) FILTER (WHERE severity='info' AND confidence='normal') FROM findings WHERE scan_id = s.id),
		(SELECT count(*) FILTER (WHERE confidence='low') FROM findings WHERE scan_id = s.id)
		FROM scans s WHERE s.codebase_id = $1 AND s.status = 'succeeded' AND s.duplicate_of_scan_id IS NULL`, f.cb.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		var a [6]int
		var b [6]int
		if err := rows.Scan(&id, &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]); err != nil {
			f.t.Fatal(err)
		}
		if a != b {
			f.t.Errorf("invariant 1: scan %d summary %v != group by %v", id, a, b)
		}
	}
	rows.Close()
	// (2) codebases.n_* = GROUP BY of is_current.
	var cur [6]int
	if err := f.env.Pool.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE severity='critical' AND confidence='normal'),
		count(*) FILTER (WHERE severity='high' AND confidence='normal'), count(*) FILTER (WHERE severity='medium' AND confidence='normal'),
		count(*) FILTER (WHERE severity='low' AND confidence='normal'), count(*) FILTER (WHERE severity='info' AND confidence='normal'),
		count(*) FILTER (WHERE confidence='low') FROM findings WHERE codebase_id = $1 AND is_current`, f.cb.ID).
		Scan(&cur[0], &cur[1], &cur[2], &cur[3], &cur[4], &cur[5]); err != nil {
		f.t.Fatal(err)
	}
	have := [6]int{cb.NCritical, cb.NHigh, cb.NMedium, cb.NLow, cb.NInfo, cb.NLowConfidence}
	if cur != have {
		f.t.Errorf("invariant 2: codebase summary %v != current %v", have, cur)
	}
	if cb.BaseScanID == nil {
		if n := f.count(`SELECT count(*) FROM findings WHERE codebase_id = $1 AND is_current`, f.cb.ID); n != 0 {
			f.t.Errorf("no base scan but %d current findings", n)
		}
		return
	}
	// (3) is_current = canonical query.
	canon, err := f.env.Store.CanonicalCurrentIDs(f.ctx, nil, f.cb.ID, *cb.BaseScanID)
	if err != nil {
		f.t.Fatal(err)
	}
	var flagged []int64
	r2, _ := f.env.Pool.Query(f.ctx, `SELECT id FROM findings WHERE codebase_id = $1 AND is_current ORDER BY id`, f.cb.ID)
	for r2.Next() {
		var id int64
		_ = r2.Scan(&id)
		flagged = append(flagged, id)
	}
	r2.Close()
	sort.Slice(canon, func(i, j int) bool { return canon[i] < canon[j] })
	if fmt.Sprint(canon) != fmt.Sprint(flagged) && !(len(canon) == 0 && len(flagged) == 0) {
		f.t.Errorf("invariant 3: is_current %v != canonical %v", flagged, canon)
	}
	// (4) without partial scans since base, codebase summary = base scan summary.
	st, _ := f.env.Store.States(f.ctx, []store.Codebase{cb})
	if st[cb.ID].PartialSinceBase == 0 && st[cb.ID].LatestScan != nil && st[cb.ID].LatestScan.ID == *cb.BaseScanID {
		base, _ := f.env.Store.GetScan(f.ctx, *cb.BaseScanID)
		if base.Counts() != cb.Counts() {
			f.t.Errorf("invariant 4: base %v != codebase %v", base.Counts(), cb.Counts())
		}
	}
}

func TestFullIngestMapsFindings(t *testing.T) {
	f := newFx(t)
	d := full(
		res("php-sql-injection", "src/a.php", 10, "mysqli_query($c, $q)"),
		res("php-xss-echo", "src/a.php", 20, "echo $_GET['x']"),
		res("php-weak-password-hash", "b.php", 5, "md5($p)"),
		res("php-info", "b.php", 9, "x"),
	)
	r := f.must(d, "abc123")
	if r.Duplicate || r.Scan.Status != "succeeded" || r.Scan.Coverage != "full" || r.Scan.Type != "sast" {
		t.Fatalf("scan: %+v", r.Scan)
	}
	want := store.Counts{Critical: 1, High: 1, Medium: 1, Low: 0, Info: 1}
	if r.ScanSummary != want || r.CodebaseSummary != want {
		t.Fatalf("summaries: scan=%v cb=%v want %v", r.ScanSummary, r.CodebaseSummary, want)
	}
	if r.Scan.Engine == nil || *r.Scan.Engine != "sdrscan-sast" || r.Scan.Ref != "abc123" {
		t.Fatalf("engine/ref: %+v", r.Scan)
	}
	cb, _ := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
	if cb.BaseScanID == nil || *cb.BaseScanID != r.Scan.ID || cb.LatestScanID == nil || *cb.LatestScanID != r.Scan.ID {
		t.Fatalf("codebase pointers: %+v", cb)
	}
	fs, total, _ := f.env.Store.ListFindings(f.ctx, store.FindingFilter{CodebaseID: f.cb.ID}, store.Page{Page: 1, Size: 50})
	if total != 4 || fs[0].RuleID != "php-sql-injection" || fs[0].SeverityRank != 4 {
		t.Fatalf("findings order: %d %+v", total, fs)
	}
	if len(fs[0].CWE) != 1 || fs[0].CWE[0] != "CWE-89" || fs[0].LocationKind != "file" || *fs[0].Path != "src/a.php" || *fs[0].StartLine != 10 {
		t.Fatalf("finding: %+v", fs[0])
	}
	if f.count(`SELECT count(*) FROM ingest_digest WHERE codebase_id = $1`, f.cb.ID) != 1 {
		t.Fatal("digest not stored")
	}
}

func TestZeroResultsIsCleanNotUnscanned(t *testing.T) {
	f := newFx(t)
	r := f.must(full(), "r1")
	if r.CodebaseSummary != (store.Counts{}) || !r.CodebaseScanned {
		t.Fatalf("%+v", r)
	}
	cb, _ := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
	if !cb.Scanned() {
		t.Fatal("clean codebase must count as scanned")
	}
}

func TestLowConfidenceStoredButNotCounted(t *testing.T) {
	f := newFx(t)
	low := res("php-info", "a.php", 1, "x")
	low.Level, low.Low = "note", true
	r := f.must(full(res("php-sql-injection", "a.php", 3, "q"), low), "")
	if r.LowConfidence != 1 || r.ScanSummary.Info != 0 || r.ScanSummary.Critical != 1 {
		t.Fatalf("%+v", r)
	}
	if f.count(`SELECT count(*) FROM findings WHERE confidence = 'low'`) != 1 {
		t.Fatal("low confidence finding not stored")
	}
	_, total, _ := f.env.Store.ListFindings(f.ctx, store.FindingFilter{CodebaseID: f.cb.ID}, store.Page{Page: 1, Size: 10})
	if total != 1 {
		t.Fatalf("default list must hide low confidence, got %d", total)
	}
	_, total, _ = f.env.Store.ListFindings(f.ctx, store.FindingFilter{CodebaseID: f.cb.ID, IncludeLow: true}, store.Page{Page: 1, Size: 10})
	if total != 2 {
		t.Fatalf("include_low_confidence must show both, got %d", total)
	}
}

func apiCode(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprintf("%T:%v", err, err)
}

func TestInvalidSarifWritesNothing(t *testing.T) {
	f := newFx(t)
	f.must(full(res("php-sql-injection", "a.php", 1, "q")), "base")
	scansBefore := f.count(`SELECT count(*) FROM scans`)
	findingsBefore := f.count(`SELECT count(*) FROM findings`)
	cases := []struct {
		name string
		doc  testutil.Doc
		code string
	}{
		{"dast into repo", testutil.Doc{Engine: "sdrscan-dast", Results: []testutil.SResult{{Rule: "r", URI: "https://x.example/", Level: "note"}}}, "engine_target_mismatch"},
		{"two runs", testutil.Doc{Runs: 2}, "multiple_runs"},
		{"unknown engine", testutil.Doc{Engine: "semgrep"}, "unsupported_engine"},
		{"version", testutil.Doc{Version: "2.0"}, "invalid_sarif"},
		{"no fingerprint", testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a.php", Line: 1, NoFP: true}}}, "missing_fingerprint"},
		{"old key", testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a.php", Line: 1, FPKey: "old"}}}, "missing_fingerprint"},
		{"path traversal", full(res("php-xss-echo", "../../etc/passwd", 1, "x")), "invalid_sarif"},
		{"absolute path", full(res("php-xss-echo", "/etc/passwd", 1, "x")), "invalid_sarif"},
		{"partial outside list", partial([]string{"a.php"}, res("php-xss-echo", "other.php", 1, "x")), "finding_outside_scanned_files"},
		{"partial no list", testutil.Doc{Partial: true, Rules: testutil.StdRules}, "invalid_sarif"},
	}
	for _, c := range cases {
		_, err := f.ingest(c.doc, "", nil)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if got := apiCode(err); got != c.code {
			t.Errorf("%s: code %s want %s (%v)", c.name, got, c.code, err)
		}
	}
	if f.count(`SELECT count(*) FROM scans`) != scansBefore || f.count(`SELECT count(*) FROM findings`) != findingsBefore {
		t.Fatal("rejected ingests must not write anything")
	}
	f.check()
}

func TestTooManyResults(t *testing.T) {
	env := testutil.NewEnv(t, testutil.EnvOptions{Ingest: ingest.Config{MaxResults: 2}})
	ctx := context.Background()
	p, _ := env.Store.CreateProject(ctx, "P", "")
	repo, br := "https://h.example/r.git", "main"
	cb, _ := env.Store.CreateCodebase(ctx, store.NewCodebase{ProjectID: p.ID, Name: "c", TargetType: "repo", RepoURL: &repo, Branch: &br, GitAuthKind: "none"})
	d := full(res("php-xss-echo", "a.php", 1, "a"), res("php-xss-echo", "a.php", 2, "b"), res("php-xss-echo", "a.php", 3, "c"))
	_, err := env.Ingest.Run(ctx, ingest.Params{Codebase: cb, Body: d.Build(), Trigger: "ci"})
	if apiCode(err) != "too_many_results" {
		t.Fatalf("got %v", err)
	}
}

func TestPartialNeedsBaseline(t *testing.T) {
	f := newFx(t)
	_, err := f.ingest(partial([]string{"a.php"}, res("php-xss-echo", "a.php", 1, "x")), "", nil)
	if apiCode(err) != "baseline_required" {
		t.Fatalf("got %v", err)
	}
	if f.count(`SELECT count(*) FROM scans`) != 0 {
		t.Fatal("scan row written for a refused partial scan")
	}
	// A failed or non-full scan does not count as a baseline: only a full one does.
	f.must(full(), "full")
	if _, err := f.ingest(partial([]string{"a.php"}), "p1", nil); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateDetection(t *testing.T) {
	f := newFx(t)
	d := full(res("php-sql-injection", "a.php", 1, "q"))
	r1 := f.must(d, "c1")
	r2, err := f.ingest(d, "c1", nil)
	if err != nil || !r2.Duplicate || r2.Scan.ID != r1.Scan.ID || !r2.IsLatestScan {
		t.Fatalf("same hash+ref: %+v %v", r2, err)
	}
	if r2.ScanSummary != r1.ScanSummary {
		t.Fatalf("duplicate summary: %v", r2.ScanSummary)
	}
	// Same content, other ref -> new scan.
	r3 := f.must(d, "c2")
	if r3.Duplicate || r3.Scan.ID == r1.Scan.ID {
		t.Fatal("different ref must create a new scan")
	}
	// Without ref the hash alone matches (any earlier ref).
	r4, _ := f.ingest(d, "", nil)
	if !r4.Duplicate {
		t.Fatal("empty ref must match on hash only")
	}
	// A duplicate of an older, non-latest scan points at it without changing state.
	f.must(full(res("php-xss-echo", "b.php", 2, "z")), "c3")
	before, _ := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
	r5, err := f.ingest(d, "c1", nil)
	if err != nil || !r5.Duplicate || r5.Scan.ID != r1.Scan.ID || r5.IsLatestScan {
		t.Fatalf("duplicate of an old scan: %+v %v", r5, err)
	}
	after, _ := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
	if before.LatestScanID == nil || *before.LatestScanID != *after.LatestScanID || before.Counts() != after.Counts() {
		t.Fatal("duplicate changed the current state")
	}
	if f.count(`SELECT count(*) FROM scans`) != 3 {
		t.Fatalf("expected 3 scans, got %d", f.count(`SELECT count(*) FROM scans`))
	}
}

func TestConcurrentIdenticalIngestsMakeOneScan(t *testing.T) {
	f := newFx(t)
	d := full(res("php-sql-injection", "a.php", 1, "q"))
	var wg sync.WaitGroup
	results := make([]ingest.Result, 6)
	errs := make([]error, 6)
	at := f.base
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cb, _ := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
			results[i], errs[i] = f.env.Ingest.Run(f.ctx, ingest.Params{Codebase: cb, Body: d.Build(), Ref: "same", StartedAt: &at, Trigger: "ci"})
		}()
	}
	wg.Wait()
	created := 0
	for i, e := range errs {
		if e != nil {
			t.Fatalf("ingest %d: %v", i, e)
		}
		if !results[i].Duplicate {
			created++
		}
	}
	if created != 1 || f.count(`SELECT count(*) FROM scans`) != 1 {
		t.Fatalf("created=%d scans=%d", created, f.count(`SELECT count(*) FROM scans`))
	}
	f.check()
}

func TestCurrentStateWithPartialScans(t *testing.T) {
	f := newFx(t)
	// Full scan: a.php has two findings, b.php one.
	f.must(full(
		res("php-sql-injection", "a.php", 1, "A1"),
		res("php-xss-echo", "a.php", 2, "A2"),
		res("php-weak-password-hash", "b.php", 3, "B1"),
	), "full1")
	if got := f.currentPaths(); fmt.Sprint(got) != "[a.php:1 a.php:2 b.php:3]" {
		t.Fatalf("after full: %v", got)
	}
	// Partial on a.php replaces only a.php.
	rp := f.must(partial([]string{"a.php"}, res("php-xss-echo", "a.php", 7, "A3")), "p1")
	if rp.Scan.Coverage != "partial" || *rp.Scan.ScannedFileCount != 1 {
		t.Fatalf("partial scan: %+v", rp.Scan)
	}
	if got := f.currentPaths(); fmt.Sprint(got) != "[a.php:7 b.php:3]" {
		t.Fatalf("after partial 1: %v", got)
	}
	if rp.ScanSummary != (store.Counts{High: 1}) || rp.CodebaseSummary != (store.Counts{High: 1, Medium: 1}) {
		t.Fatalf("summaries: scan=%v cb=%v", rp.ScanSummary, rp.CodebaseSummary)
	}
	// Partial again on the same file.
	f.must(partial([]string{"a.php"}, res("php-sql-injection", "a.php", 9, "A4")), "p2")
	if got := f.currentPaths(); fmt.Sprint(got) != "[a.php:9 b.php:3]" {
		t.Fatalf("after partial 2: %v", got)
	}
	// Partial without findings clears b.php.
	f.must(partial([]string{"b.php"}), "p3")
	if got := f.currentPaths(); fmt.Sprint(got) != "[a.php:9]" {
		t.Fatalf("after clearing partial: %v", got)
	}
	st, _ := f.env.Store.States(f.ctx, []store.Codebase{mustCB(f)})
	if st[f.cb.ID].PartialSinceBase != 3 {
		t.Fatalf("partials since base = %d", st[f.cb.ID].PartialSinceBase)
	}
	// A new full scan resets everything.
	f.must(full(res("php-xss-echo", "c.php", 1, "C1")), "full2")
	if got := f.currentPaths(); fmt.Sprint(got) != "[c.php:1]" {
		t.Fatalf("after new full: %v", got)
	}
	st, _ = f.env.Store.States(f.ctx, []store.Codebase{mustCB(f)})
	if st[f.cb.ID].PartialSinceBase != 0 {
		t.Fatal("partials since base must reset")
	}
}

func mustCB(f *fx) store.Codebase {
	cb, err := f.env.Store.GetCodebase(f.ctx, f.cb.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return cb
}

func TestLateScanDoesNotChangeCurrentState(t *testing.T) {
	f := newFx(t)
	t1 := f.base.Add(10 * time.Hour)
	t0 := f.base.Add(1 * time.Hour)
	new1, err := f.ingest(full(res("php-sql-injection", "new.php", 1, "N")), "newer", &t1)
	if err != nil {
		t.Fatal(err)
	}
	late, err := f.ingest(full(res("php-xss-echo", "old.php", 1, "O")), "older", &t0)
	if err != nil {
		t.Fatal(err)
	}
	f.check()
	if !late.Superseded || new1.Superseded {
		t.Fatalf("superseded flags: new=%v late=%v", new1.Superseded, late.Superseded)
	}
	if got := f.currentPaths(); fmt.Sprint(got) != "[new.php:1]" {
		t.Fatalf("current state changed by a late scan: %v", got)
	}
	cb := mustCB(f)
	if *cb.LatestScanID != new1.Scan.ID || *cb.BaseScanID != new1.Scan.ID {
		t.Fatalf("pointers moved: %+v", cb)
	}
	if f.count(`SELECT count(*) FROM findings WHERE scan_id = $1 AND NOT is_current`, late.Scan.ID) != 1 {
		t.Fatal("late scan findings must be stored with is_current = false")
	}
}

func TestOccurrenceForTwinFingerprints(t *testing.T) {
	f := newFx(t)
	fp := testutil.FP("twin")
	a := res("php-xss-echo", "a.php", 10, "same")
	b := res("php-xss-echo", "a.php", 3, "same")
	a.FP, b.FP = fp, fp
	f.must(full(a, b), "")
	rows, _ := f.env.Pool.Query(f.ctx, `SELECT start_line, occurrence FROM findings ORDER BY start_line`)
	defer rows.Close()
	var got []string
	for rows.Next() {
		var l, o int
		_ = rows.Scan(&l, &o)
		got = append(got, fmt.Sprintf("%d:%d", l, o))
	}
	if fmt.Sprint(got) != "[3:1 10:2]" {
		t.Fatalf("occurrence order: %v", got)
	}
}

func TestRedaction(t *testing.T) {
	f := newFx(t)
	const secretVal = "sk_live_REALSECRETVALUE9876"
	const awsVal = "AKIAIOSFODNN7EXAMPLE"
	const pw = "hunter2hunter2"
	sec := res("php-hardcoded-secret", "cfg.php", 3, "$apiKey = '"+secretVal+"'")
	sec.Message = "Hard-coded secret '" + secretVal + "' in code"
	sec.FP = testutil.FP("secret-fingerprint")
	def := res("php-hardcoded-secret", "cfg.php", 4, "define('STRIPE_KEY', '"+secretVal+"2')")
	arr := res("php-hardcoded-secret", "cfg.php", 5, "$c = ['db_pass' => '"+pw+"', 'user' => 'root']")
	aws := res("php-xss-echo", "x.php", 1, "echo '"+awsVal+"'")
	aws.Message = "token " + awsVal
	d := full(sec, def, arr, aws)
	r := f.must(d, "")
	if r.RedactedCount != 4 {
		t.Fatalf("redacted findings = %d", r.RedactedCount)
	}
	// No real value anywhere in the database.
	for _, v := range []string{secretVal, awsVal, pw} {
		var n int
		err := f.env.Pool.QueryRow(f.ctx, `SELECT
			(SELECT count(*) FROM findings WHERE snippet LIKE '%'||$1||'%' OR message LIKE '%'||$1||'%' OR coalesce(path,'') LIKE '%'||$1||'%')`, v).Scan(&n)
		if err != nil || n != 0 {
			t.Fatalf("secret %q still stored (%d rows, %v)", v, n, err)
		}
	}
	fs, _, _ := f.env.Store.ListFindings(f.ctx, store.FindingFilter{CodebaseID: f.cb.ID}, store.Page{Page: 1, Size: 50})
	byLine := map[int]store.Finding{}
	for _, x := range fs {
		byLine[*x.StartLine] = x
	}
	if got := byLine[3].Snippet; got != "$apiKey = '[REDACTED]'" {
		t.Errorf("snippet 3 = %q", got)
	}
	if !byLine[3].Redacted || !strings.Contains(byLine[3].Message, "[REDACTED]") {
		t.Errorf("message/flag: %+v", byLine[3])
	}
	if got := byLine[4].Snippet; got != "define('STRIPE_KEY', '[REDACTED]')" {
		t.Errorf("define snippet = %q", got)
	}
	if got := byLine[5].Snippet; !strings.Contains(got, "'db_pass' => '[REDACTED]'") {
		t.Errorf("array snippet = %q", got)
	}
	// Fingerprints are stored exactly as sent.
	if byLine[3].Fingerprint != testutil.FP("secret-fingerprint") {
		t.Error("fingerprint was altered")
	}
	// A rule that is not a secret rule still gets layer-2 patterns.
	if byLine[1].Snippet != "echo '[REDACTED]'" {
		t.Errorf("pattern layer: %q", byLine[1].Snippet)
	}
}

func TestTruncationOfLongTexts(t *testing.T) {
	f := newFx(t)
	long := res("php-xss-echo", "a.php", 1, strings.Repeat("x", 100*1024))
	long.Message = strings.Repeat("m", 10*1024)
	f.must(full(long), "")
	var sn, mg int
	_ = f.env.Pool.QueryRow(f.ctx, `SELECT length(snippet), length(message) FROM findings`).Scan(&sn, &mg)
	if sn != ingest.MaxSnippetBytes || mg != ingest.MaxMessageBytes {
		t.Fatalf("snippet=%d message=%d", sn, mg)
	}
}

func TestRollbackOnMidIngestError(t *testing.T) {
	f := newFx(t)
	f.must(full(res("php-sql-injection", "a.php", 1, "keep")), "base")
	// Inject an error while findings are written.
	if _, err := f.env.Pool.Exec(f.ctx, `
		CREATE FUNCTION boom() RETURNS trigger AS $$ BEGIN IF NEW.rule_id = 'boom' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql;
		CREATE TRIGGER boom_trg BEFORE INSERT ON findings FOR EACH ROW EXECUTE FUNCTION boom();`); err != nil {
		t.Fatal(err)
	}
	scans, finds, digests := f.count(`SELECT count(*) FROM scans`), f.count(`SELECT count(*) FROM findings`), f.count(`SELECT count(*) FROM ingest_digest`)
	before := mustCB(f)
	_, err := f.ingest(full(res("php-xss-echo", "z.php", 1, "ok"), res("boom", "z.php", 2, "bad")), "next", nil)
	if err == nil {
		t.Fatal("expected the injected error")
	}
	if f.count(`SELECT count(*) FROM scans`) != scans || f.count(`SELECT count(*) FROM findings`) != finds ||
		f.count(`SELECT count(*) FROM ingest_digest`) != digests {
		t.Fatal("partial writes survived the failed ingest")
	}
	after := mustCB(f)
	if *after.LatestScanID != *before.LatestScanID || after.Counts() != before.Counts() {
		t.Fatal("codebase state changed by a failed ingest")
	}
	if got := f.currentPaths(); fmt.Sprint(got) != "[a.php:1]" {
		t.Fatalf("current state: %v", got)
	}
	f.check()
}

func TestBusyWhenCodebaseLockedTooLong(t *testing.T) {
	env := testutil.NewEnv(t, testutil.EnvOptions{Ingest: ingest.Config{LockTimeout: 300 * time.Millisecond}})
	ctx := context.Background()
	p, _ := env.Store.CreateProject(ctx, "P", "")
	repo, br := "https://h.example/r.git", "main"
	cb, _ := env.Store.CreateCodebase(ctx, store.NewCodebase{ProjectID: p.ID, Name: "c", TargetType: "repo", RepoURL: &repo, Branch: &br, GitAuthKind: "none"})
	tx, _ := env.Pool.Begin(ctx)
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT id FROM codebases WHERE id = $1 FOR UPDATE`, cb.ID); err != nil {
		t.Fatal(err)
	}
	_, err := env.Ingest.Run(ctx, ingest.Params{Codebase: cb, Body: full().Build(), Trigger: "ci"})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != "busy" || ae.Status != 503 {
		t.Fatalf("got %v", err)
	}
}

func TestDastIngest(t *testing.T) {
	env := testutil.NewEnv(t, testutil.EnvOptions{})
	ctx := context.Background()
	admin := env.CreateUser("root", "admin", false)
	p, _ := env.Store.CreateProject(ctx, "P", "")
	base := "https://shop.example.com"
	cb, err := env.Store.CreateCodebase(ctx, store.NewCodebase{ProjectID: p.ID, Name: "live", TargetType: "url", BaseURL: &base, RegisteredBy: &admin.ID})
	if err != nil {
		t.Fatal(err)
	}
	if *cb.DastStatus != "pending_confirmation" {
		t.Fatal("new URL targets must start pending")
	}
	rules := []testutil.RuleMeta{{ID: "dast-cookie", Score: "5.0", Tags: []string{"external/cwe/cwe-1004"}}}
	ok := testutil.Doc{Engine: "sdrscan-dast", Rules: rules, Results: []testutil.SResult{{Rule: "dast-cookie", URI: "https://shop.example.com/login?x=1#f",
		Message: "cookie", Level: "warning", Evidence: "Set-Cookie: sid=SUPERSECRETSESSION; Path=/; Secure"}}}
	r, err := env.Ingest.Run(ctx, ingest.Params{Codebase: cb, Body: ok.Build(), Trigger: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Scan.Type != "dast" || r.ScanSummary.Medium != 1 {
		t.Fatalf("%+v", r)
	}
	var kind, url, snippet string
	var path *string
	_ = env.Pool.QueryRow(ctx, `SELECT location_kind, url, snippet, path FROM findings`).Scan(&kind, &url, &snippet, &path)
	if kind != "url" || url != "https://shop.example.com/login" || path != nil {
		t.Fatalf("location: %s %s %v", kind, url, path)
	}
	if strings.Contains(snippet, "SUPERSECRETSESSION") || !strings.Contains(snippet, "Set-Cookie: sid=[REDACTED]; Path=/; Secure") {
		t.Fatalf("evidence not redacted: %q", snippet)
	}
	// Host outside the target is rejected.
	bad := testutil.Doc{Engine: "sdrscan-dast", Rules: rules, Results: []testutil.SResult{{Rule: "dast-cookie", URI: "https://evil.example.net/x", Level: "warning"}}}
	if _, err := env.Ingest.Run(ctx, ingest.Params{Codebase: cb, Body: bad.Build(), Trigger: "ci"}); apiCode(err) != "location_outside_target" {
		t.Fatalf("got %v", err)
	}
	// SAST SARIF into a URL codebase is a mismatch.
	if _, err := env.Ingest.Run(ctx, ingest.Params{Codebase: cb, Body: full().Build(), Trigger: "ci"}); apiCode(err) != "engine_target_mismatch" {
		t.Fatalf("got %v", err)
	}
	// Partial is never valid for DAST.
	pd := testutil.Doc{Engine: "sdrscan-dast", Partial: true, Scanned: []string{"x"}}
	if _, err := env.Ingest.Run(ctx, ingest.Params{Codebase: cb, Body: pd.Build(), Trigger: "ci"}); err == nil {
		t.Fatal("partial DAST accepted")
	}
}

func TestRebuildStateRepairsFlags(t *testing.T) {
	f := newFx(t)
	f.must(full(res("php-sql-injection", "a.php", 1, "A"), res("php-xss-echo", "b.php", 1, "B")), "f")
	f.must(partial([]string{"a.php"}, res("php-xss-echo", "a.php", 2, "A2")), "p")
	good := f.currentPaths()
	// Corrupt the materialised state.
	if _, err := f.env.Pool.Exec(f.ctx, `UPDATE findings SET is_current = NOT is_current WHERE codebase_id = $1`, f.cb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Pool.Exec(f.ctx, `UPDATE codebases SET n_critical = 99, base_scan_id = NULL WHERE id = $1`, f.cb.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := f.env.Store.RebuildState(f.ctx, 0); err != nil || n != 1 {
		t.Fatalf("rebuild: %d %v", n, err)
	}
	f.check()
	if got := f.currentPaths(); fmt.Sprint(got) != fmt.Sprint(good) {
		t.Fatalf("rebuilt state %v != %v", got, good)
	}
}
