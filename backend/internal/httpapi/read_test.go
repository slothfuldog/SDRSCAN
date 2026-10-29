package httpapi_test

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/httpapi"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

type scanFixture struct {
	w   *world
	cb  int64
	tok string
}

func newScanFixture(t *testing.T) *scanFixture {
	w := newWorld(t, testutil.EnvOptions{})
	return &scanFixture{w: w, cb: w.repo(t, w.member, "storefront"), tok: w.token(t, "ci", nil)}
}

func (f *scanFixture) push(t *testing.T, ref, at string, d testutil.Doc) map[string]any {
	t.Helper()
	qs := q("Online Shop", "storefront", ref) + "&started_at=" + at
	r := ingest(f.w, f.tok, qs, d.Build(), nil)
	if r.Status != 201 {
		t.Fatalf("push %s: %d %s", ref, r.Status, r.Body)
	}
	return r.JSON()["scan"].(map[string]any)
}

func TestFindingFiltersFacetsSortAndFiles(t *testing.T) {
	f := newScanFixture(t)
	low := sr("php-info", "a.php", 50, "low")
	low.Level, low.Low = "note", true
	f.push(t, "r1", "2026-03-01T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{
		sr("php-xss-echo", "src/b.php", 20, "echo $_GET['q']"), sr("php-sql-injection", "src/a.php", 10, "mysqli_query"),
		sr("php-sql-injection", "src/a.php", 5, "mysql_query"), sr("php-weak-password-hash", "lib/c.php", 1, "md5"), low,
	}})
	base := fmt.Sprintf("/api/v1/codebases/%d/findings", f.cb)
	list := func(qs string) map[string]any {
		r := f.w.member.Get(base + qs)
		if r.Status != 200 {
			t.Fatalf("%s: %d %s", qs, r.Status, r.Body)
		}
		return r.JSON()
	}
	all := list("")
	items := all["items"].([]any)
	if all["total"].(float64) != 4 {
		t.Fatalf("total (low confidence hidden): %v", all["total"])
	}
	// Default order: severity desc, then path, then line.
	var order []string
	for _, it := range items {
		m := it.(map[string]any)
		loc := m["location"].(map[string]any)
		order = append(order, fmt.Sprintf("%s:%v", loc["path"], loc["start_line"]))
		if _, has := m["snippet"]; has {
			t.Fatal("list items must not carry snippets")
		}
	}
	if fmt.Sprint(order) != "[src/a.php:5 src/a.php:10 src/b.php:20 lib/c.php:1]" {
		t.Fatalf("order: %v", order)
	}
	fc := all["facets"].(map[string]any)
	if sv := fc["severity"].(map[string]any); sv["critical"].(float64) != 2 || sv["high"].(float64) != 1 || sv["medium"].(float64) != 1 {
		t.Fatalf("severity facets: %v", sv)
	}
	if rules := fc["rule"].([]any); rules[0].(map[string]any)["id"] != "php-sql-injection" || rules[0].(map[string]any)["count"].(float64) != 2 {
		t.Fatalf("rule facets: %v", rules)
	}
	if got := list("?severity=high,medium")["total"].(float64); got != 2 {
		t.Fatalf("severity filter: %v", got)
	}
	if got := list("?rule=php-sql-injection")["total"].(float64); got != 2 {
		t.Fatalf("rule filter: %v", got)
	}
	if got := list("?path=src/")["total"].(float64); got != 3 {
		t.Fatalf("path prefix: %v", got)
	}
	if got := list("?q=c.php")["total"].(float64); got != 1 {
		t.Fatalf("q on path: %v", got)
	}
	if got := list("?q=m%20php-xss")["total"].(float64); got != 1 {
		t.Fatalf("q on message: %v", got)
	}
	if got := list("?q=%25")["total"].(float64); got != 0 {
		t.Fatalf("LIKE wildcards must be escaped, got %v", got)
	}
	if got := list("?q=_")["total"].(float64); got != 0 {
		t.Fatalf("underscore wildcard must be escaped, got %v", got)
	}
	if got := list("?include_low_confidence=true")["total"].(float64); got != 5 {
		t.Fatalf("low confidence: %v", got)
	}
	// Facets reflect the other active filters: the severity facet ignores the severity filter.
	fc2 := list("?severity=high&rule=php-xss-echo")["facets"].(map[string]any)
	if fc2["severity"].(map[string]any)["high"].(float64) != 1 || fc2["severity"].(map[string]any)["critical"].(float64) != 0 {
		t.Fatalf("facets with filters: %v", fc2)
	}
	if got := list("?page_size=2&page=2")["items"].([]any); len(got) != 2 {
		t.Fatalf("paging: %d", len(got))
	}
	for _, bad := range []string{"?severity=urgent", "?include_low_confidence=maybe", "?sort=path", "?page_size=0"} {
		if r := f.w.member.Get(base + bad); r.Status != 400 {
			t.Errorf("%s: %d", bad, r.Status)
		}
	}
	// SQL injection attempts are just data.
	if got := list("?q=%27%20OR%201%3D1%3B--")["total"].(float64); got != 0 {
		t.Fatalf("injection probe matched %v rows", got)
	}
	// Per-file view.
	fr := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/files", f.cb)).JSON()
	files := fr["items"].([]any)
	first := files[0].(map[string]any)
	if fr["total"].(float64) != 3 || first["location"] != "src/a.php" || first["total"].(float64) != 2 || first["critical"].(float64) != 2 || first["highest_severity"] != "critical" {
		t.Fatalf("files: %v", fr)
	}
	// A single scan's own findings and files.
	scanID := int64(f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/scans", f.cb)).JSON()["items"].([]any)[0].(map[string]any)["id"].(float64))
	if got := f.w.member.Get(fmt.Sprintf("/api/v1/scans/%d/findings", scanID)).JSON()["total"].(float64); got != 4 {
		t.Fatalf("scan findings: %v", got)
	}
	if got := f.w.member.Get(fmt.Sprintf("/api/v1/scans/%d/files", scanID)).JSON()["total"].(float64); got != 3 {
		t.Fatalf("scan files: %v", got)
	}
	if r := f.w.member.Get("/api/v1/findings/9999999"); r.Status != 404 {
		t.Fatalf("missing finding: %d", r.Status)
	}
}

func TestCompareScans(t *testing.T) {
	f := newScanFixture(t)
	a := testutil.SResult{Rule: "php-sql-injection", URI: "a.php", Line: 10, Snippet: "A", Level: "error", FP: testutil.FP("A")}
	b := testutil.SResult{Rule: "php-xss-echo", URI: "b.php", Line: 3, Snippet: "B", Level: "error", FP: testutil.FP("B")}
	c := testutil.SResult{Rule: "php-weak-password-hash", URI: "c.php", Line: 3, Snippet: "C", Level: "warning", FP: testutil.FP("C")}
	s1 := f.push(t, "r1", "2026-03-01T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{a, b}})
	// Second scan: A moved (same fingerprint, other line) = unchanged; B fixed; C new.
	a2 := a
	a2.Line = 42
	s2 := f.push(t, "r2", "2026-03-02T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{a2, c}})
	cmp := func(qs string) map[string]any {
		r := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare%s", f.cb, qs))
		if r.Status != 200 {
			t.Fatalf("%s: %d %s", qs, r.Status, r.Body)
		}
		return r.JSON()
	}
	j := cmp("")
	counts := j["counts"].(map[string]any)
	if counts["new"].(float64) != 1 || counts["unchanged"].(float64) != 1 || counts["fixed"].(float64) != 1 {
		t.Fatalf("counts: %v", counts)
	}
	if j["scope"].(map[string]any)["kind"] != "all" || j["base"].(map[string]any)["id"] != s1["id"] || j["head"].(map[string]any)["id"] != s2["id"] {
		t.Fatalf("default pair: %v", j)
	}
	ruleOf := func(qs string) string {
		items := cmp(qs)["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("%s: %d items", qs, len(items))
		}
		return items[0].(map[string]any)["finding"].(map[string]any)["rule_id"].(string)
	}
	if ruleOf("?status=new") != "php-weak-password-hash" || ruleOf("?status=fixed") != "php-xss-echo" || ruleOf("?status=unchanged") != "php-sql-injection" {
		t.Fatal("status lists")
	}
	if line := cmp("?status=unchanged")["items"].([]any)[0].(map[string]any)["finding"].(map[string]any)["location"].(map[string]any)["start_line"].(float64); line != 42 {
		t.Fatalf("unchanged must show the head line, got %v", line)
	}
	// Changed snippet (new fingerprint) = fixed + new.
	a3 := a2
	a3.FP, a3.Snippet = testutil.FP("A-changed"), "A changed"
	s3 := f.push(t, "r3", "2026-03-03T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{a3, c}})
	j = cmp(fmt.Sprintf("?base=%v&head=%v", s2["id"], s3["id"]))
	counts = j["counts"].(map[string]any)
	if counts["new"].(float64) != 1 || counts["fixed"].(float64) != 1 || counts["unchanged"].(float64) != 1 {
		t.Fatalf("changed snippet: %v", counts)
	}
	// Partial head: scope limited to the scanned files.
	sp := f.push(t, "r4", "2026-03-04T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Partial: true, Scanned: []string{"a.php"}, Results: []testutil.SResult{a3}})
	j = cmp(fmt.Sprintf("?base=%v&head=%v", s3["id"], sp["id"]))
	sc := j["scope"].(map[string]any)
	counts = j["counts"].(map[string]any)
	if sc["kind"] != "partial" || sc["file_count"].(float64) != 1 || counts["fixed"].(float64) != 0 || counts["unchanged"].(float64) != 1 || counts["new"].(float64) != 0 {
		t.Fatalf("partial scope: %v %v", sc, counts)
	}
	// Empty intersection of two partial scans -> warning.
	sp2 := f.push(t, "r5", "2026-03-05T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Partial: true, Scanned: []string{"z.php"}})
	j = cmp(fmt.Sprintf("?base=%v&head=%v", sp["id"], sp2["id"]))
	if j["warning"] == nil || j["scope"].(map[string]any)["file_count"].(float64) != 0 {
		t.Fatalf("empty intersection: %v", j)
	}
	// Errors.
	for _, bad := range []string{"?base=1", "?base=x&head=y", fmt.Sprintf("?base=%v&head=999999", s1["id"]), "?status=weird"} {
		if r := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare%s", f.cb, bad)); r.Status != 400 {
			t.Errorf("%s: %d %s", bad, r.Status, r.Body)
		}
	}
	// A failed scan cannot be compared.
	_, _ = f.w.env.Pool.Exec(context.Background(), `UPDATE scans SET status='failed' WHERE id = $1`, int64(s1["id"].(float64)))
	if r := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare?base=%v&head=%v", f.cb, s1["id"], s2["id"])); r.Status != 400 {
		t.Fatalf("failed scan in compare: %d", r.Status)
	}
	// Only one scan: all new, base null.
	w2 := newScanFixture(t)
	w2.push(t, "r1", "2026-03-01T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{a}})
	r := w2.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare", w2.cb))
	if r.Status != 200 || r.JSON()["base"] != nil || r.JSON()["counts"].(map[string]any)["new"].(float64) != 1 {
		t.Fatalf("single scan compare: %d %s", r.Status, r.Body)
	}
}

func TestScanCancelAndHistory(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	ctx := context.Background()
	r := w.member.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": cb})
	if r.Status != 202 {
		t.Fatal(r.Status)
	}
	id := int64(r.JSON()["id"].(float64))
	if r2 := w.admin.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": cb}); r2.Status != 409 || r2.ErrCode() != "scan_in_progress" {
		t.Fatalf("second job: %d %s", r2.Status, r2.Body)
	}
	// Cancel a queued job (any signed-in user).
	cr := w.dastUser.Do("POST", fmt.Sprintf("/api/v1/scans/%d/cancel", id), nil)
	if cr.Status != 202 || cr.JSON()["status"] != "cancelled" {
		t.Fatalf("cancel queued: %d %s", cr.Status, cr.Body)
	}
	if cr := w.member.Do("POST", fmt.Sprintf("/api/v1/scans/%d/cancel", id), nil); cr.Status != 409 {
		t.Fatalf("cancel finished: %d", cr.Status)
	}
	if cr := w.member.Do("POST", "/api/v1/scans/999999/cancel", nil); cr.Status != 404 {
		t.Fatalf("cancel missing: %d", cr.Status)
	}
	// A running job only gets the flag.
	r = w.member.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": cb})
	id2 := int64(r.JSON()["id"].(float64))
	_, _ = w.env.Pool.Exec(ctx, `UPDATE scans SET status='running', started_at=now() WHERE id=$1`, id2)
	cr = w.member.Do("POST", fmt.Sprintf("/api/v1/scans/%d/cancel", id2), nil)
	if cr.Status != 202 || cr.JSON()["cancel_requested"] != true || cr.JSON()["status"] != "running" {
		t.Fatalf("cancel running: %d %s", cr.Status, cr.Body)
	}
	_, _ = w.env.Pool.Exec(ctx, `UPDATE scans SET status='failed', error_code='engine_failed', finished_at=now(), log_tail='boom' WHERE id=$1`, id2)
	g := w.member.Get(fmt.Sprintf("/api/v1/scans/%d", id2)).JSON()
	if g["error_code"] != "engine_failed" || g["log_tail"] != "boom" || g["status"] != "failed" {
		t.Fatalf("scan detail: %v", g)
	}
	// History: newest first, ?status= filter, duplicates hidden.
	h := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/scans", cb)).JSON()
	if h["total"].(float64) != 2 {
		t.Fatalf("history: %v", h)
	}
	if got := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/scans?status=failed", cb)).JSON()["total"].(float64); got != 1 {
		t.Fatalf("status filter: %v", got)
	}
	if r := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/scans?status=bogus", cb)); r.Status != 400 {
		t.Fatalf("bad status: %d", r.Status)
	}
	var dup int64
	_ = w.env.Pool.QueryRow(ctx, `INSERT INTO scans (codebase_id, type, trigger, status, duplicate_of_scan_id, started_at)
		VALUES ($1,'sast','manual','succeeded',$2, now()) RETURNING id`, cb, id).Scan(&dup)
	if got := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/scans", cb)).JSON()["total"].(float64); got != 2 {
		t.Fatalf("duplicate job rows must not appear in history: %v", got)
	}
	if r := w.member.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": 99999}); r.Status != 404 {
		t.Fatalf("unknown codebase: %d", r.Status)
	}
	if r := w.member.Do("POST", "/api/v1/scans", map[string]any{}); r.Status != 422 {
		t.Fatalf("missing codebase_id: %d", r.Status)
	}
}

func TestSSEStreamsStatusAndLog(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	ctx := context.Background()
	r := w.member.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": cb})
	id := int64(r.JSON()["id"].(float64))

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scans/%d/events", w.env.HTTP.URL, id), nil)
	req.AddCookie(&http.Cookie{Name: httpapi.SessionCookie, Value: w.member.Cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("sse: %d %v", resp.StatusCode, resp.Header)
	}
	events := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		var ev string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				events <- ev + " " + strings.TrimPrefix(line, "data: ")
			}
		}
		close(events)
	}()
	next := func() string {
		select {
		case e, ok := <-events:
			if !ok {
				return "<closed>"
			}
			return e
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for an SSE event")
			return ""
		}
	}
	if e := next(); !strings.HasPrefix(e, `status {"status":"queued"`) {
		t.Fatalf("first event: %s", e)
	}
	job, err := w.env.Store.ClaimJob(ctx, "w1", time.Minute)
	if err != nil || job.ID != id {
		t.Fatalf("claim: %v", err)
	}
	if e := next(); !strings.HasPrefix(e, `status {"status":"running"`) {
		t.Fatalf("running: %s", e)
	}
	w.env.Store.AppendLog(ctx, id, "cloned a1b2c3d (depth 1)")
	if e := next(); e != `log {"line":"cloned a1b2c3d (depth 1)"}` {
		t.Fatalf("log: %s", e)
	}
	_, _ = w.env.Pool.Exec(ctx, `UPDATE scans SET status='succeeded', finished_at=now(), n_high=3 WHERE id=$1`, id)
	last := next()
	if !strings.HasPrefix(last, `status {"status":"succeeded"`) || !strings.Contains(last, `"high":3`) {
		t.Fatalf("final: %s", last)
	}
	if e := next(); e != "<closed>" {
		t.Fatalf("stream must close after the scan ends, got %s", e)
	}
	// Unauthenticated streams are refused.
	if r := w.anon.Get(fmt.Sprintf("/api/v1/scans/%d/events", id)); r.Status != 401 {
		t.Fatalf("anonymous SSE: %d", r.Status)
	}
}
