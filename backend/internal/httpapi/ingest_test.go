package httpapi_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/httpapi"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func sarifDoc(rs ...testutil.SResult) []byte {
	return testutil.Doc{Rules: testutil.StdRules, Results: rs}.Build()
}

func sr(rule, file string, line int, snippet string) testutil.SResult {
	return testutil.SResult{Rule: rule, URI: file, Line: line, Snippet: snippet, Level: "error", Message: "m " + rule}
}

func ingest(w *world, token, query string, body []byte, hdr map[string]string) testutilResp {
	h := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	for k, v := range hdr {
		h[k] = v
	}
	return w.anon.Raw("POST", "/api/v1/ingest?"+query, bytes.NewReader(body), h)
}

type testutilResp = testutil.Resp

func q(project, codebase, ref string) string {
	v := url.Values{"project": {project}, "codebase": {codebase}}
	if ref != "" {
		v.Set("ref", ref)
	}
	return v.Encode()
}

func TestIngestByNameEndToEnd(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	tok := w.token(t, "ci", nil)
	body := sarifDoc(sr("php-sql-injection", "src/a.php", 4, "q"), sr("php-xss-echo", "src/b.php", 9, "e"))
	r := ingest(w, tok, q("online shop", "STOREFRONT", "abc"), body, nil) // names are case-insensitive
	j := r.JSON()
	if r.Status != 201 || j["duplicate"] != false {
		t.Fatalf("ingest: %d %s", r.Status, r.Body)
	}
	if s := j["scan_summary"].(map[string]any); s["critical"].(float64) != 1 || s["high"].(float64) != 1 || s["highest_severity"] != "critical" {
		t.Fatalf("scan_summary: %v", s)
	}
	if s := j["codebase_summary"].(map[string]any); s["critical"].(float64) != 1 {
		t.Fatalf("codebase_summary: %v", s)
	}
	sc := j["scan"].(map[string]any)
	if sc["coverage"] != "full" || sc["status"] != "succeeded" || sc["engine"] != "sdrscan-sast" || j["superseded"] != false {
		t.Fatalf("scan: %v", sc)
	}
	// The data is readable through the session API.
	fl := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/findings", cb)).JSON()
	if fl["total"].(float64) != 2 {
		t.Fatalf("findings: %v", fl)
	}
	// Same payload again: 200 duplicate pointing at the first scan.
	r2 := ingest(w, tok, q("Online Shop", "storefront", "abc"), body, nil)
	j2 := r2.JSON()
	if r2.Status != 200 || j2["duplicate"] != true || j2["scan"].(map[string]any)["id"] != sc["id"] || j2["is_latest_scan"] != true {
		t.Fatalf("duplicate: %d %s", r2.Status, r2.Body)
	}
	// by id
	r3 := w.anon.Raw("POST", fmt.Sprintf("/api/v1/codebases/%d/ingest?ref=zzz", cb), bytes.NewReader(sarifDoc()), map[string]string{
		"Authorization": "Bearer " + tok, "Content-Type": "application/sarif+json"})
	if r3.Status != 201 {
		t.Fatalf("by id: %d %s", r3.Status, r3.Body)
	}
	if cbj := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d", cb)).JSON(); cbj["summary"].(map[string]any)["highest_severity"] != nil {
		t.Fatalf("the clean full scan must reset the summary: %v", cbj["summary"])
	}
	// last_used_at is stamped.
	var used bool
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT last_used_at IS NOT NULL FROM ingest_tokens`).Scan(&used)
	if !used {
		t.Fatal("last_used_at not set")
	}
}

func TestIngestRejectsUnknownTargetsWithSuggestions(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	w.repo(t, w.member, "storefront")
	w.urlTarget(t, w.admin, "storefront (live)", "https://shop.example.com")
	tok := w.token(t, "ci", nil)
	r := ingest(w, tok, q("Online Shop", "storefrnt", ""), sarifDoc(), nil)
	j := r.JSON()["error"].(map[string]any)
	d := j["details"].(map[string]any)
	if r.Status != 404 || j["code"] != "codebase_not_found" || !strings.Contains(j["message"].(string), "storefrnt") {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	av := d["available_codebases"].([]any)
	if len(av) != 2 || av[0] != "storefront" || d["project"].(map[string]any)["name"] != "Online Shop" {
		t.Fatalf("suggestions (closest first): %v", d)
	}
	r = ingest(w, tok, q("Onlin Shop", "storefront", ""), sarifDoc(), nil)
	j = r.JSON()["error"].(map[string]any)
	if r.Status != 404 || j["code"] != "project_not_found" || j["details"].(map[string]any)["available_projects"].([]any)[0] != "Online Shop" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// Nothing was created.
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM projects) + (SELECT count(*) FROM codebases) + (SELECT count(*) FROM scans)`).Scan(&n)
	if n != 3 {
		t.Fatalf("rows after rejected ingests: %d", n)
	}
	// Suggestions are capped at 20.
	for i := 0; i < 25; i++ {
		w.repo(t, w.member, fmt.Sprintf("svc-%02d", i))
	}
	r = ingest(w, tok, q("Online Shop", "svc", ""), sarifDoc(), nil)
	if got := len(r.JSON()["error"].(map[string]any)["details"].(map[string]any)["available_codebases"].([]any)); got != 20 {
		t.Fatalf("suggestion cap: %d", got)
	}
	if r := ingest(w, tok, "codebase=x", sarifDoc(), nil); r.Status != 400 {
		t.Fatalf("missing project param: %d", r.Status)
	}
}

func TestIngestTokenRules(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	w.repo(t, w.member, "storefront")
	other := w.member.Do("POST", "/api/v1/projects", map[string]any{"name": "Other"})
	otherID := testutil.MustID(t, other.JSON(), "id")
	w.admin.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", otherID), map[string]any{"name": "svc", "target_type": "repo", "repo_url": "https://git.example.com/s.git"})
	body := sarifDoc()
	if r := ingest(w, "", q("Online Shop", "storefront", ""), body, nil); r.Status != 401 || r.ErrCode() != "invalid_token" {
		t.Fatalf("no token: %d %s", r.Status, r.Body)
	}
	if r := ingest(w, "sdrscan_wrong", q("Online Shop", "storefront", ""), body, nil); r.Status != 401 || r.ErrCode() != "invalid_token" {
		t.Fatalf("wrong token: %d", r.Status)
	}
	scoped := w.token(t, "scoped", &otherID)
	if r := ingest(w, scoped, q("Online Shop", "storefront", ""), body, nil); r.Status != 401 || r.ErrCode() != "invalid_token" {
		t.Fatalf("token for another project: %d %s", r.Status, r.Body)
	}
	if r := ingest(w, scoped, q("Other", "svc", ""), body, nil); r.Status != 201 {
		t.Fatalf("token inside its project: %d %s", r.Status, r.Body)
	}
	// Tokens are stored hashed and the raw value is shown once only.
	tok := w.token(t, "plain", nil)
	var stored string
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT token_hash FROM ingest_tokens WHERE name = 'plain'`).Scan(&stored)
	if stored == tok || strings.Contains(stored, "sdrscan_") || len(stored) != 64 {
		t.Fatalf("token stored as %q", stored)
	}
	list := w.admin.Get("/api/v1/ingest-tokens")
	if bytes.Contains(list.Body, []byte(tok)) || !bytes.Contains(list.Body, []byte(`"token_prefix"`)) {
		t.Fatalf("list must show the prefix only: %s", list.Body)
	}
	// Revoke takes effect at once.
	items := list.JSON()["items"].([]any)
	var id int64
	for _, it := range items {
		m := it.(map[string]any)
		if m["name"] == "plain" {
			id = int64(m["id"].(float64))
		}
	}
	if r := ingest(w, tok, q("Online Shop", "storefront", "r1"), body, nil); r.Status != 201 {
		t.Fatalf("before revoke: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("DELETE", fmt.Sprintf("/api/v1/ingest-tokens/%d", id), nil); r.Status != 204 {
		t.Fatalf("revoke: %d", r.Status)
	}
	if r := ingest(w, tok, q("Online Shop", "storefront", "r2"), body, nil); r.Status != 401 {
		t.Fatalf("after revoke: %d", r.Status)
	}
	if r := w.admin.Do("POST", "/api/v1/ingest-tokens", map[string]any{"name": "x", "project_id": 99999}); r.Status != 422 {
		t.Fatalf("token for a missing project: %d", r.Status)
	}
}

func TestIngestSizeEncodingAndContentType(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{Server: httpapi.Options{MaxBodyBytes: 20000}})
	w.repo(t, w.member, "storefront")
	tok := w.token(t, "ci", nil)
	qs := q("Online Shop", "storefront", "")
	big := sarifDoc(sr("php-xss-echo", "a.php", 1, strings.Repeat("x", 30000)))
	if r := ingest(w, tok, qs, big, nil); r.Status != 413 || r.ErrCode() != "payload_too_large" {
		t.Fatalf("oversize: %d %s", r.Status, r.Body)
	}
	if r := ingest(w, tok, qs, sarifDoc(), map[string]string{"Content-Type": "text/plain"}); r.Status != 415 {
		t.Fatalf("text/plain: %d", r.Status)
	}
	if r := ingest(w, tok, qs, []byte("{broken"), nil); r.Status != 422 || r.ErrCode() != "invalid_sarif" {
		t.Fatalf("broken JSON: %d %s", r.Status, r.Body)
	}
	// gzip is accepted and the limit applies to the decompressed size (gzip bomb).
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(sarifDoc(sr("php-xss-echo", "a.php", 1, "x")))
	zw.Close()
	if r := ingest(w, tok, qs, gz.Bytes(), map[string]string{"Content-Encoding": "gzip"}); r.Status != 201 {
		t.Fatalf("gzip: %d %s", r.Status, r.Body)
	}
	gz.Reset()
	zw = gzip.NewWriter(&gz)
	zw.Write(big)
	zw.Close()
	if gz.Len() > 20000 {
		t.Fatalf("test premise: compressed bomb is %d bytes", gz.Len())
	}
	if r := ingest(w, tok, qs+"&ref=bomb", gz.Bytes(), map[string]string{"Content-Encoding": "gzip"}); r.Status != 413 {
		t.Fatalf("gzip bomb: %d %s", r.Status, r.Body)
	}
	if r := ingest(w, tok, qs, []byte("not gzip"), map[string]string{"Content-Encoding": "gzip"}); r.Status != 400 {
		t.Fatalf("bad gzip: %d", r.Status)
	}
	if r := ingest(w, tok, qs, sarifDoc(), map[string]string{"Content-Encoding": "br"}); r.Status != 415 {
		t.Fatalf("unsupported encoding: %d", r.Status)
	}
	if r := ingest(w, tok, qs+"&started_at=yesterday", sarifDoc(), nil); r.Status != 400 {
		t.Fatalf("bad started_at: %d", r.Status)
	}
}

func TestIngestValidationErrorsOverHTTP(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	w.repo(t, w.member, "storefront")
	u := w.urlTarget(t, w.admin, "live", "https://shop.example.com")
	tok := w.token(t, "ci", nil)
	qs := q("Online Shop", "storefront", "")
	cases := []struct {
		name   string
		body   []byte
		status int
		code   string
	}{
		{"two runs", testutil.Doc{Runs: 2}.Build(), 422, "multiple_runs"},
		{"unknown engine", testutil.Doc{Engine: "other"}.Build(), 422, "unsupported_engine"},
		{"dast engine on repo", testutil.Doc{Engine: "sdrscan-dast"}.Build(), 422, "engine_target_mismatch"},
		{"no fingerprint", testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a.php", Line: 1, NoFP: true}}}.Build(), 422, "missing_fingerprint"},
		{"old fingerprint key", testutil.Doc{Results: []testutil.SResult{{Rule: "r", URI: "a.php", Line: 1, FPKey: "primaryLocationLineHash"}}}.Build(), 422, "missing_fingerprint"},
		{"partial before a full scan", testutil.Doc{Partial: true, Scanned: []string{"a.php"}}.Build(), 409, "baseline_required"},
	}
	for _, c := range cases {
		r := ingest(w, tok, qs, c.body, nil)
		if r.Status != c.status || r.ErrCode() != c.code {
			t.Errorf("%s: %d %s", c.name, r.Status, r.Body)
		}
	}
	// The error names the index of the offending result.
	r := ingest(w, tok, qs, testutil.Doc{Results: []testutil.SResult{
		{Rule: "r", URI: "a.php", Line: 1}, {Rule: "r", URI: "a.php", Line: 2, NoFP: true}}}.Build(), nil)
	if d := r.JSON()["error"].(map[string]any)["details"].(map[string]any); d["result_index"].(float64) != 1 {
		t.Fatalf("details: %s", r.Body)
	}
	// DAST target: result outside the host.
	rr := w.anon.Raw("POST", fmt.Sprintf("/api/v1/codebases/%d/ingest", u), bytes.NewReader(testutil.Doc{Engine: "sdrscan-dast", Results: []testutil.SResult{
		{Rule: "dast-x", URI: "https://evil.example/", Level: "note"}}}.Build()), map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
	if rr.Status != 422 || rr.ErrCode() != "location_outside_target" {
		t.Fatalf("outside host: %d %s", rr.Status, rr.Body)
	}
	if n := countRows(w, "scans"); n != 0 {
		t.Fatalf("rejected ingests created %d scans", n)
	}
}

func countRows(w *world, table string) int {
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n)
	return n
}

func TestPartialIngestAndLateScanOverHTTP(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	tok := w.token(t, "ci", nil)
	qs := q("Online Shop", "storefront", "")
	r := ingest(w, tok, qs+"&ref=full&started_at=2026-03-01T10:00:00Z", sarifDoc(sr("php-sql-injection", "a.php", 1, "A"), sr("php-xss-echo", "b.php", 1, "B")), nil)
	if r.Status != 201 {
		t.Fatalf("full: %d %s", r.Status, r.Body)
	}
	pdoc := testutil.Doc{Rules: testutil.StdRules, Partial: true, Scanned: []string{"a.php"}}.Build()
	r = ingest(w, tok, qs+"&ref=p1&started_at=2026-03-01T11:00:00Z", pdoc, nil)
	j := r.JSON()
	if r.Status != 201 || j["scan"].(map[string]any)["coverage"] != "partial" {
		t.Fatalf("partial: %d %s", r.Status, r.Body)
	}
	if s := j["codebase_summary"].(map[string]any); s["critical"].(float64) != 0 || s["high"].(float64) != 1 {
		t.Fatalf("a.php fixed, b.php stays: %v", s)
	}
	cbj := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d", cb)).JSON()
	if st := cbj["state"].(map[string]any); st["partial_scans_since_base"].(float64) != 1 {
		t.Fatalf("state: %v", st)
	}
	// A late scan is stored but does not move the current state.
	r = ingest(w, tok, qs+"&ref=late&started_at=2026-02-01T00:00:00Z", sarifDoc(sr("php-sql-injection", "z.php", 1, "Z")), nil)
	if r.Status != 201 || r.JSON()["superseded"] != true {
		t.Fatalf("late: %d %s", r.Status, r.Body)
	}
	fl := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/findings", cb)).JSON()
	if fl["total"].(float64) != 1 {
		t.Fatalf("current findings after the late scan: %v", fl["total"])
	}
	// Partial scan history shows scan_files count.
	h := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/scans", cb)).JSON()
	if h["total"].(float64) != 3 {
		t.Fatalf("history: %v", h)
	}
}

func TestSecretsNeverAppearInResponsesOrDatabase(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	tok := w.token(t, "ci", nil)
	const secret = "sk_live_VERYSECRETVALUE_0987654321"
	res := sr("php-hardcoded-secret", "cfg.php", 2, "$apiKey = '"+secret+"'")
	res.Message = "secret '" + secret + "'"
	r := ingest(w, tok, q("Online Shop", "storefront", ""), sarifDoc(res), nil)
	if r.Status != 201 || r.JSON()["redacted_findings"].(float64) != 1 {
		t.Fatalf("ingest: %d %s", r.Status, r.Body)
	}
	fl := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/findings", cb))
	fid := testutil.MustID(t, fl.JSON()["items"].([]any)[0].(map[string]any), "id")
	det := w.member.Get(fmt.Sprintf("/api/v1/findings/%d", fid))
	for _, b := range [][]byte{r.Body, fl.Body, det.Body} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("secret in an API response")
		}
	}
	d := det.JSON()
	if d["snippet"] != "$apiKey = '[REDACTED]'" || d["redacted"] != true {
		t.Fatalf("detail: %s", det.Body)
	}
	loc := d["location"].(map[string]any)
	if loc["kind"] != "file" || loc["path"] != "cfg.php" || loc["start_line"].(float64) != 2 {
		t.Fatalf("location: %v", loc)
	}
	// Whole-database search for the value (all tables, as text).
	var hits int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings f WHERE f::text LIKE '%'||$1||'%'`, secret).Scan(&hits)
	if hits != 0 {
		t.Fatal("secret found in the findings table")
	}
}
