package httpapi_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

var blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

// parseExample turns a TRD example (JSON with /* ... */ comments) into a value.
func parseExample(t *testing.T, src string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(blockComment.ReplaceAllString(src, "null")), &v); err != nil {
		t.Fatalf("bad example JSON: %v\n%s", err, src)
	}
	return v
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "?"
}

// assertShape checks that actual has exactly the keys and value types of the
// example: null vs absent matters (keys are never omitted), `null` in the
// example means the value must be null, and arrays are checked element-wise
// against the example's first element.
func assertShape(t *testing.T, path string, actual, example any) {
	t.Helper()
	switch ex := example.(type) {
	case map[string]any:
		ac, ok := actual.(map[string]any)
		if !ok {
			t.Errorf("%s: want an object, got %s", path, typeName(actual))
			return
		}
		var missing, extra []string
		for k := range ex {
			if _, ok := ac[k]; !ok {
				missing = append(missing, k)
			}
		}
		for k := range ac {
			if _, ok := ex[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 || len(extra) > 0 {
			t.Errorf("%s: missing keys %v, unexpected keys %v", path, missing, extra)
		}
		for k, ev := range ex {
			if av, ok := ac[k]; ok {
				assertShape(t, path+"."+k, av, ev)
			}
		}
	case []any:
		aa, ok := actual.([]any)
		if !ok {
			t.Errorf("%s: want an array, got %s", path, typeName(actual))
			return
		}
		if len(ex) > 0 {
			for i, av := range aa {
				assertShape(t, fmt.Sprintf("%s[%d]", path, i), av, ex[0])
			}
		}
	case nil:
		if actual != nil {
			t.Errorf("%s: want null, got %s (%v)", path, typeName(actual), actual)
		}
	default:
		if typeName(actual) != typeName(example) {
			t.Errorf("%s: want %s, got %s (%v)", path, typeName(example), typeName(actual), actual)
		}
	}
}

const exProjects = `{ "items": [ { "id": 3, "name": "Online Shop", "description": "Web and API", "codebase_count": 2,
    "totals": { "critical": 0, "high": 4, "medium": 11, "low": 3, "info": 0 }, "highest_severity": "high",
    "created_at": "2026-10-20T07:00:00Z" } ],
  "total": 1, "page": 1, "page_size": 50 }`

const exCodebaseURL = `{ "id": 8, "name": "storefront (live)", "target_type": "url", "project": { "id": 3, "name": "Online Shop" },
  "language": "", "base_url": "https://shop.example.com", "dast_max_rps": 5,
  "dast": { "status": "pending_confirmation", "registered_by": { "id": 4, "username": "dewi" },
            "confirmed_by": null, "confirmed_at": null },
  "dast_active": { "authorized": false, "authorized_at": null, "authorized_by": null, "openapi_spec_url": null },
  "confirmation_statement": "I confirm that I am authorized to run security scans against https://shop.example.com.",
  "active_scan": { "id": 61, "type": "dast", "status": "running", "trigger": "manual",
                   "queued_at": "2026-10-27T09:00:00Z", "started_at": "2026-10-27T09:00:03Z" },
  "latest_scan": null, "base_scan": null, "state": null, "summary": null, "schedule": null,
  "dast_auth": { "type": "none", "has_secret": false, "login_url": null, "method": null, "body_format": null, "username_field": null,
    "password_field": null, "username": null, "extra_field_names": [], "csrf": null, "token": null, "success": null, "header_names": [],
    "cookie_names": [], "updated_at": null, "updated_by": null },
  "dast_crawl": { "enabled": false, "max_depth": 3, "max_pages": 50, "exclude": [] },
  "created_at": "2026-10-27T08:00:00Z", "updated_at": "2026-10-27T08:00:00Z" }`

const exFindings = `{ "items": [ { "id": 1, "rule_id": "php-sql-injection", "severity": "high", "confidence": "normal", "message": "m",
      "location": { "kind": "file", "path": "a.php", "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 5 }, "redacted": false,
      "kind": "code", "vulnerability": null } ],
  "total": 14, "page": 1, "page_size": 50,
  "facets": { "severity": { "critical": 0, "high": 3, "medium": 8, "low": 2, "info": 1 },
              "rule": [ { "id": "php-sql-injection", "count": 5 }, { "id": "php-xss-echo", "count": 4 } ],
              "kind": { "code": 14, "vulnerability": 0 }, "cve": [], "vulnerable_packages": 0,
              "confidence": { "high": 0, "low": 0 }, "scope": { "runtime": 0, "dev": 0 } } }`

const exCompare = `{ "base": { "id": 39, "started_at": "2026-10-20T08:00:00Z", "coverage": "full" },
  "head": { "id": 58, "started_at": "2026-10-27T08:30:04Z", "coverage": "partial" },
  "counts": { "new": 2, "unchanged": 9, "fixed": 1 },
  "scope": { "kind": "partial", "file_count": 14 },
  "warning": null, "status": "new",
  "items": [ { "status": "new", "finding": { "id": 1, "rule_id": "r", "severity": "high", "confidence": "normal", "message": "m",
      "location": { "kind": "file", "path": "a.php", "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 5 }, "redacted": false,
      "kind": "code", "vulnerability": null } } ],
  "total": 2, "page": 1, "page_size": 50 }`

const exTokens = `{ "items": [ { "id": 2, "name": "gitlab-ci", "token_prefix": "sdrscan_a", "project": { "id": 3, "name": "Online Shop" },
    "created_by": { "id": 1, "username": "admin" }, "created_at": "2026-10-21T07:00:00Z",
    "last_used_at": null, "revoked_at": null, "status": "active" } ],
  "total": 1, "page": 1, "page_size": 50 }`

const exScheduleRow = `{ "codebase": { "id": 7, "name": "storefront", "target_type": "repo" }, "project": { "id": 3, "name": "Online Shop" },
  "cron": "0 2 * * *", "status": "suspended", "owner": { "id": 4, "username": "dewi" },
  "suspended_reason": "owner_lost_permission", "suspended_at": "2026-10-26T10:00:00Z",
  "last_enqueued_at": "2026-10-26T02:00:00Z", "next_run_at": null }`

func TestDTOProjectsList(t *testing.T) {
	v := newVisWorld(t)
	r := v.admin.Get("/api/v1/projects")
	assertShape(t, "GET /projects", r.JSON(), parseExample(t, exProjects))
	it := r.JSON()["items"].([]any)[0].(map[string]any)
	if it["codebase_count"].(float64) != 2 || it["highest_severity"] != "critical" || it["totals"].(map[string]any)["critical"].(float64) != 2 {
		t.Fatalf("values: %v", it)
	}
	// A project without findings: totals is an object of zeros, highest_severity null.
	e := v.admin.Do("POST", "/api/v1/projects", map[string]any{"name": "Empty"})
	_ = e
	for _, x := range v.admin.Get("/api/v1/projects").JSON()["items"].([]any) {
		m := x.(map[string]any)
		if m["name"] == "Empty" && (m["highest_severity"] != nil || m["codebase_count"].(float64) != 0 || m["totals"].(map[string]any)["high"].(float64) != 0) {
			t.Fatalf("empty project: %v", m)
		}
	}
}

func TestDTOCodebase(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "storefront (live)", "https://shop.example.com")
	// An active (running) scan, as in the example.
	_, err := w.env.Pool.Exec(t.Context(), `INSERT INTO scans (codebase_id, type, trigger, status, started_at) VALUES ($1, 'dast', 'manual', 'running', now())`, id)
	if err != nil {
		t.Fatal(err)
	}
	r := w.dastUser.Get(fmt.Sprintf("/api/v1/codebases/%d", id))
	assertShape(t, "GET /codebases/{id} (url)", r.JSON(), parseExample(t, exCodebaseURL))
	// Once confirmed the statement is null and the confirmation fields are filled.
	w.confirm(t, id)
	j := w.dastUser.Get(fmt.Sprintf("/api/v1/codebases/%d", id)).JSON()
	if j["confirmation_statement"] != nil || j["dast"].(map[string]any)["confirmed_by"] == nil {
		t.Fatalf("confirmed: %v", j)
	}
	// A repo has every URL key (null) plus the repo keys (filled).
	rid := w.repo(t, w.member, "storefront")
	rj := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d", rid)).JSON()
	uj := w.dastUser.Get(fmt.Sprintf("/api/v1/codebases/%d", id)).JSON()
	for k := range uj {
		if _, ok := rj[k]; !ok {
			t.Errorf("repo DTO lacks key %q", k)
		}
	}
	for _, k := range []string{"repo_url", "branch", "subdirectory", "git_auth_kind", "has_credential"} {
		if _, ok := uj[k]; ok {
			t.Errorf("URL DTO must not carry %q", k)
		}
	}
	for _, k := range []string{"dast", "dast_active", "base_url", "confirmation_statement"} {
		if rj[k] != nil {
			t.Errorf("repo %s must be null, got %v", k, rj[k])
		}
	}
	for _, k := range []string{"repo_url", "branch", "subdirectory", "git_auth_kind", "has_credential"} {
		if rj[k] == nil {
			t.Errorf("repo %s must be filled", k)
		}
	}
	if rj["project"].(map[string]any)["name"] != "Online Shop" || rj["active_scan"] != nil {
		t.Fatalf("repo: %v", rj)
	}
	// active_scan is the queued or running scan.
	w.member.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": rid})
	a := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d", rid)).JSON()["active_scan"].(map[string]any)
	if a["status"] != "queued" || a["started_at"] != nil || a["type"] != "sast" || a["trigger"] != "manual" {
		t.Fatalf("active_scan: %v", a)
	}
}

func TestDTOFindingsFacetsAndCompare(t *testing.T) {
	f := newScanFixture(t)
	a := testutil.SResult{Rule: "php-sql-injection", URI: "a.php", Line: 10, Snippet: "A", Level: "error", FP: testutil.FP("A")}
	b := testutil.SResult{Rule: "php-xss-echo", URI: "b.php", Line: 3, Snippet: "B", Level: "error", FP: testutil.FP("B")}
	s1 := f.push(t, "r1", "2026-03-01T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{a, b}})
	r := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/findings", f.cb))
	assertShape(t, "GET /codebases/{id}/findings", r.JSON(), parseExample(t, exFindings))
	// facets.rule is ordered by count desc then id; the selected rule stays listed with 0.
	fc := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/findings?rule=php-xss-echo", f.cb)).JSON()["facets"].(map[string]any)
	rules := fc["rule"].([]any)
	if len(rules) != 2 || rules[0].(map[string]any)["id"] != "php-sql-injection" || rules[1].(map[string]any)["id"] != "php-xss-echo" {
		t.Fatalf("rule facets: %v", rules)
	}
	z := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/findings?rule=php-weak-password-hash", f.cb)).JSON()
	if z["total"].(float64) != 0 || z["items"] == nil {
		t.Fatalf("empty result must still carry items: %v", z)
	}
	found := false
	for _, x := range z["facets"].(map[string]any)["rule"].([]any) {
		if x.(map[string]any)["id"] == "php-weak-password-hash" && x.(map[string]any)["count"].(float64) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the selected rule must stay in facets.rule: %v", z["facets"])
	}
	// compare: partial head.
	sp := f.push(t, "r2", "2026-03-02T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Partial: true, Scanned: []string{"a.php"}, Results: []testutil.SResult{a}})
	c := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare?base=%v&head=%v", f.cb, s1["id"], sp["id"]))
	assertShape(t, "GET /codebases/{id}/compare", c.JSON(), parseExample(t, exCompare))
	// status filter shows only that list while counts stay complete.
	cu := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare?base=%v&head=%v&status=unchanged", f.cb, s1["id"], sp["id"])).JSON()
	if cu["status"] != "unchanged" || len(cu["items"].([]any)) != 1 || cu["items"].([]any)[0].(map[string]any)["status"] != "unchanged" || cu["counts"].(map[string]any)["unchanged"].(float64) != 1 {
		t.Fatalf("unchanged: %v", cu)
	}
	// warning {code, message} for an empty intersection.
	sp2 := f.push(t, "r3", "2026-03-03T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Partial: true, Scanned: []string{"z.php"}})
	w := f.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare?base=%v&head=%v", f.cb, sp["id"], sp2["id"])).JSON()["warning"].(map[string]any)
	if w["code"] != "empty_scope" || w["message"] == "" {
		t.Fatalf("warning: %v", w)
	}
	// Full vs full: scope kind "all"; a single scan: base null.
	f2 := newScanFixture(t)
	f2.push(t, "r1", "2026-03-01T10:00:00Z", testutil.Doc{Rules: testutil.StdRules, Results: []testutil.SResult{a}})
	one := f2.w.member.Get(fmt.Sprintf("/api/v1/codebases/%d/compare", f2.cb)).JSON()
	if one["base"] != nil || one["scope"].(map[string]any)["kind"] != "all" || one["warning"] != nil || one["counts"].(map[string]any)["new"].(float64) != 1 {
		t.Fatalf("single scan: %v", one)
	}
}

func TestDTOTokensAndSchedules(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	pid := w.projectID
	tok := w.token(t, "gitlab-ci", &pid)
	if !strings.HasPrefix(tok, "sdrscan_") {
		t.Fatal(tok)
	}
	assertShape(t, "GET /ingest-tokens", w.admin.Get("/api/v1/ingest-tokens").JSON(), parseExample(t, exTokens))
	// POST answers {token, secret}; the list never contains the secret; project null for all-projects tokens.
	r := w.admin.Do("POST", "/api/v1/ingest-tokens", map[string]any{"name": "all"})
	j := r.JSON()
	if r.Status != 201 || len(j) != 2 || j["secret"] == nil || j["token"].(map[string]any)["project"] != nil {
		t.Fatalf("POST: %d %s", r.Status, r.Body)
	}
	ex := parseExample(t, exTokens).(map[string]any)["items"].([]any)[0].(map[string]any)
	ex["project"] = nil
	assertShape(t, "POST /ingest-tokens .token", j["token"], ex)
	if strings.Contains(string(w.admin.Get("/api/v1/ingest-tokens").Body), j["secret"].(string)) {
		t.Fatal("the secret appears in the list")
	}

	// Schedule row: suspended with every field filled.
	id := w.repo(t, w.member, "storefront")
	if r := w.member.Do("PUT", fmt.Sprintf("/api/v1/codebases/%d/schedule", id), map[string]any{"cron": "0 2 * * *"}); r.Status != 200 {
		t.Fatalf("PUT: %d %s", r.Status, r.Body)
	}
	_, _ = w.env.Pool.Exec(t.Context(), `UPDATE codebases SET schedule_last_enqueued_at = now() WHERE id = $1`, id)
	w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", w.member.User.ID), map[string]any{"is_active": false})
	list := w.admin.Get("/api/v1/schedules")
	assertShape(t, "GET /schedules", list.JSON(), map[string]any{"items": []any{parseExample(t, exScheduleRow)}, "total": 1.0, "page": 1.0, "page_size": 50.0})
	// An active schedule: owner set, suspended_* null, next_run_at filled.
	w.admin.Do("PUT", fmt.Sprintf("/api/v1/codebases/%d/schedule", id), map[string]any{"cron": "0 2 * * *"})
	row := w.admin.Get("/api/v1/schedules").JSON()["items"].([]any)[0].(map[string]any)
	if row["status"] != "active" || row["suspended_reason"] != nil || row["suspended_at"] != nil || row["next_run_at"] == nil || row["owner"] == nil {
		t.Fatalf("active row: %v", row)
	}
	ex2 := parseExample(t, exScheduleRow).(map[string]any)
	ex2["suspended_reason"], ex2["suspended_at"], ex2["next_run_at"] = nil, nil, "2026-10-28T02:00:00Z"
	assertShape(t, "active schedule row", row, ex2)
	// The same object nested in GET /codebases/{id}: {cron, status, owner, suspended_reason, suspended_at, last_enqueued_at, next_run_at}.
	cs := w.admin.Get(fmt.Sprintf("/api/v1/codebases/%d", id)).JSON()["schedule"]
	assertShape(t, "codebase.schedule", cs, map[string]any{"cron": "x", "status": "x", "owner": map[string]any{"id": 1.0, "username": "x"},
		"suspended_reason": nil, "suspended_at": nil, "last_enqueued_at": "x", "next_run_at": "x"})
}

// Every list endpoint answers with the envelope {items, total, page, page_size}
// and never a bare array; items is [] (not null) when empty.
func TestEveryListUsesTheEnvelope(t *testing.T) {
	v := newVisWorld(t)
	paths := []string{"/api/v1/projects", "/api/v1/users", "/api/v1/audit-log", "/api/v1/ingest-tokens", "/api/v1/codebases", "/api/v1/schedules",
		fmt.Sprintf("/api/v1/codebases/%d/scans", v.repo), fmt.Sprintf("/api/v1/codebases/%d/findings", v.repo),
		fmt.Sprintf("/api/v1/codebases/%d/files", v.repo), fmt.Sprintf("/api/v1/codebases/%d/compare", v.repo),
		fmt.Sprintf("/api/v1/scans/%d/findings", v.repoScan), fmt.Sprintf("/api/v1/scans/%d/files", v.repoScan),
		"/api/v1/projects?page=99", "/api/v1/codebases?project_id=99999", "/api/v1/schedules?status=suspended",
		fmt.Sprintf("/api/v1/codebases/%d/findings?rule=none", v.repo), fmt.Sprintf("/api/v1/codebases/%d/scans?status=failed", v.repo)}
	for _, p := range paths {
		r := v.admin.Get(p)
		if r.Status != 200 {
			t.Errorf("%s: %d %s", p, r.Status, r.Body)
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(string(r.Body)), "[") {
			t.Errorf("%s answers with a bare array", p)
			continue
		}
		j := r.JSON()
		for _, k := range []string{"items", "total", "page", "page_size"} {
			if _, ok := j[k]; !ok {
				t.Errorf("%s lacks %q", p, k)
			}
		}
		if _, ok := j["items"].([]any); !ok {
			t.Errorf("%s: items is %v (want an array, never null)", p, j["items"])
		}
	}
}
