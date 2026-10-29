package httpapi_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

// visWorld has one repo codebase (1 high finding) and one URL codebase (2
// critical findings) in the same project, plus a schedule on each.
type visWorld struct {
	*world
	repo, url               int64
	repoScan, urlScan       int64
	repoFinding, urlFinding int64
}

func firstFindingID(t *testing.T, c *testutil.Client, scanID int64) int64 {
	t.Helper()
	items := c.Get(fmt.Sprintf("/api/v1/scans/%d/findings", scanID)).JSON()["items"].([]any)
	if len(items) == 0 {
		t.Fatal("no findings")
	}
	return testutil.MustID(t, items[0].(map[string]any), "id")
}

func newVisWorld(t *testing.T) *visWorld {
	w := newWorld(t, testutil.EnvOptions{})
	v := &visWorld{world: w}
	v.repo = w.repo(t, w.member, "storefront")
	v.url = w.urlTarget(t, w.admin, "storefront (live)", "https://shop.example.com")
	w.confirm(t, v.url)
	tok := w.token(t, "ci", nil)
	r1 := ingest(w, tok, q("Online Shop", "storefront", "r1"), sarifDoc(sr("php-xss-echo", "a.php", 1, "x")), nil)
	if r1.Status != 201 {
		t.Fatalf("repo ingest: %d %s", r1.Status, r1.Body)
	}
	v.repoScan = testutil.MustID(t, r1.JSON()["scan"].(map[string]any), "id")
	dast := testutil.Doc{Engine: "sdrscan-dast", Rules: []testutil.RuleMeta{{ID: "dast-x", Score: "9.5", Tags: []string{"external/cwe/cwe-1"}}},
		Results: []testutil.SResult{
			{Rule: "dast-x", URI: "https://shop.example.com/a", Level: "error", Message: "m", Evidence: "e1"},
			{Rule: "dast-x", URI: "https://shop.example.com/b", Level: "error", Message: "m", Evidence: "e2"}}}
	r2 := ingest(w, tok, q("Online Shop", "storefront (live)", "d1"), dast.Build(), nil)
	if r2.Status != 201 {
		t.Fatalf("dast ingest: %d %s", r2.Status, r2.Body)
	}
	v.urlScan = testutil.MustID(t, r2.JSON()["scan"].(map[string]any), "id")
	v.repoFinding = firstFindingID(t, w.admin, v.repoScan)
	v.urlFinding = firstFindingID(t, w.admin, v.urlScan)
	// Schedules on both.
	if r := w.admin.Do("PUT", fmt.Sprintf("/api/v1/codebases/%d/schedule", v.repo), map[string]any{"cron": "0 3 * * *"}); r.Status != 200 {
		t.Fatalf("repo schedule: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("PUT", fmt.Sprintf("/api/v1/codebases/%d/schedule", v.url), map[string]any{"cron": "0 4 * * *"}); r.Status != 200 {
		t.Fatalf("url schedule: %d %s", r.Status, r.Body)
	}
	return v
}

func count(t *testing.T, r testutil.Resp) int {
	t.Helper()
	if r.Status != 200 {
		t.Fatalf("status %d: %s", r.Status, r.Body)
	}
	return int(r.JSON()["total"].(float64))
}

func TestMemberWithoutDastAccessNeverSeesUrlTargets(t *testing.T) {
	v := newVisWorld(t)
	m := v.member
	u := fmt.Sprintf("/api/v1/codebases/%d", v.url)
	ghost := "/api/v1/codebases/987654"

	// (b) Every endpoint on the URL codebase answers 404, byte-identical to a codebase that does not exist.
	type call struct {
		method, path string
		body         any
	}
	calls := []call{
		{"GET", u, nil}, {"PATCH", u, map[string]any{"language": "x"}},
		{"GET", u + "/findings", nil}, {"GET", u + "/files", nil}, {"GET", u + "/scans", nil}, {"GET", u + "/compare", nil},
		{"PUT", u + "/schedule", map[string]any{"cron": "0 5 * * *"}}, {"DELETE", u + "/schedule", nil},
		{"POST", u + "/schedule/resume", nil},
		{"POST", "/api/v1/scans", map[string]any{"codebase_id": v.url}},
		{"GET", fmt.Sprintf("/api/v1/scans/%d", v.urlScan), nil},
		{"GET", fmt.Sprintf("/api/v1/scans/%d/events", v.urlScan), nil},
		{"GET", fmt.Sprintf("/api/v1/scans/%d/findings", v.urlScan), nil},
		{"GET", fmt.Sprintf("/api/v1/scans/%d/files", v.urlScan), nil},
		{"POST", fmt.Sprintf("/api/v1/scans/%d/cancel", v.urlScan), nil},
		{"GET", fmt.Sprintf("/api/v1/findings/%d", v.urlFinding), nil}, // (e)
	}
	for _, c := range calls {
		r := m.Do(c.method, c.path, c.body)
		if r.Status != 404 || r.ErrCode() != "not_found" {
			t.Errorf("%s %s as member: %d %s (want 404 not_found)", c.method, c.path, r.Status, r.Body)
		}
	}
	// 404 for a URL target is indistinguishable from "does not exist".
	a, b := m.Get(u), m.Get(ghost)
	if a.Status != b.Status || a.ErrCode() != b.ErrCode() || a.JSON()["error"].(map[string]any)["message"] != b.JSON()["error"].(map[string]any)["message"] {
		t.Errorf("distinguishable 404: %s vs %s", a.Body, b.Body)
	}
	// The repo codebase next to it is fully available.
	for _, p := range []string{fmt.Sprintf("/api/v1/codebases/%d", v.repo), fmt.Sprintf("/api/v1/codebases/%d/findings", v.repo),
		fmt.Sprintf("/api/v1/scans/%d", v.repoScan), fmt.Sprintf("/api/v1/findings/%d", v.repoFinding)} {
		if r := m.Get(p); r.Status != 200 {
			t.Errorf("GET %s as member: %d %s", p, r.Status, r.Body)
		}
	}

	// (a) Codebase lists leave URL targets out.
	if n := count(t, m.Get("/api/v1/codebases")); n != 1 {
		t.Errorf("GET /codebases: %d items, want 1", n)
	}
	if n := count(t, m.Get("/api/v1/codebases?target_type=url")); n != 0 {
		t.Errorf("target_type=url filter leaked %d items", n)
	}
	if n := count(t, m.Get(fmt.Sprintf("/api/v1/codebases?project_id=%d", v.projectID))); n != 1 {
		t.Errorf("project filter: %d", n)
	}
	// (c) Dashboard, project list and totals only count what the caller can see.
	dash := m.Get(fmt.Sprintf("/api/v1/projects/%d", v.projectID)).JSON()
	if len(dash["codebases"].([]any)) != 1 {
		t.Errorf("dashboard codebases: %v", dash["codebases"])
	}
	tot := dash["totals"].(map[string]any)
	if tot["critical"].(float64) != 0 || tot["high"].(float64) != 1 || tot["highest_severity"] != "high" {
		t.Errorf("dashboard totals leak URL findings: %v", tot)
	}
	pl := m.Get("/api/v1/projects").JSON()["items"].([]any)[0].(map[string]any)
	if pl["codebase_count"].(float64) != 1 || pl["totals"].(map[string]any)["critical"].(float64) != 0 || pl["highest_severity"] != "high" {
		t.Errorf("project list leaks URL targets: %v", pl)
	}
	// (d) Schedules.
	sl := m.Get("/api/v1/schedules")
	if count(t, sl) != 1 || sl.JSON()["items"].([]any)[0].(map[string]any)["codebase"].(map[string]any)["target_type"] != "repo" {
		t.Errorf("schedules: %s", sl.Body)
	}
	// Nothing about the URL target appears anywhere in what the member can list.
	for _, p := range []string{"/api/v1/codebases", "/api/v1/schedules", "/api/v1/projects", fmt.Sprintf("/api/v1/projects/%d", v.projectID)} {
		body := m.Get(p).Body
		for _, needle := range []string{"shop.example.com", "storefront (live)", "pending_confirmation", `"url"`} {
			if bytes.Contains(body, []byte(needle)) {
				t.Errorf("%s leaks %q: %s", p, needle, body)
			}
		}
	}
	// Findings listed through the repo codebase never contain URL findings.
	if n := count(t, m.Get(fmt.Sprintf("/api/v1/codebases/%d/findings", v.repo))); n != 1 {
		t.Errorf("repo findings: %d", n)
	}
	// Member cannot register or change URL targets either (403 for a new resource).
	if r := m.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", v.projectID), map[string]any{"name": "n", "target_type": "url", "base_url": "https://shop.example.com"}); r.Status != 403 || r.ErrCode() != "dast_forbidden" {
		t.Errorf("register: %d %s", r.Status, r.Body)
	}
}

func TestAdminAndDastMemberSeeEverything(t *testing.T) {
	v := newVisWorld(t)
	for _, c := range []*testutil.Client{v.admin, v.dastUser} {
		name := c.User.Username
		if n := count(t, c.Get("/api/v1/codebases")); n != 2 {
			t.Errorf("%s: codebases %d", name, n)
		}
		if n := count(t, c.Get("/api/v1/codebases?target_type=url")); n != 1 {
			t.Errorf("%s: url filter %d", name, n)
		}
		if n := count(t, c.Get("/api/v1/schedules")); n != 2 {
			t.Errorf("%s: schedules %d", name, n)
		}
		dash := c.Get(fmt.Sprintf("/api/v1/projects/%d", v.projectID)).JSON()
		tot := dash["totals"].(map[string]any)
		if len(dash["codebases"].([]any)) != 2 || tot["critical"].(float64) != 2 || tot["high"].(float64) != 1 || tot["highest_severity"] != "critical" {
			t.Errorf("%s: dashboard %v", name, dash)
		}
		if pl := c.Get("/api/v1/projects").JSON()["items"].([]any)[0].(map[string]any); pl["codebase_count"].(float64) != 2 {
			t.Errorf("%s: project list %v", name, pl)
		}
		for _, p := range []string{fmt.Sprintf("/api/v1/codebases/%d", v.url), fmt.Sprintf("/api/v1/codebases/%d/findings", v.url),
			fmt.Sprintf("/api/v1/codebases/%d/files", v.url), fmt.Sprintf("/api/v1/codebases/%d/scans", v.url),
			fmt.Sprintf("/api/v1/codebases/%d/compare", v.url),
			fmt.Sprintf("/api/v1/scans/%d", v.urlScan), fmt.Sprintf("/api/v1/scans/%d/findings", v.urlScan),
			fmt.Sprintf("/api/v1/scans/%d/files", v.urlScan), fmt.Sprintf("/api/v1/findings/%d", v.urlFinding)} {
			if r := c.Get(p); r.Status != 200 {
				t.Errorf("%s GET %s: %d %s", name, p, r.Status, r.Body)
			}
		}
	}
}

func TestRevokingDastAccessHidesUrlTargetsImmediately(t *testing.T) {
	v := newVisWorld(t)
	c := v.dastUser
	u := fmt.Sprintf("/api/v1/codebases/%d", v.url)
	f := fmt.Sprintf("/api/v1/findings/%d", v.urlFinding)
	if c.Get(u).Status != 200 || c.Get(f).Status != 200 || count(t, c.Get("/api/v1/codebases")) != 2 {
		t.Fatal("test premise: a member with DAST access sees the target")
	}
	// Same session, no re-login.
	if r := v.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", c.User.ID), map[string]any{"can_run_dast": false}); r.Status != 200 {
		t.Fatalf("revoke: %d", r.Status)
	}
	if r := c.Get(u); r.Status != 404 {
		t.Errorf("target visible after the revocation: %d", r.Status)
	}
	if r := c.Get(f); r.Status != 404 {
		t.Errorf("finding visible after the revocation: %d", r.Status)
	}
	if n := count(t, c.Get("/api/v1/codebases")); n != 1 {
		t.Errorf("list after revocation: %d", n)
	}
	if tot := c.Get(fmt.Sprintf("/api/v1/projects/%d", v.projectID)).JSON()["totals"].(map[string]any); tot["critical"].(float64) != 0 {
		t.Errorf("totals after revocation: %v", tot)
	}
	// Granting it back works at once as well.
	_ = v.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", c.User.ID), map[string]any{"can_run_dast": true})
	if r := c.Get(u); r.Status != 200 {
		t.Errorf("after the grant: %d", r.Status)
	}
	// An Admin whose can_run_dast column is false still sees everything.
	if v.admin.Get(u).Status != 200 {
		t.Error("admin lost sight of the target")
	}
}
