package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

// routeAccess is the single list of routes and who may call them. The test
// below walks the real router and fails when a route is missing here, so a new
// endpoint cannot ship without an authorization decision.
//
//	open   - no session needed
//	token  - ingest token only (a session is not accepted)
//	any    - any signed-in user (Admin and Member)
//	admin  - Admin only
var routeAccess = map[string]string{
	"GET /api/v1/healthz":                                     "open",
	"POST /api/v1/auth/login":                                 "open",
	"POST /api/v1/ingest":                                     "token",
	"POST /api/v1/codebases/{id}/ingest":                      "token",
	"POST /api/v1/auth/logout":                                "any",
	"GET /api/v1/auth/me":                                     "any",
	"POST /api/v1/auth/password":                              "any",
	"GET /api/v1/projects":                                    "any",
	"POST /api/v1/projects":                                   "any",
	"GET /api/v1/projects/{id}":                               "any",
	"PATCH /api/v1/projects/{id}":                             "any",
	"POST /api/v1/projects/{id}/codebases":                    "any",
	"GET /api/v1/codebases":                                   "any",
	"GET /api/v1/schedules":                                   "any",
	"PUT /api/v1/codebases/{id}/schedule":                     "any",
	"DELETE /api/v1/codebases/{id}/schedule":                  "any",
	"POST /api/v1/codebases/{id}/schedule/resume":             "any",
	"GET /api/v1/codebases/{id}":                              "any",
	"PATCH /api/v1/codebases/{id}":                            "any",
	"GET /api/v1/codebases/{id}/dast-auth":                    "any",
	"PUT /api/v1/codebases/{id}/dast-auth":                    "any",
	"DELETE /api/v1/codebases/{id}/dast-auth":                 "any",
	"POST /api/v1/codebases/{id}/dast-auth/test":              "any",
	"POST /api/v1/codebases/{id}/authorize-active-scanning":   "any",
	"DELETE /api/v1/codebases/{id}/authorize-active-scanning": "any",
	"GET /api/v1/codebases/{id}/scans":                        "any",
	"GET /api/v1/codebases/{id}/compare":                      "any",
	"GET /api/v1/codebases/{id}/findings":                     "any",
	"GET /api/v1/codebases/{id}/files":                        "any",
	"POST /api/v1/scans":                                      "any",
	"GET /api/v1/scans/{id}":                                  "any",
	"GET /api/v1/scans/{id}/events":                           "any",
	"POST /api/v1/scans/{id}/cancel":                          "any",
	"GET /api/v1/scans/{id}/findings":                         "any",
	"GET /api/v1/scans/{id}/files":                            "any",
	"GET /api/v1/findings/{id}":                               "any",
	"GET /api/v1/system/info":                                 "any",
	"GET /api/v1/system/vulndb":                               "admin",
	"POST /api/v1/system/vulndb/update":                       "admin",
	"POST /api/v1/system/vulndb/update/cancel":                "admin",
	"GET /api/v1/users":                                       "admin",
	"POST /api/v1/users":                                      "admin",
	"PATCH /api/v1/users/{id}":                                "admin",
	"POST /api/v1/users/{id}/reset-password":                  "admin",
	"GET /api/v1/audit-log":                                   "admin",
	"GET /api/v1/ingest-tokens":                               "admin",
	"POST /api/v1/ingest-tokens":                              "admin",
	"DELETE /api/v1/ingest-tokens/{id}":                       "admin",
	"DELETE /api/v1/projects/{id}":                            "admin",
	"DELETE /api/v1/codebases/{id}":                           "admin",
	"POST /api/v1/codebases/{id}/confirm-authorization":       "admin",
}

func TestEveryRouteHasAnAuthorizationDecision(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	mux, ok := w.env.API.Router().(chi.Routes)
	if !ok {
		t.Fatal("router is not a chi router")
	}
	seen := map[string]bool{}
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if !strings.HasPrefix(route, "/api/v1") {
			return nil
		}
		key := method + " " + route
		seen[key] = true
		if _, ok := routeAccess[key]; !ok {
			t.Errorf("route %q has no entry in routeAccess (add its authorization expectation)", key)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for k := range routeAccess {
		if !seen[k] {
			t.Errorf("routeAccess lists %q but the router has no such route", k)
		}
	}
}

func TestAuthorizationMatrix(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	type actor struct {
		name string
		c    *testutil.Client
	}
	actors := []actor{{"admin", w.admin}, {"member+dast", w.dastUser}, {"member", w.member}, {"anonymous", w.anon}}
	for key, access := range routeAccess {
		parts := strings.SplitN(key, " ", 2)
		method, route := parts[0], strings.ReplaceAll(parts[1], "{id}", "999999")
		if route == "/api/v1/auth/logout" || route == "/api/v1/scans/999999/events" || route == "/api/v1/auth/login" {
			continue // logout would end the shared session; SSE and login are covered elsewhere
		}
		for _, a := range actors {
			var body any
			if method != "GET" && method != "DELETE" {
				body = map[string]any{}
			}
			r := a.c.Do(method, route, body)
			switch access {
			case "open":
				if r.Status == 401 || r.Status == 403 {
					t.Errorf("%s as %s: %d", key, a.name, r.Status)
				}
			case "token":
				// A session never opens an ingest endpoint; without a bearer token it is 401 invalid_token.
				if r.Status != 401 || r.ErrCode() != "invalid_token" {
					t.Errorf("%s as %s: %d %s (want 401 invalid_token)", key, a.name, r.Status, r.ErrCode())
				}
			case "any":
				if a.name == "anonymous" {
					if r.Status != 401 || r.ErrCode() != "not_authenticated" {
						t.Errorf("%s as anonymous: %d %s", key, r.Status, r.ErrCode())
					}
				} else if r.Status == 401 || (r.Status == 403 && r.ErrCode() == "forbidden_role") {
					t.Errorf("%s as %s: %d %s (must be allowed)", key, a.name, r.Status, r.ErrCode())
				}
			case "admin":
				switch a.name {
				case "admin":
					if r.Status == 401 || r.Status == 403 {
						t.Errorf("%s as admin: %d %s", key, r.Status, r.ErrCode())
					}
				case "anonymous":
					if r.Status != 401 {
						t.Errorf("%s as anonymous: %d", key, r.Status)
					}
				default:
					if r.Status != 403 || r.ErrCode() != "forbidden_role" {
						t.Errorf("%s as %s: %d %s (want 403 forbidden_role)", key, a.name, r.Status, r.ErrCode())
					}
				}
			}
		}
	}
}

func TestTokensOpenNoReadEndpointsAndSessionsNoIngest(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	tok := w.token(t, "ci", nil)
	for _, p := range []string{"/api/v1/projects", "/api/v1/auth/me", fmt.Sprintf("/api/v1/codebases/%d", cb), "/api/v1/users", "/api/v1/ingest-tokens"} {
		r := w.anon.Raw("GET", p, nil, map[string]string{"Authorization": "Bearer " + tok})
		if r.Status != 401 {
			t.Errorf("bearer token opened %s (%d)", p, r.Status)
		}
	}
	doc := testutil.Doc{Rules: testutil.StdRules}.Build()
	for _, c := range []*testutil.Client{w.admin, w.member} {
		r := c.Raw("POST", fmt.Sprintf("/api/v1/codebases/%d/ingest", cb), strings.NewReader(string(doc)), map[string]string{"Content-Type": "application/json"})
		if r.Status != 401 || r.ErrCode() != "invalid_token" {
			t.Errorf("session cookie opened ingest: %d %s", r.Status, r.Body)
		}
	}
}

func TestSastScanPermissions(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	for _, c := range []*testutil.Client{w.member, w.dastUser, w.admin} {
		r := c.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": cb})
		if r.Status != 202 {
			t.Fatalf("%s: SAST scan: %d %s", c.User.Username, r.Status, r.Body)
		}
		j := r.JSON()
		if j["type"] != "sast" || j["coverage"] != "full" || j["status"] != "queued" || j["trigger"] != "manual" {
			t.Fatalf("scan body: %s", r.Body)
		}
		// Finish the job so the next actor can queue one (one active job per codebase).
		_, _ = w.env.Pool.Exec(context.Background(), `UPDATE scans SET status='cancelled', finished_at=now() WHERE status='queued'`)
	}
}

func TestDastPermissionsAndTargetConfirmation(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	ctx := context.Background()
	base := "https://shop.example.com"
	post := func(c *testutil.Client, name string) testutil.Resp {
		return c.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID), map[string]any{"name": name, "target_type": "url", "base_url": base})
	}
	// Registering a URL target: Admin and Member with can_run_dast only.
	if r := post(w.member, "live-m"); r.Status != 403 || r.ErrCode() != "dast_forbidden" {
		t.Fatalf("member without access: %d %s", r.Status, r.Body)
	}
	ra := post(w.admin, "live-a")
	rd := post(w.dastUser, "live-d")
	if ra.Status != 201 || rd.Status != 201 {
		t.Fatalf("register: %d %d", ra.Status, rd.Status)
	}
	// Always pending_confirmation, also for an Admin.
	for _, r := range []testutil.Resp{ra, rd} {
		j := r.JSON()
		if d := j["dast"].(map[string]any); d["status"] != "pending_confirmation" || d["confirmed_by"] != nil {
			t.Fatalf("new target: %s", r.Body)
		}
		if !strings.Contains(j["confirmation_statement"].(string), base) {
			t.Fatalf("statement: %v", j["confirmation_statement"])
		}
	}
	idA, idD := testutil.MustID(t, ra.JSON(), "id"), testutil.MustID(t, rd.JSON(), "id")
	if ra.JSON()["dast"].(map[string]any)["registered_by"].(map[string]any)["username"] != "admin" || rd.JSON()["dast"].(map[string]any)["registered_by"].(map[string]any)["username"] != "dastuser" {
		t.Fatal("registrant not recorded")
	}
	scan := func(c *testutil.Client, id int64) testutil.Resp {
		return c.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id})
	}
	// A pending target cannot be scanned, not even by an Admin.
	for _, c := range []*testutil.Client{w.admin, w.dastUser} {
		if r := scan(c, idA); r.Status != 409 || r.ErrCode() != "target_not_confirmed" {
			t.Fatalf("%s on pending: %d %s", c.User.Username, r.Status, r.Body)
		}
	}
	// A member without access cannot even see the target: 404, as if it did not exist.
	if r := scan(w.member, idA); r.Status != 404 {
		t.Fatalf("member: %d %s", r.Status, r.Body)
	}
	// Only an Admin confirms.
	for _, c := range []*testutil.Client{w.member, w.dastUser} {
		r := c.Do("POST", fmt.Sprintf("/api/v1/codebases/%d/confirm-authorization", idA), map[string]any{"statement_accepted": true})
		if r.Status != 403 || r.ErrCode() != "forbidden_role" {
			t.Fatalf("%s confirm: %d %s", c.User.Username, r.Status, r.Body)
		}
	}
	conf := func(body any) testutil.Resp {
		return w.admin.Do("POST", fmt.Sprintf("/api/v1/codebases/%d/confirm-authorization", idA), body)
	}
	if r := conf(map[string]any{"statement_accepted": false}); r.Status != 422 {
		t.Fatalf("not accepted: %d", r.Status)
	}
	if r := conf(map[string]any{}); r.Status != 422 {
		t.Fatalf("missing flag: %d", r.Status)
	}
	r := conf(map[string]any{"statement_accepted": true})
	j := r.JSON()
	d := j["dast"].(map[string]any)
	if r.Status != 200 || d["status"] != "confirmed" || d["confirmed_by"].(map[string]any)["username"] != "admin" || d["confirmed_at"] == nil || j["confirmation_statement"] != nil {
		t.Fatalf("confirm: %d %s", r.Status, r.Body)
	}
	var text string
	_ = w.env.Pool.QueryRow(ctx, `SELECT dast_confirmation_text FROM codebases WHERE id = $1`, idA).Scan(&text)
	if !strings.Contains(text, base) {
		t.Fatalf("the statement text must be stored as a trail: %q", text)
	}
	firstAt := d["confirmed_at"]
	// Idempotent for the same base_url.
	if r2 := conf(map[string]any{"statement_accepted": true}); r2.Status != 200 || r2.JSON()["dast"].(map[string]any)["confirmed_at"] != firstAt {
		t.Fatalf("second confirm changed the trail: %s", r2.Body)
	}
	// Confirming a repo is a 409.
	repo := w.repo(t, w.admin, "repo")
	if r := w.admin.Do("POST", fmt.Sprintf("/api/v1/codebases/%d/confirm-authorization", repo), map[string]any{"statement_accepted": true}); r.Status != 409 || r.ErrCode() != "not_a_url_target" {
		t.Fatalf("confirm repo: %d %s", r.Status, r.Body)
	}
	// Scan on the confirmed target: Admin yes, Member with access yes, without no.
	if r := scan(w.member, idA); r.Status != 404 {
		t.Fatalf("member on confirmed: %d %s", r.Status, r.Body)
	}
	// Loopback hostnames cannot slip past the network policy (the guard runs at POST /scans).
	rs := scan(w.dastUser, idA)
	if rs.Status != 202 || rs.JSON()["type"] != "dast" {
		t.Fatalf("dastuser on confirmed: %d %s", rs.Status, rs.Body)
	}
	if r := scan(w.admin, idA); r.Status != 409 || r.ErrCode() != "scan_in_progress" {
		t.Fatalf("second active job: %d %s", r.Status, r.Body)
	}
	_ = idD
	_, _ = w.env.Pool.Exec(ctx, `UPDATE scans SET status='cancelled' WHERE status='queued'`)

	// Revoking can_run_dast takes effect on the very next request with the same session.
	if r := scan(w.dastUser, idA); r.Status != 202 {
		t.Fatalf("before revoke: %d", r.Status)
	}
	_, _ = w.env.Pool.Exec(ctx, `UPDATE scans SET status='cancelled' WHERE status='queued'`)
	if r := w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", w.dastUser.User.ID), map[string]any{"can_run_dast": false}); r.Status != 200 {
		t.Fatalf("revoke: %d %s", r.Status, r.Body)
	}
	if r := scan(w.dastUser, idA); r.Status != 404 {
		t.Fatalf("after revoke the target must vanish at once: %d %s", r.Status, r.Body)
	}
	if r := post(w.dastUser, "live-d2"); r.Status != 403 || r.ErrCode() != "dast_forbidden" {
		t.Fatalf("register after revoke: %d", r.Status)
	}
	// Granting again works at once; an Admin is allowed whatever the column says.
	_ = w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", w.dastUser.User.ID), map[string]any{"can_run_dast": true})
	if r := post(w.dastUser, "live-d3"); r.Status != 201 {
		t.Fatalf("register after grant: %d", r.Status)
	}
	var col bool
	_ = w.env.Pool.QueryRow(ctx, `SELECT can_run_dast FROM users WHERE username = 'admin'`).Scan(&col)
	if col {
		t.Fatal("test premise: admin's can_run_dast column is false")
	}
	if r := post(w.admin, "live-a2"); r.Status != 201 {
		t.Fatalf("admin with can_run_dast=false must be allowed: %d", r.Status)
	}
	// Audit.
	rows, _ := w.env.Pool.Query(ctx, `SELECT DISTINCT action FROM audit_log`)
	defer rows.Close()
	acts := map[string]bool{}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		acts[a] = true
	}
	for _, want := range []string{"dast_target_registered", "dast_target_confirmed", "user_dast_access_changed", "forbidden_role"} {
		if !acts[want] {
			t.Errorf("audit action %q missing (have %v)", want, acts)
		}
	}
}

func TestChangingBaseURLResetsConfirmationAndGuardsSchedule(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", "https://shop.example.com")
	w.confirm(t, id)
	path := fmt.Sprintf("/api/v1/codebases/%d", id)
	// A member without DAST access cannot see the target, so every change is a 404.
	for _, body := range []map[string]any{{"base_url": "https://other.example.com"}, {"schedule_cron": "0 3 * * *"}, {"language": "n/a"}} {
		if r := w.member.Do("PATCH", path, body); r.Status != 404 {
			t.Fatalf("PATCH %v by member: %d %s", body, r.Status, r.Body)
		}
	}
	// The same base_url keeps the confirmation.
	if r := w.dastUser.Do("PATCH", path, map[string]any{"base_url": "https://shop.example.com"}); r.Status != 200 || r.JSON()["dast"].(map[string]any)["status"] != "confirmed" {
		t.Fatalf("unchanged base_url: %d %s", r.Status, r.Body)
	}
	r := w.dastUser.Do("PATCH", path, map[string]any{"base_url": "https://shop2.example.com"})
	j := r.JSON()
	if d := j["dast"].(map[string]any); r.Status != 200 || d["status"] != "pending_confirmation" || d["confirmed_by"] != nil || d["confirmed_at"] != nil {
		t.Fatalf("base_url change: %d %s", r.Status, r.Body)
	}
	var trail *string
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT dast_confirmation_text FROM codebases WHERE id = $1`, id).Scan(&trail)
	if trail != nil {
		t.Fatal("the confirmation trail must be cleared")
	}
	if r := w.dastUser.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id}); r.Status != 409 || r.ErrCode() != "target_not_confirmed" {
		t.Fatalf("scan after reset: %d %s", r.Status, r.Body)
	}
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'dast_target_reset'`).Scan(&n)
	if n != 1 {
		t.Fatalf("dast_target_reset audit rows = %d", n)
	}
	// target_type is immutable.
	if r := w.admin.Do("PATCH", path, map[string]any{"target_type": "repo"}); r.Status != 422 {
		t.Fatalf("target_type change: %d", r.Status)
	}
}

func TestAdminOnlyDeleteAndConfirmation(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	cb := w.repo(t, w.member, "storefront")
	cpath := fmt.Sprintf("/api/v1/codebases/%d", cb)
	if r := w.member.Do("DELETE", cpath+"?confirm=storefront", nil); r.Status != 403 || r.ErrCode() != "forbidden_role" {
		t.Fatalf("member delete: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("DELETE", cpath, nil); r.Status != 422 || r.ErrCode() != "confirmation_required" {
		t.Fatalf("no confirm: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("DELETE", cpath+"?confirm=Storefront", nil); r.Status != 422 || r.ErrCode() != "confirmation_mismatch" {
		t.Fatalf("mismatch (case-sensitive): %d %s", r.Status, r.Body)
	}
	if r := w.admin.Get(cpath); r.Status != 200 {
		t.Fatal("codebase must survive a refused delete")
	}
	if r := w.admin.Do("DELETE", cpath+"?confirm=storefront", nil); r.Status != 200 {
		t.Fatalf("delete: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Get(cpath); r.Status != 404 {
		t.Fatalf("deleted codebase still there: %d", r.Status)
	}
	ppath := fmt.Sprintf("/api/v1/projects/%d", w.projectID)
	if r := w.member.Do("DELETE", ppath+"?confirm=Online%20Shop", nil); r.Status != 403 {
		t.Fatalf("member project delete: %d", r.Status)
	}
	if r := w.admin.Do("DELETE", ppath+"?confirm=nope", nil); r.Status != 422 || r.ErrCode() != "confirmation_mismatch" {
		t.Fatalf("project mismatch: %d", r.Status)
	}
	if r := w.admin.Do("DELETE", ppath+"?confirm=Online%20Shop", nil); r.Status != 200 {
		t.Fatalf("project delete: %d %s", r.Status, r.Body)
	}
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action IN ('project_deleted','codebase_deleted')`).Scan(&n)
	if n != 2 {
		t.Fatalf("delete audit rows = %d", n)
	}
}
