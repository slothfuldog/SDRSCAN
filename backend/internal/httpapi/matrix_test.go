package httpapi_test

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sdrscan/sdrscan/backend/internal/httpapi"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

// Visibility classification of every route (same route list as routeAccess).
//
//	byURLCodebase  - addressed by an id that resolves to a URL codebase or one of its scans/findings
//	special        - touches codebases without such an id; covered by dedicated tests below
//	none           - never touches codebase data
const (
	byCodebase = "codebase-id"
	byScan     = "scan-id"
	byFinding  = "finding-id"
	special    = "special"
	none       = "none"
)

var routeVisibility = map[string]string{
	"GET /api/v1/healthz": none, "POST /api/v1/auth/login": none, "POST /api/v1/auth/logout": none, "GET /api/v1/auth/me": none,
	"POST /api/v1/auth/password": none, "GET /api/v1/users": none, "POST /api/v1/users": none, "PATCH /api/v1/users/{id}": none,
	"POST /api/v1/users/{id}/reset-password": none, "GET /api/v1/audit-log": none, "GET /api/v1/ingest-tokens": none,
	"POST /api/v1/ingest-tokens": none, "DELETE /api/v1/ingest-tokens/{id}": none,
	"GET /api/v1/system/vulndb": none, "POST /api/v1/system/vulndb/update": none, "POST /api/v1/system/vulndb/update/cancel": none,
	"POST /api/v1/ingest": special, "POST /api/v1/codebases/{id}/ingest": special, // token endpoints: not affected by user visibility
	"GET /api/v1/projects": special, "POST /api/v1/projects": none, "GET /api/v1/projects/{id}": special, "PATCH /api/v1/projects/{id}": none,
	"DELETE /api/v1/projects/{id}": none, "POST /api/v1/projects/{id}/codebases": special,
	"GET /api/v1/codebases": special, "GET /api/v1/schedules": special, "POST /api/v1/scans": special, "GET /api/v1/system/info": special,
	"GET /api/v1/codebases/{id}": byCodebase, "PATCH /api/v1/codebases/{id}": byCodebase, "DELETE /api/v1/codebases/{id}": byCodebase,
	"POST /api/v1/codebases/{id}/confirm-authorization": byCodebase, "GET /api/v1/codebases/{id}/scans": byCodebase,
	"GET /api/v1/codebases/{id}/compare": byCodebase, "GET /api/v1/codebases/{id}/findings": byCodebase,
	"GET /api/v1/codebases/{id}/files": byCodebase, "PUT /api/v1/codebases/{id}/schedule": byCodebase,
	"GET /api/v1/codebases/{id}/dast-auth": byCodebase, "PUT /api/v1/codebases/{id}/dast-auth": byCodebase,
	"DELETE /api/v1/codebases/{id}/dast-auth": byCodebase, "POST /api/v1/codebases/{id}/dast-auth/test": byCodebase,
	"POST /api/v1/codebases/{id}/authorize-active-scanning": byCodebase, "DELETE /api/v1/codebases/{id}/authorize-active-scanning": byCodebase,
	"DELETE /api/v1/codebases/{id}/schedule": byCodebase, "POST /api/v1/codebases/{id}/schedule/resume": byCodebase,
	"GET /api/v1/scans/{id}": byScan, "GET /api/v1/scans/{id}/events": byScan, "POST /api/v1/scans/{id}/cancel": byScan,
	"GET /api/v1/scans/{id}/findings": byScan, "GET /api/v1/scans/{id}/files": byScan,
	"GET /api/v1/findings/{id}": byFinding,
}

func TestEveryRouteHasAVisibilityClassification(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	mux := w.env.API.Router().(chi.Routes)
	seen := map[string]bool{}
	_ = chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if !strings.HasPrefix(route, "/api/v1") {
			return nil
		}
		key := method + " " + route
		seen[key] = true
		if _, ok := routeVisibility[key]; !ok {
			t.Errorf("route %q is not classified in routeVisibility (does it touch codebase data?)", key)
		}
		return nil
	})
	for k := range routeVisibility {
		if !seen[k] {
			t.Errorf("routeVisibility lists %q but the router has no such route", k)
		}
	}
}

// TestVisibilityMatrix calls every route that is addressed by the id of a URL
// codebase (or of one of its scans or findings) as Admin, Member with DAST access
// and Member without, each in a fresh world, and compares with what the
// authorization rules demand.
func TestVisibilityMatrix(t *testing.T) {
	adminOnly := map[string]bool{"DELETE /api/v1/codebases/{id}": true, "POST /api/v1/codebases/{id}/confirm-authorization": true}
	var keys []string
	for k, v := range routeVisibility {
		if v == byCodebase || v == byScan || v == byFinding {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	// DELETE last: it destroys the fixture.
	const destroy = "DELETE /api/v1/codebases/{id}"
	sort.SliceStable(keys, func(i, j int) bool { return keys[i] != destroy && keys[j] == destroy })

	for _, actor := range []string{"admin", "member+dast", "member", "anonymous"} {
		t.Run(actor, func(t *testing.T) {
			v := newVisWorld(t)
			c := map[string]*testutil.Client{"admin": v.admin, "member+dast": v.dastUser, "member": v.member, "anonymous": v.anon}[actor]
			ghost := map[string]string{byCodebase: "987654", byScan: "987654", byFinding: "987654"}
			real := map[string]string{byCodebase: fmt.Sprint(v.url), byScan: fmt.Sprint(v.urlScan), byFinding: fmt.Sprint(v.urlFinding)}
			for _, key := range keys {
				parts := strings.SplitN(key, " ", 2)
				method, route := parts[0], parts[1]
				kind := routeVisibility[key]
				var body any
				switch {
				case method == "PUT":
					body = map[string]any{"cron": "0 5 * * *"}
				case method == "PATCH":
					body = map[string]any{"language": "x"}
				case strings.HasSuffix(route, "confirm-authorization"):
					body = map[string]any{"statement_accepted": true}
				case method == "POST":
					body = map[string]any{}
				}
				path := strings.ReplaceAll(route, "{id}", real[kind])
				if key == destroy {
					path += "?confirm=" + "storefront%20%28live%29"
				}
				r := c.Do(method, path, body)
				ghostPath := strings.ReplaceAll(route, "{id}", ghost[kind])
				gr := c.Do(method, ghostPath, body)
				switch {
				case actor == "anonymous":
					if r.Status != 401 {
						t.Errorf("%s: %d (want 401)", key, r.Status)
					}
				case actor == "member" && adminOnly[key]:
					if r.Status != 403 || r.ErrCode() != "forbidden_role" {
						t.Errorf("%s: %d %s (want 403 forbidden_role)", key, r.Status, r.ErrCode())
					}
				case actor == "member":
					if r.Status != 404 || r.ErrCode() != "not_found" {
						t.Errorf("%s: %d %s (want 404 not_found)", key, r.Status, r.Body)
					}
					if gr.Status != r.Status || string(stripReq(gr.Body)) != string(stripReq(r.Body)) {
						t.Errorf("%s: answer differs from a missing id:\n url:   %s\n ghost: %s", key, r.Body, gr.Body)
					}
				case actor == "member+dast" && adminOnly[key]:
					if r.Status != 403 {
						t.Errorf("%s: %d (want 403)", key, r.Status)
					}
				default: // Admin, or a DAST member on a non-admin route: the target is visible
					if r.Status == 401 || r.Status == 403 || r.Status == 404 {
						t.Errorf("%s as %s: %d %s (the target must be visible)", key, actor, r.Status, r.Body)
					}
				}
			}
		})
	}
}

func stripReq(b []byte) []byte {
	s := string(b)
	if i := strings.Index(s, `,"request_id"`); i >= 0 {
		s = s[:i] + "}}"
	}
	return []byte(s)
}

func TestProjectWithOnlyUrlCodebasesLooksEmptyToMembers(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	r := w.admin.Do("POST", "/api/v1/projects", map[string]any{"name": "Live only"})
	pid := testutil.MustID(t, r.JSON(), "id")
	cr := w.admin.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", pid), map[string]any{"name": "live", "target_type": "url", "base_url": "https://shop.example.com"})
	if cr.Status != 201 {
		t.Fatalf("%d %s", cr.Status, cr.Body)
	}
	for _, it := range w.member.Get("/api/v1/projects").JSON()["items"].([]any) {
		m := it.(map[string]any)
		if m["name"] == "Live only" && (m["codebase_count"].(float64) != 0 || m["highest_severity"] != nil) {
			t.Fatalf("member sees %v", m)
		}
	}
	d := w.member.Get(fmt.Sprintf("/api/v1/projects/%d", pid)).JSON()
	if len(d["codebases"].([]any)) != 0 || strings.Contains(fmt.Sprint(d), "shop.example.com") {
		t.Fatalf("dashboard: %v", d)
	}
	for _, it := range w.dastUser.Get("/api/v1/projects").JSON()["items"].([]any) {
		if m := it.(map[string]any); m["name"] == "Live only" && m["codebase_count"].(float64) != 1 {
			t.Fatalf("dast member: %v", m)
		}
	}
}

func TestSystemInfoQueueCountsHideDastJobs(t *testing.T) {
	v := newVisWorld(t)
	ctx := context.Background()
	_, err := v.env.Pool.Exec(ctx, `INSERT INTO scans (codebase_id, type, trigger, status) VALUES ($1, 'dast', 'manual', 'queued')`, v.url)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = v.env.Pool.Exec(ctx, `INSERT INTO scans (codebase_id, type, trigger, status) VALUES ($1, 'sast', 'manual', 'queued')`, v.repo)
	q := func(c *testutil.Client) float64 {
		return c.Get("/api/v1/system/info").JSON()["queue"].(map[string]any)["queued"].(float64)
	}
	if q(v.member) != 1 || q(v.dastUser) != 2 || q(v.admin) != 2 {
		t.Fatalf("queued: member=%v dast=%v admin=%v", q(v.member), q(v.dastUser), q(v.admin))
	}
}

func TestSSEClosesWhenAccessIsRevoked(t *testing.T) {
	v := newVisWorld(t)
	ctx := context.Background()
	// A running DAST scan that never finishes during the test.
	var id int64
	if err := v.env.Pool.QueryRow(ctx, `INSERT INTO scans (codebase_id, type, trigger, status, started_at) VALUES ($1, 'dast', 'manual', 'running', now()) RETURNING id`, v.url).Scan(&id); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scans/%d/events", v.env.HTTP.URL, id), nil)
	req.AddCookie(&http.Cookie{Name: httpapi.SessionCookie, Value: v.dastUser.Cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	closed := make(chan struct{})
	first := make(chan struct{}, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "event: status") {
				select {
				case first <- struct{}{}:
				default:
				}
			}
		}
		close(closed)
	}()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("no first event")
	}
	select {
	case <-closed:
		t.Fatal("the stream must stay open while the scan runs")
	case <-time.After(1500 * time.Millisecond):
	}
	if r := v.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", v.dastUser.User.ID), map[string]any{"can_run_dast": false}); r.Status != 200 {
		t.Fatal(r.Status)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream was not closed after the permission was revoked")
	}
}
