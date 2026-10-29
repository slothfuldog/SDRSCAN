package httpapi_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func activePath(id int64) string {
	return fmt.Sprintf("/api/v1/codebases/%d/authorize-active-scanning", id)
}

// authorizeActive is the happy-path call: statement accepted and the codebase name typed back exactly.
func authorizeActive(c *testutil.Client, id int64, name string) testutil.Resp {
	return c.Do("POST", activePath(id), map[string]any{"statement_accepted": true, "codebase_name": name})
}

func TestAuthorizeActiveScanningRequiresConfirmationFirst(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	// Not yet confirmed: active authorization is a layer on top of confirm-authorization, not a
	// replacement, so it is refused first with the same conflict as running a scan would be.
	if r := authorizeActive(w.admin, id, "live"); r.Status != 409 || r.ErrCode() != "target_not_confirmed" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	w.confirm(t, id)
	if r := authorizeActive(w.admin, id, "live"); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestAuthorizeActiveScanningStatementAndNameValidation(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	w.confirm(t, id)
	runFieldCases(t, w.admin, "POST", activePath(id), []fieldCase{
		{name: "nothing accepted", body: map[string]any{}, status: 422, field: "statement_accepted"},
		{name: "not accepted", body: map[string]any{"statement_accepted": false, "codebase_name": "live"}, status: 422, field: "statement_accepted"},
		{name: "wrong name", body: map[string]any{"statement_accepted": true, "codebase_name": "liv"}, status: 422, field: "codebase_name"},
		{name: "empty name", body: map[string]any{"statement_accepted": true, "codebase_name": ""}, status: 422, field: "codebase_name"},
		{name: "case mismatch is still wrong", body: map[string]any{"statement_accepted": true, "codebase_name": "LIVE"}, status: 422, field: "codebase_name"},
	})
	r := authorizeActive(w.admin, id, "live")
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	j := r.JSON()
	da := j["dast_active"].(map[string]any)
	if da["authorized"] != true || da["authorized_at"] == nil || da["authorized_by"].(map[string]any)["username"] != "admin" {
		t.Fatalf("dast_active: %v", da)
	}
}

func TestAuthorizeActiveScanningRoleAndTargetType(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	w.confirm(t, id)
	// A Member without DAST access cannot even see the target: identical 404 as a missing id.
	r1 := authorizeActive(w.member, id, "live")
	r2 := authorizeActive(w.member, 987654, "live")
	if r1.Status != 404 || r1.ErrCode() != "not_found" || string(stripReq(r1.Body)) != string(stripReq(r2.Body)) {
		t.Fatalf("member: %d %s vs ghost %d %s", r1.Status, r1.Body, r2.Status, r2.Body)
	}
	// A Member with can_run_dast may authorize it too (same rule as confirm's siblings, dast-auth).
	if r := authorizeActive(w.dastUser, id, "live"); r.Status != 200 {
		t.Fatalf("dastUser: %d %s", r.Status, r.Body)
	}
	// A repository codebase: 409, whoever calls it.
	rid := w.repo(t, w.member, "storefront")
	if r := authorizeActive(w.admin, rid, "storefront"); r.Status != 409 || r.ErrCode() != "not_a_url_target" {
		t.Fatalf("repo: %d %s", r.Status, r.Body)
	}
}

func TestAuthorizeActiveScanningAudit(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	w.confirm(t, id)
	if r := authorizeActive(w.dastUser, id, "live"); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("DELETE", activePath(id), nil); r.Status != 204 {
		t.Fatalf("revoke: %d %s", r.Status, r.Body)
	}
	// Idempotent: revoking again is still 204, with no extra audit row.
	if r := w.admin.Do("DELETE", activePath(id), nil); r.Status != 204 {
		t.Fatalf("second revoke: %d %s", r.Status, r.Body)
	}
	a := w.admin.Get("/api/v1/audit-log?page_size=100")
	counts := map[string]int{}
	for _, it := range a.JSON()["items"].([]any) {
		m := it.(map[string]any)
		counts[m["action"].(string)]++
		if act := m["action"].(string); act == "dast_active_authorized" {
			if m["actor_name"] != "dastuser" || !strings.Contains(fmt.Sprint(m["target"]), "live") {
				t.Errorf("audit row: %v", m)
			}
		}
		if act := m["action"].(string); act == "dast_active_revoked" && m["actor_name"] != "admin" {
			t.Errorf("revoke audit row: %v", m)
		}
	}
	if counts["dast_active_authorized"] != 1 || counts["dast_active_revoked"] != 1 {
		t.Fatalf("audit actions: %v", counts)
	}
	j := w.admin.Get(fmt.Sprintf("/api/v1/codebases/%d", id)).JSON()
	if j["dast_active"].(map[string]any)["authorized"] != false {
		t.Fatalf("after revoke: %v", j["dast_active"])
	}
}

func TestChangingTheTargetOriginRevokesActiveScanningAuthorization(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	w.confirm(t, id)
	if r := authorizeActive(w.admin, id, "live"); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// Same origin, different path: active authorization is NOT revoked by a mere path change... actually
	// it must be revoked whenever base_url changes at all (dastChange), same as the basic confirmation.
	patch := func(base string) testutil.Resp {
		return w.admin.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", id), map[string]any{"base_url": base})
	}
	r1 := patch(target + "/app")
	if r1.Status != 200 {
		t.Fatalf("%d %s", r1.Status, r1.Body)
	}
	if r1.JSON()["dast_active"].(map[string]any)["authorized"] != false {
		t.Fatalf("active authorization must be revoked on any base_url change: %v", r1.JSON()["dast_active"])
	}
	// Re-authorize, then change to another host entirely: revoked too, audited as an origin change.
	w.confirm(t, id)
	if r := authorizeActive(w.admin, id, "live"); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	r := patch("https://shop2.example.com")
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r.JSON()["dast_active"].(map[string]any)["authorized"] != false {
		t.Fatalf("after host change: %v", r.JSON()["dast_active"])
	}
	found := false
	for _, it := range w.admin.Get("/api/v1/audit-log?page_size=100").JSON()["items"].([]any) {
		m := it.(map[string]any)
		if m["action"] == "dast_active_revoked" && strings.Contains(fmt.Sprint(m["target"]), "origin changed") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a dast_active_revoked audit row for the origin change")
	}
}

func TestCreateScanWithActiveScanningValidationOrder(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)

	// 1. active_timing without active: a pure field error, checked before the codebase is even loaded.
	runFieldCases(t, w.dastUser, "POST", "/api/v1/scans", []fieldCase{
		{name: "active_timing without active", body: map[string]any{"codebase_id": id, "active_timing": true}, status: 422, field: "active_timing"},
	})

	// 2. Not confirmed yet: target_not_confirmed, even with active requested.
	if r := w.dastUser.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id, "active": true}); r.Status != 409 || r.ErrCode() != "target_not_confirmed" {
		t.Fatalf("pending: %d %s", r.Status, r.Body)
	}

	// 3. Confirmed but not authorized for active scanning: active_scanning_not_authorized.
	w.confirm(t, id)
	if r := w.dastUser.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id, "active": true}); r.Status != 409 || r.ErrCode() != "active_scanning_not_authorized" {
		t.Fatalf("not authorized: %d %s", r.Status, r.Body)
	}
	// A plain passive scan still works at this point.
	if r := w.dastUser.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id}); r.Status != 202 {
		t.Fatalf("passive scan: %d %s", r.Status, r.Body)
	}
	cancelActive(t, w, id)

	// 4. Authorized: active true (and active_timing true) is accepted and recorded on the scan row.
	if r := authorizeActive(w.admin, id, "live"); r.Status != 200 {
		t.Fatalf("authorize: %d %s", r.Status, r.Body)
	}
	r := w.dastUser.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id, "active": true, "active_timing": true})
	if r.Status != 202 {
		t.Fatalf("active scan: %d %s", r.Status, r.Body)
	}
	j := r.JSON()
	if j["active"] != true || j["active_timing"] != true {
		t.Fatalf("scan DTO must carry active flags: %v", j)
	}
	scanID := testutil.MustID(t, j, "id")
	var active, timing bool
	if err := w.env.Pool.QueryRow(context.Background(), `SELECT active, active_timing FROM scans WHERE id = $1`, scanID).Scan(&active, &timing); err != nil || !active || !timing {
		t.Fatalf("scan row: active=%v timing=%v err=%v", active, timing, err)
	}
	cancelActive(t, w, id)

	// 5. A plain passive scan after authorization stays passive (active is opt-in per request).
	r2 := w.dastUser.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id})
	if r2.Status != 202 || r2.JSON()["active"] != false {
		t.Fatalf("still-passive scan: %d %s", r2.Status, r2.Body)
	}
}

// cancelActive cancels whatever scan is queued/running for id, so the next POST /scans in the same
// test is not blocked by "a scan is already queued or running".
func cancelActive(t *testing.T, w *world, id int64) {
	t.Helper()
	if _, err := w.env.Pool.Exec(context.Background(), `UPDATE scans SET status = 'cancelled', finished_at = now()
		WHERE codebase_id = $1 AND status IN ('queued', 'running')`, id); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleRejectsActiveScanningFields(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	w.confirm(t, id)
	sp := fmt.Sprintf("/api/v1/codebases/%d/schedule", id)
	runFieldCases(t, w.dastUser, "PUT", sp, []fieldCase{
		{name: "active", body: map[string]any{"cron": "0 3 * * *", "active": true}, status: 422, field: "active"},
		{name: "active_timing", body: map[string]any{"cron": "0 3 * * *", "active_timing": true}, status: 422, field: "active_timing"},
	})
	// Without those fields the schedule still works as before.
	if r := w.dastUser.Do("PUT", sp, map[string]any{"cron": "0 3 * * *"}); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}
