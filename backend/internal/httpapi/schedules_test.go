package httpapi_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func auditHas(t *testing.T, w *world, action string) bool {
	t.Helper()
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n)
	return n > 0
}

func schedOf(r testutil.Resp) map[string]any {
	s, _ := r.JSON()["schedule"].(map[string]any)
	return s
}

func TestScheduleLifecycle(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.repo(t, w.member, "storefront")
	sp := fmt.Sprintf("/api/v1/codebases/%d/schedule", id)
	cp := fmt.Sprintf("/api/v1/codebases/%d", id)
	if w.admin.Get(cp).JSON()["schedule"] != nil {
		t.Fatal("a codebase without a schedule has schedule = null")
	}
	for name, body := range map[string]map[string]any{"garbage": {"cron": "garbage"}, "empty": {"cron": ""}, "missing": {}, "6 fields": {"cron": "0 0 3 * * *"}} {
		if r := w.member.Do("PUT", sp, body); r.Status != 422 || r.ErrCode() != "invalid_cron" {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	if r := w.member.Do("PUT", sp, map[string]any{"cron": "*/5 * * * *"}); r.Status != 422 || r.ErrCode() != "schedule_too_frequent" {
		t.Fatalf("too frequent: %d %s", r.Status, r.Body)
	}
	if r := w.member.Do("PUT", sp, map[string]any{"cron": "0,5 * * * *"}); r.Status != 422 || r.ErrCode() != "schedule_too_frequent" {
		t.Fatalf("irregular but too frequent: %d %s", r.Status, r.Body)
	}
	r := w.member.Do("PUT", sp, map[string]any{"cron": "*/15 * * * *"})
	s := schedOf(r)
	if r.Status != 200 || s["status"] != "active" || s["cron"] != "*/15 * * * *" || s["owner"].(map[string]any)["username"] != "member" ||
		s["next_run_at"] == nil || s["suspended_reason"] != nil || s["suspended_at"] != nil || s["last_enqueued_at"] != nil {
		t.Fatalf("PUT: %d %s", r.Status, r.Body)
	}
	if got := w.admin.Get(cp).JSON()["schedule"].(map[string]any); got["cron"] != "*/15 * * * *" {
		t.Fatalf("codebase schedule: %v", got)
	}
	// Resume on an active schedule is a conflict.
	if r := w.member.Do("POST", sp+"/resume", nil); r.Status != 409 || r.ErrCode() != "schedule_not_suspended" {
		t.Fatalf("resume active: %d %s", r.Status, r.Body)
	}
	// PUT by someone else changes the owner.
	r = w.admin.Do("PUT", sp, map[string]any{"cron": "0 5 * * *"})
	if s := schedOf(r); s["owner"].(map[string]any)["username"] != "admin" || s["cron"] != "0 5 * * *" {
		t.Fatalf("PUT by admin: %s", r.Body)
	}
	// DELETE is 204; PATCH may not touch the schedule; resume without a schedule is a conflict.
	if r := w.admin.Do("DELETE", sp, nil); r.Status != 204 {
		t.Fatalf("DELETE: %d %s", r.Status, r.Body)
	}
	if w.admin.Get(cp).JSON()["schedule"] != nil {
		t.Fatal("schedule must be null after DELETE")
	}
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM codebases WHERE id = $1 AND schedule_cron IS NULL AND schedule_owner_id IS NULL
		AND schedule_status IS NULL AND schedule_suspended_reason IS NULL AND schedule_suspended_at IS NULL AND schedule_last_enqueued_at IS NULL`, id).Scan(&n)
	if n != 1 {
		t.Fatal("DELETE must clear every schedule column")
	}
	if r := w.member.Do("POST", sp+"/resume", nil); r.Status != 409 {
		t.Fatalf("resume without a schedule: %d", r.Status)
	}
	if r := w.admin.Do("PATCH", cp, map[string]any{"schedule_cron": "0 3 * * *"}); r.Status != 422 {
		t.Fatalf("PATCH schedule_cron: %d", r.Status)
	}
	for _, a := range []string{"schedule_set", "schedule_deleted"} {
		if !auditHas(t, w, a) {
			t.Errorf("audit lacks %s", a)
		}
	}
	// Creating a codebase with a schedule makes the creator the owner.
	r = w.member.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID), map[string]any{"name": "with-sched", "target_type": "repo",
		"repo_url": "https://git.example.com/s.git", "schedule_cron": "0 2 * * *"})
	if s := r.JSON()["schedule"].(map[string]any); r.Status != 201 || s["owner"].(map[string]any)["username"] != "member" || s["status"] != "active" {
		t.Fatalf("create with schedule: %d %s", r.Status, r.Body)
	}
	if r := w.member.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID), map[string]any{"name": "too-often", "target_type": "repo",
		"repo_url": "https://git.example.com/s.git", "schedule_cron": "* * * * *"}); r.Status != 422 || r.ErrCode() != "schedule_too_frequent" {
		t.Fatalf("create with a too frequent schedule: %d %s", r.Status, r.Body)
	}
}

func TestOwnerChangesSuspendSchedulesImmediately(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	ctx := context.Background()
	// A SAST schedule and a DAST schedule owned by the same member (can_run_dast).
	repo := w.repo(t, w.dastUser, "storefront")
	rp := fmt.Sprintf("/api/v1/codebases/%d", repo)
	url := w.urlTarget(t, w.dastUser, "live", "https://shop.example.com")
	w.confirm(t, url)
	up := fmt.Sprintf("/api/v1/codebases/%d", url)
	if r := w.dastUser.Do("PUT", rp+"/schedule", map[string]any{"cron": "0 3 * * *"}); r.Status != 200 {
		t.Fatal(r.Status, string(r.Body))
	}
	if r := w.dastUser.Do("PUT", up+"/schedule", map[string]any{"cron": "*/30 * * * *"}); r.Status != 422 || r.ErrCode() != "schedule_too_frequent" {
		t.Fatalf("DAST minimum interval is 60 minutes: %d %s", r.Status, r.Body)
	}
	if r := w.dastUser.Do("PUT", up+"/schedule", map[string]any{"cron": "0 4 * * *"}); r.Status != 200 {
		t.Fatal(r.Status, string(r.Body))
	}
	// Losing can_run_dast suspends the DAST schedule at once; the SAST one stays active.
	if r := w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", w.dastUser.User.ID), map[string]any{"can_run_dast": false}); r.Status != 200 {
		t.Fatal(r.Status)
	}
	var st1, st2, reason string
	_ = w.env.Pool.QueryRow(ctx, `SELECT schedule_status FROM codebases WHERE id = $1`, repo).Scan(&st1)
	_ = w.env.Pool.QueryRow(ctx, `SELECT schedule_status, schedule_suspended_reason FROM codebases WHERE id = $1`, url).Scan(&st2, &reason)
	if st1 != "active" || st2 != "suspended" || reason != "owner_lost_permission" {
		t.Fatalf("after losing DAST access: repo=%s url=%s/%s", st1, st2, reason)
	}
	if !auditHas(t, w, "schedule_suspended") {
		t.Fatal("audit lacks schedule_suspended")
	}
	// The admin sees the suspension in the DTO and in the list (with the status filter).
	s := w.admin.Get(up).JSON()["schedule"].(map[string]any)
	if s["status"] != "suspended" || s["suspended_reason"] != "owner_lost_permission" || s["suspended_at"] == nil || s["next_run_at"] != nil || s["owner"].(map[string]any)["username"] != "dastuser" {
		t.Fatalf("suspended DTO: %v", s)
	}
	list := w.admin.Get("/api/v1/schedules?status=suspended")
	if count(t, list) != 1 {
		t.Fatalf("suspended list: %s", list.Body)
	}
	row := list.JSON()["items"].([]any)[0].(map[string]any)
	if row["codebase"].(map[string]any)["name"] != "live" || row["codebase"].(map[string]any)["target_type"] != "url" || row["project"].(map[string]any)["name"] != "Online Shop" ||
		row["suspended_reason"] != "owner_lost_permission" || row["next_run_at"] != nil || row["cron"] != "0 4 * * *" {
		t.Fatalf("row: %v", row)
	}
	if count(t, w.admin.Get("/api/v1/schedules?status=active")) != 1 || count(t, w.admin.Get("/api/v1/schedules")) != 2 {
		t.Fatal("status filter")
	}
	if r := w.admin.Get("/api/v1/schedules?status=bogus"); r.Status != 400 {
		t.Fatalf("bad filter: %d", r.Status)
	}
	// Resume: not by someone who cannot see the target; by the admin it changes the owner.
	if r := w.member.Do("POST", up+"/schedule/resume", nil); r.Status != 404 {
		t.Fatalf("resume by a member without DAST access: %d", r.Status)
	}
	if r := w.dastUser.Do("POST", up+"/schedule/resume", nil); r.Status != 404 {
		t.Fatalf("the old owner no longer sees the target: %d", r.Status)
	}
	r := w.admin.Do("POST", up+"/schedule/resume", nil)
	if s := schedOf(r); r.Status != 200 || s["status"] != "active" || s["owner"].(map[string]any)["username"] != "admin" || s["suspended_reason"] != nil || s["suspended_at"] != nil {
		t.Fatalf("resume: %d %s", r.Status, r.Body)
	}
	// Deactivating the owner of the SAST schedule suspends it; PUT by another user clears the suspension.
	w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", w.dastUser.User.ID), map[string]any{"is_active": false})
	_ = w.env.Pool.QueryRow(ctx, `SELECT schedule_status, schedule_suspended_reason FROM codebases WHERE id = $1`, repo).Scan(&st1, &reason)
	if st1 != "suspended" || reason != "owner_deactivated" {
		t.Fatalf("deactivated owner: %s/%s", st1, reason)
	}
	r = w.member.Do("PUT", rp+"/schedule", map[string]any{"cron": "0 3 * * *"})
	if s := schedOf(r); s["status"] != "active" || s["owner"].(map[string]any)["username"] != "member" || s["suspended_reason"] != nil {
		t.Fatalf("PUT clears the suspension: %s", r.Body)
	}
	// Demoting an Admin owner of a DAST schedule (no can_run_dast) suspends it.
	other := w.env.CreateUser("admin2", "admin", false)
	oc := w.env.Login(other)
	if r := oc.Do("PUT", up+"/schedule", map[string]any{"cron": "0 6 * * *"}); r.Status != 200 {
		t.Fatalf("admin2 PUT: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", other.ID), map[string]any{"role": "member"}); r.Status != 200 {
		t.Fatal(r.Status)
	}
	_ = w.env.Pool.QueryRow(ctx, `SELECT schedule_status, schedule_suspended_reason FROM codebases WHERE id = $1`, url).Scan(&st2, &reason)
	if st2 != "suspended" || reason != "owner_lost_permission" {
		t.Fatalf("demoted owner: %s/%s", st2, reason)
	}
}

func TestDastScheduleEndpointsAreInvisibleToMembersWithoutAccess(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	url := w.urlTarget(t, w.admin, "live", "https://shop.example.com")
	sp := fmt.Sprintf("/api/v1/codebases/%d/schedule", url)
	for _, call := range [][2]string{{"PUT", sp}, {"DELETE", sp}, {"POST", sp + "/resume"}} {
		var body any
		if call[0] == "PUT" {
			body = map[string]any{"cron": "0 3 * * *"}
		}
		if r := w.member.Do(call[0], call[1], body); r.Status != 404 || r.ErrCode() != "not_found" {
			t.Errorf("%s %s: %d %s", call[0], call[1], r.Status, r.Body)
		}
	}
	// A DAST member and an admin can set it.
	for _, c := range []*testutil.Client{w.dastUser, w.admin} {
		if r := c.Do("PUT", sp, map[string]any{"cron": "0 3 * * *"}); r.Status != 200 {
			t.Errorf("%s: %d %s", c.User.Username, r.Status, r.Body)
		}
	}
	// The schedules list for the member leaks nothing.
	if r := w.member.Get("/api/v1/schedules"); count(t, r) != 0 || strings.Contains(string(r.Body), "shop.example.com") {
		t.Errorf("member schedules: %s", r.Body)
	}
}
