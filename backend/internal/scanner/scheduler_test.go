package scanner_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

type schedRig struct {
	*rig
	ctx context.Context
	sch *scanner.Scheduler
}

func newSchedRig(t *testing.T) *schedRig {
	r := newRig(t, rigOpts{guard: local()})
	return &schedRig{rig: r, ctx: context.Background(), sch: &scanner.Scheduler{Store: r.env.Store}}
}

func (s *schedRig) set(cb store.Codebase, cron string, owner int64) store.Codebase {
	s.t.Helper()
	out, err := s.env.Store.SetSchedule(s.ctx, cb.ID, cron, owner)
	if err != nil {
		s.t.Fatal(err)
	}
	return out
}

func (s *schedRig) jobs() map[string]string {
	rows, err := s.env.Pool.Query(s.ctx, `SELECT c.name, s.type || '/' || s.trigger || '/' || s.status FROM scans s JOIN codebases c ON c.id = s.codebase_id`)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var n, v string
		_ = rows.Scan(&n, &v)
		out[n] = v
	}
	return out
}

func (s *schedRig) status(cb store.Codebase) (string, string) {
	var st, reason *string
	_ = s.env.Pool.QueryRow(s.ctx, `SELECT schedule_status, schedule_suspended_reason FROM codebases WHERE id = $1`, cb.ID).Scan(&st, &reason)
	a, b := "", ""
	if st != nil {
		a = *st
	}
	if reason != nil {
		b = *reason
	}
	return a, b
}

func TestSchedulerEnqueuesDueSlotsExactlyOnce(t *testing.T) {
	s := newSchedRig(t)
	owner := s.env.CreateUser("owner", "member", false)
	cb := s.repoCB("a", "https://git.example.com/a.git")
	s.set(cb, "0 3 * * *", owner.ID)
	other := s.repoCB("b", "https://git.example.com/b.git")
	s.set(other, "30 4 * * *", owner.ID)
	slot := time.Date(2026, 5, 4, 3, 0, 0, 0, time.UTC)

	if n := s.sch.Tick(s.ctx, slot.Add(10*time.Second)); n != 1 {
		t.Fatalf("created %d jobs, want 1", n)
	}
	if got := s.jobs(); len(got) != 1 || got["a"] != "sast/schedule/queued" {
		t.Fatalf("jobs: %v", got)
	}
	var by *int64
	var last *time.Time
	_ = s.env.Pool.QueryRow(s.ctx, `SELECT requested_by FROM scans`).Scan(&by)
	_ = s.env.Pool.QueryRow(s.ctx, `SELECT schedule_last_enqueued_at FROM codebases WHERE id = $1`, cb.ID).Scan(&last)
	if by == nil || *by != owner.ID {
		t.Fatalf("requested_by must be the schedule owner, got %v", by)
	}
	if last == nil || !last.Equal(slot) {
		t.Fatalf("last_enqueued_at = %v, want the slot %v", last, slot)
	}
	// Same slot again (also after the job finished): not queued twice.
	_, _ = s.env.Pool.Exec(s.ctx, `UPDATE scans SET status = 'succeeded', started_at = now(), finished_at = now()`)
	if n := s.sch.Tick(s.ctx, slot.Add(40*time.Second)); n != 0 {
		t.Fatalf("second tick in the same slot queued %d jobs", n)
	}
	// Two scheduler instances ticking at the same moment queue it once.
	slot2 := slot.Add(24 * time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := (&scanner.Scheduler{Store: s.env.Store}).Tick(s.ctx, slot2.Add(time.Second))
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 1 {
		t.Fatalf("4 concurrent instances queued %d jobs", total)
	}
	// Slots missed while the backend was down are not back-filled.
	_, _ = s.env.Pool.Exec(s.ctx, `UPDATE scans SET status = 'succeeded', started_at = now(), finished_at = now() WHERE status = 'queued'`)
	if n := s.sch.Tick(s.ctx, slot2.Add(5*time.Hour)); n != 0 {
		t.Fatalf("a missed slot was back-filled (%d jobs)", n)
	}
}

func TestSchedulerSuspendsWhenTheOwnerNoLongerQualifies(t *testing.T) {
	s := newSchedRig(t)
	minute := time.Date(2026, 5, 4, 3, 0, 5, 0, time.UTC)
	inactive := s.env.CreateUser("inactive", "member", false)
	plain := s.env.CreateUser("plain", "member", false)
	dastOwner := s.env.CreateUser("dastowner", "member", true)

	repoInactive := s.repoCB("repo-inactive-owner", "https://git.example.com/a.git")
	repoNoDAST := s.repoCB("repo-owner-without-dast", "https://git.example.com/b.git")
	urlNoDAST := s.urlCB("url-owner-without-dast", "https://shop.example.com", true)
	urlOK := s.urlCB("url-ok", "https://shop.example.com", true)
	urlAdmin := s.urlCB("url-admin", "https://shop.example.com", true)
	urlPending := s.urlCB("url-pending", "https://shop.example.com", false)
	for _, x := range []struct {
		cb    store.Codebase
		owner int64
	}{{repoInactive, inactive.ID}, {repoNoDAST, plain.ID}, {urlNoDAST, plain.ID}, {urlOK, dastOwner.ID}, {urlAdmin, s.adm.ID}, {urlPending, dastOwner.ID}} {
		s.set(x.cb, "0 3 * * *", x.owner)
	}
	// Changes made behind the API's back (the scheduler must read the database).
	_, _ = s.env.Pool.Exec(s.ctx, `UPDATE users SET is_active = false WHERE id = $1`, inactive.ID)

	if n := s.sch.Tick(s.ctx, minute); n != 3 {
		t.Fatalf("created %d jobs, want 3 (repo with a plain member owner, URL with a DAST owner, URL with an Admin owner): %v", n, s.jobs())
	}
	want := map[string]string{"repo-owner-without-dast": "sast/schedule/queued", "url-ok": "dast/schedule/queued", "url-admin": "dast/schedule/queued"}
	got := s.jobs()
	if len(got) != len(want) {
		t.Fatalf("jobs: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
	if st, why := s.status(repoInactive); st != "suspended" || why != "owner_deactivated" {
		t.Errorf("inactive owner: %s/%s", st, why)
	}
	if st, why := s.status(urlNoDAST); st != "suspended" || why != "owner_lost_permission" {
		t.Errorf("owner without DAST access: %s/%s", st, why)
	}
	if st, _ := s.status(repoNoDAST); st != "active" {
		t.Errorf("a SAST schedule whose owner merely lacks can_run_dast must stay active, got %s", st)
	}
	// A pending target waits without being suspended; it runs once confirmed.
	if st, _ := s.status(urlPending); st != "active" {
		t.Errorf("pending target schedule: %s", st)
	}
	var n int
	_ = s.env.Pool.QueryRow(s.ctx, `SELECT count(*) FROM audit_log WHERE action = 'schedule_suspended'`).Scan(&n)
	if n != 2 {
		t.Errorf("schedule_suspended audit rows: %d", n)
	}
	// Suspended schedules produce no jobs on later slots either.
	_, _ = s.env.Pool.Exec(s.ctx, `UPDATE scans SET status = 'succeeded', started_at = now(), finished_at = now()`)
	if n := s.sch.Tick(s.ctx, minute.Add(24*time.Hour)); n != 3 {
		t.Fatalf("next day: %d jobs, want 3 (the same three active schedules)", n)
	}
	if _, err := s.env.Store.ConfirmDast(s.ctx, urlPending.ID, s.adm.ID, "ok"); err != nil {
		t.Fatal(err)
	}
	_, _ = s.env.Pool.Exec(s.ctx, `UPDATE scans SET status = 'succeeded', started_at = now(), finished_at = now()`)
	if n := s.sch.Tick(s.ctx, minute.Add(48*time.Hour)); n != 4 {
		t.Fatalf("after the confirmation: %d jobs, want 4", n)
	}
}

func TestNoJobWhileOneIsActive(t *testing.T) {
	s := newSchedRig(t)
	owner := s.env.CreateUser("owner", "member", false)
	cb := s.repoCB("a", "https://git.example.com/a.git")
	s.set(cb, "0 3 * * *", owner.ID)
	s.enqueue(cb) // a manual job is queued
	if n := s.sch.Tick(s.ctx, time.Date(2026, 5, 4, 3, 0, 1, 0, time.UTC)); n != 0 {
		t.Fatalf("queued a scheduled job on top of an active one: %d", n)
	}
}

func TestValidateScheduleAndSlots(t *testing.T) {
	for _, ok := range []string{"*/15 * * * *", "0 3 * * *", "0 0 * * 1", "30 2 1 * *", "0 * * * *"} {
		if err := scanner.ValidateSchedule(ok, 15*time.Minute); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "every day", "0 3 * *", "0 0 3 * * *", "61 * * * *", "@bogus"} {
		if err := scanner.ValidateSchedule(bad, 15*time.Minute); err != scanner.ErrInvalidCron {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, often := range []string{"* * * * *", "*/5 * * * *", "0,10 * * * *", "0 * * * 1-5,0 *"} {
		if err := scanner.ValidateSchedule(often, 15*time.Minute); err == nil {
			t.Errorf("%q accepted", often)
		}
	}
	if err := scanner.ValidateSchedule("*/30 * * * *", 60*time.Minute); err == nil {
		t.Error("30-minute schedule accepted for DAST")
	}
	if err := scanner.ValidateSchedule("0 * * * *", 60*time.Minute); err != nil {
		t.Error(err)
	}
	next, ok := scanner.NextRun("0 3 * * *", time.Date(2026, 5, 4, 3, 0, 1, 0, time.UTC))
	if !ok || !next.Equal(time.Date(2026, 5, 5, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("next = %v", next)
	}
	now := time.Date(2026, 5, 4, 3, 0, 40, 0, time.UTC)
	if slot, ok := scanner.LatestSlot("0 3 * * *", now, 90*time.Second); !ok || !slot.Equal(time.Date(2026, 5, 4, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("slot = %v %v", slot, ok)
	}
	if _, ok := scanner.LatestSlot("0 3 * * *", now.Add(10*time.Minute), 90*time.Second); ok {
		t.Fatal("a slot older than the tolerance must not be used")
	}
	if slot, ok := scanner.LatestSlot("*/15 * * * *", time.Date(2026, 5, 4, 3, 31, 0, 0, time.UTC), 90*time.Second); !ok || !slot.Equal(time.Date(2026, 5, 4, 3, 30, 0, 0, time.UTC)) {
		t.Fatalf("latest of several: %v", slot)
	}
}
