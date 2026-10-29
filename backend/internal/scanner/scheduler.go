package scanner

import (
	"context"
	"log/slog"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/store"
)

const schedulerLockKey int64 = 0x5344525343414e // "SDRSCAN"

// slotTolerance lets a tick that is a little late still catch its slot while
// slots missed during a longer outage are not back-filled.
const slotTolerance = 90 * time.Second

// Scheduler enqueues scheduled scans (trigger = 'schedule'). Only the instance
// holding the advisory lock is active.
type Scheduler struct {
	Store *store.Store
	Log   *slog.Logger
	// OnTick, when set, is called once per tick while this instance holds the lock (used for the
	// scheduled vulnerability database update).
	OnTick func(now time.Time)
}

// Run blocks until ctx is done, ticking once a minute while holding the lock.
func (s *Scheduler) Run(ctx context.Context) {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	conn, err := s.Store.Pool.Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	held := false
	for {
		if !held {
			var ok bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, schedulerLockKey).Scan(&ok); err == nil {
				held = ok
			}
		}
		if held {
			now := time.Now()
			s.Tick(ctx, now)
			if s.OnTick != nil {
				s.OnTick(now)
			}
		}
		select {
		case <-ctx.Done():
			if held {
				_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, schedulerLockKey)
			}
			return
		case <-t.C:
		}
	}
}

// Tick looks at every active schedule. The owner's rights are re-read from the
// database: an owner who is deactivated or lost the right to trigger this kind
// of scan gets the schedule suspended (audit schedule_suspended, no job).
// A URL target that is not confirmed is skipped without suspending. Otherwise a
// due slot is queued exactly once (slot recorded in the same transaction).
// It returns the number of jobs created.
func (s *Scheduler) Tick(ctx context.Context, now time.Time) int {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	cbs, err := s.Store.ScheduleCandidates(ctx)
	if err != nil {
		s.Log.Warn("scheduler query failed", "err", err)
		return 0
	}
	created := 0
	for _, cb := range cbs {
		if cb.ScheduleCron == nil || cb.ScheduleOwnerID == nil {
			continue
		}
		var owner *store.User
		if u, err := s.Store.GetUser(ctx, *cb.ScheduleOwnerID); err == nil {
			owner = &u
		}
		if reason := SuspensionFor(cb, owner); reason != "" {
			if ok, err := s.Store.SuspendSchedule(ctx, cb.ID, reason); err == nil && ok {
				s.Store.Audit(ctx, nil, nil, "scheduler", "schedule_suspended", cb.Name+" ("+reason+")")
				s.Log.Warn("schedule suspended", "codebase_id", cb.ID, "reason", reason)
			}
			continue
		}
		if cb.TargetType == "url" && (cb.DastStatus == nil || *cb.DastStatus != "confirmed") {
			continue // waits for the confirmation; not suspended
		}
		slot, ok := LatestSlot(*cb.ScheduleCron, now, slotTolerance)
		if !ok {
			continue
		}
		typ := "sast"
		if cb.TargetType == "url" {
			typ = "dast"
		}
		queued, err := s.Store.EnqueueScheduled(ctx, cb, typ, owner.ID, slot)
		if err != nil {
			s.Log.Warn("scheduled scan not queued", "codebase_id", cb.ID, "err", err)
			continue
		}
		if queued {
			created++
		}
	}
	return created
}
