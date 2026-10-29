package scanner

import (
	"errors"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// Schedule validation errors (mapped to 422 invalid_cron / schedule_too_frequent).
var (
	ErrInvalidCron      = errors.New("schedule is not a valid 5-field cron expression (UTC)")
	ErrScheduleTooOften = errors.New("schedule runs too often")
)

// Default minimum intervals between two runs.
const (
	DefaultMinIntervalSAST = 15 * time.Minute
	DefaultMinIntervalDAST = 60 * time.Minute
)

// ValidateCron checks a 5-field cron expression (UTC).
func ValidateCron(expr string) error {
	if _, err := cron.ParseStandard(expr); err != nil {
		return ErrInvalidCron
	}
	return nil
}

// ValidateSchedule checks the expression and that consecutive runs (over the
// next 100 occurrences) are at least min apart.
func ValidateSchedule(expr string, min time.Duration) error {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return ErrInvalidCron
	}
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := sched.Next(t)
	for i := 0; i < 100; i++ {
		next := sched.Next(prev)
		if next.IsZero() {
			break
		}
		if next.Sub(prev) < min {
			return fmt.Errorf("%w: the minimum interval is %s", ErrScheduleTooOften, min)
		}
		prev = next
	}
	return nil
}

// SuspensionFor decides whether the owner of a schedule may still own it. It
// returns "" when the schedule may run, otherwise the suspension reason. A
// schedule is suspended when its owner is gone or deactivated, or when the
// owner of a URL target is neither Admin nor a Member with can_run_dast.
func SuspensionFor(cb store.Codebase, owner *store.User) string {
	if owner == nil || !owner.IsActive {
		return store.SuspendOwnerDeactivated
	}
	if cb.TargetType == "url" && !owner.MayRunDAST() {
		return store.SuspendOwnerLostPermission
	}
	return ""
}

// NextRun returns the next UTC run time of a cron expression after from.
func NextRun(expr string, from time.Time) (time.Time, bool) {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return time.Time{}, false
	}
	return sched.Next(from.UTC()), true
}

// LatestSlot returns the most recent cron slot in (now-tolerance, now]; slots
// missed during longer outages are not back-filled.
func LatestSlot(expr string, now time.Time, tolerance time.Duration) (time.Time, bool) {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return time.Time{}, false
	}
	now = now.UTC()
	var latest time.Time
	t := now.Add(-tolerance)
	for i := 0; i < 200; i++ {
		n := sched.Next(t)
		if n.IsZero() || n.After(now) {
			break
		}
		latest, t = n, n
	}
	return latest, !latest.IsZero()
}
