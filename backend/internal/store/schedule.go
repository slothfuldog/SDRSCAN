package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Schedule suspension reasons.
const (
	SuspendOwnerDeactivated    = "owner_deactivated"
	SuspendOwnerLostPermission = "owner_lost_permission"
)

// SetSchedule sets (or changes) the schedule: the caller becomes the owner and
// the schedule is active (a previous suspension is cleared).
func (s *Store) SetSchedule(ctx context.Context, id int64, cron string, ownerID int64) (Codebase, error) {
	return collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET schedule_cron = $2, schedule_owner_id = $3,
		schedule_status = 'active', schedule_suspended_reason = NULL, schedule_suspended_at = NULL,
		schedule_last_enqueued_at = CASE WHEN schedule_cron IS DISTINCT FROM $2 THEN NULL ELSE schedule_last_enqueued_at END,
		updated_at = now() WHERE id = $1 RETURNING `+codebaseCols, id, cron, ownerID))
}

// ClearSchedule deletes the schedule (all schedule columns become NULL).
func (s *Store) ClearSchedule(ctx context.Context, id int64) (Codebase, error) {
	return collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET schedule_cron = NULL, schedule_owner_id = NULL,
		schedule_status = NULL, schedule_suspended_reason = NULL, schedule_suspended_at = NULL, schedule_last_enqueued_at = NULL,
		updated_at = now() WHERE id = $1 RETURNING `+codebaseCols, id))
}

// ErrNotSuspended is returned by ResumeSchedule when the schedule is not suspended.
var ErrNotSuspended = errors.New("schedule is not suspended")

// ResumeSchedule re-activates a suspended schedule; the caller becomes the owner.
func (s *Store) ResumeSchedule(ctx context.Context, id, ownerID int64) (Codebase, error) {
	cb, err := collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET schedule_owner_id = $2, schedule_status = 'active',
		schedule_suspended_reason = NULL, schedule_suspended_at = NULL, updated_at = now()
		WHERE id = $1 AND schedule_status = 'suspended' RETURNING `+codebaseCols, id, ownerID))
	if errors.Is(err, ErrNotFound) {
		if _, gerr := s.GetCodebase(ctx, id); gerr != nil {
			return Codebase{}, gerr
		}
		return Codebase{}, ErrNotSuspended
	}
	return cb, err
}

// SuspendSchedule marks an active schedule suspended (used by the scheduler).
// It reports whether a row changed.
func (s *Store) SuspendSchedule(ctx context.Context, id int64, reason string) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE codebases SET schedule_status = 'suspended', schedule_suspended_reason = $2,
		schedule_suspended_at = now(), updated_at = now() WHERE id = $1 AND schedule_status = 'active'`, id, reason)
	return tag.RowsAffected() == 1, err
}

// suspendOwnedSchedules suspends, inside the user-update transaction, the active
// schedules owned by a user who was deactivated or (for URL targets) lost DAST
// permission. It returns "name (reason)" strings for the audit log.
func suspendOwnedSchedules(ctx context.Context, tx pgx.Tx, userID int64, deactivated, mayRunDAST bool) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE codebases SET schedule_status = 'suspended',
			schedule_suspended_reason = CASE WHEN $2 THEN 'owner_deactivated' ELSE 'owner_lost_permission' END,
			schedule_suspended_at = now(), updated_at = now()
		WHERE schedule_owner_id = $1 AND schedule_status = 'active' AND ($2 OR (target_type = 'url' AND NOT $3))
		RETURNING name, schedule_suspended_reason`, userID, deactivated, mayRunDAST)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, reason string
		if err := rows.Scan(&name, &reason); err != nil {
			return nil, err
		}
		out = append(out, name+" ("+reason+")")
	}
	return out, rows.Err()
}

// ScheduleCandidates returns codebases with an active schedule and no active job.
func (s *Store) ScheduleCandidates(ctx context.Context) ([]Codebase, error) {
	return collectAll[Codebase](s.Pool.Query(ctx, `SELECT `+codebaseCols+` FROM codebases c WHERE schedule_status = 'active'
		AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.codebase_id = c.id AND s.status IN ('queued','running') AND s.trigger <> 'ci')`))
}

// EnqueueScheduled queues one scheduled job for a cron slot and records the
// slot, in one transaction. It returns false when the slot was already taken
// (another instance) or the codebase already has an active job.
func (s *Store) EnqueueScheduled(ctx context.Context, cb Codebase, typ string, ownerID int64, slot time.Time) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE codebases SET schedule_last_enqueued_at = $2 WHERE id = $1 AND schedule_status = 'active'
		AND schedule_owner_id = $3 AND (schedule_last_enqueued_at IS NULL OR schedule_last_enqueued_at < $2)`, cb.ID, slot, ownerID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO scans (codebase_id, type, coverage, trigger, status, requested_by)
		VALUES ($1, $2, 'full', 'schedule', 'queued', $3)`, cb.ID, typ, ownerID); err != nil {
		if IsUnique(err, "uq_scans_active") {
			return false, nil
		}
		return false, err
	}
	return true, tx.Commit(ctx)
}

// ListSchedules lists codebases with a schedule (URL targets only when includeURL).
func (s *Store) ListSchedules(ctx context.Context, status string, includeURL bool, p Page) ([]CodebaseWithProject, int, error) {
	where := `c.schedule_cron IS NOT NULL AND ($1 = '' OR c.schedule_status = $1) AND (c.target_type = 'repo' OR $2)`
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM codebases c WHERE `+where, status, includeURL).Scan(&total); err != nil {
		return nil, 0, err
	}
	items, err := collectAll[CodebaseWithProject](s.Pool.Query(ctx, `SELECT `+prefixCols("c", codebaseCols)+`, p.name AS project_name
		FROM codebases c JOIN projects p ON p.id = c.project_id WHERE `+where+`
		ORDER BY lower(p.name), lower(c.name), c.id LIMIT $3 OFFSET $4`, status, includeURL, p.Size, p.Offset()))
	return items, total, err
}
