package store

import (
	"context"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
)

// MaxLogTail is the size cap of scans.log_tail.
const MaxLogTail = 16 * 1024

// JobOptions carries optional settings for a queued job beyond the base fields. The zero value is a
// plain passive job.
type JobOptions struct {
	// Active requests active (payload-sending) DAST scanning. Ignored for sast jobs.
	Active bool
	// ActiveTiming additionally requests the time-based SQLi checks. Meaningful only together with Active.
	ActiveTiming bool
}

// CreateJob queues a runner job. An active job on the codebase is 409
// scan_in_progress carrying the active scan id. opts is optional (defaults to a passive job).
func (s *Store) CreateJob(ctx context.Context, codebaseID int64, typ, trigger string, requestedBy *int64, opts ...JobOptions) (Scan, error) {
	var o JobOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	sc, err := collectOne[Scan](s.Pool.Query(ctx, `INSERT INTO scans (codebase_id, type, coverage, trigger, status, requested_by, active, active_timing)
		VALUES ($1, $2, 'full', $3, 'queued', $4, $5, $6) RETURNING `+scanCols, codebaseID, typ, trigger, requestedBy, o.Active, o.ActiveTiming))
	if IsUnique(err, "uq_scans_active") {
		var active int64
		_ = s.Pool.QueryRow(ctx, `SELECT id FROM scans WHERE codebase_id = $1 AND status IN ('queued','running') AND trigger <> 'ci' LIMIT 1`, codebaseID).Scan(&active)
		return Scan{}, apierr.Conflict("scan_in_progress", "A scan is already queued or running for this codebase.").
			WithDetails(map[string]any{"scan_id": active})
	}
	return sc, err
}

// GetScan loads a scan with its log.
func (s *Store) GetScan(ctx context.Context, id int64) (Scan, error) {
	return collectOne[Scan](s.Pool.Query(ctx, `SELECT `+scanCols+` FROM scans WHERE id = $1`, id))
}

// ListScans returns the visible history of a codebase (job rows that ended as
// duplicates are not part of the history), newest first.
func (s *Store) ListScans(ctx context.Context, codebaseID int64, status string, p Page) ([]Scan, int, error) {
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM scans WHERE codebase_id = $1 AND duplicate_of_scan_id IS NULL
		AND ($2 = '' OR status = $2)`, codebaseID, status).Scan(&total); err != nil {
		return nil, 0, err
	}
	items, err := collectAll[Scan](s.Pool.Query(ctx, `SELECT `+scanCols+` FROM scans WHERE codebase_id = $1
		AND duplicate_of_scan_id IS NULL AND ($2 = '' OR status = $2)
		ORDER BY started_at DESC, id DESC LIMIT $3 OFFSET $4`, codebaseID, status, p.Size, p.Offset()))
	for i := range items {
		items[i].LogTail = nil
	}
	return items, total, err
}

// CancelScan cancels a queued job at once or flags a running one. It returns
// the scan and whether it was a running job (the worker finishes cancellation).
func (s *Store) CancelScan(ctx context.Context, id int64) (Scan, error) {
	sc, err := collectOne[Scan](s.Pool.Query(ctx, `UPDATE scans SET status = 'cancelled', cancel_requested = true, finished_at = now()
		WHERE id = $1 AND status = 'queued' AND trigger <> 'ci' RETURNING `+scanCols, id))
	if err == nil {
		return sc, nil
	}
	if err != ErrNotFound {
		return Scan{}, err
	}
	sc, err = collectOne[Scan](s.Pool.Query(ctx, `UPDATE scans SET cancel_requested = true
		WHERE id = $1 AND status = 'running' AND trigger <> 'ci' RETURNING `+scanCols, id))
	if err == nil {
		return sc, nil
	}
	if err != ErrNotFound {
		return Scan{}, err
	}
	if _, err := s.GetScan(ctx, id); err != nil {
		return Scan{}, err
	}
	return Scan{}, apierr.Conflict("scan_finished", "The scan has already finished.")
}

// ClaimJob atomically takes the oldest queued runner job.
func (s *Store) ClaimJob(ctx context.Context, workerID string, lease time.Duration) (Scan, error) {
	return collectOne[Scan](s.Pool.Query(ctx, `UPDATE scans SET status = 'running', started_at = now(), worker_id = $1,
			lease_expires_at = now() + $2::interval
		WHERE id = (SELECT id FROM scans WHERE status = 'queued' AND trigger <> 'ci' ORDER BY queued_at, id
			FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING `+scanCols, workerID, lease.String()))
}

// RenewLease extends the lease and reports whether cancellation was requested
// (or the job is no longer running).
func (s *Store) RenewLease(ctx context.Context, id int64, workerID string, lease time.Duration) (cancel bool, err error) {
	var status string
	var cr bool
	err = s.Pool.QueryRow(ctx, `UPDATE scans SET lease_expires_at = now() + $3::interval
		WHERE id = $1 AND worker_id = $2 AND status = 'running' RETURNING status, cancel_requested`, id, workerID, lease.String()).Scan(&status, &cr)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return true, nil
		}
		return false, err
	}
	return cr, nil
}

// CancelRequested reads the cancel flag.
func (s *Store) CancelRequested(ctx context.Context, id int64) (bool, error) {
	var cr bool
	var status string
	if err := s.Pool.QueryRow(ctx, `SELECT cancel_requested, status FROM scans WHERE id = $1`, id).Scan(&cr, &status); err != nil {
		return false, notFound(err)
	}
	return cr || status != "running", nil
}

// AppendLog adds a line to log_tail, keeping the last 16 KiB.
func (s *Store) AppendLog(ctx context.Context, id int64, line string) {
	_, _ = s.Pool.Exec(context.WithoutCancel(ctx), `UPDATE scans SET log_tail = right(COALESCE(log_tail, '') || $2 || E'\n', $3) WHERE id = $1`, id, line, MaxLogTail)
}

// FailJob marks a running job failed.
func (s *Store) FailJob(ctx context.Context, id int64, code, logLine string) {
	_, _ = s.Pool.Exec(context.WithoutCancel(ctx), `UPDATE scans SET status = 'failed', finished_at = now(), error_code = $2,
		log_tail = right(COALESCE(log_tail, '') || $3 || E'\n', $4), lease_expires_at = NULL
		WHERE id = $1 AND status IN ('running','queued')`, id, code, logLine, MaxLogTail)
}

// CancelJob finishes a running job as cancelled.
func (s *Store) CancelJob(ctx context.Context, id int64) {
	_, _ = s.Pool.Exec(context.WithoutCancel(ctx), `UPDATE scans SET status = 'cancelled', finished_at = now(), cancel_requested = true,
		lease_expires_at = NULL WHERE id = $1 AND status IN ('running','queued')`, id)
}

// SweepLostJobs fails running jobs whose lease expired.
func (s *Store) SweepLostJobs(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE scans SET status = 'failed', finished_at = now(), error_code = 'worker_lost',
		log_tail = right(COALESCE(log_tail, '') || 'worker lost: lease expired' || E'\n', $1), lease_expires_at = NULL
		WHERE status = 'running' AND lease_expires_at < now()`, MaxLogTail)
	return tag.RowsAffected(), err
}

// QueueStats returns the number of queued and running jobs.
func (s *Store) QueueStats(ctx context.Context, includeURL bool) (queued, running int, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'queued'), count(*) FILTER (WHERE status = 'running')
		FROM scans WHERE trigger <> 'ci' AND (type = 'sast' OR $1)`, includeURL).Scan(&queued, &running)
	return
}
