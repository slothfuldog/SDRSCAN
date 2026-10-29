package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

const canonicalSQL = `WITH base AS (SELECT started_at, id FROM scans WHERE id = $2),
owner AS (
  SELECT DISTINCT ON (sf.path) sf.path, sf.scan_id
  FROM scan_files sf
  JOIN scans s ON s.id = sf.scan_id, base b
  WHERE s.codebase_id = $1 AND s.coverage = 'partial' AND s.status = 'succeeded' AND s.duplicate_of_scan_id IS NULL
    AND (s.started_at, s.id) > (b.started_at, b.id)
  ORDER BY sf.path, s.started_at DESC, s.id DESC
)
SELECT f.id
FROM findings f
LEFT JOIN owner o ON o.path = f.path
WHERE f.codebase_id = $1 AND f.scan_id = COALESCE(o.scan_id, $2)`

// CanonicalCurrentIDs returns the ids of the findings that make up the current
// state of a codebase by the canonical definition (full base scan plus later
// partial scans, per path). It is the reference the is_current flag must match.
func (s *Store) CanonicalCurrentIDs(ctx context.Context, q DBTX, codebaseID, baseScanID int64) ([]int64, error) {
	if q == nil {
		q = s.Pool
	}
	rows, err := q.Query(ctx, canonicalSQL, codebaseID, baseScanID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// RebuildState recomputes is_current and the codebase summary from the
// canonical definition for one codebase (0 = all). It returns the number of
// codebases processed.
func (s *Store) RebuildState(ctx context.Context, codebaseID int64) (int, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM codebases WHERE $1 = 0 OR id = $1 ORDER BY id`, codebaseID)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := s.rebuildOne(ctx, id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (s *Store) rebuildOne(ctx context.Context, id int64) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT id FROM codebases WHERE id = $1 FOR UPDATE`, id); err != nil {
		return err
	}
	var base, latest *int64
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT id FROM scans WHERE codebase_id = $1 AND status = 'succeeded' AND coverage = 'full' AND duplicate_of_scan_id IS NULL
		 ORDER BY started_at DESC, id DESC LIMIT 1),
		(SELECT id FROM scans WHERE codebase_id = $1 AND status = 'succeeded' AND duplicate_of_scan_id IS NULL
		 ORDER BY started_at DESC, id DESC LIMIT 1)`, id).Scan(&base, &latest); err != nil {
		return err
	}
	if base == nil {
		if _, err := tx.Exec(ctx, `UPDATE findings SET is_current = false WHERE codebase_id = $1 AND is_current`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE codebases SET n_critical = 0, n_high = 0, n_medium = 0, n_low = 0, n_info = 0,
			n_low_confidence = 0, base_scan_id = NULL, latest_scan_id = $2, updated_at = now() WHERE id = $1`, id, latest); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	cur, err := s.CanonicalCurrentIDs(ctx, tx, id, *base)
	if err != nil {
		return err
	}
	if cur == nil {
		cur = []int64{}
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET is_current = (id = ANY($2)) WHERE codebase_id = $1 AND is_current <> (id = ANY($2))`, id, cur); err != nil {
		return err
	}
	var c Counts
	var low int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE severity = 'critical' AND confidence = 'normal'),
		count(*) FILTER (WHERE severity = 'high' AND confidence = 'normal'), count(*) FILTER (WHERE severity = 'medium' AND confidence = 'normal'),
		count(*) FILTER (WHERE severity = 'low' AND confidence = 'normal'), count(*) FILTER (WHERE severity = 'info' AND confidence = 'normal'),
		count(*) FILTER (WHERE confidence = 'low') FROM findings WHERE codebase_id = $1 AND is_current`, id).
		Scan(&c.Critical, &c.High, &c.Medium, &c.Low, &c.Info, &low); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE codebases SET n_critical = $2, n_high = $3, n_medium = $4, n_low = $5, n_info = $6,
		n_low_confidence = $7, base_scan_id = $8, latest_scan_id = $9, updated_at = now() WHERE id = $1`,
		id, c.Critical, c.High, c.Medium, c.Low, c.Info, low, base, latest); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
