package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
)

// Project is a row of projects.
type Project struct {
	ID          int64     `db:"id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

const projectCols = `id, name, description, created_at, updated_at`

// CreateProject inserts a project; a taken name is 409 name_taken.
func (s *Store) CreateProject(ctx context.Context, name, desc string) (Project, error) {
	p, err := collectOne[Project](s.Pool.Query(ctx, `INSERT INTO projects (name, description) VALUES ($1, $2) RETURNING `+projectCols, name, desc))
	if IsUnique(err, "uq_projects_name") {
		return Project{}, nameTaken("Project")
	}
	return p, err
}

// GetProject loads a project.
func (s *Store) GetProject(ctx context.Context, id int64) (Project, error) {
	return collectOne[Project](s.Pool.Query(ctx, `SELECT `+projectCols+` FROM projects WHERE id = $1`, id))
}

// FindProjectByName loads a project by case-insensitive name.
func (s *Store) FindProjectByName(ctx context.Context, name string) (Project, error) {
	return collectOne[Project](s.Pool.Query(ctx, `SELECT `+projectCols+` FROM projects WHERE lower(name) = lower($1)`, name))
}

// UpdateProject changes name and/or description.
func (s *Store) UpdateProject(ctx context.Context, id int64, name, desc *string) (Project, error) {
	p, err := collectOne[Project](s.Pool.Query(ctx, `UPDATE projects SET name = COALESCE($2, name),
		description = COALESCE($3, description), updated_at = now() WHERE id = $1 RETURNING `+projectCols, id, name, desc))
	if IsUnique(err, "uq_projects_name") {
		return Project{}, nameTaken("Project")
	}
	return p, err
}

// ProjectRow is a project with its roll-up.
type ProjectRow struct {
	Project
	CodebaseCount int
	Totals        Counts
}

// ListProjects returns a page of projects (by name) with totals.
func (s *Store) ListProjects(ctx context.Context, p Page, includeURL bool) ([]ProjectRow, int, error) {
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM projects`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT p.id, p.name, p.description, p.created_at, p.updated_at,
			count(c.id),
			COALESCE(sum(c.n_critical) FILTER (WHERE c.base_scan_id IS NOT NULL), 0),
			COALESCE(sum(c.n_high)     FILTER (WHERE c.base_scan_id IS NOT NULL), 0),
			COALESCE(sum(c.n_medium)   FILTER (WHERE c.base_scan_id IS NOT NULL), 0),
			COALESCE(sum(c.n_low)      FILTER (WHERE c.base_scan_id IS NOT NULL), 0),
			COALESCE(sum(c.n_info)     FILTER (WHERE c.base_scan_id IS NOT NULL), 0)
		FROM projects p LEFT JOIN codebases c ON c.project_id = p.id AND (c.target_type = 'repo' OR $3)
		GROUP BY p.id ORDER BY lower(p.name), p.id LIMIT $1 OFFSET $2`, p.Size, p.Offset(), includeURL)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ProjectRow
	for rows.Next() {
		var r ProjectRow
		var cr, hi, me, lo, in int64
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt, &r.UpdatedAt, &r.CodebaseCount, &cr, &hi, &me, &lo, &in); err != nil {
			return nil, 0, err
		}
		r.Totals = Counts{int(cr), int(hi), int(me), int(lo), int(in)}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ProjectTotals sums the current-state counts of scanned codebases.
func (s *Store) ProjectTotals(ctx context.Context, projectID int64, includeURL bool) (Counts, error) {
	var c Counts
	var cr, hi, me, lo, in int64
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(n_critical), 0), COALESCE(SUM(n_high), 0), COALESCE(SUM(n_medium), 0),
		COALESCE(SUM(n_low), 0), COALESCE(SUM(n_info), 0) FROM codebases WHERE project_id = $1 AND base_scan_id IS NOT NULL AND (target_type = 'repo' OR $2)`, projectID, includeURL).
		Scan(&cr, &hi, &me, &lo, &in)
	c = Counts{int(cr), int(hi), int(me), int(lo), int(in)}
	return c, err
}

// DeleteCounts is the number of rows removed by a delete.
type DeleteCounts struct {
	Codebases int `json:"codebases,omitempty"`
	Scans     int `json:"scans"`
	Findings  int `json:"findings"`
}

// DeleteProject removes a project and everything below it in one transaction.
func (s *Store) DeleteProject(ctx context.Context, id int64) (DeleteCounts, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DeleteCounts{}, err
	}
	defer tx.Rollback(ctx)
	var dc DeleteCounts
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM codebases WHERE project_id = $1),
		(SELECT count(*) FROM scans s JOIN codebases c ON c.id = s.codebase_id WHERE c.project_id = $1),
		(SELECT count(*) FROM findings f JOIN codebases c ON c.id = f.codebase_id WHERE c.project_id = $1)`, id).
		Scan(&dc.Codebases, &dc.Scans, &dc.Findings); err != nil {
		return dc, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
	if err != nil {
		return dc, err
	}
	if tag.RowsAffected() == 0 {
		return dc, ErrNotFound
	}
	return dc, tx.Commit(ctx)
}

// ----- codebases -----

// NewCodebase carries the validated values for an insert.
type NewCodebase struct {
	ProjectID     int64
	Name          string
	TargetType    string
	Language      string
	RepoURL       *string
	Branch        *string
	Subdirectory  string
	GitAuthKind   string
	GitUsername   *string
	GitSecretEnc  []byte
	BaseURL       *string
	RegisteredBy  *int64
	ScheduleCron  *string
	ScheduleOwner *int64
	MaxRPS        int
}

// CreateCodebase inserts a codebase (URL targets start pending_confirmation).
func (s *Store) CreateCodebase(ctx context.Context, n NewCodebase) (Codebase, error) {
	var dastStatus *string
	if n.TargetType == "url" {
		v := "pending_confirmation"
		dastStatus = &v
	}
	if n.MaxRPS == 0 {
		n.MaxRPS = 5
	}
	if n.GitAuthKind == "" {
		n.GitAuthKind = "none"
	}
	cb, err := collectOne[Codebase](s.Pool.Query(ctx, `INSERT INTO codebases
		(project_id, name, target_type, language, repo_url, branch, subdirectory, git_auth_kind, git_username,
		 git_secret_enc, base_url, dast_status, dast_registered_by, schedule_cron, schedule_owner_id, schedule_status, dast_max_rps)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,CASE WHEN $14::text IS NULL THEN NULL ELSE 'active' END,$16) RETURNING `+codebaseCols,
		n.ProjectID, n.Name, n.TargetType, n.Language, n.RepoURL, n.Branch, n.Subdirectory, n.GitAuthKind, n.GitUsername,
		n.GitSecretEnc, n.BaseURL, dastStatus, n.RegisteredBy, n.ScheduleCron, n.ScheduleOwner, n.MaxRPS))
	if IsUnique(err, "uq_codebases_name") {
		return Codebase{}, nameTaken("Codebase")
	}
	if IsFKViolation(err) {
		return Codebase{}, ErrNotFound
	}
	return cb, err
}

// GetCodebase loads a codebase.
func (s *Store) GetCodebase(ctx context.Context, id int64) (Codebase, error) {
	return collectOne[Codebase](s.Pool.Query(ctx, `SELECT `+codebaseCols+` FROM codebases WHERE id = $1`, id))
}

// FindCodebaseByName loads a codebase of a project by case-insensitive name.
func (s *Store) FindCodebaseByName(ctx context.Context, projectID int64, name string) (Codebase, error) {
	return collectOne[Codebase](s.Pool.Query(ctx, `SELECT `+codebaseCols+` FROM codebases WHERE project_id = $1 AND lower(name) = lower($2)`, projectID, name))
}

// ListCodebases returns the codebases of a project ordered by name.
func (s *Store) ListCodebases(ctx context.Context, projectID int64, includeURL bool) ([]Codebase, error) {
	return collectAll[Codebase](s.Pool.Query(ctx, `SELECT `+codebaseCols+` FROM codebases WHERE project_id = $1
		AND (target_type = 'repo' OR $2) ORDER BY lower(name), id`, projectID, includeURL))
}

// CodebaseWithProject adds the project name to a codebase row.
type CodebaseWithProject struct {
	Codebase
	ProjectName string `db:"project_name"`
}

// ListAllCodebases lists codebases across projects (optionally one project or
// target type), hiding URL targets unless includeURL.
func (s *Store) ListAllCodebases(ctx context.Context, projectID int64, targetType string, scheduledOnly, includeURL bool, p Page) ([]CodebaseWithProject, int, error) {
	where := `($1 = 0 OR c.project_id = $1) AND ($2 = '' OR c.target_type = $2) AND (NOT $3 OR c.schedule_cron IS NOT NULL) AND (c.target_type = 'repo' OR $4)`
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM codebases c WHERE `+where, projectID, targetType, scheduledOnly, includeURL).Scan(&total); err != nil {
		return nil, 0, err
	}
	items, err := collectAll[CodebaseWithProject](s.Pool.Query(ctx, `SELECT `+prefixCols("c", codebaseCols)+`, p.name AS project_name
		FROM codebases c JOIN projects p ON p.id = c.project_id WHERE `+where+`
		ORDER BY lower(p.name), lower(c.name), c.id LIMIT $5 OFFSET $6`, projectID, targetType, scheduledOnly, includeURL, p.Size, p.Offset()))
	return items, total, err
}

// CodebaseNames lists codebase names of a project (for ingest suggestions).
func (s *Store) CodebaseNames(ctx context.Context, projectID int64) ([]string, error) {
	return stringColumn(s.Pool.Query(ctx, `SELECT name FROM codebases WHERE project_id = $1`, projectID))
}

// ProjectNames lists all project names (for ingest suggestions).
func (s *Store) ProjectNames(ctx context.Context) ([]string, error) {
	return stringColumn(s.Pool.Query(ctx, `SELECT name FROM projects`))
}

// codebaseUpdatable lists the columns UpdateCodebase may set.
var codebaseUpdatable = map[string]bool{
	"project_id": true, "name": true, "language": true, "repo_url": true, "branch": true, "subdirectory": true,
	"git_auth_kind": true, "schedule_owner_id": true, "schedule_status": true, "schedule_suspended_reason": true, "schedule_suspended_at": true, "schedule_last_enqueued_at": true, "git_username": true, "git_secret_enc": true, "base_url": true, "schedule_cron": true,
	"dast_max_rps": true, "dast_status": true, "dast_confirmed_by": true, "dast_confirmed_at": true,
	"dast_confirmation_text": true,
	"dast_auth_type":         true, "dast_auth_enc": true, "dast_auth_meta": true,
	"dast_crawl_enabled": true, "dast_crawl_max_depth": true, "dast_crawl_max_pages": true, "dast_crawl_exclude": true,
	"dast_active_authorized_at": true, "dast_active_authorized_by": true, "dast_active_statement": true,
	"dast_openapi_spec_url": true,
}

// UpdateCodebase sets the given whitelisted columns.
func (s *Store) UpdateCodebase(ctx context.Context, id int64, sets map[string]any) (Codebase, error) {
	if len(sets) == 0 {
		return s.GetCodebase(ctx, id)
	}
	cols := make([]string, 0, len(sets))
	for k := range sets {
		if !codebaseUpdatable[k] {
			return Codebase{}, fmt.Errorf("column %q is not updatable", k)
		}
		cols = append(cols, k)
	}
	sort.Strings(cols)
	args := []any{id}
	var parts []string
	for _, c := range cols {
		if ex, ok := sets[c].([]string); ok && ex == nil {
			sets[c] = []string{} // a nil slice would be SQL NULL (the column is NOT NULL)
		}
		args = append(args, sets[c])
		parts = append(parts, fmt.Sprintf("%s = $%d", c, len(args)))
	}
	cb, err := collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET `+strings.Join(parts, ", ")+`, updated_at = now()
		WHERE id = $1 RETURNING `+codebaseCols, args...))
	if IsUnique(err, "uq_codebases_name") {
		return Codebase{}, nameTaken("Codebase")
	}
	if IsFKViolation(err) {
		return Codebase{}, apierr.ValidationField("project_id", "project_id does not exist.")
	}
	return cb, err
}

// SetDastAuth stores (or, with typ "none" and nil enc/meta, removes) the DAST authentication of a URL
// target. It only applies while the target still has the given base URL, so that credentials are never
// attached to a target whose host changed in the meantime (ErrNotFound otherwise).
func (s *Store) SetDastAuth(ctx context.Context, id int64, baseURL, typ string, enc []byte, meta json.RawMessage) (Codebase, error) {
	var m any
	if len(meta) > 0 {
		m = []byte(meta)
	}
	return collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET dast_auth_type = $3, dast_auth_enc = $4,
		dast_auth_meta = $5::jsonb, updated_at = now() WHERE id = $1 AND target_type = 'url' AND base_url = $2 RETURNING `+codebaseCols,
		id, baseURL, typ, enc, m))
}

// ConfirmDast marks a URL target confirmed with its audit trail.
func (s *Store) ConfirmDast(ctx context.Context, id, userID int64, text string) (Codebase, error) {
	return collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET dast_status = 'confirmed', dast_confirmed_by = $2,
		dast_confirmed_at = now(), dast_confirmation_text = $3, updated_at = now()
		WHERE id = $1 AND target_type = 'url' RETURNING `+codebaseCols, id, userID, text))
}

// AuthorizeActiveScanning marks active (payload-sending) DAST scanning authorized for a URL target,
// with its audit trail (the typed statement, kept for audit, not a secret). This is a separate,
// stricter layer on top of ConfirmDast.
func (s *Store) AuthorizeActiveScanning(ctx context.Context, id, userID int64, statement string) (Codebase, error) {
	return collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET dast_active_authorized_at = now(),
		dast_active_authorized_by = $2, dast_active_statement = $3, updated_at = now()
		WHERE id = $1 AND target_type = 'url' RETURNING `+codebaseCols, id, userID, statement))
}

// RevokeActiveScanning clears the active-scanning authorization of a URL target.
func (s *Store) RevokeActiveScanning(ctx context.Context, id int64) (Codebase, error) {
	return collectOne[Codebase](s.Pool.Query(ctx, `UPDATE codebases SET dast_active_authorized_at = NULL,
		dast_active_authorized_by = NULL, dast_active_statement = NULL, updated_at = now()
		WHERE id = $1 AND target_type = 'url' RETURNING `+codebaseCols, id))
}

// DeleteCodebase removes a codebase with its scans and findings.
func (s *Store) DeleteCodebase(ctx context.Context, id int64) (DeleteCounts, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DeleteCounts{}, err
	}
	defer tx.Rollback(ctx)
	var dc DeleteCounts
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM scans WHERE codebase_id = $1),
		(SELECT count(*) FROM findings WHERE codebase_id = $1)`, id).Scan(&dc.Scans, &dc.Findings); err != nil {
		return dc, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM codebases WHERE id = $1`, id)
	if err != nil {
		return dc, err
	}
	if tag.RowsAffected() == 0 {
		return dc, ErrNotFound
	}
	return dc, tx.Commit(ctx)
}

// CodebaseState describes how the current state of a codebase is composed.
type CodebaseState struct {
	LatestScan       *Scan
	BaseScan         *Scan
	PartialSinceBase int
	ActiveScan       *Scan
}

// States loads latest/base scans, partial counts and active jobs for codebases.
func (s *Store) States(ctx context.Context, cbs []Codebase) (map[int64]CodebaseState, error) {
	out := make(map[int64]CodebaseState, len(cbs))
	if len(cbs) == 0 {
		return out, nil
	}
	var ids, scanIDs []int64
	for _, c := range cbs {
		ids = append(ids, c.ID)
		if c.LatestScanID != nil {
			scanIDs = append(scanIDs, *c.LatestScanID)
		}
		if c.BaseScanID != nil {
			scanIDs = append(scanIDs, *c.BaseScanID)
		}
	}
	byID := map[int64]*Scan{}
	if len(scanIDs) > 0 {
		scans, err := collectAll[Scan](s.Pool.Query(ctx, `SELECT `+scanCols+` FROM scans WHERE id = ANY($1)`, scanIDs))
		if err != nil {
			return nil, err
		}
		for i := range scans {
			scans[i].LogTail = nil
			byID[scans[i].ID] = &scans[i]
		}
	}
	partials := map[int64]int{}
	rows, err := s.Pool.Query(ctx, `SELECT c.id, count(p.id) FROM codebases c
		JOIN scans b ON b.id = c.base_scan_id
		JOIN scans p ON p.codebase_id = c.id AND p.coverage = 'partial' AND p.status = 'succeeded'
			AND p.duplicate_of_scan_id IS NULL AND (p.started_at, p.id) > (b.started_at, b.id)
		WHERE c.id = ANY($1) GROUP BY c.id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return nil, err
		}
		partials[id] = n
	}
	rows.Close()
	active, err := collectAll[Scan](s.Pool.Query(ctx, `SELECT `+scanCols+` FROM scans
		WHERE codebase_id = ANY($1) AND status IN ('queued','running') AND trigger <> 'ci'`, ids))
	if err != nil {
		return nil, err
	}
	activeBy := map[int64]*Scan{}
	for i := range active {
		active[i].LogTail = nil
		activeBy[active[i].CodebaseID] = &active[i]
	}
	for _, c := range cbs {
		st := CodebaseState{PartialSinceBase: partials[c.ID], ActiveScan: activeBy[c.ID]}
		if c.LatestScanID != nil {
			st.LatestScan = byID[*c.LatestScanID]
		}
		if c.BaseScanID != nil {
			st.BaseScan = byID[*c.BaseScanID]
		}
		out[c.ID] = st
	}
	return out, nil
}

// CollectCodebaseCounts reloads a codebase inside a transaction.
func CollectCodebaseCounts(ctx context.Context, q DBTX, id int64) (Codebase, error) {
	return collectOne[Codebase](q.Query(ctx, `SELECT `+codebaseCols+` FROM codebases WHERE id = $1`, id))
}
