// Package store holds the PostgreSQL queries (pgx, hand-written SQL).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
)

// Store is the data access layer.
type Store struct {
	Pool *pgxpool.Pool
}

// New wraps a pool.
func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

// DBTX is satisfied by *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// IsUnique reports whether err is a unique violation, optionally on a constraint/index.
func IsUnique(err error, name string) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return name == "" || strings.Contains(pe.ConstraintName, name)
	}
	return false
}

// IsFKViolation reports whether err is a foreign key violation.
func IsFKViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23503"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// Page is a pagination request.
type Page struct {
	Page, Size int
}

// Offset returns the SQL OFFSET.
func (p Page) Offset() int { return (p.Page - 1) * p.Size }

// Counts holds the severity counts of a summary.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Add returns the sum of two Counts.
func (c Counts) Add(o Counts) Counts {
	return Counts{c.Critical + o.Critical, c.High + o.High, c.Medium + o.Medium, c.Low + o.Low, c.Info + o.Info}
}

// Highest returns the highest severity with a non-zero count, or "" when none.
func (c Counts) Highest() string {
	switch {
	case c.Critical > 0:
		return "critical"
	case c.High > 0:
		return "high"
	case c.Medium > 0:
		return "medium"
	case c.Low > 0:
		return "low"
	case c.Info > 0:
		return "info"
	}
	return ""
}

// ----- users -----

// User is a row of users.
type User struct {
	ID                 int64      `db:"id"`
	Username           string     `db:"username"`
	PasswordHash       string     `db:"password_hash"`
	Role               string     `db:"role"`
	CanRunDAST         bool       `db:"can_run_dast"`
	IsActive           bool       `db:"is_active"`
	MustChangePassword bool       `db:"must_change_password"`
	FailedAttempts     int        `db:"failed_attempts"`
	LockedUntil        *time.Time `db:"locked_until"`
	LastLoginAt        *time.Time `db:"last_login_at"`
	CreatedAt          time.Time  `db:"created_at"`
	UpdatedAt          time.Time  `db:"updated_at"`
}

// IsAdmin reports the admin role.
func (u User) IsAdmin() bool { return u.Role == "admin" }

// MayRunDAST reports whether the user may register DAST targets and trigger DAST.
func (u User) MayRunDAST() bool { return u.Role == "admin" || u.CanRunDAST }

const userCols = `id, username, password_hash, role, can_run_dast, is_active, must_change_password,
	failed_attempts, locked_until, last_login_at, created_at, updated_at`

// ----- codebases -----

// Codebase is a row of codebases.
type Codebase struct {
	ID                      int64      `db:"id"`
	ProjectID               int64      `db:"project_id"`
	Name                    string     `db:"name"`
	TargetType              string     `db:"target_type"`
	Language                string     `db:"language"`
	RepoURL                 *string    `db:"repo_url"`
	Branch                  *string    `db:"branch"`
	Subdirectory            string     `db:"subdirectory"`
	GitAuthKind             string     `db:"git_auth_kind"`
	GitUsername             *string    `db:"git_username"`
	GitSecretEnc            []byte     `db:"git_secret_enc"`
	BaseURL                 *string    `db:"base_url"`
	DastStatus              *string    `db:"dast_status"`
	DastRegisteredBy        *int64     `db:"dast_registered_by"`
	DastConfirmedBy         *int64     `db:"dast_confirmed_by"`
	DastConfirmedAt         *time.Time `db:"dast_confirmed_at"`
	DastConfirmationText    *string    `db:"dast_confirmation_text"`
	DastMaxRPS              int        `db:"dast_max_rps"`
	ScheduleCron            *string    `db:"schedule_cron"`
	ScheduleOwnerID         *int64     `db:"schedule_owner_id"`
	ScheduleStatus          *string    `db:"schedule_status"`
	ScheduleSuspendedReason *string    `db:"schedule_suspended_reason"`
	ScheduleSuspendedAt     *time.Time `db:"schedule_suspended_at"`
	ScheduleLastEnqueuedAt  *time.Time `db:"schedule_last_enqueued_at"`
	// Authenticated DAST: DastAuthEnc is the AES-GCM sealed configuration (secrets included, never
	// exposed); DastAuthMeta is the non-secret description for display.
	DastAuthType      string          `db:"dast_auth_type"`
	DastAuthEnc       []byte          `db:"dast_auth_enc"`
	DastAuthMeta      json.RawMessage `db:"dast_auth_meta"`
	DastCrawlEnabled  bool            `db:"dast_crawl_enabled"`
	DastCrawlMaxDepth int             `db:"dast_crawl_max_depth"`
	DastCrawlMaxPages int             `db:"dast_crawl_max_pages"`
	DastCrawlExclude  []string        `db:"dast_crawl_exclude"`
	// Active scanning authorization: a separate, stricter layer on top of DastStatus == "confirmed".
	// Nil DastActiveAuthorizedAt means active (payload-sending) DAST scanning is not authorized, so a
	// scan must stay passive.
	DastActiveAuthorizedAt *time.Time `db:"dast_active_authorized_at"`
	DastActiveAuthorizedBy *int64     `db:"dast_active_authorized_by"`
	DastActiveStatement    *string    `db:"dast_active_statement"`
	// DastOpenAPISpecURL optionally points to an OpenAPI/Swagger spec: when set, active scanning also
	// exercises the API operations it describes (GET/POST/PUT/PATCH; DELETE is never tested), on top of
	// whatever auto-discovery finds during the crawl.
	DastOpenAPISpecURL *string   `db:"dast_openapi_spec_url"`
	LatestScanID       *int64    `db:"latest_scan_id"`
	BaseScanID         *int64    `db:"base_scan_id"`
	NCritical          int       `db:"n_critical"`
	NHigh              int       `db:"n_high"`
	NMedium            int       `db:"n_medium"`
	NLow               int       `db:"n_low"`
	NInfo              int       `db:"n_info"`
	NLowConfidence     int       `db:"n_low_confidence"`
	CreatedAt          time.Time `db:"created_at"`
	UpdatedAt          time.Time `db:"updated_at"`
}

// Counts returns the current-state severity counts.
func (c Codebase) Counts() Counts {
	return Counts{c.NCritical, c.NHigh, c.NMedium, c.NLow, c.NInfo}
}

// Scanned reports whether the codebase has a current state (a successful full scan).
func (c Codebase) Scanned() bool { return c.BaseScanID != nil }

// ActiveScanAuthorized reports whether active (payload-sending) DAST scanning is authorized for this target.
func (c Codebase) ActiveScanAuthorized() bool { return c.DastActiveAuthorizedAt != nil }

const codebaseCols = `id, project_id, name, target_type, language, repo_url, branch, subdirectory,
	git_auth_kind, git_username, git_secret_enc, base_url, dast_status, dast_registered_by,
	dast_confirmed_by, dast_confirmed_at, dast_confirmation_text, dast_max_rps, schedule_cron,
	schedule_owner_id, schedule_status, schedule_suspended_reason, schedule_suspended_at, schedule_last_enqueued_at,
	dast_auth_type, dast_auth_enc, dast_auth_meta, dast_crawl_enabled, dast_crawl_max_depth, dast_crawl_max_pages, dast_crawl_exclude,
	dast_active_authorized_at, dast_active_authorized_by, dast_active_statement, dast_openapi_spec_url,
	latest_scan_id, base_scan_id, n_critical, n_high, n_medium, n_low, n_info, n_low_confidence,
	created_at, updated_at`

// ----- scans -----

// Scan is a row of scans.
type Scan struct {
	ID                int64      `db:"id"`
	CodebaseID        int64      `db:"codebase_id"`
	Type              string     `db:"type"`
	Coverage          string     `db:"coverage"`
	Trigger           string     `db:"trigger"`
	Status            string     `db:"status"`
	RequestedBy       *int64     `db:"requested_by"`
	IngestTokenID     *int64     `db:"ingest_token_id"`
	QueuedAt          time.Time  `db:"queued_at"`
	StartedAt         *time.Time `db:"started_at"`
	FinishedAt        *time.Time `db:"finished_at"`
	Engine            *string    `db:"engine"`
	EngineVersion     *string    `db:"engine_version"`
	Ref               string     `db:"ref"`
	ScannedFileCount  *int       `db:"scanned_file_count"`
	NCritical         int        `db:"n_critical"`
	NHigh             int        `db:"n_high"`
	NMedium           int        `db:"n_medium"`
	NLow              int        `db:"n_low"`
	NInfo             int        `db:"n_info"`
	NLowConfidence    int        `db:"n_low_confidence"`
	DuplicateOfScanID *int64     `db:"duplicate_of_scan_id"`
	CancelRequested   bool       `db:"cancel_requested"`
	WorkerID          *string    `db:"worker_id"`
	LeaseExpiresAt    *time.Time `db:"lease_expires_at"`
	ErrorCode         *string    `db:"error_code"`
	LogTail           *string    `db:"log_tail"`
	// Active (payload-sending) DAST scanning and its time-based SQLi extra. Always false for sast and
	// for a passive dast scan; recorded on the scan row so history and re-runs never inherit it silently.
	Active       bool `db:"active"`
	ActiveTiming bool `db:"active_timing"`
}

// Counts returns this scan's own severity counts.
func (s Scan) Counts() Counts { return Counts{s.NCritical, s.NHigh, s.NMedium, s.NLow, s.NInfo} }

// Terminal reports whether the scan reached a final status.
func (s Scan) Terminal() bool {
	return s.Status == "succeeded" || s.Status == "failed" || s.Status == "cancelled"
}

const scanCols = `id, codebase_id, type, coverage, trigger, status, requested_by, ingest_token_id, queued_at,
	started_at, finished_at, engine, engine_version, ref, scanned_file_count, n_critical, n_high, n_medium,
	n_low, n_info, n_low_confidence, duplicate_of_scan_id, cancel_requested, worker_id, lease_expires_at,
	error_code, log_tail, active, active_timing`

// ----- helpers -----

func collectOne[T any](rows pgx.Rows, err error) (T, error) {
	var zero T
	if err != nil {
		return zero, err
	}
	v, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[T])
	if err != nil {
		return zero, notFound(err)
	}
	return v, nil
}

func collectAll[T any](rows pgx.Rows, err error) ([]T, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[T])
}

// Validation helper shared with handlers.
func nameTaken(what string) error {
	return apierr.Conflict("name_taken", what+" name is already in use.").WithField("name")
}

func stringColumn(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// HasDastAuth reports whether DAST authentication is configured.
func (c Codebase) HasDastAuth() bool { return c.DastAuthType != "" && c.DastAuthType != "none" }
