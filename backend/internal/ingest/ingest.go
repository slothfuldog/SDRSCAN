// Package ingest turns a SARIF document into exactly one Scan (or nothing),
// in one PostgreSQL transaction. It is shared by the CI endpoint and the runner.
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/redact"
	"github.com/sdrscan/sdrscan/backend/internal/sarif"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// Limits on stored text.
const (
	MaxMessageBytes = 4 * 1024
	MaxSnippetBytes = 8 * 1024
	maxPathBytes    = 1024
)

// ErrCancelled is returned to the runner when the job row is no longer running
// (cancelled) at the moment of the write; nothing was written.
var ErrCancelled = errors.New("ingest: job cancelled")

// Config tunes the ingester.
type Config struct {
	MaxResults  int
	SecretRules []string
	LockTimeout time.Duration
}

// Ingester runs ingests.
type Ingester struct {
	Store *store.Store
	Cfg   Config
}

// New builds an Ingester with defaults filled in.
func New(st *store.Store, cfg Config) *Ingester {
	if cfg.MaxResults == 0 {
		cfg.MaxResults = 100000
	}
	if cfg.LockTimeout == 0 {
		cfg.LockTimeout = 30 * time.Second
	}
	if len(cfg.SecretRules) == 0 {
		cfg.SecretRules = []string{"php-hardcoded-secret"}
	}
	return &Ingester{Store: st, Cfg: cfg}
}

// Params describes one ingest.
type Params struct {
	Codebase  store.Codebase
	Body      []byte
	Ref       string
	StartedAt *time.Time
	Trigger   string // ci | manual | schedule
	TokenID   *int64 // CI token
	JobScanID *int64 // runner job row to complete
}

// Result is the outcome of an ingest.
type Result struct {
	Duplicate       bool
	Scan            store.Scan
	ScanSummary     store.Counts
	CodebaseSummary store.Counts
	CodebaseScanned bool
	LowConfidence   int
	RedactedCount   int
	Superseded      bool
	IsLatestScan    bool // duplicate only: the referenced scan is the latest one
	// VulnerabilityFindings counts the CVE findings of the scan; VulnerabilityIgnored counts results
	// whose properties.vulnerability was unusable and were stored as plain findings.
	VulnerabilityFindings int
	VulnerabilityIgnored  int
}

type finding struct {
	ruleID         string
	severity       string
	lowConf        bool
	message        string
	kind           string
	path, url      string
	sl, sc, el, ec *int
	snippet        string
	redacted       bool
	fingerprint    string
	occurrence     int
	cwe            []string
	vuln           []byte   // validated vulnerability JSON, nil for code findings
	vulnIDs        []string // advisory ids of vuln
}

func clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.ReplaceAll(s, "\x00", "")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

func invalid(code string, idx int, msg string) *apierr.Error {
	e := apierr.New(http.StatusUnprocessableEntity, code, msg)
	if idx >= 0 {
		e = e.WithDetails(map[string]any{"result_index": idx})
	}
	return e
}

// Run performs the ingest.
func (in *Ingester) Run(ctx context.Context, p Params) (Result, error) {
	cb := p.Codebase
	sum := sha256.Sum256(p.Body)
	digest := hex.EncodeToString(sum[:])

	// 4. Duplicate detection (fast path, no locks).
	if dup, ok, err := in.findDuplicate(ctx, in.Store.Pool, cb.ID, digest, p.Ref); err != nil {
		return Result{}, err
	} else if ok {
		return in.duplicateResult(ctx, p, dup)
	}

	// 5-7. Parse, validate, map.
	run, err := sarif.Parse(p.Body, sarif.Options{MaxResults: in.Cfg.MaxResults})
	if err != nil {
		var se *sarif.Error
		if errors.As(err, &se) {
			return Result{}, invalid(se.Code, se.Index, se.Message)
		}
		return Result{}, err
	}
	switch {
	case run.ToolName == sarif.EngineSAST && cb.TargetType != "repo",
		run.ToolName == sarif.EngineDAST && cb.TargetType != "url":
		return Result{}, invalid("engine_target_mismatch", -1,
			fmt.Sprintf("%s results cannot be ingested into a %q codebase.", run.ToolName, cb.TargetType))
	}
	partial := run.Kind == sarif.Partial
	if partial && p.Trigger != "ci" {
		return Result{}, invalid("invalid_sarif", -1, "A partial scan can only come from CI ingest.")
	}
	if partial && run.ToolName != sarif.EngineSAST {
		return Result{}, invalid("invalid_sarif", -1, "Only sdrscan-sast results can be partial.")
	}
	if partial && cb.BaseScanID == nil {
		return Result{}, apierr.Conflict("baseline_required", "A partial scan needs a successful full scan of this codebase first.")
	}
	findings, scanned, redactedN, err := in.mapResults(run, cb)
	if err != nil {
		return Result{}, err
	}

	// 9. Transaction.
	var res Result
	res, err = in.write(ctx, p, run, digest, partial, findings, scanned, redactedN)
	if err == nil && !res.Duplicate {
		for _, f := range findings {
			if f.vuln != nil {
				res.VulnerabilityFindings++
			}
		}
		for _, r := range run.Results {
			if r.VulnerabilityIgnored {
				res.VulnerabilityIgnored++
			}
		}
	}
	return res, err
}

func (in *Ingester) mapResults(run *sarif.Run, cb store.Codebase) (out []finding, scanned []string, redacted int, err error) {
	secretRule := map[string]bool{}
	for _, r := range in.Cfg.SecretRules {
		secretRule[r] = true
	}
	scannedSet := map[string]bool{}
	if run.Kind == sarif.Partial {
		for _, f := range run.ScannedFiles {
			np, perr := sarif.NormalizePath(f)
			if perr != nil {
				return nil, nil, 0, invalid("invalid_sarif", -1, "scannedFiles: "+perr.Error())
			}
			if !scannedSet[np] {
				scannedSet[np] = true
				scanned = append(scanned, np)
			}
		}
	}
	targetHost := ""
	if cb.TargetType == "url" && cb.BaseURL != nil {
		targetHost, _ = netguard.HostOf(*cb.BaseURL)
	}
	out = make([]finding, 0, len(run.Results))
	for _, r := range run.Results {
		f := finding{
			ruleID:      truncate(clean(r.RuleID), 200),
			severity:    r.Severity,
			lowConf:     r.LowConfidence,
			fingerprint: r.Fingerprint,
		}
		if cb.TargetType == "url" {
			f.kind = "url"
			u, uerr := sarif.NormalizeURL(r.URI)
			if uerr != nil {
				return nil, nil, 0, invalid("location_outside_target", r.Index, fmt.Sprintf("Result %d: %v.", r.Index, uerr))
			}
			h, _ := netguard.HostOf(u)
			if targetHost == "" || h != targetHost {
				return nil, nil, 0, invalid("location_outside_target", r.Index,
					fmt.Sprintf("Result %d: URL host %q is outside the target host %q.", r.Index, h, targetHost))
			}
			f.url = clean(u)
		} else {
			f.kind = "file"
			np, perr := sarif.NormalizePath(r.URI)
			if perr != nil {
				return nil, nil, 0, invalid("invalid_sarif", r.Index, fmt.Sprintf("Result %d: %v.", r.Index, perr))
			}
			if run.Kind == sarif.Partial && !scannedSet[np] {
				return nil, nil, 0, invalid("finding_outside_scanned_files", r.Index,
					fmt.Sprintf("Result %d: path %q is not listed in scannedFiles.", r.Index, np))
			}
			f.path = clean(np)
		}
		if rg := r.Region; rg != nil && cb.TargetType != "url" {
			f.sl, f.sc, f.el, f.ec = posInt(rg.StartLine), posInt(rg.StartColumn), posInt(rg.EndLine), posInt(rg.EndColumn)
		}
		snippet := ""
		if r.Region != nil {
			snippet = r.Region.Snippet
		}
		if cb.TargetType == "url" && r.Evidence != "" {
			if snippet != "" {
				snippet += "\n"
			}
			snippet += r.Evidence
		}
		rule := run.Rules[r.RuleID]
		isSecret := secretRule[r.RuleID] || (rule != nil && rule.Secret)
		if rule != nil {
			f.cwe = rule.CWE
		}
		sn := redact.Snippet(clean(snippet), isSecret)
		msg := redact.Message(clean(r.Message), isSecret)
		f.snippet = truncate(sn.Text, MaxSnippetBytes)
		f.message = truncate(msg.Text, MaxMessageBytes)
		f.redacted = sn.Changed || msg.Changed
		// The CVE object is structured data from the engine: it is validated field by field
		// (sarif.ParseVulnerability) and is not subject to snippet redaction.
		if r.Vulnerability != nil {
			if b, merr := json.Marshal(r.Vulnerability); merr == nil && len(r.Vulnerability.IDs) > 0 {
				f.vuln, f.vulnIDs = b, r.Vulnerability.IDs
				// Product decision: a CVE finding is never hidden as "low confidence" (that rule is for
				// ambiguous SAST taint warnings). Its own confidence (vulnerability.confidence, e.g. a
				// version-based DAST match) is stored and shown, but does not filter or exclude it from
				// totals, summaries or compare.
				f.lowConf = false
			}
		}
		if f.redacted {
			redacted++
		}
		out = append(out, f)
	}
	// Occurrence numbering: order by (location, line, column), stable.
	idx := make([]int, len(out))
	for i := range idx {
		idx[i] = i
	}
	loc := func(i int) string {
		if out[i].kind == "url" {
			return out[i].url
		}
		return out[i].path
	}
	num := func(p *int) int {
		if p == nil {
			return 0
		}
		return *p
	}
	sort.SliceStable(idx, func(a, b int) bool {
		i, j := idx[a], idx[b]
		if li, lj := loc(i), loc(j); li != lj {
			return li < lj
		}
		if x, y := num(out[i].sl), num(out[j].sl); x != y {
			return x < y
		}
		return num(out[i].sc) < num(out[j].sc)
	})
	seen := map[string]int{}
	for _, i := range idx {
		seen[out[i].fingerprint]++
		out[i].occurrence = seen[out[i].fingerprint]
	}
	return out, scanned, redacted, nil
}

func posInt(v int) *int {
	if v <= 0 {
		return nil
	}
	return &v
}

// findDuplicate looks up a prior ingest with the same hash (and ref when given).
func (in *Ingester) findDuplicate(ctx context.Context, q store.DBTX, cbID int64, digest, ref string) (int64, bool, error) {
	var id int64
	err := q.QueryRow(ctx, `SELECT scan_id FROM ingest_digest WHERE codebase_id = $1 AND sarif_sha256 = $2
		AND ($3 = '' OR ref = $3) ORDER BY created_at LIMIT 1`, cbID, digest, ref).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

func (in *Ingester) duplicateResult(ctx context.Context, p Params, dupScanID int64) (Result, error) {
	existing, err := in.Store.GetScan(ctx, dupScanID)
	if err != nil {
		return Result{}, err
	}
	existing.LogTail = nil
	var latest *int64
	if err := in.Store.Pool.QueryRow(ctx, `SELECT latest_scan_id FROM codebases WHERE id = $1`, p.Codebase.ID).Scan(&latest); err != nil {
		return Result{}, err
	}
	res := Result{Duplicate: true, Scan: existing, ScanSummary: existing.Counts(), LowConfidence: existing.NLowConfidence,
		IsLatestScan: latest != nil && *latest == existing.ID}
	if p.JobScanID != nil {
		// Runner job with an identical result: finish the job without a new scan.
		tag, err := in.Store.Pool.Exec(ctx, `UPDATE scans SET status = 'succeeded', finished_at = now(), duplicate_of_scan_id = $2,
			lease_expires_at = NULL WHERE id = $1 AND status = 'running' AND NOT cancel_requested`, *p.JobScanID, dupScanID)
		if err != nil {
			return Result{}, err
		}
		if tag.RowsAffected() == 0 {
			return Result{}, ErrCancelled
		}
	}
	return res, nil
}

func isLockTimeout(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "55P03"
}

func (in *Ingester) write(ctx context.Context, p Params, run *sarif.Run, digest string, partial bool,
	findings []finding, scanned []string, redactedN int) (Result, error) {

	cb := p.Codebase
	tx, err := in.Store.Pool.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	// 9.1 Serialise per codebase.
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL lock_timeout = '%dms'`, in.Cfg.LockTimeout.Milliseconds())); err != nil {
		return Result{}, err
	}
	var baseScanID *int64
	if err := tx.QueryRow(ctx, `SELECT base_scan_id FROM codebases WHERE id = $1 FOR UPDATE`, cb.ID).Scan(&baseScanID); err != nil {
		if isLockTimeout(err) {
			return Result{}, apierr.New(http.StatusServiceUnavailable, "busy", "The codebase is busy with another ingest; retry shortly.")
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, apierr.NotFound("Codebase")
		}
		return Result{}, err
	}
	if partial && baseScanID == nil {
		return Result{}, apierr.Conflict("baseline_required", "A partial scan needs a successful full scan of this codebase first.")
	}
	// Re-check duplicates under the lock (identical concurrent ingests).
	if dup, ok, err := in.findDuplicate(ctx, tx, cb.ID, digest, p.Ref); err != nil {
		return Result{}, err
	} else if ok {
		_ = tx.Rollback(ctx)
		return in.duplicateResult(ctx, p, dup)
	}

	// 9.2 The scan row.
	scanType := "sast"
	if cb.TargetType == "url" {
		scanType = "dast"
	}
	coverage := "full"
	if partial {
		coverage = "partial"
	}
	var scanID int64
	var startedAt time.Time
	var fileCount *int
	if partial {
		n := len(scanned)
		fileCount = &n
	}
	if p.JobScanID != nil {
		scanID = *p.JobScanID
		var status string
		var cancel bool
		if err := tx.QueryRow(ctx, `SELECT status, cancel_requested, started_at FROM scans WHERE id = $1 FOR UPDATE`, scanID).
			Scan(&status, &cancel, &startedAt); err != nil {
			return Result{}, err
		}
		if status != "running" || cancel {
			return Result{}, ErrCancelled
		}
		if _, err := tx.Exec(ctx, `UPDATE scans SET status = 'succeeded', finished_at = now(), engine = $2, engine_version = $3,
			ref = $4, coverage = 'full', lease_expires_at = NULL WHERE id = $1`, scanID, run.ToolName, run.ToolVersion, p.Ref); err != nil {
			return Result{}, err
		}
	} else {
		startedAt = time.Now().UTC()
		if p.StartedAt != nil {
			startedAt = p.StartedAt.UTC()
		}
		if err := tx.QueryRow(ctx, `INSERT INTO scans (codebase_id, type, coverage, trigger, status, ingest_token_id, queued_at,
				started_at, finished_at, engine, engine_version, ref, scanned_file_count)
			VALUES ($1, $2, $3, 'ci', 'succeeded', $4, now(), $5, now(), $6, $7, $8, $9) RETURNING id`,
			cb.ID, scanType, coverage, p.TokenID, startedAt, run.ToolName, run.ToolVersion, p.Ref, fileCount).Scan(&scanID); err != nil {
			return Result{}, err
		}
	}
	tag, err := tx.Exec(ctx, `INSERT INTO ingest_digest (codebase_id, sarif_sha256, ref, scan_id) VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`, cb.ID, digest, p.Ref, scanID)
	if err != nil {
		return Result{}, err
	}
	if tag.RowsAffected() == 0 {
		// Identical (hash, ref) already recorded: treat as duplicate.
		if dup, ok, derr := in.findDuplicate(ctx, tx, cb.ID, digest, p.Ref); derr == nil && ok {
			_ = tx.Rollback(ctx)
			return in.duplicateResult(ctx, p, dup)
		}
	}

	// 9.3 scan_files.
	if partial {
		rows := make([][]any, len(scanned))
		for i, f := range scanned {
			rows[i] = []any{scanID, clean(f)}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_files"}, []string{"scan_id", "path"}, pgx.CopyFromRows(rows)); err != nil {
			return Result{}, err
		}
	}

	// 9.4 Is this the latest successful scan?
	var superseded bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scans WHERE codebase_id = $1 AND status = 'succeeded'
		AND duplicate_of_scan_id IS NULL AND id <> $2 AND (started_at, id) > ($3, $2))`, cb.ID, scanID, startedAt).Scan(&superseded); err != nil {
		return Result{}, err
	}
	isLatest := !superseded

	// 9.5 Replace the current state.
	if isLatest {
		if partial {
			_, err = tx.Exec(ctx, `UPDATE findings SET is_current = false WHERE codebase_id = $1 AND is_current
				AND path IN (SELECT path FROM scan_files WHERE scan_id = $2)`, cb.ID, scanID)
		} else {
			_, err = tx.Exec(ctx, `UPDATE findings SET is_current = false WHERE codebase_id = $1 AND is_current`, cb.ID)
		}
		if err != nil {
			return Result{}, err
		}
	}

	// 9.6 Findings.
	cols := []string{"scan_id", "codebase_id", "is_current", "rule_id", "severity", "severity_rank", "confidence", "message",
		"location_kind", "path", "url", "start_line", "start_column", "end_line", "end_column", "snippet", "redacted",
		"fingerprint", "occurrence", "cwe", "vulnerability", "vuln_ids"}
	frows := make([][]any, 0, len(findings))
	for _, f := range findings {
		conf := "normal"
		if f.lowConf {
			conf = "low"
		}
		var path, url any
		if f.kind == "file" {
			path = f.path
		} else {
			url = f.url
		}
		cwe := f.cwe
		if cwe == nil {
			cwe = []string{}
		}
		var vuln any
		vids := []string{}
		if f.vuln != nil {
			vuln, vids = json.RawMessage(f.vuln), f.vulnIDs
		}
		frows = append(frows, []any{scanID, cb.ID, isLatest, f.ruleID, f.severity, int16(sarif.Rank(f.severity)), conf, f.message,
			f.kind, path, url, f.sl, f.sc, f.el, f.ec, f.snippet, f.redacted, f.fingerprint, f.occurrence, cwe, vuln, vids})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"findings"}, cols, pgx.CopyFromRows(frows)); err != nil {
		return Result{}, err
	}

	// 9.7 Summaries.
	var sc store.Counts
	var low int
	if err := tx.QueryRow(ctx, summarySQL("scan_id = $1"), scanID).Scan(&sc.Critical, &sc.High, &sc.Medium, &sc.Low, &sc.Info, &low); err != nil {
		return Result{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE scans SET n_critical = $2, n_high = $3, n_medium = $4, n_low = $5, n_info = $6, n_low_confidence = $7
		WHERE id = $1`, scanID, sc.Critical, sc.High, sc.Medium, sc.Low, sc.Info, low); err != nil {
		return Result{}, err
	}
	cbCounts := sc
	scanned2 := baseScanID != nil
	if isLatest {
		var cc store.Counts
		var clow int
		if err := tx.QueryRow(ctx, summarySQL("codebase_id = $1 AND is_current"), cb.ID).Scan(&cc.Critical, &cc.High, &cc.Medium, &cc.Low, &cc.Info, &clow); err != nil {
			return Result{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE codebases SET n_critical = $2, n_high = $3, n_medium = $4, n_low = $5, n_info = $6,
			n_low_confidence = $7, latest_scan_id = $8, base_scan_id = CASE WHEN $9 THEN $8 ELSE base_scan_id END, updated_at = now()
			WHERE id = $1`, cb.ID, cc.Critical, cc.High, cc.Medium, cc.Low, cc.Info, clow, scanID, !partial); err != nil {
			return Result{}, err
		}
		cbCounts, scanned2 = cc, true
	} else {
		cbCounts = store.Counts{}
		var c store.Codebase
		c, err = store.CollectCodebaseCounts(ctx, tx, cb.ID)
		if err != nil {
			return Result{}, err
		}
		cbCounts, scanned2 = c.Counts(), c.Scanned()
	}
	if err := tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	scan, err := in.Store.GetScan(ctx, scanID)
	if err != nil {
		return Result{}, err
	}
	scan.LogTail = nil
	return Result{Scan: scan, ScanSummary: sc, CodebaseSummary: cbCounts, CodebaseScanned: scanned2,
		LowConfidence: low, RedactedCount: redactedN, Superseded: superseded}, nil
}

func summarySQL(where string) string {
	return `SELECT count(*) FILTER (WHERE severity = 'critical' AND confidence = 'normal'),
		count(*) FILTER (WHERE severity = 'high' AND confidence = 'normal'),
		count(*) FILTER (WHERE severity = 'medium' AND confidence = 'normal'),
		count(*) FILTER (WHERE severity = 'low' AND confidence = 'normal'),
		count(*) FILTER (WHERE severity = 'info' AND confidence = 'normal'),
		count(*) FILTER (WHERE confidence = 'low')
		FROM findings WHERE ` + where
}

// Ingest is an alias of Run kept for readability at call sites.
func (in *Ingester) Ingest(ctx context.Context, p Params) (Result, error) { return in.Run(ctx, p) }
