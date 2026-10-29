package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Finding is a row of findings.
type Finding struct {
	ID           int64    `db:"id"`
	ScanID       int64    `db:"scan_id"`
	CodebaseID   int64    `db:"codebase_id"`
	IsCurrent    bool     `db:"is_current"`
	RuleID       string   `db:"rule_id"`
	Severity     string   `db:"severity"`
	SeverityRank int16    `db:"severity_rank"`
	Confidence   string   `db:"confidence"`
	Message      string   `db:"message"`
	LocationKind string   `db:"location_kind"`
	Path         *string  `db:"path"`
	URL          *string  `db:"url"`
	StartLine    *int     `db:"start_line"`
	StartColumn  *int     `db:"start_column"`
	EndLine      *int     `db:"end_line"`
	EndColumn    *int     `db:"end_column"`
	Snippet      string   `db:"snippet"`
	Redacted     bool     `db:"redacted"`
	Fingerprint  string   `db:"fingerprint"`
	Occurrence   int      `db:"occurrence"`
	CWE          []string `db:"cwe"`
	// Vulnerability is the validated CVE object (nil for code findings); VulnIDs are its advisory ids.
	Vulnerability json.RawMessage `db:"vulnerability"`
	VulnIDs       []string        `db:"vuln_ids"`
}

// Kind is "vulnerability" for CVE findings and "code" for everything else.
func (f Finding) Kind() string {
	if len(f.Vulnerability) > 0 {
		return "vulnerability"
	}
	return "code"
}

const findingCols = `id, scan_id, codebase_id, is_current, rule_id, severity, severity_rank, confidence, message,
	location_kind, path, url, start_line, start_column, end_line, end_column, snippet, redacted, fingerprint, occurrence, cwe,
	vulnerability, vuln_ids`

// GetFinding loads one finding.
func (s *Store) GetFinding(ctx context.Context, id int64) (Finding, error) {
	return collectOne[Finding](s.Pool.Query(ctx, `SELECT `+findingCols+` FROM findings WHERE id = $1`, id))
}

// FindingFilter selects findings. Exactly one of ScanID (a single scan) or
// CodebaseID (current state) is used: ScanID wins when non-zero.
type FindingFilter struct {
	CodebaseID int64
	ScanID     int64
	Severities []string
	Rule       string
	PathPrefix string
	Q          string
	IncludeLow bool
	// Kind is "", "code" or "vulnerability". CVE is a normalised advisory id matched against all ids of a finding.
	Kind string
	CVE  string
	// VulnConfidence ("high"/"low") and Scope ("runtime"/"dev") filter on the CVE object; code
	// findings never match them.
	VulnConfidence string
	Scope          string
}

// LikeEscape escapes %, _ and \ for LIKE/ILIKE.
func LikeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// Names of the filters that facet queries leave out.
const (
	skipSeverity = "severity"
	skipRule     = "rule"
	skipKind     = "kind"
	skipCVE      = "cve"
	skipVConf    = "vconf"
	skipScope    = "scope"
)

func (f FindingFilter) where(skip ...string) (string, []any) {
	skipped := func(n string) bool {
		for _, s := range skip {
			if s == n {
				return true
			}
		}
		return false
	}
	var conds []string
	var args []any
	add := func(cond string, a any) {
		args = append(args, a)
		conds = append(conds, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if f.ScanID != 0 {
		add("scan_id = ?", f.ScanID)
	} else {
		add("codebase_id = ?", f.CodebaseID)
		conds = append(conds, "is_current")
	}
	if !f.IncludeLow {
		conds = append(conds, "confidence = 'normal'")
	}
	if !skipped(skipSeverity) && len(f.Severities) > 0 {
		add("severity = ANY(?)", f.Severities)
	}
	if !skipped(skipRule) && f.Rule != "" {
		add("rule_id = ?", f.Rule)
	}
	if !skipped(skipKind) {
		switch f.Kind {
		case "vulnerability":
			conds = append(conds, "vulnerability IS NOT NULL")
		case "code":
			conds = append(conds, "vulnerability IS NULL")
		}
	}
	if !skipped(skipCVE) && f.CVE != "" {
		add("vuln_ids @> ARRAY[?]::text[]", f.CVE)
	}
	if !skipped(skipVConf) && f.VulnConfidence != "" {
		add("vulnerability->>'confidence' = ?", f.VulnConfidence)
	}
	if !skipped(skipScope) && f.Scope != "" {
		add("vulnerability->>'scope' = ?", f.Scope)
	}
	if f.PathPrefix != "" {
		add(`COALESCE(path, url) LIKE ? ESCAPE '\'`, LikeEscape(f.PathPrefix)+"%")
	}
	if f.Q != "" {
		// Location, message, advisory ids and the affected package / product.
		add(`(COALESCE(path, url) ILIKE ? ESCAPE '\' OR message ILIKE ? ESCAPE '\'
			OR EXISTS (SELECT 1 FROM unnest(vuln_ids) AS qv(id) WHERE qv.id ILIKE ? ESCAPE '\')
			OR COALESCE(vulnerability->'package'->>'name', vulnerability->'package'->>'product', '') ILIKE ? ESCAPE '\')`, "%"+LikeEscape(f.Q)+"%")
	}
	return strings.Join(conds, " AND "), args
}

// ListFindings returns a page of findings, severity descending then location.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter, p Page) ([]Finding, int, error) {
	w, args := f.where()
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.Size, p.Offset())
	items, err := collectAll[Finding](s.Pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM findings WHERE %s
		ORDER BY severity_rank DESC, COALESCE(path, url), start_line NULLS FIRST, id LIMIT $%d OFFSET $%d`,
		findingCols, w, len(args)-1, len(args)), args...))
	return items, total, err
}

// RuleCount is a facet entry.
type RuleCount struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

// KindCounts splits the findings into CVE findings and code findings.
type KindCounts struct {
	Code          int `json:"code"`
	Vulnerability int `json:"vulnerability"`
}

// Facets holds the counts per severity, rule, kind and CVE for the active filter.
type Facets struct {
	Severity map[string]int `json:"severity"`
	Rule     []RuleCount    `json:"rule"`
	Kind     KindCounts     `json:"kind"`
	// CVE lists the CVE ids (not GHSA / OSV aliases), most frequent first, at most 100.
	CVE []RuleCount `json:"cve"`
	// VulnerablePackages is the number of distinct package@version (or product@version) among
	// the CVE findings, ignoring the kind and cve filters.
	VulnerablePackages int `json:"vulnerable_packages"`
	// Confidence and Scope count the CVE findings by vulnerability.confidence (high/low) and
	// vulnerability.scope (runtime/dev), each ignoring its own filter.
	Confidence map[string]int `json:"confidence"`
	Scope      map[string]int `json:"scope"`
}

// FindingFacets counts findings per severity (ignoring the severity filter),
// per rule (ignoring the rule filter), per kind (ignoring the kind filter), per
// CVE id (ignoring the cve filter) and the distinct vulnerable packages.
func (s *Store) FindingFacets(ctx context.Context, f FindingFilter) (Facets, error) {
	fc := Facets{Severity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, Rule: []RuleCount{}, CVE: []RuleCount{},
		Confidence: map[string]int{"high": 0, "low": 0}, Scope: map[string]int{"runtime": 0, "dev": 0}}
	w, args := f.where(skipSeverity)
	rows, err := s.Pool.Query(ctx, `SELECT severity, count(*) FROM findings WHERE `+w+` GROUP BY severity`, args...)
	if err != nil {
		return fc, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return fc, err
		}
		fc.Severity[sev] = n
	}
	rows.Close()
	w, args = f.where(skipRule)
	rows, err = s.Pool.Query(ctx, `SELECT rule_id, count(*) FROM findings WHERE `+w+` GROUP BY rule_id ORDER BY count(*) DESC, rule_id LIMIT 500`, args...)
	if err != nil {
		return fc, err
	}
	defer rows.Close()
	for rows.Next() {
		var rc RuleCount
		if err := rows.Scan(&rc.ID, &rc.Count); err != nil {
			return fc, err
		}
		fc.Rule = append(fc.Rule, rc)
	}
	if err := rows.Err(); err != nil {
		return fc, err
	}
	rows.Close()
	// The selected rule stays listed even when its count is 0.
	if f.Rule != "" {
		fc.Rule = withSelected(fc.Rule, f.Rule)
	}

	w, args = f.where(skipKind)
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE vulnerability IS NULL), count(*) FILTER (WHERE vulnerability IS NOT NULL)
		FROM findings WHERE `+w, args...).Scan(&fc.Kind.Code, &fc.Kind.Vulnerability); err != nil {
		return fc, err
	}

	w, args = f.where(skipCVE)
	crows, err := s.Pool.Query(ctx, `SELECT v.id, count(*) FROM findings, unnest(vuln_ids) AS v(id)
		WHERE `+w+` AND vulnerability IS NOT NULL AND v.id LIKE 'CVE-%' GROUP BY v.id ORDER BY count(*) DESC, v.id LIMIT 100`, args...)
	if err != nil {
		return fc, err
	}
	defer crows.Close()
	for crows.Next() {
		var rc RuleCount
		if err := crows.Scan(&rc.ID, &rc.Count); err != nil {
			return fc, err
		}
		fc.CVE = append(fc.CVE, rc)
	}
	if err := crows.Err(); err != nil {
		return fc, err
	}
	crows.Close()
	if f.CVE != "" && strings.HasPrefix(f.CVE, "CVE-") {
		fc.CVE = withSelected(fc.CVE, f.CVE)
	}

	w, args = f.where(skipKind, skipCVE)
	if err := s.Pool.QueryRow(ctx, `SELECT count(DISTINCT concat_ws('|', vulnerability->'package'->>'ecosystem',
			COALESCE(vulnerability->'package'->>'name', vulnerability->'package'->>'product'), vulnerability->'package'->>'version'))
		FROM findings WHERE `+w+` AND vulnerability IS NOT NULL AND jsonb_typeof(vulnerability->'package') = 'object'`, args...).Scan(&fc.VulnerablePackages); err != nil {
		return fc, err
	}
	for _, fv := range []struct {
		key, skip string
		dst       map[string]int
	}{{"confidence", skipVConf, fc.Confidence}, {"scope", skipScope, fc.Scope}} {
		w, args = f.where(fv.skip)
		vrows, err := s.Pool.Query(ctx, `SELECT vulnerability->>'`+fv.key+`', count(*) FROM findings WHERE `+w+`
			AND vulnerability IS NOT NULL GROUP BY 1`, args...)
		if err != nil {
			return fc, err
		}
		for vrows.Next() {
			var k *string
			var n int
			if err := vrows.Scan(&k, &n); err != nil {
				vrows.Close()
				return fc, err
			}
			if k != nil {
				if _, known := fv.dst[*k]; known {
					fv.dst[*k] = n
				}
			}
		}
		vrows.Close()
		if err := vrows.Err(); err != nil {
			return fc, err
		}
	}
	return fc, nil
}

// withSelected keeps the selected facet value listed (count 0 when absent), in count order.
func withSelected(list []RuleCount, id string) []RuleCount {
	for _, rc := range list {
		if rc.ID == id {
			return list
		}
	}
	list = append(list, RuleCount{ID: id, Count: 0})
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].ID < list[j].ID
	})
	return list
}

// FileRow is one row of the per-file (or per-URL) view.
type FileRow struct {
	Location string
	Total    int
	TopRank  int
	Counts   Counts
}

// ListFiles groups findings by path (or URL for DAST) for a codebase's current
// state, or for one scan when scanID is non-zero.
func (s *Store) ListFiles(ctx context.Context, codebaseID, scanID int64, p Page) ([]FileRow, int, error) {
	cond := "codebase_id = $1 AND is_current AND confidence = 'normal'"
	id := codebaseID
	if scanID != 0 {
		cond, id = "scan_id = $1 AND confidence = 'normal'", scanID
	}
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(DISTINCT COALESCE(path, url)) FROM findings WHERE `+cond, id).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT COALESCE(path, url) AS location, count(*) AS total, max(severity_rank) AS top_rank,
			count(*) FILTER (WHERE severity = 'critical'), count(*) FILTER (WHERE severity = 'high'),
			count(*) FILTER (WHERE severity = 'medium'), count(*) FILTER (WHERE severity = 'low'),
			count(*) FILTER (WHERE severity = 'info')
		FROM findings WHERE `+cond+` GROUP BY COALESCE(path, url)
		ORDER BY top_rank DESC, total DESC, location LIMIT $2 OFFSET $3`, id, p.Size, p.Offset())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []FileRow
	for rows.Next() {
		var r FileRow
		if err := rows.Scan(&r.Location, &r.Total, &r.TopRank, &r.Counts.Critical, &r.Counts.High, &r.Counts.Medium, &r.Counts.Low, &r.Counts.Info); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ----- compare -----

const compareCTE = `WITH scope AS (
  SELECT path FROM scan_files WHERE scan_id = ANY($3::bigint[])
  GROUP BY path HAVING COUNT(*) = cardinality($3::bigint[])
),
b AS (SELECT * FROM findings WHERE scan_id = $1 AND confidence = 'normal'
      AND (cardinality($3::bigint[]) = 0 OR path IN (SELECT path FROM scope))),
h AS (SELECT * FROM findings WHERE scan_id = $2 AND confidence = 'normal'
      AND (cardinality($3::bigint[]) = 0 OR path IN (SELECT path FROM scope))),
r AS (
  SELECT 'new' AS status, h.id AS finding_id FROM h
   WHERE NOT EXISTS (SELECT 1 FROM b WHERE b.fingerprint = h.fingerprint AND b.occurrence = h.occurrence)
  UNION ALL
  SELECT 'unchanged', h.id FROM h
   WHERE EXISTS (SELECT 1 FROM b WHERE b.fingerprint = h.fingerprint AND b.occurrence = h.occurrence)
  UNION ALL
  SELECT 'fixed', b.id FROM b
   WHERE NOT EXISTS (SELECT 1 FROM h WHERE h.fingerprint = b.fingerprint AND h.occurrence = b.occurrence)
)`

// CompareResult is the outcome of comparing two scans.
type CompareResult struct {
	New, Unchanged, Fixed int
	ScopeFiles            int
	Items                 []Finding
	Total                 int
}

// Compare compares base (0 = none) with head restricted to partialScanIDs scope.
func (s *Store) Compare(ctx context.Context, baseID, headID int64, partialScanIDs []int64, status string, p Page) (CompareResult, error) {
	var cr CompareResult
	if partialScanIDs == nil {
		partialScanIDs = []int64{}
	}
	rows, err := s.Pool.Query(ctx, compareCTE+` SELECT status, count(*) FROM r GROUP BY status`, baseID, headID, partialScanIDs)
	if err != nil {
		return cr, err
	}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			rows.Close()
			return cr, err
		}
		switch st {
		case "new":
			cr.New = n
		case "unchanged":
			cr.Unchanged = n
		case "fixed":
			cr.Fixed = n
		}
	}
	rows.Close()
	switch status {
	case "new":
		cr.Total = cr.New
	case "unchanged":
		cr.Total = cr.Unchanged
	case "fixed":
		cr.Total = cr.Fixed
	}
	if len(partialScanIDs) > 0 {
		if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT path FROM scan_files WHERE scan_id = ANY($1::bigint[])
			GROUP BY path HAVING COUNT(*) = cardinality($1::bigint[])) x`, partialScanIDs).Scan(&cr.ScopeFiles); err != nil {
			return cr, err
		}
	}
	cr.Items, err = collectAll[Finding](s.Pool.Query(ctx, compareCTE+` SELECT `+prefixCols("f", findingCols)+` FROM r JOIN findings f ON f.id = r.finding_id
		WHERE r.status = $4 ORDER BY f.severity_rank DESC, COALESCE(f.path, f.url), f.start_line NULLS FIRST, f.id LIMIT $5 OFFSET $6`,
		baseID, headID, partialScanIDs, status, p.Size, p.Offset()))
	return cr, err
}

func prefixCols(prefix, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = prefix + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

// SuccessfulScans returns the most recent succeeded, non-duplicate scans of a
// codebase (newest first by started_at, id).
func (s *Store) SuccessfulScans(ctx context.Context, codebaseID int64, limit int) ([]Scan, error) {
	items, err := collectAll[Scan](s.Pool.Query(ctx, `SELECT `+scanCols+` FROM scans WHERE codebase_id = $1 AND status = 'succeeded'
		AND duplicate_of_scan_id IS NULL ORDER BY started_at DESC, id DESC LIMIT $2`, codebaseID, limit))
	for i := range items {
		items[i].LogTail = nil
	}
	return items, err
}
