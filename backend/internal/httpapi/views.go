package httpapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// countsView is {critical, high, medium, low, info, highest_severity}.
func countsView(c store.Counts) map[string]any {
	m := countsOnly(c)
	m["highest_severity"] = nil
	if h := c.Highest(); h != "" {
		m["highest_severity"] = h
	}
	return m
}

// countsOnly is {critical, high, medium, low, info}.
func countsOnly(c store.Counts) map[string]any {
	return map[string]any{"critical": c.Critical, "high": c.High, "medium": c.Medium, "low": c.Low, "info": c.Info}
}

func highestOf(c store.Counts) any {
	if h := c.Highest(); h != "" {
		return h
	}
	return nil
}

func userView(u store.User) map[string]any {
	return map[string]any{"id": u.ID, "username": u.Username, "role": u.Role, "can_run_dast": u.CanRunDAST}
}

func userAdminView(u store.User) map[string]any {
	m := userView(u)
	m["is_active"] = u.IsActive
	m["last_login_at"] = tsp(u.LastLoginAt)
	m["must_change_password"] = u.MustChangePassword
	m["created_at"] = ts(u.CreatedAt)
	return m
}

func scanBrief(s *store.Scan) any {
	if s == nil {
		return nil
	}
	return map[string]any{"id": s.ID, "type": s.Type, "coverage": s.Coverage, "trigger": s.Trigger, "status": s.Status,
		"started_at": tsp(s.StartedAt), "finished_at": tsp(s.FinishedAt), "ref": s.Ref}
}

// activeScanView is {id, type, status, trigger, queued_at, started_at}.
func activeScanView(s *store.Scan) any {
	if s == nil {
		return nil
	}
	return map[string]any{"id": s.ID, "type": s.Type, "status": s.Status, "trigger": s.Trigger,
		"queued_at": ts(s.QueuedAt), "started_at": tsp(s.StartedAt)}
}

// compareScanView is {id, started_at, coverage}.
func compareScanView(s *store.Scan) any {
	if s == nil {
		return nil
	}
	return map[string]any{"id": s.ID, "started_at": tsp(s.StartedAt), "coverage": s.Coverage}
}

func scanView(s store.Scan, withLog bool) map[string]any {
	m := map[string]any{
		"id": s.ID, "codebase_id": s.CodebaseID, "type": s.Type, "coverage": s.Coverage, "trigger": s.Trigger,
		"status": s.Status, "requested_by": s.RequestedBy, "queued_at": ts(s.QueuedAt), "started_at": tsp(s.StartedAt),
		"finished_at": tsp(s.FinishedAt), "engine": s.Engine, "engine_version": s.EngineVersion, "ref": s.Ref,
		"scanned_file_count": s.ScannedFileCount, "summary": countsView(s.Counts()), "low_confidence": s.NLowConfidence,
		"duplicate_of_scan_id": s.DuplicateOfScanID, "cancel_requested": s.CancelRequested, "error_code": s.ErrorCode,
		"active": s.Active, "active_timing": s.ActiveTiming,
	}
	if withLog {
		log := ""
		if s.LogTail != nil {
			log = *s.LogTail
		}
		m["log_tail"] = log
	}
	return m
}

func findingLocation(f store.Finding) map[string]any {
	if f.LocationKind == "url" {
		return map[string]any{"kind": "url", "url": f.URL}
	}
	loc := map[string]any{"kind": "file", "path": f.Path}
	if f.StartLine != nil {
		loc["start_line"], loc["start_column"], loc["end_line"], loc["end_column"] = f.StartLine, f.StartColumn, f.EndLine, f.EndColumn
	}
	return loc
}

// vulnerabilityOf is the stored CVE object, or nil (JSON null) for code findings.
func vulnerabilityOf(f store.Finding) any {
	if len(f.Vulnerability) == 0 {
		return nil
	}
	return json.RawMessage(f.Vulnerability)
}

// findingSummary is {id, rule_id, severity, confidence, message, location, redacted, kind, vulnerability}.
func findingSummary(f store.Finding) map[string]any {
	return map[string]any{"id": f.ID, "rule_id": f.RuleID, "severity": f.Severity, "confidence": f.Confidence,
		"message": f.Message, "location": findingLocation(f), "redacted": f.Redacted,
		"kind": f.Kind(), "vulnerability": vulnerabilityOf(f)}
}

// findingDetail is the full finding of GET /findings/{id}.
func findingDetail(f store.Finding) map[string]any {
	cwe := f.CWE
	if cwe == nil {
		cwe = []string{}
	}
	return map[string]any{
		"id": f.ID, "scan_id": f.ScanID, "codebase_id": f.CodebaseID, "is_current": f.IsCurrent, "rule_id": f.RuleID,
		"severity": f.Severity, "confidence": f.Confidence, "message": f.Message, "location": findingLocation(f),
		"snippet": f.Snippet, "redacted": f.Redacted, "cwe": cwe, "fingerprint": f.Fingerprint,
		"kind": f.Kind(), "vulnerability": vulnerabilityOf(f),
	}
}

func (s *Server) userRefs(ctx context.Context, ids ...*int64) map[int64]map[string]any {
	out := map[int64]map[string]any{}
	var want []int64
	for _, p := range ids {
		if p != nil {
			want = append(want, *p)
		}
	}
	if len(want) == 0 {
		return out
	}
	rows, err := s.Store.Pool.Query(ctx, `SELECT id, username FROM users WHERE id = ANY($1)`, want)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if rows.Scan(&id, &name) == nil {
			out[id] = map[string]any{"id": id, "username": name}
		}
	}
	return out
}

func refOf(m map[int64]map[string]any, id *int64) any {
	if id == nil {
		return nil
	}
	if v, ok := m[*id]; ok {
		return v
	}
	return map[string]any{"id": *id}
}

// ConfirmationStatement is the text an Admin accepts to confirm a DAST target.
func ConfirmationStatement(baseURL string) string {
	return "I confirm that I am authorized to run security scans against " + baseURL + "."
}

func projectRef(id int64, name string) map[string]any { return map[string]any{"id": id, "name": name} }

// codebaseView builds the GET /codebases/{id} DTO. Keys are never omitted:
// fields that do not apply to the target type are null.
func (s *Server) codebaseView(ctx context.Context, cb store.Codebase, st store.CodebaseState, projectName string) map[string]any {
	m := map[string]any{
		"id": cb.ID, "name": cb.Name, "target_type": cb.TargetType, "project": projectRef(cb.ProjectID, projectName),
		"language": cb.Language, "active_scan": activeScanView(st.ActiveScan),
		"latest_scan": scanBrief(st.LatestScan), "base_scan": scanBrief(st.BaseScan),
		"created_at": ts(cb.CreatedAt), "updated_at": ts(cb.UpdatedAt),
		"schedule": s.scheduleView(ctx, cb),
		"state":    nil, "summary": nil,
	}
	if cb.Scanned() {
		m["summary"] = countsView(cb.Counts())
		m["state"] = map[string]any{"base_scan_id": cb.BaseScanID, "partial_scans_since_base": st.PartialSinceBase}
	}
	if cb.TargetType == "repo" {
		// Repo targets carry the repo fields and null DAST fields; URL targets carry no repo fields.
		m["base_url"], m["dast_max_rps"], m["dast"], m["confirmation_statement"] = nil, nil, nil, nil
		m["dast_auth"], m["dast_crawl"], m["dast_active"] = nil, nil, nil
		m["repo_url"], m["branch"], m["subdirectory"] = cb.RepoURL, cb.Branch, cb.Subdirectory
		m["git_auth_kind"], m["git_username"] = cb.GitAuthKind, cb.GitUsername
		m["has_credential"] = len(cb.GitSecretEnc) > 0
		return m
	}
	refs := s.userRefs(ctx, cb.DastRegisteredBy, cb.DastConfirmedBy, cb.DastActiveAuthorizedBy)
	m["base_url"], m["dast_max_rps"] = cb.BaseURL, cb.DastMaxRPS
	m["dast_auth"], m["dast_crawl"] = dastAuthView(cb), dastCrawlView(cb)
	m["dast"] = map[string]any{"status": cb.DastStatus, "registered_by": refOf(refs, cb.DastRegisteredBy),
		"confirmed_by": refOf(refs, cb.DastConfirmedBy), "confirmed_at": tsp(cb.DastConfirmedAt)}
	m["dast_active"] = map[string]any{"authorized": cb.ActiveScanAuthorized(), "authorized_at": tsp(cb.DastActiveAuthorizedAt),
		"authorized_by": refOf(refs, cb.DastActiveAuthorizedBy), "openapi_spec_url": cb.DastOpenAPISpecURL}
	if cb.DastStatus != nil && *cb.DastStatus == "pending_confirmation" && cb.BaseURL != nil {
		m["confirmation_statement"] = ConfirmationStatement(*cb.BaseURL)
	}
	return m
}

// scheduleView is {cron, status, owner, suspended_reason, suspended_at,
// last_enqueued_at, next_run_at}, or nil when the codebase has no schedule.
func (s *Server) scheduleView(ctx context.Context, cb store.Codebase) any {
	if cb.ScheduleCron == nil {
		return nil
	}
	status := "active"
	if cb.ScheduleStatus != nil {
		status = *cb.ScheduleStatus
	}
	v := map[string]any{"cron": *cb.ScheduleCron, "status": status, "owner": nil, "suspended_reason": nil, "suspended_at": nil,
		"last_enqueued_at": tsp(cb.ScheduleLastEnqueuedAt), "next_run_at": nil}
	if cb.ScheduleOwnerID != nil {
		v["owner"] = refOf(s.userRefs(ctx, cb.ScheduleOwnerID), cb.ScheduleOwnerID)
	}
	if status == "suspended" {
		if cb.ScheduleSuspendedReason != nil {
			v["suspended_reason"] = *cb.ScheduleSuspendedReason
		}
		v["suspended_at"] = tsp(cb.ScheduleSuspendedAt)
		return v
	}
	if t, ok := scanner.NextRun(*cb.ScheduleCron, time.Now()); ok {
		v["next_run_at"] = ts(t)
	}
	return v
}
