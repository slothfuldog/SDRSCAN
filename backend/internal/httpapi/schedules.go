package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// listCodebases implements GET /codebases (all projects; URL targets are left
// out for callers without DAST access). Filters: project_id, target_type.
func (s *Server) listCodebases(w http.ResponseWriter, r *http.Request) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var projectID int64
	if v := r.URL.Query().Get("project_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			s.writeError(w, r, apierr.BadRequestField("project_id", "project_id must be a positive integer."))
			return
		}
		projectID = n
	}
	tt := r.URL.Query().Get("target_type")
	if tt != "" && tt != "repo" && tt != "url" {
		s.writeError(w, r, apierr.BadRequestField("target_type", "target_type must be 'repo' or 'url'."))
		return
	}
	rows, total, err := s.Store.ListAllCodebases(r.Context(), projectID, tt, false, canSeeURL(r), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	cbs := make([]store.Codebase, len(rows))
	for i, row := range rows {
		cbs[i] = row.Codebase
	}
	states, err := s.Store.States(r.Context(), cbs)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, s.codebaseView(r.Context(), row.Codebase, states[row.ID], row.ProjectName))
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

// listSchedules implements GET /schedules (?status=active|suspended): one row
// per schedule with nested codebase and project; only visible codebases.
func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != "active" && status != "suspended" {
		s.writeError(w, r, apierr.BadRequestField("status", "status must be 'active' or 'suspended'."))
		return
	}
	rows, total, err := s.Store.ListSchedules(r.Context(), status, canSeeURL(r), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(rows))
	for _, row := range rows {
		sv, _ := s.scheduleView(r.Context(), row.Codebase).(map[string]any)
		items = append(items, map[string]any{
			"codebase": map[string]any{"id": row.ID, "name": row.Name, "target_type": row.TargetType},
			"project":  projectRef(row.ProjectID, row.ProjectName),
			"cron":     sv["cron"], "status": sv["status"], "owner": sv["owner"], "suspended_reason": sv["suspended_reason"],
			"suspended_at": sv["suspended_at"], "last_enqueued_at": sv["last_enqueued_at"], "next_run_at": sv["next_run_at"],
		})
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

func scanTypeOf(cb store.Codebase) string {
	if cb.TargetType == "url" {
		return "dast"
	}
	return "sast"
}

// putSchedule sets the schedule; the caller becomes its owner and the schedule
// is active (a suspension of the previous owner is cleared).
func (s *Server) putSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var raw map[string]json.RawMessage
	if err := s.decode(w, r, &raw); err != nil {
		s.writeError(w, r, err)
		return
	}
	// Scheduled DAST scans are always passive in this version: active scanning is not supported for
	// schedules, and it is rejected rather than silently ignored.
	var fe apierr.FieldErrors
	for _, k := range []string{"active", "active_timing"} {
		if _, ok := raw[k]; ok {
			fe.Add(k, "Scheduled scans are always passive; "+k+" is not supported here.")
		}
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	var cron string
	if rm, ok := raw["cron"]; ok {
		if json.Unmarshal(rm, &cron) != nil {
			s.writeError(w, r, apierr.ValidationField("cron", "cron must be a string."))
			return
		}
	}
	cb, err := s.visibleCodebase(r, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	if cb.TargetType == "url" && !me.MayRunDAST() {
		s.writeError(w, r, dastForbidden())
		return
	}
	if err := s.validateSchedule(scanTypeOf(cb), cron, "cron"); err != nil {
		s.writeError(w, r, err)
		return
	}
	updated, err := s.Store.SetSchedule(r.Context(), id, cron, me.ID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "schedule_set", updated.Name+" "+cron)
	writeJSON(w, http.StatusOK, map[string]any{"schedule": s.scheduleView(r.Context(), updated)})
}

// deleteSchedule removes the schedule (204).
func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	cb, err := s.visibleCodebase(r, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	if cb.TargetType == "url" && !me.MayRunDAST() {
		s.writeError(w, r, dastForbidden())
		return
	}
	updated, err := s.Store.ClearSchedule(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "schedule_deleted", updated.Name)
	w.WriteHeader(http.StatusNoContent)
}

// resumeSchedule re-activates a suspended schedule; the caller becomes the
// owner. 409 schedule_not_suspended when it is not suspended.
func (s *Server) resumeSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	cb, err := s.visibleCodebase(r, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	if cb.TargetType == "url" && !me.MayRunDAST() {
		s.writeError(w, r, dastForbidden())
		return
	}
	updated, err := s.Store.ResumeSchedule(r.Context(), id, me.ID)
	if err != nil {
		if err == store.ErrNotSuspended {
			s.writeError(w, r, apierr.Conflict("schedule_not_suspended", "The schedule is not suspended."))
			return
		}
		s.writeError(w, r, err)
		return
	}
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "schedule_resumed", updated.Name)
	writeJSON(w, http.StatusOK, map[string]any{"schedule": s.scheduleView(r.Context(), updated)})
}
