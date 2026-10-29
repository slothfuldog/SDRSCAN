package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/vulndb"
)

// vulnJobView is the update job of GET /system/vulndb.
func vulnJobView(j *vulndb.Job) any {
	if j == nil {
		return nil
	}
	eco := j.Ecosystems
	if eco == nil {
		eco = []string{}
	}
	var by, code, exit any
	if j.RequestedBy != "" {
		by = j.RequestedBy
	}
	if j.ErrorCode != "" {
		code = j.ErrorCode
	}
	if j.ExitCode != nil {
		exit = *j.ExitCode
	}
	return map[string]any{"id": j.ID, "state": j.State, "trigger": j.Trigger, "requested_by": by, "ecosystems": eco, "nvd": j.NVD,
		"started_at": ts(j.StartedAt), "finished_at": tsp(j.FinishedAt), "exit_code": exit, "error_code": code, "log_tail": j.LogTail}
}

func vulnStatusView(st *vulndb.Status) any {
	if st == nil {
		return nil
	}
	sources := make([]any, 0, len(st.Sources))
	for _, s := range st.Sources {
		var eco, age any
		if s.Ecosystem != "" {
			eco = s.Ecosystem
		}
		if s.AgeDays != nil {
			age = *s.AgeDays
		}
		products := s.Products
		if products == nil {
			products = []string{}
		}
		sources = append(sources, map[string]any{"name": s.Name, "ecosystem": eco, "advisories": s.Advisories,
			"updated_at": tsp(s.UpdatedAt), "age_days": age, "products": products})
	}
	var age, format any
	if st.AgeDays != nil {
		age = *st.AgeDays
	}
	if st.FormatVersion != nil {
		format = *st.FormatVersion
	}
	return map[string]any{"installed": st.Installed, "advisory_count": st.AdvisoryCount, "updated_at": tsp(st.UpdatedAt),
		"age_days": age, "max_age_days": st.MaxAgeDays, "format_version": format, "sources": sources}
}

// getVulnDB implements GET /system/vulndb (Admin): configuration, database state and the latest update job.
func (s *Server) getVulnDB(w http.ResponseWriter, r *http.Request) {
	m := s.VulnDB
	cfg := m.Config()
	out := map[string]any{
		"configured": m.Configured(), "sca_enabled": cfg.ScaEnabled, "db_path": nil, "db_present": m.DirPresent(),
		"tool":   map[string]any{"available": m.ToolAvailable(), "path": cfg.Bin},
		"status": nil, "status_error": nil, "stale": false, "stale_after_days": int(cfg.StaleAfter / (24 * time.Hour)),
		"ecosystems": vulndb.AllowedEcosystems, "update_timeout_seconds": int(cfg.Timeout / time.Second), "update_cron": nil,
		"update": vulnJobView(m.Current()),
	}
	if cfg.Dir != "" {
		out["db_path"] = cfg.Dir
	}
	if cfg.Cron != "" {
		out["update_cron"] = cfg.Cron
	}
	if m.Configured() {
		st, err := m.Status(r.Context())
		switch {
		case err == nil:
			out["status"] = vulnStatusView(st)
			out["stale"] = st.Stale
			out["stale_after_days"] = st.MaxAgeDays
		case errors.Is(err, vulndb.ErrToolUnavailable):
			out["status_error"] = "sdrscan-vuln is not available on this server."
		default:
			out["status_error"] = "Could not read the database status: " + truncateMsg(err.Error(), 300)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func truncateMsg(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "") + "..."
	}
	return s
}

// startVulnDBUpdate implements POST /system/vulndb/update (Admin) {ecosystems?, nvd?}.
func (s *Server) startVulnDBUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ecosystems []string `json:"ecosystems"`
		NVD        bool     `json:"nvd"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, r, apierr.BadRequest("Request body is not valid JSON."))
		return
	}
	var eco []string
	seen := map[string]bool{}
	if len(in.Ecosystems) > len(vulndb.AllowedEcosystems)*2 {
		s.writeError(w, r, apierr.Validation("ecosystems has too many entries.", map[string]any{"field": "ecosystems", "allowed": vulndb.AllowedEcosystems}))
		return
	}
	var fe apierr.FieldErrors
	for i, e := range in.Ecosystems {
		canon := ""
		for _, a := range vulndb.AllowedEcosystems {
			if strings.EqualFold(strings.TrimSpace(e), a) {
				canon = a
			}
		}
		if canon == "" {
			fe.Add("ecosystems["+strconv.Itoa(i)+"]", "Unknown ecosystem "+strconv.Quote(truncateMsg(e, 40))+". Allowed: "+strings.Join(vulndb.AllowedEcosystems, ", ")+".")
			continue
		}
		if !seen[canon] {
			seen[canon] = true
			eco = append(eco, canon)
		}
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	job, err := s.VulnDB.Start(vulndb.StartOptions{Trigger: vulndb.TriggerManual, Actor: &me, Ecosystems: eco, NVD: in.NVD})
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]any{"update": vulnJobView(&job)})
	case errors.Is(err, vulndb.ErrNotConfigured):
		s.writeError(w, r, apierr.Conflict("vulndb_not_configured", "The vulnerability database is not configured (set SDRSCAN_VULN_DB)."))
	case errors.Is(err, vulndb.ErrToolUnavailable):
		s.writeError(w, r, apierr.Conflict("vuln_tool_unavailable", "The sdrscan-vuln tool is not available on this server (SDRSCAN_VULN_BIN)."))
	case errors.Is(err, vulndb.ErrInProgress):
		s.writeError(w, r, apierr.Conflict("update_in_progress", "A vulnerability database update is already running."))
	default:
		s.writeError(w, r, err)
	}
}

// cancelVulnDBUpdate implements POST /system/vulndb/update/cancel (Admin).
func (s *Server) cancelVulnDBUpdate(w http.ResponseWriter, r *http.Request) {
	me := current(r)
	job, err := s.VulnDB.Cancel(&me)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]any{"update": vulnJobView(&job)})
	case errors.Is(err, vulndb.ErrNoneRunning):
		s.writeError(w, r, apierr.Conflict("no_update_running", "No vulnerability database update is running."))
	default:
		s.writeError(w, r, err)
	}
}
