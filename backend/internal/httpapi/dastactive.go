package httpapi

import (
	"net/http"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// ActiveScanStatement is the text a user accepts to authorize active (payload-sending) DAST scanning
// of a URL target. Unlike ConfirmationStatement this also requires retyping the codebase name, as
// deliberate friction for a riskier action.
func ActiveScanStatement(name string) string {
	return "I confirm that I am authorized to run ACTIVE security scans (SQL injection, XSS, open redirect and header " +
		"injection test payloads) against " + name + ", and that I understand this may affect the target application."
}

// authorizeActiveScanning implements POST /codebases/{id}/authorize-active-scanning. This is a
// separate, stricter layer on top of the basic DAST target confirmation: it requires the target to
// already be confirmed, an explicit statement acceptance AND the codebase name typed back exactly.
func (s *Server) authorizeActiveScanning(w http.ResponseWriter, r *http.Request) {
	cb, err := s.dastTarget(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in struct {
		StatementAccepted bool   `json:"statement_accepted"`
		CodebaseName      string `json:"codebase_name"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	if cb.DastStatus == nil || *cb.DastStatus != "confirmed" {
		s.writeError(w, r, apierr.Conflict("target_not_confirmed",
			"An Admin must confirm authorization for this target before active scanning can be authorized."))
		return
	}
	if !in.StatementAccepted {
		s.writeError(w, r, apierr.ValidationField("statement_accepted",
			"statement_accepted must be true: confirm that you understand the risks of active scanning."))
		return
	}
	if in.CodebaseName != cb.Name {
		s.writeError(w, r, apierr.ValidationField("codebase_name", "codebase_name must exactly match the codebase name."))
		return
	}
	me := current(r)
	updated, err := s.Store.AuthorizeActiveScanning(r.Context(), cb.ID, me.ID, ActiveScanStatement(cb.Name))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_active_authorized", updated.Name+" "+*updated.BaseURL)
	states, err := s.Store.States(r.Context(), []store.Codebase{updated})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.codebaseView(r.Context(), updated, states[updated.ID], s.projectNameOf(r.Context(), updated.ProjectID)))
}

// revokeActiveScanning implements DELETE /codebases/{id}/authorize-active-scanning (204, idempotent).
func (s *Server) revokeActiveScanning(w http.ResponseWriter, r *http.Request) {
	cb, err := s.dastTarget(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	if cb.ActiveScanAuthorized() {
		if _, err := s.Store.RevokeActiveScanning(r.Context(), cb.ID); err != nil {
			s.writeError(w, r, err)
			return
		}
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_active_revoked", cb.Name)
	}
	w.WriteHeader(http.StatusNoContent)
}
