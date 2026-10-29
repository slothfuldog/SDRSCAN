package httpapi

import (
	"net/http"
	"strings"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

func projectView(p store.Project) map[string]any {
	return map[string]any{"id": p.ID, "name": p.Name, "description": p.Description,
		"created_at": ts(p.CreatedAt), "updated_at": ts(p.UpdatedAt)}
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	rows, total, err := s.Store.ListProjects(r.Context(), p, canSeeURL(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(rows))
	for _, pr := range rows {
		items = append(items, map[string]any{"id": pr.ID, "name": pr.Name, "description": pr.Description,
			"codebase_count": pr.CodebaseCount, "totals": countsOnly(pr.Totals), "highest_severity": highestOf(pr.Totals),
			"created_at": ts(pr.CreatedAt)})
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

func validDescription(s string) (string, error) {
	v := strings.TrimSpace(s)
	if len([]rune(v)) > 1000 {
		return "", apierr.ValidationField("description", "description must be at most 1000 characters.")
	}
	for _, r := range v {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return "", apierr.ValidationField("description", "description must not contain control characters.")
		}
	}
	return v, nil
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var fe apierr.FieldErrors
	name, err := validName("name", in.Name)
	fe.AddError(err)
	desc, err := validDescription(in.Description)
	fe.AddError(err)
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	p, err := s.Store.CreateProject(r.Context(), name, desc)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, projectView(p))
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	p, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	totals, err := s.Store.ProjectTotals(r.Context(), id, canSeeURL(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	cbs, err := s.Store.ListCodebases(r.Context(), id, canSeeURL(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	states, err := s.Store.States(r.Context(), cbs)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(cbs))
	for _, cb := range cbs {
		items = append(items, s.codebaseView(r.Context(), cb, states[cb.ID], p.Name))
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": projectView(p), "totals": countsView(totals), "codebases": items})
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var name, desc *string
	var fe apierr.FieldErrors
	if in.Name != nil {
		v, err := validName("name", *in.Name)
		if !fe.AddError(err) {
			name = &v
		}
	}
	if in.Description != nil {
		v, err := validDescription(*in.Description)
		if !fe.AddError(err) {
			desc = &v
		}
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	p, err := s.Store.UpdateProject(r.Context(), id, name, desc)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, projectView(p))
}

// checkConfirm validates ?confirm=<exact name>.
func checkConfirm(r *http.Request, name string) error {
	c, present := r.URL.Query()["confirm"]
	if !present || len(c) == 0 || c[0] == "" {
		return apierr.New(http.StatusUnprocessableEntity, "confirmation_required", "Pass ?confirm=<exact name> to delete.").WithField("confirm")
	}
	if c[0] != name {
		return apierr.New(http.StatusUnprocessableEntity, "confirmation_mismatch", "The confirmation does not match the name.").WithField("confirm")
	}
	return nil
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	p, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := checkConfirm(r, p.Name); err != nil {
		s.writeError(w, r, err)
		return
	}
	dc, err := s.Store.DeleteProject(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "project_deleted", p.Name)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": map[string]int{"codebases": dc.Codebases, "scans": dc.Scans, "findings": dc.Findings}})
}
