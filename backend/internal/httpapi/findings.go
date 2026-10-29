package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/sarif"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

func parseFilter(r *http.Request) (store.FindingFilter, error) {
	q := r.URL.Query()
	f := store.FindingFilter{Rule: q.Get("rule"), PathPrefix: q.Get("path"), Q: q.Get("q")}
	if v := q.Get("severity"); v != "" {
		for _, sv := range strings.Split(v, ",") {
			sv = strings.ToLower(strings.TrimSpace(sv))
			if !severities[sv] {
				return f, apierr.BadRequestField("severity", "severity must be a comma-separated list of critical, high, medium, low, info.")
			}
			f.Severities = append(f.Severities, sv)
		}
	}
	if v := q.Get("include_low_confidence"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return f, apierr.BadRequestField("include_low_confidence", "include_low_confidence must be true or false.")
		}
		f.IncludeLow = b
	}
	if v := q.Get("kind"); v != "" {
		if v != "code" && v != "vulnerability" {
			return f, apierr.BadRequestField("kind", "kind must be 'code' or 'vulnerability'.")
		}
		f.Kind = v
	}
	if v := q.Get("confidence"); v != "" {
		if v != "high" && v != "low" {
			return f, apierr.BadRequestField("confidence", "confidence must be 'high' or 'low' (the confidence of a CVE finding).")
		}
		f.VulnConfidence = v
	}
	if v := q.Get("scope"); v != "" {
		if v != "runtime" && v != "dev" {
			return f, apierr.BadRequestField("scope", "scope must be 'runtime' or 'dev'.")
		}
		f.Scope = v
	}
	if v := q.Get("cve"); v != "" {
		id, ok := sarif.NormalizeAdvisoryID(v)
		if !ok {
			return f, apierr.BadRequestField("cve", "cve must be an advisory id such as CVE-2024-12345 or GHSA-xxxx-xxxx-xxxx.")
		}
		f.CVE = id
	}
	if v := q.Get("sort"); v != "" && v != "severity" {
		return f, apierr.BadRequestField("sort", "sort must be 'severity'.")
	}
	if len(f.Rule) > 200 || len(f.PathPrefix) > 1024 || len(f.Q) > 200 {
		return f, apierr.BadRequest("A filter value is too long.")
	}
	return f, nil
}

func (s *Server) findingsPage(w http.ResponseWriter, r *http.Request, f store.FindingFilter) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items, total, err := s.Store.ListFindings(r.Context(), f, p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	facets, err := s.Store.FindingFacets(r.Context(), f)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	views := make([]any, 0, len(items))
	for _, it := range items {
		views = append(views, findingSummary(it))
	}
	out := pageJSON(views, total, p)
	out["facets"] = facets
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) codebaseFindings(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	f, err := parseFilter(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, err := s.visibleCodebase(r, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	f.CodebaseID = id
	s.findingsPage(w, r, f)
}

func (s *Server) scanFindings(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	f, err := parseFilter(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, err := s.visibleScan(r, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	f.ScanID = id
	s.findingsPage(w, r, f)
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	f, err := s.Store.GetFinding(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, err := s.visibleCodebase(r, f.CodebaseID); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, findingDetail(f))
}

func (s *Server) filesPage(w http.ResponseWriter, r *http.Request, codebaseID, scanID int64) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	rows, total, err := s.Store.ListFiles(r.Context(), codebaseID, scanID, p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(rows))
	for _, fr := range rows {
		v := countsView(fr.Counts)
		v["location"], v["total"] = fr.Location, fr.Total
		items = append(items, v)
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

func (s *Server) codebaseFiles(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, err := s.visibleCodebase(r, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.filesPage(w, r, id, 0)
}

func (s *Server) scanFiles(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, err := s.visibleScan(r, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.filesPage(w, r, 0, id)
}
