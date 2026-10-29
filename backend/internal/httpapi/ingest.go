package httpapi

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/auth"
	"github.com/sdrscan/sdrscan/backend/internal/ingest"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

func invalidToken() error {
	return apierr.New(http.StatusUnauthorized, "invalid_token", "The ingest token is missing, invalid, revoked or not valid for this project.")
}

func (s *Server) ingestToken(r *http.Request) (store.Token, error) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return store.Token{}, invalidToken()
	}
	tok := strings.TrimSpace(h[len(prefix):])
	t, err := s.Store.LookupToken(r.Context(), auth.HashToken(tok))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.Log.Info("ingest rejected: invalid token", "request_id", requestIDOf(r))
			return store.Token{}, invalidToken()
		}
		return store.Token{}, err
	}
	return t, nil
}

// similarity ranks candidates: smaller Levenshtein distance first.
func suggest(want string, names []string) []string {
	type cand struct {
		n string
		d int
	}
	w := strings.ToLower(want)
	cs := make([]cand, 0, len(names))
	for _, n := range names {
		cs = append(cs, cand{n, levenshtein(w, strings.ToLower(n))})
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].d != cs[j].d {
			return cs[i].d < cs[j].d
		}
		return strings.ToLower(cs[i].n) < strings.ToLower(cs[j].n)
	})
	out := make([]string, 0, 20)
	for i, c := range cs {
		if i >= 20 {
			break
		}
		out = append(out, c.n)
	}
	return out
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func (s *Server) ingestByName(w http.ResponseWriter, r *http.Request) {
	tok, err := s.ingestToken(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	q := r.URL.Query()
	pname, cname := q.Get("project"), q.Get("codebase")
	if pname == "" || cname == "" {
		s.writeError(w, r, apierr.BadRequest("Query parameters 'project' and 'codebase' are required."))
		return
	}
	// A token restricted to one project must name exactly that project.
	if tok.ProjectID != nil {
		own, err := s.Store.GetProject(r.Context(), *tok.ProjectID)
		if err != nil || !strings.EqualFold(own.Name, pname) {
			s.writeError(w, r, invalidToken())
			return
		}
	}
	proj, err := s.Store.FindProjectByName(r.Context(), pname)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.writeError(w, r, err)
			return
		}
		names, _ := s.Store.ProjectNames(r.Context())
		s.writeError(w, r, apierr.Newf(http.StatusNotFound, "project_not_found", "Project '%s' is not registered.", pname).
			WithDetails(map[string]any{"available_projects": suggest(pname, names)}))
		return
	}
	cb, err := s.Store.FindCodebaseByName(r.Context(), proj.ID, cname)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.writeError(w, r, err)
			return
		}
		names, _ := s.Store.CodebaseNames(r.Context(), proj.ID)
		s.writeError(w, r, apierr.Newf(http.StatusNotFound, "codebase_not_found", "Codebase '%s' is not registered in project '%s'.", cname, proj.Name).
			WithDetails(map[string]any{"project": map[string]any{"id": proj.ID, "name": proj.Name}, "available_codebases": suggest(cname, names)}))
		return
	}
	s.doIngest(w, r, tok, cb)
}

func (s *Server) ingestByID(w http.ResponseWriter, r *http.Request) {
	tok, err := s.ingestToken(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	cb, err := s.Store.GetCodebase(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Do not reveal anything to a project-restricted token.
			if tok.ProjectID != nil {
				s.writeError(w, r, invalidToken())
				return
			}
			s.writeError(w, r, apierr.New(http.StatusNotFound, "codebase_not_found", "Codebase is not registered."))
			return
		}
		s.writeError(w, r, err)
		return
	}
	if tok.ProjectID != nil && *tok.ProjectID != cb.ProjectID {
		s.writeError(w, r, invalidToken())
		return
	}
	s.doIngest(w, r, tok, cb)
}

func (s *Server) doIngest(w http.ResponseWriter, r *http.Request, tok store.Token, cb store.Codebase) {
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct != "application/json" && ct != "application/sarif+json" {
		s.writeError(w, r, apierr.New(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json or application/sarif+json."))
		return
	}
	q := r.URL.Query()
	ref := strings.TrimSpace(q.Get("ref"))
	if len(ref) > 200 || strings.ContainsAny(ref, "\r\n\x00") {
		s.writeError(w, r, apierr.BadRequest("ref is invalid."))
		return
	}
	var startedAt *time.Time
	if v := q.Get("started_at"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			s.writeError(w, r, apierr.BadRequest("started_at must be an RFC 3339 timestamp."))
			return
		}
		startedAt = &t
	}

	max := s.Opt.MaxBodyBytes
	var body io.Reader = r.Body
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		// Bound the compressed input too, then bound the decompressed output.
		zr, err := gzip.NewReader(io.LimitReader(r.Body, max+1))
		if err != nil {
			s.writeError(w, r, apierr.BadRequest("Body is not valid gzip."))
			return
		}
		defer zr.Close()
		body = zr
	default:
		s.writeError(w, r, apierr.New(http.StatusUnsupportedMediaType, "unsupported_media_type", "Unsupported Content-Encoding."))
		return
	}
	data, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		s.writeError(w, r, apierr.BadRequest("Could not read the request body."))
		return
	}
	if int64(len(data)) > max {
		s.writeError(w, r, apierr.Newf(http.StatusRequestEntityTooLarge, "payload_too_large", "SARIF is larger than %d MB.", max>>20))
		return
	}
	start := time.Now()
	tid := tok.ID
	res, err := s.Ingest.Run(r.Context(), ingest.Params{Codebase: cb, Body: data, Ref: ref, StartedAt: startedAt, Trigger: "ci", TokenID: &tid})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.Log.Info("ingest", "request_id", requestIDOf(r), "scan_id", res.Scan.ID, "codebase_id", cb.ID, "type", res.Scan.Type,
		"coverage", res.Scan.Coverage, "trigger", "ci", "duplicate", res.Duplicate, "findings", res.ScanSummary.Critical+res.ScanSummary.High+res.ScanSummary.Medium+res.ScanSummary.Low+res.ScanSummary.Info,
		"redacted", res.RedactedCount, "vulnerabilities", res.VulnerabilityFindings, "vulnerability_ignored", res.VulnerabilityIgnored, "duration", time.Since(start).Round(time.Millisecond))
	if res.Duplicate {
		writeJSON(w, http.StatusOK, map[string]any{
			"duplicate":      true,
			"scan":           map[string]any{"id": res.Scan.ID, "codebase_id": res.Scan.CodebaseID, "started_at": tsp(res.Scan.StartedAt)},
			"scan_summary":   countsView(res.ScanSummary),
			"is_latest_scan": res.IsLatestScan,
		})
		return
	}
	scan := map[string]any{"id": res.Scan.ID, "codebase_id": res.Scan.CodebaseID, "type": res.Scan.Type, "coverage": res.Scan.Coverage,
		"status": res.Scan.Status, "engine": res.Scan.Engine, "engine_version": res.Scan.EngineVersion, "ref": res.Scan.Ref,
		"started_at": tsp(res.Scan.StartedAt)}
	var cbSummary any
	if res.CodebaseScanned {
		cbSummary = countsView(res.CodebaseSummary)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"duplicate": false, "scan": scan, "scan_summary": countsView(res.ScanSummary), "codebase_summary": cbSummary,
		"low_confidence": res.LowConfidence, "redacted_findings": res.RedactedCount, "superseded": res.Superseded,
		"vulnerability_findings": res.VulnerabilityFindings, "vulnerability_ignored": res.VulnerabilityIgnored,
	})
}
