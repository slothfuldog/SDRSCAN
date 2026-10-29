package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CodebaseID   int64 `json:"codebase_id"`
		Active       bool  `json:"active"`
		ActiveTiming bool  `json:"active_timing"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	if in.CodebaseID <= 0 {
		s.writeError(w, r, apierr.ValidationField("codebase_id", "codebase_id is required."))
		return
	}
	if in.ActiveTiming && !in.Active {
		s.writeError(w, r, apierr.ValidationField("active_timing", "active_timing requires active to be true."))
		return
	}
	cb, err := s.visibleCodebase(r, in.CodebaseID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	typ := "sast"
	active, activeTiming := false, false
	if cb.TargetType == "url" {
		typ = "dast"
		// Permission comes from the database row loaded for this request.
		if !me.MayRunDAST() {
			s.writeError(w, r, dastForbidden())
			return
		}
		if cb.DastStatus == nil || *cb.DastStatus != "confirmed" {
			s.writeError(w, r, apierr.Conflict("target_not_confirmed", "An Admin must confirm authorization for this target first."))
			return
		}
		if in.Active {
			// Active scanning is a separate, stricter authorization layer on top of the confirmation
			// above: without it the scan must stay passive, never silently.
			if !cb.ActiveScanAuthorized() {
				s.writeError(w, r, apierr.Conflict("active_scanning_not_authorized",
					"Active scanning has not been authorized for this target. Authorize it in the codebase's settings first."))
				return
			}
			active, activeTiming = true, in.ActiveTiming
		}
		if cb.BaseURL != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			err := s.Guard.CheckResolved(ctx, hostOnly(*cb.BaseURL))
			cancel()
			if err != nil {
				s.writeError(w, r, addressError(err, "base_url"))
				return
			}
		}
	}
	sc, err := s.Store.CreateJob(r.Context(), cb.ID, typ, "manual", &me.ID, store.JobOptions{Active: active, ActiveTiming: activeTiming})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if typ == "dast" {
		target := cb.Name + " scan #" + fmt.Sprint(sc.ID)
		if active {
			target += " active:true"
			if activeTiming {
				target += "+timing"
			}
		}
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_scan_started", target)
	}
	writeJSON(w, http.StatusAccepted, scanView(sc, false))
}

func hostOnly(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if strings.HasPrefix(rest, "[") {
		if j := strings.Index(rest, "]"); j >= 0 {
			return rest[:j+1]
		}
	}
	if j := strings.LastIndex(rest, ":"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	sc, err := s.visibleScan(r, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scanView(sc, true))
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, err := s.visibleScan(r, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	sc, err := s.Store.CancelScan(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, scanView(sc, false))
}

var scanStatuses = map[string]bool{"queued": true, "running": true, "succeeded": true, "failed": true, "cancelled": true}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && !scanStatuses[status] {
		s.writeError(w, r, apierr.BadRequestField("status", "status must be one of queued, running, succeeded, failed, cancelled."))
		return
	}
	if _, err := s.visibleCodebase(r, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	scans, total, err := s.Store.ListScans(r.Context(), id, status, p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(scans))
	for _, sc := range scans {
		items = append(items, scanView(sc, false))
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

// compare implements GET /codebases/{id}/compare.
func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	q := r.URL.Query()
	status := q.Get("status")
	if status == "" {
		status = "new"
	}
	if status != "new" && status != "unchanged" && status != "fixed" {
		s.writeError(w, r, apierr.BadRequestField("status", "status must be new, unchanged or fixed."))
		return
	}
	if _, err := s.visibleCodebase(r, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	var base, head *store.Scan
	if q.Get("base") != "" || q.Get("head") != "" {
		bid, e1 := parseInt64(q.Get("base"))
		hid, e2 := parseInt64(q.Get("head"))
		if e1 != nil || e2 != nil || bid <= 0 || hid <= 0 {
			s.writeError(w, r, apierr.BadRequestField("base", "base and head must both be scan ids."))
			return
		}
		b, err := s.Store.GetScan(r.Context(), bid)
		if err != nil {
			s.writeError(w, r, apierr.BadRequestField("base", "base scan not found."))
			return
		}
		h, err := s.Store.GetScan(r.Context(), hid)
		if err != nil {
			s.writeError(w, r, apierr.BadRequestField("head", "head scan not found."))
			return
		}
		for _, sc := range []store.Scan{b, h} {
			if sc.CodebaseID != id || sc.Status != "succeeded" || sc.DuplicateOfScanID != nil {
				s.writeError(w, r, apierr.BadRequest("Both scans must be succeeded scans of this codebase."))
				return
			}
		}
		base, head = &b, &h
	} else {
		scans, err := s.Store.SuccessfulScans(r.Context(), id, 2)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		if len(scans) == 0 {
			s.writeError(w, r, apierr.NotFound("Succeeded scan"))
			return
		}
		head = &scans[0]
		if len(scans) > 1 {
			base = &scans[1]
		}
	}
	var baseID int64
	var partials []int64
	if base != nil {
		baseID = base.ID
		if base.Coverage == "partial" {
			partials = append(partials, base.ID)
		}
	}
	if head.Coverage == "partial" {
		partials = append(partials, head.ID)
	}
	cr, err := s.Store.Compare(r.Context(), baseID, head.ID, partials, status, p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	scope := map[string]any{"kind": "all", "file_count": nil}
	var warning any
	if len(partials) > 0 {
		scope = map[string]any{"kind": "partial", "file_count": cr.ScopeFiles}
		if cr.ScopeFiles == 0 {
			warning = map[string]any{"code": "empty_scope", "message": "The two scans share no scanned files; nothing can be compared."}
		}
	}
	items := make([]any, 0, len(cr.Items))
	for _, f := range cr.Items {
		items = append(items, map[string]any{"status": status, "finding": findingSummary(f)})
	}
	var baseView any
	if base != nil {
		baseView = compareScanView(base)
	}
	out := pageJSON(items, cr.Total, p)
	out["base"], out["head"], out["scope"], out["warning"], out["status"] = baseView, compareScanView(head), scope, warning, status
	out["counts"] = map[string]int{"new": cr.New, "unchanged": cr.Unchanged, "fixed": cr.Fixed}
	writeJSON(w, http.StatusOK, out)
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ----- SSE -----

type statusEvent struct {
	Status     string `json:"status"`
	StartedAt  any    `json:"started_at,omitempty"`
	FinishedAt any    `json:"finished_at,omitempty"`
	ErrorCode  any    `json:"error_code,omitempty"`
	Summary    any    `json:"summary,omitempty"`
}

func eventFor(sc store.Scan) statusEvent {
	ev := statusEvent{Status: sc.Status}
	if sc.StartedAt != nil {
		ev.StartedAt = ts(*sc.StartedAt)
	}
	if sc.FinishedAt != nil {
		ev.FinishedAt = ts(*sc.FinishedAt)
	}
	if sc.ErrorCode != nil {
		ev.ErrorCode = *sc.ErrorCode
	}
	if sc.Status == "succeeded" {
		c := sc.Counts()
		ev.Summary = map[string]int{"critical": c.Critical, "high": c.High, "medium": c.Medium, "low": c.Low, "info": c.Info}
	}
	return ev
}

// newLogLines returns the lines of cur that are new relative to prev (log_tail
// is a sliding window, so prev may have lost its head).
func newLogLines(prev, cur string) []string {
	if cur == prev {
		return nil
	}
	curLines := splitLines(cur)
	prevLines := splitLines(prev)
	if len(prevLines) == 0 {
		return curLines
	}
	last := prevLines[len(prevLines)-1]
	for i := len(curLines) - 1; i >= 0; i-- {
		if curLines[i] == last {
			return curLines[i+1:]
		}
	}
	return curLines
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func (s *Server) scanEvents(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	sc, err := s.visibleScan(r, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	prevLog := ""
	lastStatus := ""
	var lastEv string
	emit := func(sc store.Scan) (cont bool, ok bool) {
		log := ""
		if sc.LogTail != nil {
			log = *sc.LogTail
		}
		ev := eventFor(sc)
		evJSON, _ := json.Marshal(ev)
		sendStatus := func() bool {
			if sc.Status != lastStatus || string(evJSON) != lastEv {
				if !send("status", ev) {
					return false
				}
				lastStatus, lastEv = sc.Status, string(evJSON)
			}
			return true
		}
		if !sc.Terminal() && !sendStatus() {
			return false, false
		}
		for _, line := range newLogLines(prevLog, log) {
			if !send("log", map[string]string{"line": line}) {
				return false, false
			}
		}
		if sc.Terminal() && !sendStatus() {
			return false, false
		}
		prevLog = log
		return !sc.Terminal(), true
	}
	if cont, ok := emit(sc); !ok || !cont {
		if ok {
			// terminal: events already sent; ensure final status ordering
		}
		return
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.Done:
			return
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		case <-tick.C:
			// Visibility is re-checked every second: when the caller loses the
			// right to see this codebase the stream is closed.
			fresh, err := s.Store.GetUser(r.Context(), current(r).ID)
			if err != nil || !fresh.IsActive {
				return
			}
			sc, err := s.visibleScanFor(r.Context(), fresh, id)
			if err != nil {
				return
			}
			if cont, ok := emit(sc); !ok || !cont {
				return
			}
		}
	}
}
