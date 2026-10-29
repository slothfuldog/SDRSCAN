package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

type errBody struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Details   any    `json:"details,omitempty"`
		RequestID string `json:"request_id,omitempty"`
	} `json:"error"`
}

// writeError maps any error to the typed JSON error.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	ae, ok := apierr.As(err)
	if !ok {
		switch {
		case errors.Is(err, store.ErrNotFound):
			ae = apierr.NotFound("Resource")
		case isDBDown(err):
			ae = apierr.New(http.StatusServiceUnavailable, "database_unavailable", "The database is unavailable.")
		default:
			s.Log.Error("internal error", "request_id", requestIDOf(r), "method", r.Method, "path", r.URL.Path, "err", err)
			ae = apierr.Internal()
		}
	}
	var b errBody
	b.Error.Code, b.Error.Message, b.Error.Details, b.Error.RequestID = ae.Code, ae.Message, ae.Details, requestIDOf(r)
	for k, v := range ae.Headers {
		w.Header().Set(k, v)
	}
	writeJSON(w, ae.Status, b)
}

func isDBDown(err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return strings.HasPrefix(pe.Code, "08") || pe.Code == "57P01" || pe.Code == "57P03"
	}
	var ce interface{ SafeToRetry() bool }
	return errors.As(err, &ce)
}

// decode reads a JSON body (max 1 MiB) into dst.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return apierr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "Request body is too large.")
		}
		if errors.Is(err, io.EOF) {
			return apierr.BadRequest("Request body is empty.")
		}
		return apierr.BadRequest("Request body is not valid JSON.")
	}
	if dec.More() {
		return apierr.BadRequest("Request body must contain a single JSON value.")
	}
	return nil
}

func pathID(r *http.Request, name string) (int64, error) {
	v := chi.URLParam(r, name)
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return 0, apierr.BadRequest("Invalid id.")
	}
	return id, nil
}

func parsePage(r *http.Request) (store.Page, error) {
	p := store.Page{Page: 1, Size: 50}
	q := r.URL.Query()
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return p, apierr.BadRequestField("page", "page must be a positive integer.")
		}
		p.Page = n
	}
	if v := q.Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			return p, apierr.BadRequestField("page_size", "page_size must be between 1 and 200.")
		}
		p.Size = n
	}
	return p, nil
}

func pageJSON(items any, total int, p store.Page) map[string]any {
	return map[string]any{"items": items, "total": total, "page": p.Page, "page_size": p.Size}
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func tsp(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

// cleanText trims and rejects control characters.
func cleanText(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

func validName(field, s string) (string, error) {
	v, ok := cleanText(s)
	if !ok {
		return "", apierr.ValidationField(field, field+" must not contain control characters.")
	}
	n := len([]rune(v))
	if n < 1 {
		return "", apierr.ValidationField(field, field+" is required.")
	}
	if n > 100 {
		return "", apierr.ValidationField(field, field+" must be at most 100 characters.")
	}
	return v, nil
}
