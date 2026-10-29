package httpapi

import (
	"context"
	"net/http"

	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// canSeeURL reports whether the caller may see URL (DAST) targets at all.
// Members without DAST access must not learn that such targets exist, so every
// lookup below answers 404 for them. The permission comes from the user row
// loaded for this very request, so a revocation applies at once.
func canSeeURL(r *http.Request) bool { return current(r).MayRunDAST() }

// codebaseVisibleTo is the visibility predicate: repo targets are visible to
// everyone, URL targets to Admins and Members with can_run_dast.
func codebaseVisibleTo(u store.User, cb store.Codebase) bool {
	return cb.TargetType == "repo" || u.MayRunDAST()
}

func (s *Server) visibleCodebaseFor(ctx context.Context, u store.User, id int64) (store.Codebase, error) {
	cb, err := s.Store.GetCodebase(ctx, id)
	if err != nil {
		return cb, err
	}
	if !codebaseVisibleTo(u, cb) {
		return store.Codebase{}, store.ErrNotFound
	}
	return cb, nil
}

// visibleCodebase loads a codebase, or ErrNotFound when it is a URL target the
// caller may not see.
func (s *Server) visibleCodebase(r *http.Request, id int64) (store.Codebase, error) {
	return s.visibleCodebaseFor(r.Context(), current(r), id)
}

func (s *Server) visibleScanFor(ctx context.Context, u store.User, id int64) (store.Scan, error) {
	sc, err := s.Store.GetScan(ctx, id)
	if err != nil {
		return sc, err
	}
	if _, err := s.visibleCodebaseFor(ctx, u, sc.CodebaseID); err != nil {
		return store.Scan{}, err
	}
	return sc, nil
}

// visibleScan loads a scan whose codebase the caller may see.
func (s *Server) visibleScan(r *http.Request, id int64) (store.Scan, error) {
	return s.visibleScanFor(r.Context(), current(r), id)
}
