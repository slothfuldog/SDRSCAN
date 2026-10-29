package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/dastauth"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// LoginTester runs the engine's login check (implemented by *scanner.Runner).
type LoginTester interface {
	TestLogin(ctx context.Context, cb store.Codebase) (scanner.LoginCheck, error)
}

var loginTests sync.Map // codebase id -> struct{}: one login test at a time per target

func secretKeyRequired() error {
	return apierr.New(http.StatusServiceUnavailable, "secret_key_required",
		"DAST credentials cannot be stored: SDRSCAN_SECRET_KEY is not configured on the server.")
}

// dastTarget loads a URL target the caller may see. Callers that may not see URL targets get the
// same 404 as for a missing id; repository targets answer 409 not_a_url_target.
func (s *Server) dastTarget(r *http.Request) (store.Codebase, error) {
	id, err := pathID(r, "id")
	if err != nil {
		return store.Codebase{}, err
	}
	cb, err := s.visibleCodebase(r, id)
	if err != nil {
		return cb, err
	}
	if cb.TargetType != "url" || cb.BaseURL == nil {
		return cb, apierr.Conflict("not_a_url_target", "DAST authentication applies only to URL targets.")
	}
	return cb, nil
}

// dastAuthView is the `dast_auth` object of a codebase (never contains a secret).
func dastAuthView(cb store.Codebase) map[string]any {
	typ := cb.DastAuthType
	if typ == "" {
		typ = dastauth.TypeNone
	}
	return dastauth.View(typ, len(cb.DastAuthEnc) > 0, cb.DastAuthMeta)
}

// dastCrawlView is the `dast_crawl` object of a codebase.
func dastCrawlView(cb store.Codebase) map[string]any {
	ex := cb.DastCrawlExclude
	if ex == nil {
		ex = []string{}
	}
	return map[string]any{"enabled": cb.DastCrawlEnabled, "max_depth": cb.DastCrawlMaxDepth, "max_pages": cb.DastCrawlMaxPages, "exclude": ex}
}

func (s *Server) getDastAuth(w http.ResponseWriter, r *http.Request) {
	cb, err := s.dastTarget(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, dastAuthView(cb))
}

func (s *Server) putDastAuth(w http.ResponseWriter, r *http.Request) {
	cb, err := s.dastTarget(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in dastauth.Config
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	if !s.Box.Enabled() {
		s.writeError(w, r, secretKeyRequired())
		return
	}
	// Blank secrets keep the stored values, so non-secret settings can be edited without re-entering them.
	var prev *dastauth.Config
	if cb.HasDastAuth() {
		if p, err := scanner.OpenAuth(s.Box, cb); err == nil {
			prev = &p
		}
	}
	cfg, err := dastauth.Validate(dastauth.Merge(in, prev), *cb.BaseURL)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if cfg.Login != nil {
		// The login host is the target host (same origin); the network policy still applies to it.
		if err := s.checkHostAddress(r.Context(), cfg.Login.URL, "login.url", false); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	plain, err := json.Marshal(cfg)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	enc, err := s.Box.Seal(plain)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	meta, err := json.Marshal(dastauth.MetaOf(cfg, time.Now(), map[string]any{"id": me.ID, "username": me.Username}))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	updated, err := s.Store.SetDastAuth(r.Context(), cb.ID, *cb.BaseURL, cfg.Type, enc, meta)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, r, apierr.Conflict("target_changed", "The target URL changed while saving; try again."))
		return
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_auth_set", fmt.Sprintf("%s type=%s", cb.Name, cfg.Type))
	writeJSON(w, http.StatusOK, dastAuthView(updated))
}

func (s *Server) deleteDastAuth(w http.ResponseWriter, r *http.Request) {
	cb, err := s.dastTarget(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	if cb.HasDastAuth() || len(cb.DastAuthEnc) > 0 {
		if _, err := s.Store.SetDastAuth(r.Context(), cb.ID, *cb.BaseURL, dastauth.TypeNone, nil, nil); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.writeError(w, r, err)
			return
		}
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_auth_deleted", cb.Name)
	}
	w.WriteHeader(http.StatusNoContent)
}

// testDastAuth runs the engine's login check against the confirmed target.
func (s *Server) testDastAuth(w http.ResponseWriter, r *http.Request) {
	cb, err := s.dastTarget(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if cb.DastStatus == nil || *cb.DastStatus != "confirmed" {
		s.writeError(w, r, apierr.Conflict("target_not_confirmed", "The target must be confirmed by an Admin before the login can be tested."))
		return
	}
	if !cb.HasDastAuth() {
		s.writeError(w, r, apierr.Conflict("no_auth_configured", "No authentication is configured for this target."))
		return
	}
	if s.LoginTester == nil {
		s.writeError(w, r, apierr.New(http.StatusServiceUnavailable, "engine_unavailable", "The DAST engine is not available."))
		return
	}
	if err := s.checkHostAddress(r.Context(), *cb.BaseURL, "base_url", false); err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, busy := loginTests.LoadOrStore(cb.ID, struct{}{}); busy {
		s.writeError(w, r, apierr.Conflict("test_in_progress", "A login test is already running for this target."))
		return
	}
	defer loginTests.Delete(cb.ID)
	res, err := s.LoginTester.TestLogin(r.Context(), cb)
	switch {
	case errors.Is(err, scanner.ErrEngineUnsupported):
		s.writeError(w, r, apierr.New(http.StatusNotImplemented, "engine_unsupported", "The installed sdrscan-dast engine does not support authenticated scans."))
		return
	case errors.Is(err, scanner.ErrAuthUnreadable):
		s.writeError(w, r, apierr.Conflict("auth_unreadable", "The stored credentials cannot be decrypted (check SDRSCAN_SECRET_KEY); set them again."))
		return
	case errors.Is(err, scanner.ErrNoLogin):
		s.writeError(w, r, apierr.Conflict("no_login_configured", "Only a login form can be tested. Fixed headers and cookies have no login step."))
		return
	case errors.Is(err, scanner.ErrNoAuth):
		s.writeError(w, r, apierr.Conflict("no_auth_configured", "No authentication is configured for this target."))
		return
	case err != nil:
		s.Log.Warn("dast auth test failed to run", "codebase_id", cb.ID, "err", err)
		s.writeError(w, r, apierr.Internal())
		return
	}
	me := current(r)
	outcome := "failed"
	if res.OK {
		outcome = "ok"
	}
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_auth_tested", cb.Name+" "+outcome)
	writeJSON(w, http.StatusOK, map[string]any{"ok": res.OK, "message": res.Message})
}
