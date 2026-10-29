package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/dastauth"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

func dastForbidden() error {
	return apierr.Forbidden("dast_forbidden", "You do not have DAST access. Ask an Admin to enable it for your account.")
}

// normalizeSubdirectory validates a relative sub-directory (” = whole repo).
func normalizeSubdirectory(s string) (string, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", nil
	}
	if strings.ContainsAny(v, "\\\x00") || strings.HasPrefix(v, "/") || len(v) > 500 {
		return "", apierr.ValidationField("subdirectory", "subdirectory must be a relative path with '/' separators (at most 500 characters).")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", apierr.ValidationField("subdirectory", "subdirectory must not contain control characters.")
		}
	}
	for _, seg := range strings.Split(v, "/") {
		if seg == ".." {
			return "", apierr.ValidationField("subdirectory", "subdirectory must not contain '..'.")
		}
	}
	c := path.Clean(v)
	if c == "." {
		return "", nil
	}
	return c, nil
}

// validateSchedule checks a cron expression for the given scan type:
// 422 invalid_cron or 422 schedule_too_frequent, both carrying details.field = field.
func (s *Server) validateSchedule(typ, expr, field string) error {
	min := s.Opt.MinIntervalSAST
	if typ == "dast" {
		min = s.Opt.MinIntervalDAST
	}
	if strings.TrimSpace(expr) == "" {
		return apierr.New(http.StatusUnprocessableEntity, "invalid_cron", field+" is required: enter a 5-field cron expression (UTC), for example '0 3 * * *'.").WithField(field)
	}
	err := scanner.ValidateSchedule(expr, min)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, scanner.ErrScheduleTooOften):
		return apierr.New(http.StatusUnprocessableEntity, "schedule_too_frequent", err.Error()+".").WithField(field)
	default:
		return apierr.New(http.StatusUnprocessableEntity, "invalid_cron", "The schedule is not a valid 5-field cron expression (UTC).").WithField(field)
	}
}

// collect records a validation error in fe; any other error is returned so the caller aborts.
func collect(fe *apierr.FieldErrors, err error) error {
	if err == nil || fe.AddError(err) {
		return nil
	}
	return err
}

// addressError maps a netguard error to 422 address_not_allowed (or a plain
// validation error for other URL problems).
func addressError(err error, field string) error {
	if errors.Is(err, netguard.ErrAddressNotAllowed) {
		return apierr.New(http.StatusUnprocessableEntity, "address_not_allowed", netguard.ErrBlocked+".").WithField(field)
	}
	return apierr.ValidationField(field, err.Error()+".")
}

// checkHostAddress resolves the host of rawURL and applies the network policy
// (every A/AAAA record must pass).
func (s *Server) checkHostAddress(ctx context.Context, rawURL, field string, repo bool) error {
	var host string
	if repo {
		host, _ = netguard.RepoHost(rawURL)
	} else {
		host = hostOnly(rawURL)
	}
	if host == "" {
		return nil // local test repositories have no host
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := s.Guard.Resolve(cctx, host); err != nil {
		return addressError(err, field)
	}
	return nil
}

func (s *Server) projectNameOf(ctx context.Context, id int64) string {
	if p, err := s.Store.GetProject(ctx, id); err == nil {
		return p.Name
	}
	return ""
}

type codebaseInput struct {
	Name         string `json:"name"`
	TargetType   string `json:"target_type"`
	Language     string `json:"language"`
	RepoURL      string `json:"repo_url"`
	Branch       string `json:"branch"`
	Subdirectory string `json:"subdirectory"`
	GitAuthKind  string `json:"git_auth_kind"`
	GitUsername  string `json:"git_username"`
	GitSecret    string `json:"git_secret"`
	BaseURL      string `json:"base_url"`
	ScheduleCron string `json:"schedule_cron"`
	DastMaxRPS   int    `json:"dast_max_rps"`
}

func (s *Server) sealSecret(secret string) ([]byte, error) {
	if !s.Box.Enabled() {
		return nil, apierr.New(http.StatusServiceUnavailable, "credentials_unavailable",
			"Git credentials cannot be stored: SDRSCAN_SECRET_KEY is not configured on the server.")
	}
	b, err := s.Box.Seal([]byte(secret))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Server) createCodebase(w http.ResponseWriter, r *http.Request) {
	projectID, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in codebaseInput
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		s.writeError(w, r, err)
		return
	}
	if in.TargetType == "url" && !me.MayRunDAST() {
		s.writeError(w, r, dastForbidden())
		return
	}
	// Every field is validated before answering, so the client learns about all of them at once.
	var fe apierr.FieldErrors
	abort := func(err error) bool {
		if err = collect(&fe, err); err != nil {
			s.writeError(w, r, err)
			return true
		}
		return false
	}
	name, err := validName("name", in.Name)
	if abort(err) {
		return
	}
	lang, ok := cleanText(in.Language)
	if !ok || len(lang) > 50 {
		fe.Add("language", "language must be at most 50 characters without control characters.")
	}
	n := store.NewCodebase{ProjectID: projectID, Name: name, Language: lang, TargetType: in.TargetType, GitAuthKind: "none", RegisteredBy: nil}
	var secret string
	switch in.TargetType {
	case "repo":
		u := strings.TrimSpace(in.RepoURL)
		if _, _, err := s.Guard.ValidateRepoURL(u); err != nil {
			fe.AddError(addressError(err, "repo_url"))
		} else if abort(s.checkHostAddress(r.Context(), u, "repo_url", true)) {
			return
		} else {
			n.RepoURL = &u
		}
		branch := strings.TrimSpace(in.Branch)
		if branch == "" {
			branch = "main"
		}
		if !scanner.ValidBranch(branch) {
			fe.Add("branch", "branch must match ^[A-Za-z0-9._/-]{1,200}$ and must not start with '-' or contain '..'.")
		}
		n.Branch = &branch
		sd, err := normalizeSubdirectory(in.Subdirectory)
		if abort(err) {
			return
		}
		n.Subdirectory = sd
		kind := in.GitAuthKind
		if kind == "" {
			kind = "none"
		}
		if kind != "none" && kind != "https_token" && kind != "ssh_key" {
			fe.Add("git_auth_kind", "git_auth_kind must be none, https_token or ssh_key.")
		} else {
			n.GitAuthKind = kind
		}
		if kind == "https_token" || kind == "ssh_key" {
			if in.GitSecret == "" {
				fe.Add("git_secret", "git_secret is required when git_auth_kind is "+kind+".")
			}
			secret = in.GitSecret
			if u := strings.TrimSpace(in.GitUsername); u != "" {
				if _, ok := cleanText(u); !ok || len(u) > 200 {
					fe.Add("git_username", "git_username must be at most 200 characters without control characters.")
				}
				n.GitUsername = &u
			}
		}
		if in.ScheduleCron != "" {
			if abort(s.validateSchedule("sast", in.ScheduleCron, "schedule_cron")) {
				return
			}
			c := in.ScheduleCron
			n.ScheduleCron = &c
			n.ScheduleOwner = &me.ID
		}
	case "url":
		base, err := s.Guard.ValidateBaseURL(in.BaseURL)
		if err != nil {
			fe.AddError(addressError(err, "base_url"))
		} else if abort(s.checkHostAddress(r.Context(), base, "base_url", false)) {
			return
		} else {
			n.BaseURL = &base
		}
		n.RegisteredBy = &me.ID
		if in.DastMaxRPS != 0 {
			if in.DastMaxRPS < 1 || in.DastMaxRPS > 100 {
				fe.Add("dast_max_rps", "dast_max_rps must be between 1 and 100.")
			}
			n.MaxRPS = in.DastMaxRPS
		}
		if in.ScheduleCron != "" {
			if abort(s.validateSchedule("dast", in.ScheduleCron, "schedule_cron")) {
				return
			}
			c := in.ScheduleCron
			n.ScheduleCron = &c
			n.ScheduleOwner = &me.ID
		}
	case "":
		fe.Add("target_type", "target_type is required: choose 'repo' or 'url'.")
	default:
		fe.Add("target_type", "target_type must be 'repo' or 'url'.")
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	if secret != "" {
		if n.GitSecretEnc, err = s.sealSecret(secret); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	cb, err := s.Store.CreateCodebase(r.Context(), n)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if cb.TargetType == "url" {
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_target_registered", cb.Name+" "+*cb.BaseURL)
	}
	writeJSON(w, http.StatusCreated, s.codebaseView(r.Context(), cb, store.CodebaseState{}, s.projectNameOf(r.Context(), cb.ProjectID)))
}

func (s *Server) loadCodebaseView(r *http.Request, id int64) (map[string]any, error) {
	cb, err := s.visibleCodebase(r, id)
	if err != nil {
		return nil, err
	}
	states, err := s.Store.States(r.Context(), []store.Codebase{cb})
	if err != nil {
		return nil, err
	}
	return s.codebaseView(r.Context(), cb, states[cb.ID], s.projectNameOf(r.Context(), cb.ProjectID)), nil
}

func (s *Server) getCodebase(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	v, err := s.loadCodebaseView(r, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) updateCodebase(w http.ResponseWriter, r *http.Request) {
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
	cur, err := s.visibleCodebase(r, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	sets := map[string]any{}
	// Every field is validated before answering, so the client learns about all of them at once.
	var fe apierr.FieldErrors
	var fatal error // a non-validation error (403, 503, database): answered instead of the field errors
	abort := func(err error) {
		if err = collect(&fe, err); err != nil && fatal == nil {
			fatal = err
		}
	}
	getStr := func(key string) (string, bool) {
		rm, ok := raw[key]
		if !ok {
			return "", false
		}
		if string(rm) == "null" {
			return "", true
		}
		var v string
		if err := json.Unmarshal(rm, &v); err != nil {
			fe.Add(key, key+" must be a string.")
			return "", false
		}
		return v, true
	}
	if _, ok := raw["schedule_cron"]; ok {
		fe.Add("schedule_cron", "The schedule is managed with PUT, DELETE and POST .../schedule/resume on /codebases/{id}/schedule.")
	}
	if rm, ok := raw["target_type"]; ok {
		var v string
		if json.Unmarshal(rm, &v) != nil || v != cur.TargetType {
			fe.Add("target_type", "target_type cannot be changed.")
		}
	}
	if v, ok := getStr("name"); ok {
		nv, err := validName("name", v)
		abort(err)
		if err == nil {
			sets["name"] = nv
		}
	}
	if v, ok := getStr("language"); ok {
		lang, okc := cleanText(v)
		if !okc || len(lang) > 50 {
			fe.Add("language", "language must be at most 50 characters without control characters.")
		} else {
			sets["language"] = lang
		}
	}
	if rm, ok := raw["project_id"]; ok {
		var pid int64
		if json.Unmarshal(rm, &pid) != nil || pid <= 0 {
			fe.Add("project_id", "project_id must be a positive integer.")
		} else if pid != cur.ProjectID {
			if _, err := s.Store.GetProject(r.Context(), pid); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					fe.Add("project_id", "project_id does not exist.")
				} else {
					abort(err)
				}
			} else {
				sets["project_id"] = pid
			}
		}
	}
	dastChange, authCleared, activeAuthCleared := false, false, false
	crawlChange := false
	switch cur.TargetType {
	case "repo":
		for _, k := range []string{"base_url", "dast_max_rps", "dast_crawl_enabled", "dast_crawl_max_depth", "dast_crawl_max_pages", "dast_crawl_exclude"} {
			if _, ok := raw[k]; ok {
				fe.Add(k, k+" applies only to URL targets.")
			}
		}
		if v, ok := getStr("repo_url"); ok {
			v = strings.TrimSpace(v)
			if _, _, err := s.Guard.ValidateRepoURL(v); err != nil {
				fe.AddError(addressError(err, "repo_url"))
			} else if err := s.checkHostAddress(r.Context(), v, "repo_url", true); err != nil {
				abort(err)
			} else {
				sets["repo_url"] = v
			}
		}
		if v, ok := getStr("branch"); ok {
			v = strings.TrimSpace(v)
			if v == "" {
				v = "main"
			}
			if !scanner.ValidBranch(v) {
				fe.Add("branch", "branch must match ^[A-Za-z0-9._/-]{1,200}$ and must not start with '-' or contain '..'.")
			} else {
				sets["branch"] = v
			}
		}
		if v, ok := getStr("subdirectory"); ok {
			sd, err := normalizeSubdirectory(v)
			abort(err)
			if err == nil {
				sets["subdirectory"] = sd
			}
		}
		// Credentials: merge with the stored state and validate the result.
		kind := cur.GitAuthKind
		if v, ok := getStr("git_auth_kind"); ok {
			if v != "none" && v != "https_token" && v != "ssh_key" {
				fe.Add("git_auth_kind", "git_auth_kind must be none, https_token or ssh_key.")
			} else {
				kind = v
			}
		}
		haveSecret := len(cur.GitSecretEnc) > 0
		if v, ok := getStr("git_secret"); ok && v != "" {
			enc, err := s.sealSecret(v)
			if err != nil {
				abort(err)
			} else {
				sets["git_secret_enc"] = enc
				haveSecret = true
			}
		}
		if v, ok := getStr("git_username"); ok {
			if v = strings.TrimSpace(v); v == "" {
				sets["git_username"] = nil
			} else if _, okc := cleanText(v); !okc || len(v) > 200 {
				fe.Add("git_username", "git_username must be at most 200 characters without control characters.")
			} else {
				sets["git_username"] = v
			}
		}
		if kind == "none" {
			sets["git_secret_enc"], sets["git_username"] = nil, nil
		} else if !haveSecret {
			fe.Add("git_secret", "git_secret is required when git_auth_kind is "+kind+".")
		}
		if kind != cur.GitAuthKind {
			sets["git_auth_kind"] = kind
		}
	case "url":
		for _, k := range []string{"repo_url", "branch", "subdirectory", "git_auth_kind", "git_username", "git_secret"} {
			if _, ok := raw[k]; ok {
				fe.Add(k, k+" applies only to repository targets.")
			}
		}
		if v, ok := getStr("base_url"); ok {
			if !me.MayRunDAST() {
				abort(dastForbidden())
			} else if nv, err := s.Guard.ValidateBaseURL(v); err != nil {
				fe.AddError(addressError(err, "base_url"))
			} else if err := s.checkHostAddress(r.Context(), nv, "base_url", false); err != nil {
				abort(err)
			} else if cur.BaseURL == nil || nv != *cur.BaseURL {
				sets["base_url"] = nv
				sets["dast_status"] = "pending_confirmation"
				sets["dast_confirmed_by"], sets["dast_confirmed_at"], sets["dast_confirmation_text"] = nil, nil, nil
				dastChange = true
				// Credentials must never reach another host: a changed origin removes them.
				if cur.HasDastAuth() && (cur.BaseURL == nil || !dastauth.SameOrigin(*cur.BaseURL, nv)) {
					sets["dast_auth_type"], sets["dast_auth_enc"], sets["dast_auth_meta"] = dastauth.TypeNone, nil, nil
					authCleared = true
				}
				// Active scanning authorization is a separate, stricter layer on top of the basic
				// confirmation above: any base_url change revokes it too, in the same update.
				if cur.ActiveScanAuthorized() {
					sets["dast_active_authorized_at"], sets["dast_active_authorized_by"], sets["dast_active_statement"] = nil, nil, nil
					activeAuthCleared = true
				}
				// The OpenAPI/Swagger spec URL is tied to the target's origin, like credentials.
				if cur.DastOpenAPISpecURL != nil && (cur.BaseURL == nil || !dastauth.SameOrigin(*cur.BaseURL, nv)) {
					sets["dast_openapi_spec_url"] = nil
				}
			}
		}
		if rm, ok := raw["dast_max_rps"]; ok {
			if !me.MayRunDAST() {
				abort(dastForbidden())
			} else {
				var n int
				if json.Unmarshal(rm, &n) != nil || n < 1 || n > 100 {
					fe.Add("dast_max_rps", "dast_max_rps must be between 1 and 100.")
				} else {
					sets["dast_max_rps"] = n
				}
			}
		}
		if v, ok := getStr("dast_openapi_spec_url"); ok {
			effectiveBase := cur.BaseURL
			if nv, ok := sets["base_url"].(string); ok {
				effectiveBase = &nv
			}
			if !me.MayRunDAST() {
				abort(dastForbidden())
			} else if v = strings.TrimSpace(v); v == "" {
				sets["dast_openapi_spec_url"] = nil
			} else if nv, err := s.Guard.ValidateBaseURL(v); err != nil {
				fe.AddError(addressError(err, "dast_openapi_spec_url"))
			} else if effectiveBase == nil || !dastauth.SameOrigin(nv, *effectiveBase) {
				fe.Add("dast_openapi_spec_url", "dast_openapi_spec_url must be on the same origin as base_url.")
			} else if err := s.checkHostAddress(r.Context(), nv, "dast_openapi_spec_url", false); err != nil {
				abort(err)
			} else {
				sets["dast_openapi_spec_url"] = nv
			}
		}
		cc, err := parseCrawlSettings(raw)
		if err != nil {
			if !fe.Merge(err) {
				abort(err)
			}
		} else {
			for k, v := range cc {
				sets[k] = v
				crawlChange = true
			}
		}
	}
	if fatal != nil {
		s.writeError(w, r, fatal)
		return
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	cb, err := s.Store.UpdateCodebase(r.Context(), id, sets)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if dastChange && cur.DastStatus != nil {
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_target_reset", cb.Name+" -> "+*cb.BaseURL)
	}
	if authCleared {
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_auth_deleted", cb.Name+" (target origin changed)")
	}
	if activeAuthCleared {
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_active_revoked", cb.Name+" (target origin changed)")
	}
	if crawlChange {
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_crawl_updated", fmt.Sprintf("%s enabled=%t depth=%d pages=%d exclude=%d",
			cb.Name, cb.DastCrawlEnabled, cb.DastCrawlMaxDepth, cb.DastCrawlMaxPages, len(cb.DastCrawlExclude)))
	}
	states, err := s.Store.States(r.Context(), []store.Codebase{cb})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.codebaseView(r.Context(), cb, states[cb.ID], s.projectNameOf(r.Context(), cb.ProjectID)))
}

func (s *Server) confirmAuthorization(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in struct {
		StatementAccepted bool `json:"statement_accepted"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	cb, err := s.Store.GetCodebase(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if cb.TargetType != "url" {
		s.writeError(w, r, apierr.Conflict("not_a_url_target", "Only URL targets need an authorization confirmation."))
		return
	}
	if !in.StatementAccepted {
		s.writeError(w, r, apierr.ValidationField("statement_accepted", "statement_accepted must be true: confirm that you are authorized to scan this target."))
		return
	}
	me := current(r)
	if cb.DastStatus == nil || *cb.DastStatus != "confirmed" {
		cb, err = s.Store.ConfirmDast(r.Context(), id, me.ID, ConfirmationStatement(*cb.BaseURL))
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "dast_target_confirmed", cb.Name+" "+*cb.BaseURL)
	}
	states, err := s.Store.States(r.Context(), []store.Codebase{cb})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.codebaseView(r.Context(), cb, states[cb.ID], s.projectNameOf(r.Context(), cb.ProjectID)))
}

func (s *Server) deleteCodebase(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	cb, err := s.Store.GetCodebase(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := checkConfirm(r, cb.Name); err != nil {
		s.writeError(w, r, err)
		return
	}
	dc, err := s.Store.DeleteCodebase(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "codebase_deleted", cb.Name)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": map[string]int{"scans": dc.Scans, "findings": dc.Findings}})
}

// parseCrawlSettings reads the dast_crawl_* fields of a PATCH body into column values; every
// invalid field is reported.
func parseCrawlSettings(raw map[string]json.RawMessage) (map[string]any, error) {
	out := map[string]any{}
	var fe apierr.FieldErrors
	if rm, ok := raw["dast_crawl_enabled"]; ok {
		var b bool
		if json.Unmarshal(rm, &b) != nil {
			fe.Add("dast_crawl_enabled", "dast_crawl_enabled must be true or false.")
		} else {
			out["dast_crawl_enabled"] = b
		}
	}
	num := func(key string, lo, hi int) {
		rm, ok := raw[key]
		if !ok {
			return
		}
		var n int
		if json.Unmarshal(rm, &n) != nil || n < lo || n > hi {
			fe.Add(key, fmt.Sprintf("%s must be a whole number between %d and %d.", key, lo, hi))
			return
		}
		out[key] = n
	}
	num("dast_crawl_max_depth", 1, dastauth.MaxCrawlDepthCap)
	num("dast_crawl_max_pages", 1, dastauth.MaxCrawlPagesCap)
	if rm, ok := raw["dast_crawl_exclude"]; ok {
		var list []string
		if string(rm) != "null" && json.Unmarshal(rm, &list) != nil {
			fe.Add("dast_crawl_exclude", "dast_crawl_exclude must be a list of strings.")
		} else if clean, err := dastauth.ValidateExclude(list); err != nil {
			if !fe.Merge(err) {
				return nil, err
			}
		} else {
			out["dast_crawl_exclude"] = clean
		}
	}
	if err := fe.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
