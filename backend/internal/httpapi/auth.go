package httpapi

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/auth"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.Store.Pool.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.Opt.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if e := checkOrigin(r); e != nil {
		s.writeError(w, r, e)
		return
	}
	if !isJSONContent(r) {
		s.writeError(w, r, apierr.New(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json."))
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var fe apierr.FieldErrors
	if strings.TrimSpace(in.Username) == "" {
		fe.Add("username", "Username is required.")
	}
	if in.Password == "" {
		fe.Add("password", "Password is required.")
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	ip := clientIP(r, s.Opt.TrustProxy)
	if ok, wait := s.loginLimiter.Allow(ip); !ok {
		s.throttled(w, r, wait)
		return
	}
	if len(in.Password) > 1024 || len(in.Username) > 128 {
		s.writeError(w, r, apierr.New(http.StatusUnauthorized, "invalid_credentials", "Invalid username or password."))
		return
	}
	u, err := s.Store.GetUserByUsername(r.Context(), in.Username)
	if err != nil {
		if err != store.ErrNotFound {
			s.writeError(w, r, err)
			return
		}
		s.Hasher.BurnVerify(in.Password)
		s.Log.Info("login failed", "request_id", requestIDOf(r), "ip", ip)
		s.writeError(w, r, apierr.New(http.StatusUnauthorized, "invalid_credentials", "Invalid username or password."))
		return
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		s.throttled(w, r, time.Until(*u.LockedUntil))
		return
	}
	ok, rehash := s.Hasher.Verify(in.Password, u.PasswordHash)
	if !ok || !u.IsActive {
		if !ok {
			locked, _ := s.Store.RecordLoginFailure(r.Context(), u.ID, s.Opt.MaxLoginFails, s.Opt.LockFor)
			s.Store.Audit(r.Context(), nil, &u.ID, u.Username, "login_failed", u.Username)
			s.Log.Info("login failed", "request_id", requestIDOf(r), "username", u.Username, "ip", ip, "locked", locked != nil)
		}
		s.writeError(w, r, apierr.New(http.StatusUnauthorized, "invalid_credentials", "Invalid username or password."))
		return
	}
	if rehash {
		if h, err := s.Hasher.Hash(in.Password); err == nil {
			_ = s.Store.UpdateHash(r.Context(), u.ID, h)
		}
	}
	token, csrf := auth.NewToken(32), auth.NewHexToken(32)
	if err := s.Store.CreateSession(r.Context(), u.ID, auth.HashToken(token), csrf, s.Opt.SessionMax); err != nil {
		s.writeError(w, r, err)
		return
	}
	_ = s.Store.RecordLoginSuccess(r.Context(), u.ID)
	s.setSessionCookie(w, token, int(s.Opt.SessionMax.Seconds()))
	s.Log.Info("login", "request_id", requestIDOf(r), "username", u.Username, "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"user": userView(u), "csrf_token": csrf, "must_change_password": u.MustChangePassword})
}

func (s *Server) throttled(w http.ResponseWriter, r *http.Request, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	e := apierr.New(http.StatusTooManyRequests, "login_throttled", "Too many attempts. Try again in "+strconv.Itoa((secs+59)/60)+" minutes.")
	e.Headers = map[string]string{"Retry-After": strconv.Itoa(secs)}
	s.writeError(w, r, e)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	_ = s.Store.DeleteSession(r.Context(), currentSession(r).IDHash)
	s.setSessionCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	si := currentSession(r)
	writeJSON(w, http.StatusOK, map[string]any{"user": userView(si.User), "csrf_token": si.CSRF,
		"must_change_password": si.User.MustChangePassword})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	si := currentSession(r)
	var fe apierr.FieldErrors
	currentOK := false
	if in.Current == "" {
		fe.Add("current_password", "Current password is required.")
	} else if ok, _ := s.Hasher.Verify(in.Current, si.User.PasswordHash); !ok {
		fe.Add("current_password", "Current password is incorrect.")
	} else {
		currentOK = true
	}
	same := ""
	if currentOK {
		same = in.Current
	}
	if in.New == "" {
		fe.Add("new_password", "New password is required.")
	} else if err := auth.ValidatePassword(in.New, si.User.Username, same); err != nil {
		fe.Add("new_password", err.Error())
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	h, err := s.Hasher.Hash(in.New)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.Store.SetPassword(r.Context(), si.User.ID, h, false, si.IDHash); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ----- users (Admin) -----

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	us, total, err := s.Store.ListUsers(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(us))
	for _, u := range us {
		items = append(items, userAdminView(u))
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Role       string `json:"role"`
		CanRunDAST bool   `json:"can_run_dast"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var fe apierr.FieldErrors
	switch {
	case in.Username == "":
		fe.Add("username", "Username is required.")
	case !usernameRE.MatchString(in.Username):
		fe.Add("username", "Username must be 3 to 64 characters from A-Z, a-z, 0-9, '.', '_' and '-'.")
	}
	if in.Role == "" {
		in.Role = "member"
	}
	if in.Role != "admin" && in.Role != "member" {
		fe.Add("role", "role must be 'admin' or 'member'.")
	}
	if in.Password == "" {
		fe.Add("password", "Password is required.")
	} else if err := auth.ValidatePassword(in.Password, in.Username, ""); err != nil {
		fe.Add("password", err.Error())
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	h, err := s.Hasher.Hash(in.Password)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	u, err := s.Store.CreateUser(r.Context(), in.Username, h, in.Role, in.CanRunDAST, true)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "user_created", u.Username+" ("+u.Role+")")
	if u.CanRunDAST {
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "user_dast_access_changed", u.Username+" -> on")
	}
	writeJSON(w, http.StatusCreated, userAdminView(u))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in struct {
		Role       *string `json:"role"`
		IsActive   *bool   `json:"is_active"`
		CanRunDAST *bool   `json:"can_run_dast"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	u, changes, err := s.Store.UpdateUser(r.Context(), id, store.UserPatch{Role: in.Role, IsActive: in.IsActive, CanRunDAST: in.CanRunDAST})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	for _, c := range changes {
		s.Store.Audit(r.Context(), nil, &me.ID, me.Username, c.Action, c.Target)
	}
	writeJSON(w, http.StatusOK, userAdminView(u))
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in struct {
		NewPassword string `json:"new_password"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	u, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if in.NewPassword == "" {
		s.writeError(w, r, apierr.ValidationField("new_password", "New password is required."))
		return
	}
	if err := auth.ValidatePassword(in.NewPassword, u.Username, ""); err != nil {
		s.writeError(w, r, apierr.ValidationField("new_password", err.Error()))
		return
	}
	h, err := s.Hasher.Hash(in.NewPassword)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.Store.SetPassword(r.Context(), id, h, true, ""); err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "password_reset", u.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	es, total, err := s.Store.ListAudit(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(es))
	for _, e := range es {
		items = append(items, map[string]any{"id": e.ID, "at": ts(e.At), "actor_user_id": e.ActorUserID,
			"actor_name": e.ActorName, "action": e.Action, "target": e.Target})
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

// ----- ingest tokens (Admin) -----

func tokenView(t store.TokenRow) map[string]any {
	status := "active"
	if t.RevokedAt != nil {
		status = "revoked"
	}
	var project, createdBy any
	if t.ProjectID != nil {
		name := ""
		if t.ProjectName != nil {
			name = *t.ProjectName
		}
		project = projectRef(*t.ProjectID, name)
	}
	if t.CreatedBy != nil {
		name := ""
		if t.CreatedByName != nil {
			name = *t.CreatedByName
		}
		createdBy = map[string]any{"id": *t.CreatedBy, "username": name}
	}
	return map[string]any{"id": t.ID, "name": t.Name, "token_prefix": t.TokenPrefix, "project": project, "created_by": createdBy,
		"created_at": ts(t.CreatedAt), "last_used_at": tsp(t.LastUsedAt), "revoked_at": tsp(t.RevokedAt), "status": status}
}

const tokenPrefixLiteral = "sdrscan_"

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	p, err := parsePage(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	rows, total, err := s.Store.ListTokens(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]any, 0, len(rows))
	for _, t := range rows {
		items = append(items, tokenView(t))
	}
	writeJSON(w, http.StatusOK, pageJSON(items, total, p))
}

// createToken answers 201 {token, secret}; the secret is shown only here.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string `json:"name"`
		ProjectID *int64 `json:"project_id"`
	}
	if err := s.decode(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var fe apierr.FieldErrors
	name, err := validName("name", in.Name)
	fe.AddError(err)
	if in.ProjectID != nil && *in.ProjectID <= 0 {
		fe.Add("project_id", "project_id must be a positive integer.")
	}
	if err := fe.Err(); err != nil {
		s.writeError(w, r, err)
		return
	}
	raw := tokenPrefixLiteral + auth.NewToken(32)
	me := current(r)
	t, err := s.Store.CreateToken(r.Context(), name, auth.HashToken(raw), raw[:len(tokenPrefixLiteral)+4], in.ProjectID, &me.ID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "token_created", name)
	row, err := s.Store.GetTokenRow(r.Context(), t.ID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": tokenView(row), "secret": raw})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	t, err := s.Store.RevokeToken(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	me := current(r)
	s.Store.Audit(r.Context(), nil, &me.ID, me.Username, "token_revoked", t.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) systemInfo(w http.ResponseWriter, r *http.Request) {
	q, run, err := s.Store.QueueStats(r.Context(), canSeeURL(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	sast, dast := "", ""
	if s.Opt.EngineVersions != nil {
		sast, dast = s.Opt.EngineVersions()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Opt.Version,
		"engines": map[string]any{"sast": sast, "dast": dast},
		"queue":   map[string]any{"queued": q, "running": run},
	})
}
