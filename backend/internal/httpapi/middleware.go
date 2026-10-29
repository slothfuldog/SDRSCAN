package httpapi

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/auth"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

// SessionCookie is the name of the session cookie.
const SessionCookie = "sdrscan_session"

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush on the real writer (SSE).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 || strings.ContainsAny(id, "\r\n") {
			id = auth.NewHexToken(8)
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, withValue(r, ctxReqID, id))
	})
}

func requestIDOf(r *http.Request) string {
	id, _ := r.Context().Value(ctxReqID).(string)
	return id
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.Log.Error("panic in handler", "request_id", requestIDOf(r), "panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				s.writeError(w, r, apierr.Internal())
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			s.Log.Debug("request", "request_id", requestIDOf(r), "method", r.Method, "path", r.URL.Path,
				"status", sw.status, "duration", time.Since(start).Round(time.Microsecond))
		}
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		} else if s.Web != nil {
			h.Set("Content-Security-Policy", s.Web.CSP())
		}
		next.ServeHTTP(w, r)
	})
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// hostCheck rejects Host values outside SDRSCAN_ALLOWED_HOSTS (DNS rebinding).
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			s.writeError(w, r, apierr.Forbidden("forbidden_origin", "Host header is not allowed."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	if len(s.Opt.AllowedHosts) == 0 {
		return true
	}
	hn := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hn = h
	}
	hn = strings.ToLower(strings.Trim(hn, "[]"))
	lh := strings.ToLower(host)
	for _, a := range s.Opt.AllowedHosts {
		la := strings.ToLower(a)
		if la == "*" || la == lh || strings.Trim(la, "[]") == hn {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// checkOrigin enforces Origin == Host when the header is present.
func checkOrigin(r *http.Request) *apierr.Error {
	o := r.Header.Get("Origin")
	if o == "" {
		return nil
	}
	u, err := url.Parse(o)
	if err != nil || !strings.EqualFold(u.Host, r.Host) {
		return apierr.Forbidden("forbidden_origin", "Origin does not match the host.")
	}
	return nil
}

func hasBody(r *http.Request) bool { return r.ContentLength != 0 || len(r.TransferEncoding) > 0 }

func isJSONContent(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}

// session authenticates the cookie session and, for unsafe methods, enforces
// Origin, CSRF and the JSON content type.
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			s.writeError(w, r, apierr.New(http.StatusUnauthorized, "not_authenticated", "Sign in to continue."))
			return
		}
		si, err := s.Store.GetSession(r.Context(), auth.HashToken(c.Value), s.Opt.SessionIdle)
		if err != nil {
			if err == store.ErrNotFound {
				s.writeError(w, r, apierr.New(http.StatusUnauthorized, "not_authenticated", "Sign in to continue."))
				return
			}
			s.writeError(w, r, err)
			return
		}
		if !isSafeMethod(r.Method) {
			if e := checkOrigin(r); e != nil {
				s.writeError(w, r, e)
				return
			}
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(si.CSRF)) != 1 {
				s.writeError(w, r, apierr.Forbidden("csrf_invalid", "CSRF token is missing or invalid."))
				return
			}
			if hasBody(r) && !isJSONContent(r) {
				s.writeError(w, r, apierr.New(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json."))
				return
			}
		}
		r = withValue(withValue(r, ctxUser, si.User), ctxSession, si)
		// A forced password change blocks everything except the account endpoints.
		if si.User.MustChangePassword {
			p := strings.TrimPrefix(r.URL.Path, "/api/v1")
			if p != "/auth/me" && p != "/auth/password" && p != "/auth/logout" {
				s.writeError(w, r, apierr.Forbidden("password_change_required", "You must change your password before continuing."))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := current(r)
		if !u.IsAdmin() {
			uid := u.ID
			s.Store.Audit(r.Context(), nil, &uid, u.Username, "forbidden_role", r.Method+" "+r.URL.Path)
			s.writeError(w, r, apierr.Forbidden("forbidden_role", "You do not have permission to do this."))
			return
		}
		next.ServeHTTP(w, r)
	})
}
