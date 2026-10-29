// Package httpapi implements the REST API under /api/v1 and serves the web UI.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
	"github.com/sdrscan/sdrscan/backend/internal/auth"
	"github.com/sdrscan/sdrscan/backend/internal/crypt"
	"github.com/sdrscan/sdrscan/backend/internal/ingest"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/vulndb"
	"github.com/sdrscan/sdrscan/backend/internal/webui"
)

// Options configure the HTTP server.
type Options struct {
	Version       string
	AllowedHosts  []string
	CookieSecure  bool
	TrustProxy    bool
	MaxBodyBytes  int64
	SessionIdle   time.Duration
	SessionMax    time.Duration
	MaxLoginFails int
	LockFor       time.Duration
	LoginPerMin   int // per-IP login attempts per minute
	// Minimum interval between two scheduled runs (SDRSCAN_SCHEDULE_MIN_INTERVAL_*).
	MinIntervalSAST, MinIntervalDAST time.Duration
	// EngineVersions returns the cached engine version strings (may be nil).
	EngineVersions func() (sast, dast string)
}

func (o Options) withDefaults() Options {
	if o.Version == "" {
		o.Version = "dev"
	}
	if o.MaxBodyBytes == 0 {
		o.MaxBodyBytes = 50 << 20
	}
	if o.SessionIdle == 0 {
		o.SessionIdle = 8 * time.Hour
	}
	if o.SessionMax == 0 {
		o.SessionMax = 7 * 24 * time.Hour
	}
	if o.MaxLoginFails == 0 {
		o.MaxLoginFails = 5
	}
	if o.LockFor == 0 {
		o.LockFor = 15 * time.Minute
	}
	if o.LoginPerMin == 0 {
		o.LoginPerMin = 20
	}
	if o.MinIntervalSAST == 0 {
		o.MinIntervalSAST = 15 * time.Minute
	}
	if o.MinIntervalDAST == 0 {
		o.MinIntervalDAST = 60 * time.Minute
	}
	return o
}

// Server wires the handlers.
type Server struct {
	Store  *store.Store
	Ingest *ingest.Ingester
	Hasher *auth.Hasher
	Box    *crypt.Box
	Guard  *netguard.Guard
	Web    *webui.Handler
	Log    *slog.Logger
	Opt    Options
	// VulnDB manages the vulnerability database (status and the update job). New installs an inert
	// manager (feature not configured); the caller replaces it when SDRSCAN_VULN_DB is set.
	VulnDB *vulndb.Manager
	// LoginTester runs the engine's login check for POST /codebases/{id}/dast-auth/test
	// (the scan runner). When nil the endpoint answers 503 engine_unavailable.
	LoginTester LoginTester

	// Done is closed at shutdown so long-lived SSE streams end.
	Done <-chan struct{}

	loginLimiter *auth.IPLimiter
}

// New builds a Server.
func New(st *store.Store, ing *ingest.Ingester, box *crypt.Box, guard *netguard.Guard, web *webui.Handler, log *slog.Logger, opt Options) *Server {
	if log == nil {
		log = slog.Default()
	}
	opt = opt.withDefaults()
	return &Server{Store: st, Ingest: ing, Hasher: auth.NewHasher(), Box: box, Guard: guard, Web: web, Log: log, Opt: opt,
		VulnDB: vulndb.New(context.Background(), vulndb.Config{}, st, log), loginLimiter: auth.NewIPLimiter(opt.LoginPerMin)}
}

// Router returns the full handler (API, static files).
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.requestID, s.recoverer, s.accessLog, s.securityHeaders, s.hostCheck)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(noStore)
		r.Get("/healthz", s.healthz)
		r.Post("/auth/login", s.login)

		// Token endpoints (no session, no CSRF).
		r.Post("/ingest", s.ingestByName)
		r.Post("/codebases/{id}/ingest", s.ingestByID)

		// Session endpoints (CSRF enforced automatically for unsafe methods).
		r.Group(func(r chi.Router) {
			r.Use(s.session)
			r.Post("/auth/logout", s.logout)
			r.Get("/auth/me", s.me)
			r.Post("/auth/password", s.changePassword)

			r.Get("/projects", s.listProjects)
			r.Post("/projects", s.createProject)
			r.Get("/projects/{id}", s.getProject)
			r.Patch("/projects/{id}", s.updateProject)
			r.Post("/projects/{id}/codebases", s.createCodebase)

			r.Get("/codebases", s.listCodebases)
			r.Get("/schedules", s.listSchedules)
			r.Put("/codebases/{id}/schedule", s.putSchedule)
			r.Delete("/codebases/{id}/schedule", s.deleteSchedule)
			r.Post("/codebases/{id}/schedule/resume", s.resumeSchedule)
			r.Get("/codebases/{id}", s.getCodebase)
			r.Patch("/codebases/{id}", s.updateCodebase)
			r.Get("/codebases/{id}/dast-auth", s.getDastAuth)
			r.Put("/codebases/{id}/dast-auth", s.putDastAuth)
			r.Delete("/codebases/{id}/dast-auth", s.deleteDastAuth)
			r.Post("/codebases/{id}/dast-auth/test", s.testDastAuth)
			r.Post("/codebases/{id}/authorize-active-scanning", s.authorizeActiveScanning)
			r.Delete("/codebases/{id}/authorize-active-scanning", s.revokeActiveScanning)
			r.Get("/codebases/{id}/scans", s.listScans)
			r.Get("/codebases/{id}/compare", s.compare)
			r.Get("/codebases/{id}/findings", s.codebaseFindings)
			r.Get("/codebases/{id}/files", s.codebaseFiles)

			r.Post("/scans", s.createScan)
			r.Get("/scans/{id}", s.getScan)
			r.Get("/scans/{id}/events", s.scanEvents)
			r.Post("/scans/{id}/cancel", s.cancelScan)
			r.Get("/scans/{id}/findings", s.scanFindings)
			r.Get("/scans/{id}/files", s.scanFiles)

			r.Get("/findings/{id}", s.getFinding)
			r.Get("/system/info", s.systemInfo)

			// Admin only.
			r.Group(func(r chi.Router) {
				r.Use(s.requireAdmin)
				r.Get("/users", s.listUsers)
				r.Post("/users", s.createUser)
				r.Patch("/users/{id}", s.updateUser)
				r.Post("/users/{id}/reset-password", s.resetPassword)
				r.Get("/audit-log", s.listAudit)
				r.Get("/ingest-tokens", s.listTokens)
				r.Post("/ingest-tokens", s.createToken)
				r.Delete("/ingest-tokens/{id}", s.revokeToken)
				r.Delete("/projects/{id}", s.deleteProject)
				r.Delete("/codebases/{id}", s.deleteCodebase)
				r.Post("/codebases/{id}/confirm-authorization", s.confirmAuthorization)
				r.Get("/system/vulndb", s.getVulnDB)
				r.Post("/system/vulndb/update", s.startVulnDBUpdate)
				r.Post("/system/vulndb/update/cancel", s.cancelVulnDBUpdate)
			})
		})
		r.NotFound(func(w http.ResponseWriter, r *http.Request) { s.writeError(w, r, apierr.NotFound("Resource")) })
		r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			s.writeError(w, r, apierr.New(http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed."))
		})
	})

	web := http.Handler(s.Web)
	if s.Web == nil {
		web = http.NotFoundHandler()
	}
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/api/") || req.URL.Path == "/api" {
			s.writeError(w, req, apierr.NotFound("Resource"))
			return
		}
		web.ServeHTTP(w, req)
	})
	return r
}

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
	ctxReqID
)

// current returns the authenticated user of the request.
func current(r *http.Request) store.User {
	u, _ := r.Context().Value(ctxUser).(store.User)
	return u
}

func currentSession(r *http.Request) store.SessionInfo {
	si, _ := r.Context().Value(ctxSession).(store.SessionInfo)
	return si
}

func withValue(r *http.Request, k ctxKey, v any) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), k, v))
}
