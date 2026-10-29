package scanner_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/dastauth"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

// loginSite is a loopback site with a login form (CSRF token in a hidden input, JSON or form body)
// guarding /app/*; it records every path that was requested.
type loginSite struct {
	*httptest.Server
	mu   sync.Mutex
	hits []string
}

const siteUser, sitePass = "tester", "Sup3r-Secret-Pw!"

func newLoginSite(t *testing.T) *loginSite {
	t.Helper()
	s := &loginSite{}
	authed := func(r *http.Request) bool {
		c, err := r.Cookie("sid")
		return err == nil && c.Value == "session-ok-123456"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "pre", Value: "anon-1234567", Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><form method="post"><input type="hidden" name="_csrf" value="csrf-token-abc123"><input name="user"><input name="password" type="password"></form></body></html>`))
			return
		}
		var user, pass, csrf string
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var m map[string]string
			_ = json.NewDecoder(r.Body).Decode(&m)
			user, pass, csrf = m["user"], m["password"], m["_csrf"]
		} else {
			_ = r.ParseForm()
			user, pass, csrf = r.PostForm.Get("user"), r.PostForm.Get("password"), r.PostForm.Get("_csrf")
		}
		if user != siteUser || pass != sitePass || csrf != "csrf-token-abc123" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "session-ok-123456", Path: "/"})
		http.Redirect(w, r, "/app", http.StatusFound)
	})
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !authed(r) {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>" + body + "</body></html>"))
		}
	}
	mux.HandleFunc("/app", page(`<a href="/app/reports">reports</a> <a href="/logout">logout</a> <a href="/app/delete/1">delete</a>`))
	mux.HandleFunc("/app/reports", page(`<h1>Reports</h1><a href="/app">home</a>`))
	hdr := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-e2e-123456" || r.Header.Get("X-Api-Key") != "key-e2e-987654" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/api/more">more</a></body></html>`))
	}
	mux.HandleFunc("/api", hdr)
	mux.HandleFunc("/api/more", hdr)
	mux.HandleFunc("/logout", page(`bye`))
	mux.HandleFunc("/app/delete/1", page(`deleted`))
	mux.HandleFunc("/", page(`<a href="/app">app</a>`))
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *loginSite) requested(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hits {
		if strings.Contains(h, sub) {
			return true
		}
	}
	return false
}

func engineSupportsAuth(bin string) bool {
	out, err := exec.Command(bin, "scan", "--help").CombinedOutput()
	return err == nil && strings.Contains(string(out), "--auth-file") && strings.Contains(string(out), "--login-check")
}

// TestE2EAuthenticatedDastWithRealEngine runs the real dist/sdrscan-dast against a loopback site
// with a login form. It is skipped while the engine has no --auth-file support.
func TestE2EAuthenticatedDastWithRealEngine(t *testing.T) {
	e := testutil.RealEngines(t)
	if !engineSupportsAuth(e.Dast) {
		t.Skip("dist/sdrscan-dast does not support --auth-file/--login-check yet")
	}
	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	site := newLoginSite(t)
	cb := r.urlCB("live", site.URL, true)
	cfg := dastauth.Config{Type: dastauth.TypeForm, Login: &dastauth.Login{URL: site.URL + "/login", Method: "POST", BodyFormat: "json",
		UsernameField: "user", PasswordField: "password", Username: siteUser, Password: sitePass,
		CSRF:    &dastauth.CSRF{Source: "html_input", Name: "_csrf", SendAs: "field"},
		Success: &dastauth.Success{Statuses: []int{200, 302}, RedirectNotTo: "/login"}}}
	cb = r.setAuth(cb, cfg)
	r.setCrawl(cb, 3, 20, "^/app/delete")

	// The login check.
	chk, err := r.env.Runner.TestLogin(context.Background(), cb)
	if err != nil || !chk.OK || strings.Contains(chk.Message, sitePass) {
		t.Fatalf("login check: %+v %v", chk, err)
	}
	// The scan sees the pages behind the login.
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if !strings.Contains(logOf(sc), "authenticated scan") || strings.Contains(logOf(sc), sitePass) {
		t.Fatalf("log:\n%s", logOf(sc))
	}
	// The crawl reached the pages behind the login (findings are merged per rule and evidence, so the
	// proof is in the requests and in the page count of the job log).
	if !site.requested("GET /app/reports") || !strings.Contains(logOf(sc), "pages scanned") || !strings.Contains(logOf(sc), "crawl enabled") {
		t.Fatalf("the authenticated pages were not crawled: %v\n%s", site.hits, logOf(sc))
	}
	if total := r.countFindings(cb.ID); total == 0 {
		t.Fatal("expected passive findings")
	}
	if site.requested("/logout") || site.requested("/app/delete") || site.requested("POST /app") {
		t.Fatalf("the crawl must skip logout/delete paths and only GET: %v", site.hits)
	}
	var hits int
	_ = r.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings f WHERE f::text LIKE '%'||$1||'%' OR f::text LIKE '%session-ok-123456%'`, sitePass).Scan(&hits)
	if hits != 0 {
		t.Fatal("a credential or session value was stored in the findings")
	}
	r.assertWorkdirClean()

	// A wrong password fails the login check and the scan, without leaking it.
	bad := cfg
	l := *cfg.Login
	l.Password = "wrong-Passw0rd!"
	bad.Login = &l
	cb = r.setAuth(cb, bad)
	chk, err = r.env.Runner.TestLogin(context.Background(), cb)
	if err != nil || chk.OK || strings.Contains(chk.Message, "wrong-Passw0rd!") {
		t.Fatalf("wrong password check: %+v %v", chk, err)
	}
	sc = r.run(r.enqueue(cb))
	if sc.Status != "failed" || strings.Contains(logOf(sc), "wrong-Passw0rd!") {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
}

// TestE2EFixedHeadersWithRealEngine: header authentication (no login form) and a crawl behind it.
func TestE2EFixedHeadersWithRealEngine(t *testing.T) {
	e := testutil.RealEngines(t)
	if !engineSupportsAuth(e.Dast) {
		t.Skip("dist/sdrscan-dast does not support --auth-file/--login-check yet")
	}
	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	site := newLoginSite(t)
	cb := r.urlCB("api", site.URL+"/api", true)
	cb = r.setAuth(cb, dastauth.Config{Type: dastauth.TypeHeader,
		Headers: map[string]string{"Authorization": "Bearer tok-e2e-123456", "X-Api-Key": "key-e2e-987654"}})
	r.setCrawl(cb, 2, 10)
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" || !site.requested("GET /api/more") {
		t.Fatalf("%s %s\n%s\n%v", sc.Status, codeOf(sc), logOf(sc), site.hits)
	}
	if strings.Contains(logOf(sc), "tok-e2e-123456") || strings.Contains(logOf(sc), "key-e2e-987654") {
		t.Fatal("a header value reached the log")
	}
	// Fixed headers have no login step to check.
	if _, err := r.env.Runner.TestLogin(context.Background(), cb); err != scanner.ErrNoLogin {
		t.Fatalf("want ErrNoLogin, got %v", err)
	}
	r.assertWorkdirClean()
}

// TestE2ETokenLoginWithRealEngine: an API login that returns a token in the JSON body (no
// Set-Cookie), pages that need "Authorization: Bearer <token>", crawled by the real engine.
func TestE2ETokenLoginWithRealEngine(t *testing.T) {
	e := testutil.RealEngines(t)
	if !engineSupportsAuth(e.Dast) {
		t.Skip("dist/sdrscan-dast does not support --auth-file/--login-check yet")
	}
	if out, _ := exec.Command(e.Dast, "scan", "--help").CombinedOutput(); !strings.Contains(string(out), "--login-check") {
		t.Skip("old engine")
	}
	const token = "dyn.TOKEN-e2e-8812abcd"
	var mu sync.Mutex
	var seen []string
	var withToken, without int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if r.Method != http.MethodPost || m["username"] != siteUser || m["password"] != sitePass {
			http.Error(w, `{"message":"bad"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"access_token":"` + token + `"}}`))
	})
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.Method+" "+r.URL.Path)
			ok := r.Header.Get("Authorization") == "Bearer "+token
			if ok {
				withToken++
			} else {
				without++
			}
			mu.Unlock()
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>" + body + "</body></html>"))
		}
	}
	mux.HandleFunc("/app/reports", page(`<h1>Reports</h1><a href="/app">home</a>`))
	mux.HandleFunc("/app", page(`<a href="/app/reports">reports</a>`))
	mux.HandleFunc("/", page(`<a href="/app">app</a>`))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newRig(t, rigOpts{
		guard:  &netguard.Guard{AllowLoopback: true, Resolver: testutil.DefaultResolver()},
		runner: scanner.Config{SastBin: e.Sast, DastBin: e.Dast, Templates: e.Templates},
	})
	cb := r.urlCB("spa", srv.URL, true)
	cfg := dastauth.Config{Type: dastauth.TypeForm, Login: &dastauth.Login{URL: srv.URL + "/api/auth/login", Method: "POST", BodyFormat: "json",
		UsernameField: "username", PasswordField: "password", Username: siteUser, Password: sitePass,
		Token:   &dastauth.Token{From: "json", Path: "data.access_token"},
		Success: &dastauth.Success{JSONPathEquals: &dastauth.JSONEquals{Path: "status", Value: "ok"}}}}
	cb = r.setAuth(cb, cfg)
	r.setCrawl(cb, 3, 20)

	chk, err := r.env.Runner.TestLogin(context.Background(), cb)
	if err != nil || !chk.OK || !strings.Contains(chk.Message, "token diterima (header Authorization)") || strings.Contains(chk.Message, token) {
		t.Fatalf("login check: %+v %v", chk, err)
	}
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	mu.Lock()
	defer mu.Unlock()
	if without != 0 || withToken < 3 {
		t.Fatalf("every request must carry the token: with=%d without=%d %v", withToken, without, seen)
	}
	if strings.Contains(logOf(sc), token) || strings.Contains(logOf(sc), sitePass) {
		t.Fatalf("a secret reached the log:\n%s", logOf(sc))
	}
	var hits int
	_ = r.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings f WHERE f::text LIKE '%'||$1||'%'`, token).Scan(&hits)
	if hits != 0 {
		t.Fatal("the token was stored in the findings")
	}
	r.assertWorkdirClean()

	// A wrong path fails the login check with the hint-free message and without the body.
	bad := cfg
	l := *cfg.Login
	l.Token = &dastauth.Token{From: "json", Path: "data.salah"}
	bad.Login = &l
	cb = r.setAuth(cb, bad)
	chk, err = r.env.Runner.TestLogin(context.Background(), cb)
	if err != nil || chk.OK || !strings.Contains(chk.Message, "data.salah") || strings.Contains(chk.Message, token) {
		t.Fatalf("wrong path: %+v %v", chk, err)
	}
}
