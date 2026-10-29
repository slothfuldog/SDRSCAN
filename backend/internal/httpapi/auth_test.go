package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/httpapi"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func rawLogin(t *testing.T, env *testutil.Env, user, pass string) (testutil.Resp, *http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, _ := http.NewRequest("POST", env.HTTP.URL+"/api/v1/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == httpapi.SessionCookie {
			ck = c
		}
	}
	return testutil.Resp{Status: resp.StatusCode, Header: resp.Header, Body: buf.Bytes()}, ck
}

func TestLoginCookieAndSessionLifecycle(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	r, ck := rawLogin(t, w.env, "member", testutil.Password)
	if r.Status != 200 || ck == nil {
		t.Fatalf("login: %d %s", r.Status, r.Body)
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" || ck.Value == "" {
		t.Fatalf("cookie attributes: %+v", ck)
	}
	j := r.JSON()
	csrf, _ := j["csrf_token"].(string)
	if csrf == "" || j["user"].(map[string]any)["role"] != "member" {
		t.Fatalf("login body: %s", r.Body)
	}
	if strings.Contains(string(r.Body), "argon2") || strings.Contains(string(r.Body), "password_hash") {
		t.Fatal("hash leaked in login response")
	}
	c := &testutil.Client{Env: w.env, Cookie: ck.Value, CSRF: csrf}
	me := c.Get("/api/v1/auth/me")
	if me.Status != 200 || me.JSON()["csrf_token"] != csrf || me.JSON()["user"].(map[string]any)["username"] != "member" {
		t.Fatalf("me: %d %s", me.Status, me.Body)
	}
	// The token is replaced at every login.
	_, ck2 := rawLogin(t, w.env, "member", testutil.Password)
	if ck2.Value == ck.Value {
		t.Fatal("session token reused across logins")
	}
	// Only the hash of the token is stored.
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions WHERE id_hash = $1`, ck.Value).Scan(&n)
	if n != 0 {
		t.Fatal("raw session token stored in the database")
	}
	// Logout kills the session.
	if lo := c.Do("POST", "/api/v1/auth/logout", nil); lo.Status != 204 {
		t.Fatalf("logout: %d", lo.Status)
	}
	if after := c.Get("/api/v1/auth/me"); after.Status != 401 || after.ErrCode() != "not_authenticated" {
		t.Fatalf("after logout: %d %s", after.Status, after.Body)
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	bad1, _ := rawLogin(t, w.env, "member", "wrong-password-123")
	bad2, _ := rawLogin(t, w.env, "nobody", "wrong-password-123")
	if bad1.Status != 401 || bad2.Status != 401 || bad1.ErrCode() != "invalid_credentials" || bad2.ErrCode() != "invalid_credentials" {
		t.Fatalf("%d %s / %d %s", bad1.Status, bad1.Body, bad2.Status, bad2.Body)
	}
	m1, m2 := bad1.JSON()["error"].(map[string]any)["message"], bad2.JSON()["error"].(map[string]any)["message"]
	if m1 != m2 {
		t.Fatalf("messages differ: %v / %v", m1, m2)
	}
	// Inactive accounts answer the same way.
	if r := w.admin.Do("PATCH", "/api/v1/users/"+itoa(w.member.User.ID), map[string]any{"is_active": false}); r.Status != 200 {
		t.Fatalf("deactivate: %d %s", r.Status, r.Body)
	}
	in, _ := rawLogin(t, w.env, "member", testutil.Password)
	if in.Status != 401 || in.ErrCode() != "invalid_credentials" {
		t.Fatalf("inactive login: %d %s", in.Status, in.Body)
	}
}

func itoa(n int64) string {
	return strings.TrimSpace(strings.Replace(string(mustJSON(n)), "\"", "", -1))
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestAccountLockoutAfterFiveFailures(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	for i := 0; i < 5; i++ {
		r, _ := rawLogin(t, w.env, "dastuser", "wrong-password-123")
		if r.Status != 401 {
			t.Fatalf("attempt %d: %d", i, r.Status)
		}
	}
	// Even the right password is refused while locked, with Retry-After.
	r, _ := rawLogin(t, w.env, "dastuser", testutil.Password)
	if r.Status != 429 || r.ErrCode() != "login_throttled" || r.Header.Get("Retry-After") == "" {
		t.Fatalf("locked: %d %s", r.Status, r.Body)
	}
	var until time.Time
	if err := w.env.Pool.QueryRow(context.Background(), `SELECT locked_until FROM users WHERE username='dastuser'`).Scan(&until); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(until); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("lock duration %v", d)
	}
	// The lock is released after 15 minutes.
	_, _ = w.env.Pool.Exec(context.Background(), `UPDATE users SET locked_until = now() - interval '1 second' WHERE username='dastuser'`)
	if r, _ := rawLogin(t, w.env, "dastuser", testutil.Password); r.Status != 200 {
		t.Fatalf("after unlock: %d %s", r.Status, r.Body)
	}
	// Success resets the counter: four more failures do not lock.
	for i := 0; i < 4; i++ {
		rawLogin(t, w.env, "dastuser", "wrong-password-123")
	}
	if r, _ := rawLogin(t, w.env, "dastuser", testutil.Password); r.Status != 200 {
		t.Fatalf("counter not reset: %d", r.Status)
	}
	// Failures are audited.
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'login_failed'`).Scan(&n)
	if n < 5 {
		t.Fatalf("login_failed audit rows: %d", n)
	}
}

func TestPerIPLoginThrottle(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{Server: httpapi.Options{LoginPerMin: 3}})
	var last testutil.Resp
	for i := 0; i < 5; i++ {
		last, _ = rawLogin(t, w.env, "nobody"+itoa(int64(i)), "wrong-password-123")
	}
	if last.Status != 429 || last.Header.Get("Retry-After") == "" {
		t.Fatalf("expected IP throttle, got %d %s", last.Status, last.Body)
	}
}

func TestSessionExpiry(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	ctx := context.Background()
	if r := w.member.Get("/api/v1/auth/me"); r.Status != 200 {
		t.Fatal(r.Status)
	}
	_, _ = w.env.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() - interval '9 hours' WHERE user_id = $1`, w.member.User.ID)
	if r := w.member.Get("/api/v1/auth/me"); r.Status != 401 {
		t.Fatalf("idle session still valid: %d", r.Status)
	}
	if r := w.dastUser.Get("/api/v1/auth/me"); r.Status != 200 {
		t.Fatal(r.Status)
	}
	_, _ = w.env.Pool.Exec(ctx, `UPDATE sessions SET expires_at = now() - interval '1 second' WHERE user_id = $1`, w.dastUser.User.ID)
	if r := w.dastUser.Get("/api/v1/auth/me"); r.Status != 401 {
		t.Fatalf("absolutely expired session still valid: %d", r.Status)
	}
}

func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	other := w.env.Login(w.member.User)
	r := w.member.Do("POST", "/api/v1/auth/password", map[string]string{"current_password": "nope-nope-nope-1", "new_password": "a-brand-new-password"})
	if r.Status != 422 {
		t.Fatalf("wrong current password: %d", r.Status)
	}
	r = w.member.Do("POST", "/api/v1/auth/password", map[string]string{"current_password": testutil.Password, "new_password": "short"})
	if r.Status != 422 {
		t.Fatalf("short password: %d", r.Status)
	}
	r = w.member.Do("POST", "/api/v1/auth/password", map[string]string{"current_password": testutil.Password, "new_password": testutil.Password})
	if r.Status != 422 {
		t.Fatalf("same password: %d", r.Status)
	}
	r = w.member.Do("POST", "/api/v1/auth/password", map[string]string{"current_password": testutil.Password, "new_password": "a-brand-new-password"})
	if r.Status != 204 {
		t.Fatalf("change: %d %s", r.Status, r.Body)
	}
	if got := w.member.Get("/api/v1/auth/me"); got.Status != 200 {
		t.Fatalf("current session must survive: %d", got.Status)
	}
	if got := other.Get("/api/v1/auth/me"); got.Status != 401 {
		t.Fatalf("other session must be revoked: %d", got.Status)
	}
	if r, _ := rawLogin(t, w.env, "member", "a-brand-new-password"); r.Status != 200 {
		t.Fatalf("login with the new password: %d", r.Status)
	}
}

func TestForcedPasswordChange(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	// Admin creates an account: it must change the password first.
	r := w.admin.Do("POST", "/api/v1/users", map[string]any{"username": "newbie", "password": "temporary-password-1", "role": "member"})
	if r.Status != 201 || r.JSON()["must_change_password"] != true {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	lr, ck := rawLogin(t, w.env, "newbie", "temporary-password-1")
	if lr.Status != 200 || lr.JSON()["must_change_password"] != true {
		t.Fatalf("login: %d %s", lr.Status, lr.Body)
	}
	c := &testutil.Client{Env: w.env, Cookie: ck.Value, CSRF: lr.JSON()["csrf_token"].(string)}
	if g := c.Get("/api/v1/projects"); g.Status != 403 || g.ErrCode() != "password_change_required" {
		t.Fatalf("other endpoints must be blocked: %d %s", g.Status, g.Body)
	}
	if g := c.Get("/api/v1/auth/me"); g.Status != 200 || g.JSON()["must_change_password"] != true {
		t.Fatalf("me: %d", g.Status)
	}
	if g := c.Do("POST", "/api/v1/auth/password", map[string]string{"current_password": "temporary-password-1", "new_password": "my-own-new-password"}); g.Status != 204 {
		t.Fatalf("change: %d %s", g.Status, g.Body)
	}
	if g := c.Get("/api/v1/projects"); g.Status != 200 {
		t.Fatalf("after change: %d", g.Status)
	}
}

func TestResetPasswordAndDeactivateRevokeSessions(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	uid := itoa(w.member.User.ID)
	if r := w.admin.Do("POST", "/api/v1/users/"+uid+"/reset-password", map[string]string{"new_password": "temp-password-12345"}); r.Status != 204 {
		t.Fatalf("reset: %d %s", r.Status, r.Body)
	}
	if r := w.member.Get("/api/v1/auth/me"); r.Status != 401 {
		t.Fatalf("session survived the reset: %d", r.Status)
	}
	lr, _ := rawLogin(t, w.env, "member", "temp-password-12345")
	if lr.Status != 200 || lr.JSON()["must_change_password"] != true {
		t.Fatalf("login after reset: %d %s", lr.Status, lr.Body)
	}
	// Deactivation revokes too.
	if r := w.admin.Do("PATCH", "/api/v1/users/"+itoa(w.dastUser.User.ID), map[string]any{"is_active": false}); r.Status != 200 {
		t.Fatal(r.Status)
	}
	if r := w.dastUser.Get("/api/v1/auth/me"); r.Status != 401 {
		t.Fatalf("session survived deactivation: %d", r.Status)
	}
	// Audit trail.
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action IN ('password_reset','user_disabled')`).Scan(&n)
	if n != 2 {
		t.Fatalf("audit rows = %d", n)
	}
}

func TestCSRFOriginHostAndContentType(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	body := `{"name":"X"}`
	hdr := func(h map[string]string) map[string]string { h["Content-Type"] = "application/json"; return h }
	cookieOnly := &testutil.Client{Env: w.env, Cookie: w.member.Cookie} // no CSRF header
	if r := cookieOnly.Raw("POST", "/api/v1/projects", strings.NewReader(body), hdr(map[string]string{})); r.Status != 403 || r.ErrCode() != "csrf_invalid" {
		t.Fatalf("missing csrf: %d %s", r.Status, r.Body)
	}
	if r := cookieOnly.Raw("POST", "/api/v1/projects", strings.NewReader(body), hdr(map[string]string{"X-CSRF-Token": "wrong"})); r.Status != 403 || r.ErrCode() != "csrf_invalid" {
		t.Fatalf("wrong csrf: %d %s", r.Status, r.Body)
	}
	if r := w.member.Raw("POST", "/api/v1/projects", strings.NewReader(body), hdr(map[string]string{"Origin": "https://evil.example"})); r.Status != 403 || r.ErrCode() != "forbidden_origin" {
		t.Fatalf("foreign origin: %d %s", r.Status, r.Body)
	}
	if r := w.member.Raw("POST", "/api/v1/projects", strings.NewReader(body), map[string]string{"Content-Type": "text/plain"}); r.Status != 415 {
		t.Fatalf("non-JSON body: %d %s", r.Status, r.Body)
	}
	if r := w.member.Raw("POST", "/api/v1/projects", strings.NewReader("<x/>"), map[string]string{"Content-Type": "application/xml"}); r.Status != 415 {
		t.Fatalf("xml body: %d", r.Status)
	}
	if r := w.member.Raw("POST", "/api/v1/projects", strings.NewReader("{not json"), hdr(map[string]string{})); r.Status != 400 || r.ErrCode() != "bad_request" {
		t.Fatalf("broken JSON: %d %s", r.Status, r.Body)
	}
	if r := w.member.Raw("POST", "/api/v1/projects", strings.NewReader(body), hdr(map[string]string{})); r.Status != 201 {
		t.Fatalf("valid request refused: %d %s", r.Status, r.Body)
	}
	// Host header must be allowed (DNS rebinding).
	req, _ := http.NewRequest("GET", w.env.HTTP.URL+"/api/v1/healthz", nil)
	req.Host = "attacker.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("foreign Host header: %d", resp.StatusCode)
	}
	// A write without a session is 401 before CSRF is considered.
	if r := w.anon.Raw("POST", "/api/v1/projects", strings.NewReader(body), hdr(map[string]string{})); r.Status != 401 {
		t.Fatalf("anonymous write: %d", r.Status)
	}
}

func TestResponseHeaders(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	r := w.admin.Get("/api/v1/projects")
	if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("X-Content-Type-Options") != "nosniff" || r.Header.Get("X-Request-Id") == "" {
		t.Fatalf("api headers: %v", r.Header)
	}
	idx := w.anon.Get("/")
	if idx.Status != 200 || !strings.Contains(idx.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		!strings.Contains(idx.Header.Get("Content-Security-Policy"), "default-src 'none'") || idx.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("static headers: %d %v", idx.Status, idx.Header)
	}
	if spa := w.anon.Get("/projects/3/codebases"); spa.Status != 200 {
		t.Fatalf("SPA fallback: %d", spa.Status)
	}
	if nf := w.anon.Get("/api/v1/nope"); nf.Status != 404 || nf.ErrCode() != "not_found" {
		t.Fatalf("unknown API route: %d %s", nf.Status, nf.Body)
	}
	hz := w.anon.Get("/api/v1/healthz")
	if hz.Status != 200 || strings.TrimSpace(string(hz.Body)) != `{"status":"ok"}` {
		t.Fatalf("healthz: %d %s", hz.Status, hz.Body)
	}
	// Error bodies carry the request id.
	e := w.anon.Get("/api/v1/projects")
	if e.JSON()["error"].(map[string]any)["request_id"] == "" {
		t.Fatalf("error body without request_id: %s", e.Body)
	}
}

func TestLastAdminRule(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	aid := itoa(w.admin.User.ID)
	// The only admin cannot demote or deactivate themselves.
	if r := w.admin.Do("PATCH", "/api/v1/users/"+aid, map[string]any{"role": "member"}); r.Status != 409 || r.ErrCode() != "last_admin" {
		t.Fatalf("demote last admin: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("PATCH", "/api/v1/users/"+aid, map[string]any{"is_active": false}); r.Status != 409 || r.ErrCode() != "last_admin" {
		t.Fatalf("deactivate last admin: %d %s", r.Status, r.Body)
	}
	// Promote a second admin; now either may be demoted, but never both.
	other := w.env.CreateUser("admin2", "admin", false)
	oc := w.env.Login(other)
	if r := w.admin.Do("PATCH", "/api/v1/users/"+itoa(other.ID), map[string]any{"role": "admin"}); r.Status != 200 {
		t.Fatalf("no-op patch: %d", r.Status)
	}
	if r := w.admin.Do("PATCH", "/api/v1/users/"+itoa(other.ID), map[string]any{"is_active": false}); r.Status != 200 {
		t.Fatalf("deactivate second admin: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("PATCH", "/api/v1/users/"+itoa(other.ID), map[string]any{"is_active": true}); r.Status != 200 {
		t.Fatal(r.Status)
	}
	_ = oc
	// Two admins deactivating each other at the same time: exactly one wins.
	admin2 := w.env.Login(other)
	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		codes[0] = w.admin.Do("PATCH", "/api/v1/users/"+itoa(other.ID), map[string]any{"is_active": false}).Status
	}()
	go func() {
		defer wg.Done()
		codes[1] = admin2.Do("PATCH", "/api/v1/users/"+aid, map[string]any{"is_active": false}).Status
	}()
	wg.Wait()
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 409:
			conflict++
		case 401:
			// the deactivated admin's own session may already be gone
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("concurrent deactivation: %v", codes)
	}
	var n int
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE role='admin' AND is_active`).Scan(&n)
	if n != 1 {
		t.Fatalf("active admins = %d", n)
	}
}
