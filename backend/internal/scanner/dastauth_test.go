package scanner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/crypt"
	"github.com/sdrscan/sdrscan/backend/internal/dastauth"
	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

const (
	secretPassword = "S3cret-Passw0rd!"
	secretToken    = "tok-9f8e7d6c5b4a39281706"
	secretCookie   = "sess-abcdef0123456789"
	secretExtra    = "otp-77123456"
	baseURL        = "https://shop.example.com"
)

func testAuthConfig() dastauth.Config {
	return dastauth.Config{
		Type: dastauth.TypeFormHeader,
		Login: &dastauth.Login{URL: baseURL + "/login", Method: "POST", BodyFormat: "json", UsernameField: "user", PasswordField: "password",
			Username: "tester", Password: secretPassword, ExtraFields: map[string]string{"otp": secretExtra},
			CSRF:    &dastauth.CSRF{Source: "html_input", Name: "_csrf", SendAs: "field"},
			Success: &dastauth.Success{Statuses: []int{200, 302}, RedirectNotTo: "/login"}},
		Headers: map[string]string{"Authorization": "Bearer " + secretToken},
		Cookies: map[string]string{"sid": secretCookie},
	}
}

// setAuth seals cfg with the rig's key and stores it on the codebase.
func (r *rig) setAuth(cb store.Codebase, cfg dastauth.Config) store.Codebase {
	r.t.Helper()
	plain, _ := json.Marshal(cfg)
	enc, err := r.env.Box.Seal(plain)
	if err != nil {
		r.t.Fatal(err)
	}
	meta, _ := json.Marshal(dastauth.MetaOf(cfg, time.Now(), nil))
	out, err := r.env.Store.SetDastAuth(context.Background(), cb.ID, *cb.BaseURL, cfg.Type, enc, meta)
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *rig) setCrawl(cb store.Codebase, depth, pages int, exclude ...string) {
	r.t.Helper()
	if _, err := r.env.Store.UpdateCodebase(context.Background(), cb.ID, map[string]any{
		"dast_crawl_enabled": true, "dast_crawl_max_depth": depth, "dast_crawl_max_pages": pages, "dast_crawl_exclude": exclude}); err != nil {
		r.t.Fatal(err)
	}
}

// authEngine is a fake sdrscan-dast: it answers `scan --help` with flags, and on a scan records
// argv, its environment, the auth file's mode and content in rec, then runs body.
func authEngine(t *testing.T, rec, flags, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dast.sh")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "sdrscan-dast 0.1.0"; exit 0; fi
if [ "$1" = "scan" ] && [ "$2" = "--help" ]; then echo "` + flags + `"; exit 0; fi
REC='` + rec + `'
printf '%s\n' "$@" > "$REC/argv"
env > "$REC/env"
out=""; auth=""
while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift;; --auth-file) auth="$2"; shift;; esac; shift; done
if [ -n "$auth" ]; then
  echo "$auth" > "$REC/authpath"
  ls -l "$auth" | cut -c1-10 > "$REC/mode"
  cp "$auth" "$REC/auth.json"
fi
` + body
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

const allFlags = "--max-rps --templates --vuln-db --auth-file --login-check --crawl --max-depth --max-pages --exclude-path"

func dastSarif(t *testing.T, msg string) string {
	t.Helper()
	d := testutil.Doc{Engine: "sdrscan-dast", Rules: []testutil.RuleMeta{{ID: "dast-missing-csp", Score: "5.0", Tags: []string{"external/cwe/cwe-693"}}},
		Results: []testutil.SResult{{Rule: "dast-missing-csp", URI: baseURL + "/", Message: msg, Level: "warning"}}}
	return writeSarif(t, d)
}

// runnerWith is a fresh runner (its own flag probe) using another DAST engine.
func (r *rig) runnerWith(bin string) *scanner.Runner {
	cfg := r.env.Runner.Cfg
	cfg.DastBin = bin
	return scanner.New(r.env.Store, r.env.Ingest, r.env.Guard, r.env.Box, cfg, nil)
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func authRig(t *testing.T, flags, body string, sarifMsg string) (*rig, string, store.Codebase) {
	t.Helper()
	rec := t.TempDir()
	r := newRig(t, rigOpts{})
	sarif := dastSarif(t, sarifMsg)
	r.env.Runner.Cfg.DastBin = authEngine(t, rec, flags, strings.ReplaceAll(body, "$SARIF", sarif))
	cb := r.urlCB("live", baseURL, true)
	return r, rec, cb
}

func TestAuthenticatedScanUsesAnAuthFileAndNeverArgvOrEnv(t *testing.T) {
	r, rec, cb := authRig(t, allFlags, "echo 'Ringkasan: 7 halaman dipindai, 1 temuan, 0 peringatan' >&2\ncp \"$SARIF\" \"$out\"\nexit 1\n", "Content-Security-Policy is missing")
	cb = r.setAuth(cb, testAuthConfig())
	r.setCrawl(cb, 4, 20, "^/admin", "export\\.csv$")
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	argv, env := read(t, filepath.Join(rec, "argv")), read(t, filepath.Join(rec, "env"))
	for _, want := range []string{"--auth-file", "--crawl", "--max-depth\n4", "--max-pages\n20", "--exclude-path\n^/admin", "--exclude-path\nexport\\.csv$"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv lacks %q:\n%s", want, argv)
		}
	}
	for _, sec := range []string{secretPassword, secretToken, secretCookie, secretExtra, "tester"} {
		if strings.Contains(argv, sec) || strings.Contains(env, sec) {
			t.Errorf("a credential value (%q) leaked into argv or the environment", sec)
		}
	}
	if strings.Contains(env, "SDRSCAN_SECRET_KEY") || strings.Contains(env, "DATABASE_URL") {
		t.Errorf("engine environment is not clean:\n%s", env)
	}
	if mode := strings.TrimSpace(read(t, filepath.Join(rec, "mode"))); mode != "-rw-------" {
		t.Errorf("auth file mode %q, want -rw-------", mode)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, filepath.Join(rec, "auth.json"))), &doc); err != nil {
		t.Fatal(err)
	}
	login := doc["login"].(map[string]any)
	if doc["version"].(float64) != 1 || login["type"] != "form" || login["password"] != secretPassword || login["username"] != "tester" ||
		login["body_format"] != "json" || login["extra_fields"].(map[string]any)["otp"] != secretExtra ||
		doc["headers"].(map[string]any)["Authorization"] != "Bearer "+secretToken || doc["cookies"].(map[string]any)["sid"] != secretCookie {
		t.Fatalf("auth file content: %v", doc)
	}
	// The file is gone after the run, and so is everything else.
	if _, err := os.Stat(strings.TrimSpace(read(t, filepath.Join(rec, "authpath")))); !os.IsNotExist(err) {
		t.Errorf("auth file still exists: %v", err)
	}
	r.assertWorkdirClean()
	for _, want := range []string{"authenticated scan (form+header)", "crawl enabled (max depth 4, max pages 20, 2 excluded patterns)", "scan summary: 7 pages scanned"} {
		if !strings.Contains(logOf(sc), want) {
			t.Errorf("log lacks %q:\n%s", want, logOf(sc))
		}
	}
	for _, sec := range []string{secretPassword, secretToken, secretCookie, secretExtra} {
		if strings.Contains(logOf(sc), sec) {
			t.Errorf("log_tail contains a credential value")
		}
	}
	if r.countFindings(cb.ID) != 1 {
		t.Fatalf("findings: %d", r.countFindings(cb.ID))
	}
}

func TestScanWithoutAuthOrCrawlPassesNoAuthFlags(t *testing.T) {
	r, rec, cb := authRig(t, allFlags, "cp \"$SARIF\" \"$out\"\nexit 1\n", "m")
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	argv := read(t, filepath.Join(rec, "argv"))
	for _, no := range []string{"--auth-file", "--crawl", "--max-depth", "--exclude-path", "--login-check"} {
		if strings.Contains(argv, no) {
			t.Errorf("argv must not contain %s:\n%s", no, argv)
		}
	}
	if strings.Contains(logOf(sc), "authenticated") {
		t.Errorf("log: %s", logOf(sc))
	}
}

func TestEngineOutputIsRedactedInLogTailErrorsAndFindings(t *testing.T) {
	leak := "stderr: login as tester with " + secretPassword + " token " + secretToken + " cookie " + secretCookie + " otp " + secretExtra
	// 1. Failing engine: the error message (last stderr lines) and the log are redacted.
	r, _, cb := authRig(t, allFlags, "echo '"+leak+"' >&2\nexit 2\n", "m")
	cb = r.setAuth(cb, testAuthConfig())
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "engine_failed" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	assertNoSecrets(t, logOf(sc))
	if !strings.Contains(logOf(sc), "[REDACTED]") {
		t.Fatalf("expected redaction markers:\n%s", logOf(sc))
	}
	r.assertWorkdirClean()

	// 2. Succeeding engine that prints a warning with a secret and puts one into the SARIF message.
	body := "echo 'peringatan: " + leak + "' >&2\ncp \"$SARIF\" \"$out\"\nexit 1\n"
	r2, _, cb2 := authRig(t, allFlags, body, "evidence "+secretToken+" and url-encoded "+"S3cret-Passw0rd%21")
	cb2 = r2.setAuth(cb2, testAuthConfig())
	sc2 := r2.run(r2.enqueue(cb2))
	if sc2.Status != "succeeded" {
		t.Fatalf("%s %s\n%s", sc2.Status, codeOf(sc2), logOf(sc2))
	}
	assertNoSecrets(t, logOf(sc2))
	var hits int
	_ = r2.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings f WHERE f::text LIKE '%'||$1||'%'`, secretToken).Scan(&hits)
	var hits2 int
	_ = r2.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings f WHERE f::text LIKE '%S3cret-Passw0rd%'`).Scan(&hits2)
	if hits != 0 || hits2 != 0 {
		t.Fatalf("a credential reached the findings table (%d, %d)", hits, hits2)
	}
	if !strings.Contains(logOf(sc2), "were redacted") {
		t.Errorf("expected the SARIF redaction notice:\n%s", logOf(sc2))
	}
}

func assertNoSecrets(t *testing.T, text string) {
	t.Helper()
	for _, sec := range []string{secretPassword, secretToken, secretCookie, secretExtra, "S3cret-Passw0rd%21"} {
		if strings.Contains(text, sec) {
			t.Errorf("text contains the credential value %q:\n%s", sec, text)
		}
	}
}

func TestAuthConfiguredButEngineWithoutAuthFileFailsWithoutRunning(t *testing.T) {
	r, rec, cb := authRig(t, "--max-rps --templates", "cp \"$SARIF\" \"$out\"\nexit 1\n", "m")
	cb = r.setAuth(cb, testAuthConfig())
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "engine_unsupported" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if _, err := os.Stat(filepath.Join(rec, "argv")); err == nil {
		t.Fatal("the engine must not run an authenticated target without --auth-file support")
	}
	r.assertWorkdirClean()
}

func TestCrawlWithEngineLackingCrawlIsSkippedButExclusionsAreNeverDropped(t *testing.T) {
	// No --crawl at all: the scan runs without crawling and says so.
	r, rec, cb := authRig(t, "--max-rps", "cp \"$SARIF\" \"$out\"\nexit 1\n", "m")
	r.setCrawl(cb, 3, 50, "^/x")
	sc := r.run(r.enqueue(cb))
	if sc.Status != "succeeded" || !strings.Contains(logOf(sc), "does not support --crawl") {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if strings.Contains(read(t, filepath.Join(rec, "argv")), "--crawl") {
		t.Fatal("--crawl must not be passed")
	}
	// --crawl without --exclude-path: refuse rather than crawl without the user's exclusions.
	r2, rec2, cb2 := authRig(t, "--max-rps --crawl --max-depth --max-pages", "cp \"$SARIF\" \"$out\"\nexit 1\n", "m")
	r2.setCrawl(cb2, 3, 50, "^/x")
	sc2 := r2.run(r2.enqueue(cb2))
	if sc2.Status != "failed" || codeOf(sc2) != "engine_unsupported" {
		t.Fatalf("%s %s\n%s", sc2.Status, codeOf(sc2), logOf(sc2))
	}
	if _, err := os.Stat(filepath.Join(rec2, "argv")); err == nil {
		t.Fatal("the engine must not run")
	}
}

func TestAuthFileIsRemovedOnTimeoutAndCancel(t *testing.T) {
	// Timeout.
	r, rec, cb := authRig(t, allFlags, "sleep 60 &\nwait\n", "m")
	r.env.Runner.Cfg.DastTimeout = 2 * time.Second
	cb = r.setAuth(cb, testAuthConfig())
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "timeout" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if _, err := os.Stat(strings.TrimSpace(read(t, filepath.Join(rec, "authpath")))); !os.IsNotExist(err) {
		t.Errorf("auth file survived the timeout: %v", err)
	}
	r.assertWorkdirClean()

	// Cancel while the engine runs.
	r2, rec2, cb2 := authRig(t, allFlags, "sleep 60 &\nwait\n", "m")
	cb2 = r2.setAuth(cb2, testAuthConfig())
	sc2 := r2.enqueue(cb2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r2.env.Runner.RunOnce(context.Background())
	}()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(rec2, "mode")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("engine never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp := r2.env.Login(r2.adm).Do("POST", fmt.Sprintf("/api/v1/scans/%d/cancel", sc2.ID), nil); resp.Status != 202 {
		t.Fatalf("cancel: %d %s", resp.Status, resp.Body)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("job did not stop")
	}
	got, _ := r2.env.Store.GetScan(context.Background(), sc2.ID)
	if got.Status != "cancelled" {
		t.Fatalf("status %s", got.Status)
	}
	if _, err := os.Stat(strings.TrimSpace(read(t, filepath.Join(rec2, "authpath")))); !os.IsNotExist(err) {
		t.Errorf("auth file survived the cancel: %v", err)
	}
	r2.assertWorkdirClean()
}

func TestStaleAuthFilesLeftByACrashAreSweptAtStart(t *testing.T) {
	r := newRig(t, rigOpts{})
	dir := filepath.Join(r.work, "scan-99-abc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old, fresh := filepath.Join(dir, "auth-111.json"), filepath.Join(dir, "auth-222.json")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.env.Runner.Start(ctx)
	cancel()
	r.env.Runner.Wait()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("a stale auth file must be removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a recent auth file (a job may still run) must stay")
	}
}

func TestStoredCredentialsAreNotSentWhenTheOriginNoLongerMatchesOrCannotBeDecrypted(t *testing.T) {
	// The base URL moved to another host behind the API's back: refuse to send the credentials.
	r, rec, cb := authRig(t, allFlags, "cp \"$SARIF\" \"$out\"\nexit 1\n", "m")
	cb = r.setAuth(cb, testAuthConfig())
	other := "https://shop2.example.com"
	if _, err := r.env.Store.UpdateCodebase(context.Background(), cb.ID, map[string]any{"base_url": other}); err != nil {
		t.Fatal(err)
	}
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" || codeOf(sc) != "auth_unreadable" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	if _, err := os.Stat(filepath.Join(rec, "argv")); err == nil {
		t.Fatal("the engine must not run")
	}
	// A different SDRSCAN_SECRET_KEY cannot open the data.
	r2, rec2, cb2 := authRig(t, allFlags, "cp \"$SARIF\" \"$out\"\nexit 1\n", "m")
	cb2 = r2.setAuth(cb2, testAuthConfig())
	box, _ := crypt.New([]byte(strings.Repeat("k", 32)))
	r2.env.Runner.Box = box
	sc2 := r2.run(r2.enqueue(cb2))
	if sc2.Status != "failed" || codeOf(sc2) != "auth_unreadable" || !strings.Contains(logOf(sc2), "SDRSCAN_SECRET_KEY") {
		t.Fatalf("%s %s\n%s", sc2.Status, codeOf(sc2), logOf(sc2))
	}
	if _, err := os.Stat(filepath.Join(rec2, "argv")); err == nil {
		t.Fatal("the engine must not run")
	}
}

func TestScheduledDastScanUsesTheSameCredentials(t *testing.T) {
	r, rec, cb := authRig(t, allFlags, "cp \"$SARIF\" \"$out\"\nexit 1\n", "m")
	cb = r.setAuth(cb, testAuthConfig())
	ctx := context.Background()
	owner := r.env.CreateUser("owner", "member", true)
	if _, err := r.env.Store.SetSchedule(ctx, cb.ID, "0 * * * *", owner.ID); err != nil {
		t.Fatal(err)
	}
	job, err := r.env.Store.CreateJob(ctx, cb.ID, "dast", "schedule", &owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := r.run(job)
	if got.Status != "succeeded" || got.Trigger != "schedule" {
		t.Fatalf("%s %s\n%s", got.Status, codeOf(got), logOf(got))
	}
	if !strings.Contains(read(t, filepath.Join(rec, "argv")), "--auth-file") || !strings.Contains(read(t, filepath.Join(rec, "auth.json")), secretPassword) {
		t.Fatal("the scheduled scan did not use the stored credentials")
	}
}

func TestTestLoginReportsTheEngineResultRedacted(t *testing.T) {
	r, rec, cb := authRig(t, allFlags, "if grep -q '"+secretPassword+"' \"$auth\"; then echo 'login ok: HTTP 302 -> /home (cookie sid set) '"+"'"+secretCookie+"'; exit 0; fi\nexit 2\n", "m")
	cb = r.setAuth(cb, testAuthConfig())
	res, err := r.env.Runner.TestLogin(context.Background(), cb)
	if err != nil || !res.OK || !strings.Contains(res.Message, "login ok") || strings.Contains(res.Message, secretCookie) {
		t.Fatalf("%+v %v", res, err)
	}
	argv := read(t, filepath.Join(rec, "argv"))
	if !strings.Contains(argv, "--login-check") || !strings.Contains(argv, "--auth-file") || strings.Contains(argv, secretPassword) {
		t.Fatalf("argv: %s", argv)
	}
	if _, err := os.Stat(strings.TrimSpace(read(t, filepath.Join(rec, "authpath")))); !os.IsNotExist(err) {
		t.Error("auth file must be removed")
	}
	r.assertWorkdirClean()
	// A failing login (exit 2) is a result, not an error; stderr is redacted.
	res, err = r.runnerWith(authEngine(t, rec, allFlags, "echo 'Login gagal: password "+secretPassword+" ditolak (HTTP 401)' >&2\nexit 2\n")).TestLogin(context.Background(), cb)
	if err != nil || res.OK || !strings.Contains(res.Message, "Login gagal") || strings.Contains(res.Message, secretPassword) {
		t.Fatalf("%+v %v", res, err)
	}
	// An engine without --login-check.
	if _, err = r.runnerWith(authEngine(t, rec, "--max-rps", "exit 0\n")).TestLogin(context.Background(), cb); err != scanner.ErrEngineUnsupported {
		t.Fatalf("want ErrEngineUnsupported, got %v", err)
	}
}

var _ = netguard.ErrBlocked

// A token obtained at login is dynamic: it is not in the stored secrets, so a leaky engine's
// Bearer/JWT values are masked by pattern, in the job log, in errors and in the login-check message.
func TestDynamicLoginTokensAreMaskedByPatternInLogsAndLoginCheck(t *testing.T) {
	dyn := "TKN9f8e7d6c5b4a3928"
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMe"
	leak := "stderr: Authorization: Bearer " + dyn + " jwt=" + jwt
	r, rec, cb := authRig(t, allFlags, "echo '"+leak+"' >&2\nexit 2\n", "m")
	cfg := testAuthConfig()
	cfg.Login.Token = &dastauth.Token{From: "json", Path: "data.access_token", SendAs: "header", HeaderName: "Authorization"}
	cb = r.setAuth(cb, cfg)
	sc := r.run(r.enqueue(cb))
	if sc.Status != "failed" {
		t.Fatalf("%s %s\n%s", sc.Status, codeOf(sc), logOf(sc))
	}
	for _, text := range []string{logOf(sc), codeOf(sc)} {
		if strings.Contains(text, dyn) || strings.Contains(text, "SflKxwRJ") {
			t.Fatalf("a dynamic token reached the log:\n%s", text)
		}
	}
	if !strings.Contains(logOf(sc), "Bearer [REDACTED]") {
		t.Fatalf("expected the Bearer value to be masked:\n%s", logOf(sc))
	}
	// The login check message too (stdout of a successful check and stderr of a failing one).
	res, err := r.runnerWith(authEngine(t, rec, allFlags, "echo 'login berhasil: token diterima (header Authorization) Bearer "+dyn+"'\nexit 0\n")).TestLogin(context.Background(), cb)
	if err != nil || !res.OK || strings.Contains(res.Message, dyn) || !strings.Contains(res.Message, "token diterima") {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = r.runnerWith(authEngine(t, rec, allFlags, "echo 'galat "+jwt+"' >&2\nexit 2\n")).TestLogin(context.Background(), cb)
	if err != nil || res.OK || strings.Contains(res.Message, "SflKxwRJ") {
		t.Fatalf("%+v %v", res, err)
	}
	// The auth file handed to the engine carries the token settings.
	r.run(r.enqueue(cb))
	var doc map[string]any
	_ = json.Unmarshal([]byte(read(t, filepath.Join(rec, "auth.json"))), &doc)
	tk, _ := doc["login"].(map[string]any)["token"].(map[string]any)
	if tk["path"] != "data.access_token" || tk["send_as"] != "header" || tk["header_name"] != "Authorization" {
		t.Fatalf("auth file token: %v", doc["login"])
	}
	r.assertWorkdirClean()
}
