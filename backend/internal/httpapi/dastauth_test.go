package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

const (
	secPass  = "Sup3r-Secret-Pw!"
	secTok   = "tok-0123456789abcdef"
	secCook  = "cookie-value-ABCDEF"
	secExtra = "otp-424242"
	target   = "https://shop.example.com"
)

var allSecrets = []string{secPass, secTok, secCook, secExtra}

func formBody() map[string]any {
	return map[string]any{
		"type": "form+header",
		"login": map[string]any{
			"url": target + "/login", "method": "POST", "body_format": "json", "username_field": "user", "password_field": "password",
			"username": "tester", "password": secPass, "extra_fields": map[string]string{"otp": secExtra},
			"csrf":    map[string]any{"source": "html_input", "name": "_csrf", "send_as": "field"},
			"success": map[string]any{"statuses": []int{200, 302}, "cookie_set": "sid", "body_contains": "Welcome", "redirect_not_to": "/login"},
		},
		"headers": map[string]string{"Authorization": "Bearer " + secTok},
		"cookies": map[string]string{"sid": secCook},
	}
}

func authPath(id int64) string { return fmt.Sprintf("/api/v1/codebases/%d/dast-auth", id) }

func noSecrets(t *testing.T, what string, b []byte) {
	t.Helper()
	for _, s := range allSecrets {
		if strings.Contains(string(b), s) {
			t.Errorf("%s contains the secret %q:\n%s", what, s, b)
		}
	}
}

func TestDastAuthIsEncryptedAtRestAndWriteOnly(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	// Initially: type none.
	g := w.dastUser.Get(authPath(id))
	if g.Status != 200 || g.JSON()["type"] != "none" || g.JSON()["has_secret"] != false {
		t.Fatalf("initial GET: %d %s", g.Status, g.Body)
	}
	put := w.dastUser.Do("PUT", authPath(id), formBody())
	if put.Status != 200 {
		t.Fatalf("PUT: %d %s", put.Status, put.Body)
	}
	noSecrets(t, "PUT response", put.Body)
	j := put.JSON()
	if j["type"] != "form+header" || j["has_secret"] != true || j["login_url"] != target+"/login" || j["method"] != "POST" || j["body_format"] != "json" ||
		j["username_field"] != "user" || j["password_field"] != "password" || j["username"] != "tester" {
		t.Fatalf("meta: %s", put.Body)
	}
	if fmt.Sprint(j["extra_field_names"]) != "[otp]" || fmt.Sprint(j["header_names"]) != "[Authorization]" || fmt.Sprint(j["cookie_names"]) != "[sid]" {
		t.Fatalf("names: %s", put.Body)
	}
	if csrf := j["csrf"].(map[string]any); csrf["source"] != "html_input" || csrf["name"] != "_csrf" || csrf["send_as"] != "field" || csrf["header_name"] != nil {
		t.Fatalf("csrf: %v", csrf)
	}
	if su := j["success"].(map[string]any); su["cookie_set"] != "sid" || su["body_contains"] != "Welcome" || su["redirect_not_to"] != "/login" || su["body_not_contains"] != nil {
		t.Fatalf("success: %v", su)
	}
	if j["updated_at"] == nil || j["updated_by"].(map[string]any)["username"] != "dastuser" {
		t.Fatalf("updated_*: %s", put.Body)
	}
	// Every read path is free of secrets.
	for name, body := range map[string][]byte{
		"GET dast-auth": w.dastUser.Get(authPath(id)).Body,
		"GET codebase":  w.dastUser.Get(fmt.Sprintf("/api/v1/codebases/%d", id)).Body,
		"GET list":      w.dastUser.Get("/api/v1/codebases").Body,
		"GET project":   w.dastUser.Get(fmt.Sprintf("/api/v1/projects/%d", w.projectID)).Body,
		"audit log":     w.admin.Get("/api/v1/audit-log").Body,
	} {
		noSecrets(t, name, body)
	}
	cbj := w.dastUser.Get(fmt.Sprintf("/api/v1/codebases/%d", id)).JSON()
	if a := cbj["dast_auth"].(map[string]any); a["type"] != "form+header" || a["has_secret"] != true {
		t.Fatalf("codebase dast_auth: %v", a)
	}
	// At rest: ciphertext (AES-GCM, random nonce) and non-secret meta only.
	var enc []byte
	var meta string
	var typ string
	if err := w.env.Pool.QueryRow(context.Background(), `SELECT dast_auth_enc, dast_auth_meta::text, dast_auth_type FROM codebases WHERE id = $1`, id).Scan(&enc, &meta, &typ); err != nil {
		t.Fatal(err)
	}
	if typ != "form+header" || len(enc) < 40 {
		t.Fatalf("stored: %s %d", typ, len(enc))
	}
	noSecrets(t, "dast_auth_enc", enc)
	noSecrets(t, "dast_auth_meta", []byte(meta))
	var dump string
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT string_agg(c::text, ' ') FROM codebases c`).Scan(&dump)
	_ = dump // bytea prints as hex; the plaintext check above is the meaningful one
	plain, err := w.env.Box.Open(enc)
	if err != nil {
		t.Fatalf("stored data is not sealed with the server key: %v", err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(plain, &cfg)
	if cfg["login"].(map[string]any)["password"] != secPass || cfg["headers"].(map[string]any)["Authorization"] != "Bearer "+secTok {
		t.Fatalf("decrypted config: %s", plain)
	}
	// Writing the same config twice gives different ciphertext (random nonce).
	w.dastUser.Do("PUT", authPath(id), formBody())
	var enc2 []byte
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT dast_auth_enc FROM codebases WHERE id = $1`, id).Scan(&enc2)
	if string(enc) == string(enc2) {
		t.Fatal("ciphertext must differ between writes")
	}
}

func TestDastAuthBlankSecretsKeepTheStoredOnes(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.admin, "live", target)
	if r := w.admin.Do("PUT", authPath(id), formBody()); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// Edit non-secret settings only: blank password, header value, cookie value and extra field value.
	b := formBody()
	b["login"].(map[string]any)["password"] = ""
	b["login"].(map[string]any)["username"] = "tester2"
	b["login"].(map[string]any)["extra_fields"] = map[string]string{"otp": ""}
	b["headers"] = map[string]string{"authorization": ""}
	b["cookies"] = map[string]string{"sid": ""}
	r := w.admin.Do("PUT", authPath(id), b)
	if r.Status != 200 || r.JSON()["username"] != "tester2" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	var enc []byte
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT dast_auth_enc FROM codebases WHERE id = $1`, id).Scan(&enc)
	plain, _ := w.env.Box.Open(enc)
	for _, s := range allSecrets {
		if !strings.Contains(string(plain), s) {
			t.Errorf("stored config lost %q", s)
		}
	}
	// A brand-new header name without a value is rejected.
	b["headers"] = map[string]string{"X-Other": ""}
	if r := w.admin.Do("PUT", authPath(id), b); r.Status != 422 {
		t.Fatalf("blank new header: %d %s", r.Status, r.Body)
	}
	// After DELETE nothing is kept: a blank password is now an error.
	w.admin.Do("DELETE", authPath(id), nil)
	b["headers"] = map[string]string{"Authorization": "Bearer " + secTok}
	if r := w.admin.Do("PUT", authPath(id), b); r.Status != 422 || r.JSON()["error"].(map[string]any)["details"].(map[string]any)["field"] != "login.password" {
		t.Fatalf("blank password without stored: %d %s", r.Status, r.Body)
	}
}

func TestDastAuthValidationOverHTTP(t *testing.T) {
	// A target whose host passes at registration, then moves to a private address.
	res := testutil.DefaultResolver()
	res["moving.example.com"] = []string{"93.184.216.50"}
	w := newWorld(t, testutil.EnvOptions{Guard: &netguard.Guard{Resolver: res}})
	id := w.urlTarget(t, w.dastUser, "live", target)
	mod := func(f func(b map[string]any)) map[string]any {
		b := formBody()
		f(b)
		return b
	}
	login := func(b map[string]any) map[string]any { return b["login"].(map[string]any) }
	cases := []struct {
		name  string
		body  any
		field string
	}{
		{"other host", mod(func(b map[string]any) { login(b)["url"] = "https://evil.example.net/login" }), "login.url"},
		{"other port", mod(func(b map[string]any) { login(b)["url"] = target + ":8443/login" }), "login.url"},
		{"userinfo host trick", mod(func(b map[string]any) { login(b)["url"] = "https://shop.example.com@evil.example.net/" }), "login.url"},
		{"type none", map[string]any{"type": "none"}, "type"},
		{"CRLF in header", mod(func(b map[string]any) { b["headers"] = map[string]string{"X-A": "abcd\r\nX-Evil: 1"} }), "headers"},
		{"CRLF in header name", mod(func(b map[string]any) { b["headers"] = map[string]string{"X-A\r\nX-B": "abcdefgh"} }), "headers"},
		{"11 headers", mod(func(b map[string]any) {
			h := map[string]string{}
			for i := 0; i < 11; i++ {
				h[fmt.Sprintf("X-H%d", i)] = "abcdefgh"
			}
			b["headers"] = h
		}), "headers"},
		{"value over 4 KiB", mod(func(b map[string]any) { b["headers"] = map[string]string{"X-A": strings.Repeat("v", 4097)} }), "headers"},
		{"total over 16 KiB", mod(func(b map[string]any) {
			h := map[string]string{}
			for i := 0; i < 5; i++ {
				h[fmt.Sprintf("X-Big%d", i)] = strings.Repeat("v", 4000)
			}
			b["headers"] = h
		}), ""},
		{"bad csrf source", mod(func(b map[string]any) { login(b)["csrf"] = map[string]any{"source": "magic", "name": "x"} }), "login.csrf.source"},
	}
	for _, c := range cases {
		r := w.dastUser.Do("PUT", authPath(id), c.body)
		if r.Status != 422 || r.ErrCode() != "validation_failed" {
			t.Errorf("%s: %d %s", c.name, r.Status, r.Body)
			continue
		}
		if f, _ := r.JSON()["error"].(map[string]any)["details"].(map[string]any)["field"].(string); c.field != "" && f != c.field && !strings.HasPrefix(f, c.field+".") {
			t.Errorf("%s: field %q want %q", c.name, f, c.field)
		}
		noSecrets(t, c.name+" error", r.Body)
	}
	// Body far over the limit: 413.
	huge := mod(func(b map[string]any) { b["headers"] = map[string]string{"X-A": strings.Repeat("v", 100<<10)} })
	if r := w.dastUser.Do("PUT", authPath(id), huge); r.Status != 413 {
		t.Errorf("huge body: %d", r.Status)
	}
	// Malformed JSON.
	if r := w.dastUser.Raw("PUT", authPath(id), strings.NewReader("{nope"), map[string]string{"Content-Type": "application/json"}); r.Status != 400 {
		t.Errorf("malformed: %d", r.Status)
	}
	// Nothing was stored by any of the failures.
	if g := w.dastUser.Get(authPath(id)).JSON(); g["type"] != "none" {
		t.Fatalf("a rejected PUT stored something: %v", g)
	}
	// Network policy: the target host moved to a private address after registration.
	mid := w.urlTarget(t, w.dastUser, "moving", "https://moving.example.com")
	res["moving.example.com"] = []string{"10.0.0.9"}
	b := mod(func(b map[string]any) { login(b)["url"] = "https://moving.example.com/login" })
	if r := w.dastUser.Do("PUT", authPath(mid), b); r.Status != 422 || r.ErrCode() != "address_not_allowed" {
		t.Errorf("private address: %d %s", r.Status, r.Body)
	}
}

func TestDastAuthNeedsTheSecretKey(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{NoKey: true})
	id := w.urlTarget(t, w.admin, "live", target)
	r := w.admin.Do("PUT", authPath(id), formBody())
	if r.Status != 503 || r.ErrCode() != "secret_key_required" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if g := w.admin.Get(authPath(id)); g.Status != 200 || g.JSON()["type"] != "none" {
		t.Fatalf("GET: %d %s", g.Status, g.Body)
	}
}

func TestDastAuthRolesAndIdenticalNotFound(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	repo := w.repo(t, w.member, "storefront")
	w.confirm(t, id)
	for _, c := range []*testutil.Client{w.admin, w.dastUser} {
		if r := c.Do("PUT", authPath(id), formBody()); r.Status != 200 {
			t.Fatalf("%s PUT: %d %s", c.User.Username, r.Status, r.Body)
		}
		if r := c.Get(authPath(id)); r.Status != 200 {
			t.Fatalf("%s GET: %d", c.User.Username, r.Status)
		}
	}
	// A member without DAST access learns nothing: the answer equals the one for a missing id.
	for _, m := range []struct{ method, suffix string }{{"GET", ""}, {"PUT", ""}, {"DELETE", ""}, {"POST", "/test"}} {
		path := authPath(id) + m.suffix
		ghost := authPath(987654) + m.suffix
		var body any
		if m.method == "PUT" || m.method == "POST" {
			body = formBody()
		}
		r, gr := w.member.Do(m.method, path, body), w.member.Do(m.method, ghost, body)
		if r.Status != 404 || r.ErrCode() != "not_found" || r.Status != gr.Status || string(stripReq(r.Body)) != string(stripReq(gr.Body)) {
			t.Errorf("%s %s: %d %s vs ghost %d %s", m.method, path, r.Status, r.Body, gr.Status, gr.Body)
		}
	}
	// ... and the member's attempts changed nothing.
	if g := w.admin.Get(authPath(id)).JSON(); g["type"] != "form+header" {
		t.Fatalf("state: %v", g)
	}
	// Revoking DAST access closes it at once.
	f := false
	if r := w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", w.dastUser.User.ID), map[string]any{"can_run_dast": f}); r.Status != 200 {
		t.Fatal(r.Status)
	}
	if r := w.dastUser.Get(authPath(id)); r.Status != 404 {
		t.Fatalf("revoked user: %d", r.Status)
	}
	// Repository targets have no DAST authentication.
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		var body any
		if m == "PUT" {
			body = formBody()
		}
		if r := w.admin.Do(m, authPath(repo), body); r.Status != 409 || r.ErrCode() != "not_a_url_target" {
			t.Errorf("repo %s: %d %s", m, r.Status, r.Body)
		}
	}
	// The codebase DTO of a repo carries null dast_auth/dast_crawl.
	if rj := w.member.Get(fmt.Sprintf("/api/v1/codebases/%d", repo)).JSON(); rj["dast_auth"] != nil || rj["dast_crawl"] != nil {
		t.Fatalf("repo DTO: %v", rj)
	}
}

func TestDastAuthDeleteAndAudit(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	w.dastUser.Do("PUT", authPath(id), formBody())
	if r := w.dastUser.Do("DELETE", authPath(id), nil); r.Status != 204 {
		t.Fatalf("DELETE: %d %s", r.Status, r.Body)
	}
	var typ string
	var enc, meta []byte
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT dast_auth_type, dast_auth_enc, dast_auth_meta::text FROM codebases WHERE id = $1`, id).Scan(&typ, &enc, &meta)
	if typ != "none" || enc != nil || meta != nil {
		t.Fatalf("after DELETE: %s %v %v", typ, enc != nil, meta != nil)
	}
	if g := w.dastUser.Get(authPath(id)).JSON(); g["type"] != "none" || g["has_secret"] != false || g["login_url"] != nil {
		t.Fatalf("GET after DELETE: %v", g)
	}
	// Idempotent, and no second audit row.
	if r := w.dastUser.Do("DELETE", authPath(id), nil); r.Status != 204 {
		t.Fatalf("second DELETE: %d", r.Status)
	}
	w.dastUser.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", id), map[string]any{"dast_crawl_enabled": true})
	a := w.admin.Get("/api/v1/audit-log?page_size=100")
	noSecrets(t, "audit log", a.Body)
	counts := map[string]int{}
	for _, it := range a.JSON()["items"].([]any) {
		m := it.(map[string]any)
		counts[m["action"].(string)]++
		if act := m["action"].(string); strings.HasPrefix(act, "dast_auth") || act == "dast_crawl_updated" {
			if m["actor_name"] != "dastuser" || !strings.Contains(fmt.Sprint(m["target"]), "live") {
				t.Errorf("audit row: %v", m)
			}
		}
	}
	if counts["dast_auth_set"] != 1 || counts["dast_auth_deleted"] != 1 || counts["dast_crawl_updated"] != 1 {
		t.Fatalf("audit actions: %v", counts)
	}
}

func TestChangingTheTargetOriginRemovesCredentialsAndResetsConfirmation(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	w.confirm(t, id)
	w.dastUser.Do("PUT", authPath(id), formBody())
	w.dastUser.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", id), map[string]any{"dast_crawl_enabled": true, "dast_crawl_max_pages": 80, "dast_crawl_exclude": []string{"^/x"}})
	patch := func(base string) testutil_Resp {
		return w.dastUser.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", id), map[string]any{"base_url": base})
	}
	// Same origin, different path: confirmation resets (existing rule) but the credentials stay.
	if r := patch(target + "/app"); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	j := w.dastUser.Get(fmt.Sprintf("/api/v1/codebases/%d", id)).JSON()
	if j["dast"].(map[string]any)["status"] != "pending_confirmation" || j["dast_auth"].(map[string]any)["type"] != "form+header" {
		t.Fatalf("same-origin change: %v", j)
	}
	// Another host: the credentials are deleted, the crawl settings stay.
	w.confirm(t, id)
	r := patch("https://shop2.example.com")
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	j = r.JSON()
	a := j["dast_auth"].(map[string]any)
	if j["dast"].(map[string]any)["status"] != "pending_confirmation" || a["type"] != "none" || a["has_secret"] != false || a["login_url"] != nil || len(a["header_names"].([]any)) != 0 {
		t.Fatalf("other host: %v", j)
	}
	if c := j["dast_crawl"].(map[string]any); c["enabled"] != true || c["max_pages"] != float64(80) {
		t.Fatalf("crawl settings: %v", c)
	}
	var enc, meta []byte
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT dast_auth_enc, dast_auth_meta::text FROM codebases WHERE id = $1`, id).Scan(&enc, &meta)
	if enc != nil || meta != nil {
		t.Fatal("ciphertext must be gone")
	}
	// A scheme change is another origin too.
	w.confirm(t, id)
	w.dastUser.Do("PUT", authPath(id), map[string]any{"type": "header", "headers": map[string]string{"X-Api-Key": secTok}})
	// (the login URL rule does not apply to header-only auth, but the origin rule on base_url does)
	if r := patch("http://shop2.example.com"); r.Status != 200 || r.JSON()["dast_auth"].(map[string]any)["type"] != "none" {
		t.Fatalf("scheme change: %d %s", r.Status, r.Body)
	}
	counts := map[string]int{}
	for _, it := range w.admin.Get("/api/v1/audit-log?page_size=100").JSON()["items"].([]any) {
		counts[it.(map[string]any)["action"].(string)]++
	}
	if counts["dast_auth_deleted"] != 2 {
		t.Fatalf("audit: %v", counts)
	}
}

type testutil_Resp = testutil.Resp

func TestDastCrawlSettings(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	repo := w.repo(t, w.member, "storefront")
	path := fmt.Sprintf("/api/v1/codebases/%d", id)
	if c := w.dastUser.Get(path).JSON()["dast_crawl"].(map[string]any); c["enabled"] != false || c["max_depth"] != float64(3) || c["max_pages"] != float64(50) || len(c["exclude"].([]any)) != 0 {
		t.Fatalf("defaults: %v", c)
	}
	r := w.dastUser.Do("PATCH", path, map[string]any{"dast_crawl_enabled": true, "dast_crawl_max_depth": 5, "dast_crawl_max_pages": 120,
		"dast_crawl_exclude": []string{`^/admin`, `\.(pdf|zip)$`}})
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	c := r.JSON()["dast_crawl"].(map[string]any)
	if c["enabled"] != true || c["max_depth"] != float64(5) || c["max_pages"] != float64(120) || fmt.Sprint(c["exclude"]) != `[^/admin \.(pdf|zip)$]` {
		t.Fatalf("crawl: %v", c)
	}
	// Partial updates leave the rest alone; null/[] clears the exclusions.
	r = w.dastUser.Do("PATCH", path, map[string]any{"dast_crawl_enabled": false, "dast_crawl_exclude": nil})
	if c := r.JSON()["dast_crawl"].(map[string]any); r.Status != 200 || c["enabled"] != false || c["max_depth"] != float64(5) || len(c["exclude"].([]any)) != 0 {
		t.Fatalf("partial: %d %s", r.Status, r.Body)
	}
	twenty := make([]string, 20)
	for i := range twenty {
		twenty[i] = fmt.Sprintf("^/p%d", i)
	}
	if r := w.dastUser.Do("PATCH", path, map[string]any{"dast_crawl_exclude": twenty}); r.Status != 200 {
		t.Fatalf("20 patterns: %d %s", r.Status, r.Body)
	}
	bad := map[string]map[string]any{
		"depth 0":        {"dast_crawl_max_depth": 0},
		"depth 11":       {"dast_crawl_max_depth": 11},
		"pages 0":        {"dast_crawl_max_pages": 0},
		"pages 501":      {"dast_crawl_max_pages": 501},
		"pages string":   {"dast_crawl_max_pages": "many"},
		"enabled string": {"dast_crawl_enabled": "yes"},
		"21 patterns":    {"dast_crawl_exclude": append(twenty, "x")},
		"201 chars":      {"dast_crawl_exclude": []string{strings.Repeat("a", 201)}},
		"invalid regex":  {"dast_crawl_exclude": []string{"(unclosed"}},
		"lookahead":      {"dast_crawl_exclude": []string{"(?=x)"}},
		"backreference":  {"dast_crawl_exclude": []string{`(a)\1`}},
		"too large":      {"dast_crawl_exclude": []string{"((a{100}){100}){100}"}},
		"empty pattern":  {"dast_crawl_exclude": []string{""}},
		"not a list":     {"dast_crawl_exclude": "^/x"},
	}
	for name, body := range bad {
		if r := w.dastUser.Do("PATCH", path, body); r.Status != 422 || r.ErrCode() != "validation_failed" {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	// A catastrophic-backtracking pattern in a backtracking engine is harmless (and accepted) with RE2.
	if r := w.dastUser.Do("PATCH", path, map[string]any{"dast_crawl_exclude": []string{`(a+)+$`}}); r.Status != 200 {
		t.Errorf("RE2 pattern: %d %s", r.Status, r.Body)
	}
	// Repositories have no crawl settings; members without DAST access get the usual 404.
	if r := w.member.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", repo), map[string]any{"dast_crawl_enabled": true}); r.Status != 422 {
		t.Errorf("repo crawl: %d %s", r.Status, r.Body)
	}
	if r := w.member.Do("PATCH", path, map[string]any{"dast_crawl_enabled": true}); r.Status != 404 || r.ErrCode() != "not_found" {
		t.Errorf("member: %d %s", r.Status, r.Body)
	}
}

// fakeDast is a stand-in for sdrscan-dast with --login-check support.
func fakeDast(t *testing.T, flags, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dast.sh")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'sdrscan-dast 0.1.0'; exit 0; fi\n" +
		"if [ \"$1\" = \"scan\" ] && [ \"$2\" = \"--help\" ]; then echo '" + flags + "'; exit 0; fi\n" +
		"auth=\"\"; check=0\nwhile [ $# -gt 0 ]; do case \"$1\" in --auth-file) auth=\"$2\"; shift;; --login-check) check=1;; esac; shift; done\n" + body
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDastAuthTestEndpoint(t *testing.T) {
	okBody := "if grep -q '" + secPass + "' \"$auth\"; then echo 'login ok (HTTP 302 -> /home); session cookie: " + secCook + "'; exit 0; fi\n" +
		"echo 'login failed: HTTP 401 (invalid credentials)' >&2\nexit 2\n"
	w := newWorld(t, testutil.EnvOptions{Runner: scanner.Config{DastBin: fakeDast(t, "--auth-file --login-check --max-rps", okBody)}})
	id := w.urlTarget(t, w.dastUser, "live", target)
	testPath := authPath(id) + "/test"
	// Not confirmed yet.
	w.dastUser.Do("PUT", authPath(id), formBody())
	if r := w.dastUser.Do("POST", testPath, nil); r.Status != 409 || r.ErrCode() != "target_not_confirmed" {
		t.Fatalf("unconfirmed: %d %s", r.Status, r.Body)
	}
	w.confirm(t, id)
	// Success: the engine message comes back, redacted.
	r := w.dastUser.Do("POST", testPath, nil)
	if r.Status != 200 || r.JSON()["ok"] != true || !strings.Contains(r.JSON()["message"].(string), "login ok (HTTP 302") {
		t.Fatalf("success: %d %s", r.Status, r.Body)
	}
	noSecrets(t, "test response", r.Body)
	// Failure (wrong password stored): ok=false with the redacted engine message.
	b := formBody()
	b["login"].(map[string]any)["password"] = "wrong-password"
	w.dastUser.Do("PUT", authPath(id), b)
	r = w.dastUser.Do("POST", testPath, nil)
	if r.Status != 200 || r.JSON()["ok"] != false || r.JSON()["message"] == "" {
		t.Fatalf("failure: %d %s", r.Status, r.Body)
	}
	noSecrets(t, "failure response", r.Body)
	// The engine that prints the real secret to stderr: redacted in the response.
	w.dastUser.Do("PUT", authPath(id), formBody())
	failLeak := fakeDast(t, "--auth-file --login-check", "echo 'login failed: HTTP 401 for password "+secPass+" and token "+secTok+"' >&2\nexit 2\n")
	cfg := w.env.Runner.Cfg
	cfg.DastBin = failLeak
	w.env.API.LoginTester = scanner.New(w.env.Store, w.env.Ingest, w.env.Guard, w.env.Box, cfg, nil)
	r = w.dastUser.Do("POST", testPath, nil)
	if r.Status != 200 || r.JSON()["ok"] != false || !strings.Contains(r.JSON()["message"].(string), "[REDACTED]") {
		t.Fatalf("leaky engine: %d %s", r.Status, r.Body)
	}
	noSecrets(t, "leaky engine response", r.Body)
	// An engine without --login-check support.
	cfg.DastBin = fakeDast(t, "--max-rps", "exit 0\n")
	w.env.API.LoginTester = scanner.New(w.env.Store, w.env.Ingest, w.env.Guard, w.env.Box, cfg, nil)
	if r := w.dastUser.Do("POST", testPath, nil); r.Status != 501 || r.ErrCode() != "engine_unsupported" {
		t.Fatalf("old engine: %d %s", r.Status, r.Body)
	}
	// Header-only authentication has no login step.
	w.dastUser.Do("PUT", authPath(id), map[string]any{"type": "header", "headers": map[string]string{"X-Api-Key": secTok}})
	if r := w.dastUser.Do("POST", testPath, nil); r.Status != 409 || r.ErrCode() != "no_login_configured" {
		t.Fatalf("header only: %d %s", r.Status, r.Body)
	}
	w.dastUser.Do("PUT", authPath(id), formBody())
	// No auth configured.
	w.dastUser.Do("DELETE", authPath(id), nil)
	if r := w.dastUser.Do("POST", testPath, nil); r.Status != 409 || r.ErrCode() != "no_auth_configured" {
		t.Fatalf("no auth: %d %s", r.Status, r.Body)
	}
	// Audit: outcome only.
	var tested []string
	for _, it := range w.admin.Get("/api/v1/audit-log?page_size=100").JSON()["items"].([]any) {
		if m := it.(map[string]any); m["action"] == "dast_auth_tested" {
			tested = append(tested, m["target"].(string))
		}
	}
	if len(tested) != 3 {
		t.Fatalf("dast_auth_tested rows: %v", tested)
	}
	noSecrets(t, "audit", w.admin.Get("/api/v1/audit-log?page_size=100").Body)
}

func TestDastAuthTokenSettingsOverHTTP(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	b := formBody()
	b["type"] = "form"
	delete(b, "headers")
	delete(b, "cookies")
	login := b["login"].(map[string]any)
	login["url"] = target + "/api/auth/login"
	login["token"] = map[string]any{"from": "json", "path": "data.access_token"}
	login["success"] = map[string]any{"json_path_exists": "data.access_token", "json_path_equals": map[string]any{"path": "status", "value": "ok"}}
	put := w.dastUser.Do("PUT", authPath(id), b)
	if put.Status != 200 {
		t.Fatalf("PUT: %d %s", put.Status, put.Body)
	}
	noSecrets(t, "PUT response", put.Body)
	tk, ok := put.JSON()["token"].(map[string]any)
	if !ok || tk["from"] != "json" || tk["path"] != "data.access_token" || tk["send_as"] != "header" || tk["header_name"] != "Authorization" || tk["prefix"] != "Bearer " || tk["cookie_name"] != nil {
		t.Fatalf("token meta: %s", put.Body)
	}
	su := put.JSON()["success"].(map[string]any)
	if su["json_path_exists"] != "data.access_token" || su["json_path_equals"].(map[string]any)["value"] != "ok" {
		t.Fatalf("success meta: %s", put.Body)
	}
	if g := w.dastUser.Get(authPath(id)).JSON()["token"]; g == nil {
		t.Fatal("GET lacks token")
	}
	// The stored (encrypted) config carries the settings; the editor's blank password is kept.
	login["password"] = ""
	login["token"] = map[string]any{"from": "header", "path": "X-Auth-Token", "send_as": "cookie", "cookie_name": "jwt"}
	if r := w.dastUser.Do("PUT", authPath(id), b); r.Status != 200 || r.JSON()["token"].(map[string]any)["send_as"] != "cookie" {
		t.Fatalf("re-PUT: %d %s", r.Status, r.Body)
	}
	// Field errors name the failing token field.
	for _, c := range []struct {
		tok   map[string]any
		field string
	}{
		{map[string]any{"path": "data..x"}, "login.token.path"},
		{map[string]any{"path": "a", "header_name": "Host"}, "login.token.header_name"},
		{map[string]any{"path": "a", "prefix": "Bearer\r\nX: 1"}, "login.token.prefix"},
		{map[string]any{"path": "a", "send_as": "cookie"}, "login.token.cookie_name"},
		{map[string]any{"path": "a", "send_as": "body"}, "login.token.send_as"},
	} {
		login["token"] = c.tok
		r := w.dastUser.Do("PUT", authPath(id), b)
		f, _ := r.JSON()["error"].(map[string]any)["details"].(map[string]any)["field"].(string)
		if r.Status != 422 || f != c.field {
			t.Errorf("%v: %d field %q %s", c.tok, r.Status, f, r.Body)
		}
	}
}
