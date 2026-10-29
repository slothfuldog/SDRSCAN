package dastauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
)

const base = "https://shop.example.com"

func formCfg() Config {
	return Config{Type: TypeForm, Login: &Login{URL: base + "/login", UsernameField: "user", PasswordField: "pass", Username: "u1", Password: "p4ssw0rd!"}}
}

func field(t *testing.T, err error) string {
	t.Helper()
	ae, ok := apierr.As(err)
	if !ok || ae.Status != 422 {
		t.Fatalf("want a 422 validation error, got %v", err)
	}
	return apierr.FieldOf(ae)
}

func TestValidateAcceptsAndNormalises(t *testing.T) {
	c, err := Validate(formCfg(), base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Login.Method != "POST" || c.Login.BodyFormat != "form" {
		t.Fatalf("defaults: %+v", c.Login)
	}
	c2 := Config{Type: TypeFormHeader, Login: formCfg().Login, Headers: map[string]string{"Authorization": "Bearer abcdef"}, Cookies: map[string]string{"sid": "abcd1234"}}
	c2.Login.CSRF = &CSRF{Source: "cookie", Name: "XSRF-TOKEN", SendAs: "header", HeaderName: "X-XSRF-TOKEN"}
	c2.Login.Success = &Success{Statuses: []int{302, 200, 200}, RedirectNotTo: "/login"}
	out, err := Validate(c2, base)
	if err != nil || len(out.Login.Success.Statuses) != 2 || out.Login.Success.Statuses[0] != 200 {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestTokenDefaultsAndMeta(t *testing.T) {
	cfg := formCfg()
	cfg.Login.BodyFormat = "json"
	cfg.Login.Token = &Token{Path: " data.access_token "}
	cfg.Login.Success = &Success{JSONPathExists: "data.access_token", JSONPathEquals: &JSONEquals{Path: "status", Value: "ok"}}
	out, err := Validate(cfg, base)
	if err != nil {
		t.Fatal(err)
	}
	tk := out.Login.Token
	if tk.From != "json" || tk.Path != "data.access_token" || tk.SendAs != "header" || tk.HeaderName != "Authorization" || tk.Prefix == nil || *tk.Prefix != "Bearer " {
		t.Fatalf("defaults: %+v", tk)
	}
	// Custom header: no implicit prefix; explicit empty prefix is kept; cookie drops header fields.
	c2 := formCfg()
	c2.Login.Token = &Token{From: "header", Path: "X-Auth-Token", HeaderName: "X-Api-Token"}
	o2, err := Validate(c2, base)
	if err != nil || o2.Login.Token.Prefix != nil {
		t.Fatalf("custom header: %+v %v", o2.Login.Token, err)
	}
	empty := ""
	c3 := formCfg()
	c3.Login.Token = &Token{Path: "t", Prefix: &empty}
	o3, err := Validate(c3, base)
	if err != nil || o3.Login.Token.Prefix == nil || *o3.Login.Token.Prefix != "" {
		t.Fatalf("empty prefix: %+v %v", o3.Login.Token, err)
	}
	pfx := "Bearer "
	c4 := formCfg()
	c4.Login.Token = &Token{Path: "items[0].token", SendAs: "cookie", CookieName: "jwt", HeaderName: "X-Ignored", Prefix: &pfx}
	o4, err := Validate(c4, base)
	if err != nil || o4.Login.Token.HeaderName != "" || o4.Login.Token.Prefix != nil {
		t.Fatalf("cookie: %+v %v", o4.Login.Token, err)
	}

	// The meta carries the settings (no value exists to leak) and the engine file the same fields.
	raw, _ := json.Marshal(MetaOf(out, time.Now(), nil))
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	tm := m["token"].(map[string]any)
	if tm["from"] != "json" || tm["path"] != "data.access_token" || tm["send_as"] != "header" || tm["header_name"] != "Authorization" || tm["prefix"] != "Bearer " || tm["cookie_name"] != nil {
		t.Fatalf("meta token: %v", tm)
	}
	su := m["success"].(map[string]any)
	if su["json_path_exists"] != "data.access_token" || su["json_path_equals"].(map[string]any)["path"] != "status" || su["json_path_equals"].(map[string]any)["value"] != "ok" {
		t.Fatalf("meta success: %v", su)
	}
	view := View(TypeForm, true, raw)
	if view["token"] == nil {
		t.Fatal("view lacks token")
	}
	b, err := EngineFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	l := doc["login"].(map[string]any)
	et := l["token"].(map[string]any)
	if et["from"] != "json" || et["path"] != "data.access_token" || et["send_as"] != "header" || et["header_name"] != "Authorization" || et["prefix"] != "Bearer " {
		t.Fatalf("engine token: %v", et)
	}
	es := l["success"].(map[string]any)
	if es["json_path_exists"] != "data.access_token" || es["json_path_equals"].(map[string]any)["value"] != "ok" {
		t.Fatalf("engine success: %v", es)
	}
}

func TestValidJSONPath(t *testing.T) {
	for _, ok := range []string{"data.access_token", "items[0].token", "[0].token", "a[1][2]", "token", "a.b.c"} {
		if !ValidJSONPath(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", ".", "a.", ".a", "a..b", "a[", "a[]", "a[x]", "a[-1]", "a]b", "x.[0]", "a[1]b", strings.Repeat("a", 201)} {
		if ValidJSONPath(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRedactTokensMasksBearerAndJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	for _, in := range []string{
		"Authorization: Bearer abcdef0123456789",
		"authorization: bearer abc.def-ghi_jkl~m+n/o==",
		"token=" + jwt + " done",
		"Bearer " + jwt,
	} {
		out := Redact(in, nil)
		for _, leak := range []string{"abcdef0123456789", "abc.def-ghi", "SflKxwRJ", "eyJhbGci"} {
			if strings.Contains(out, leak) {
				t.Errorf("%q -> %q still has %q", in, out, leak)
			}
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("%q not redacted: %q", in, out)
		}
	}
	if got := RedactTokens("Authorization: Bearer abcdef0123456789 ok"); got != "Authorization: Bearer [REDACTED] ok" {
		t.Errorf("scheme kept? %q", got)
	}
	for _, same := range []string{"no token here", "Bearer short", "host a.b.c.example.com", "login berhasil: token diterima (header Authorization)"} {
		if RedactTokens(same) != same {
			t.Errorf("%q changed to %q", same, RedactTokens(same))
		}
	}
}

func TestCSRFDefaultsFollowTheEngine(t *testing.T) {
	for _, c := range []struct{ source, sendAs, header, wantSend, wantHeader string }{
		{"html_input", "", "", "field", ""},
		{"cookie", "", "", "header", "X-CSRF-Token"},
		{"header", "", "", "header", "X-CSRF-Token"},
		{"cookie", "header", "X-XSRF-TOKEN", "header", "X-XSRF-TOKEN"},
		{"cookie", "field", "ignored", "field", ""},
	} {
		cfg := formCfg()
		cfg.Login.CSRF = &CSRF{Source: c.source, Name: "t", SendAs: c.sendAs, HeaderName: c.header}
		out, err := Validate(cfg, base)
		if err != nil || out.Login.CSRF.SendAs != c.wantSend || out.Login.CSRF.HeaderName != c.wantHeader {
			t.Errorf("%+v -> %+v %v", c, out.Login.CSRF, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	mut := func(f func(c *Config)) Config {
		c := formCfg()
		l := *c.Login
		c.Login = &l
		f(&c)
		return c
	}
	long := strings.Repeat("a", 4097)
	cases := []struct {
		name  string
		cfg   Config
		field string
	}{
		{"type none", Config{Type: "none"}, "type"},
		{"unknown type", Config{Type: "oauth"}, "type"},
		{"form without login", Config{Type: TypeForm}, "login"},
		{"other origin (host)", mut(func(c *Config) { c.Login.URL = "https://evil.example.net/login" }), "login.url"},
		{"other origin (scheme)", mut(func(c *Config) { c.Login.URL = "http://shop.example.com/login" }), "login.url"},
		{"other origin (port)", mut(func(c *Config) { c.Login.URL = "https://shop.example.com:8443/login" }), "login.url"},
		{"userinfo trick", mut(func(c *Config) { c.Login.URL = "https://shop.example.com@evil.example.net/login" }), "login.url"},
		{"relative url", mut(func(c *Config) { c.Login.URL = "/login" }), "login.url"},
		{"credentials in url", mut(func(c *Config) { c.Login.URL = "https://a:b@shop.example.com/login" }), "login.url"},
		{"bad method", mut(func(c *Config) { c.Login.Method = "GET" }), "login.method"},
		{"bad body format", mut(func(c *Config) { c.Login.BodyFormat = "xml" }), "login.body_format"},
		{"same fields", mut(func(c *Config) { c.Login.PasswordField = "user" }), "login.password_field"},
		{"empty username", mut(func(c *Config) { c.Login.Username = "" }), "login.username"},
		{"empty password", mut(func(c *Config) { c.Login.Password = "" }), "login.password"},
		{"short password", mut(func(c *Config) { c.Login.Password = "abc" }), "login.password"},
		{"newline in password", mut(func(c *Config) { c.Login.Password = "abcd\nefgh" }), "login.password"},
		{"extra field repeats user", mut(func(c *Config) { c.Login.ExtraFields = map[string]string{"user": "x"} }), "login.extra_fields"},
		{"too many extra fields", mut(func(c *Config) {
			c.Login.ExtraFields = map[string]string{}
			for i := 0; i < 21; i++ {
				c.Login.ExtraFields[strings.Repeat("f", i+1)] = "v"
			}
		}), "login.extra_fields"},
		{"bad csrf source", mut(func(c *Config) { c.Login.CSRF = &CSRF{Source: "url", Name: "t"} }), "login.csrf.source"},
		{"csrf header with bad name", mut(func(c *Config) {
			c.Login.CSRF = &CSRF{Source: "cookie", Name: "t", SendAs: "header", HeaderName: "X Bad"}
		}), "login.csrf.header_name"},
		{"csrf header host", mut(func(c *Config) {
			c.Login.CSRF = &CSRF{Source: "cookie", Name: "t", SendAs: "header", HeaderName: "Host"}
		}), "login.csrf.header_name"},
		{"token bad path", mut(func(c *Config) { c.Login.Token = &Token{From: "json", Path: "data..x"} }), "login.token.path"},
		{"token path too long", mut(func(c *Config) { c.Login.Token = &Token{Path: strings.Repeat("a", 201)} }), "login.token.path"},
		{"token empty path", mut(func(c *Config) { c.Login.Token = &Token{} }), "login.token.path"},
		{"token bad from", mut(func(c *Config) { c.Login.Token = &Token{From: "body", Path: "a"} }), "login.token.from"},
		{"token header from needs name", mut(func(c *Config) { c.Login.Token = &Token{From: "header", Path: "a b"} }), "login.token.path"},
		{"token bad send_as", mut(func(c *Config) { c.Login.Token = &Token{Path: "a", SendAs: "body"} }), "login.token.send_as"},
		{"token host header", mut(func(c *Config) { c.Login.Token = &Token{Path: "a", HeaderName: "Host"} }), "login.token.header_name"},
		{"token cookie header", mut(func(c *Config) { c.Login.Token = &Token{Path: "a", HeaderName: "cookie"} }), "login.token.header_name"},
		{"token CRLF header name", mut(func(c *Config) { c.Login.Token = &Token{Path: "a", HeaderName: "X-A\r\nX-B"} }), "login.token.header_name"},
		{"token CRLF prefix", mut(func(c *Config) { p := "Bearer\r\nX: 1"; c.Login.Token = &Token{Path: "a", Prefix: &p} }), "login.token.prefix"},
		{"token long prefix", mut(func(c *Config) { p := strings.Repeat("p", 33); c.Login.Token = &Token{Path: "a", Prefix: &p} }), "login.token.prefix"},
		{"token cookie without name", mut(func(c *Config) { c.Login.Token = &Token{Path: "a", SendAs: "cookie"} }), "login.token.cookie_name"},
		{"token cookie bad name", mut(func(c *Config) { c.Login.Token = &Token{Path: "a", SendAs: "cookie", CookieName: "a b"} }), "login.token.cookie_name"},
		{"json_path_exists bad", mut(func(c *Config) { c.Login.Success = &Success{JSONPathExists: "a["} }), "login.success.json_path_exists"},
		{"json_path_equals bad path", mut(func(c *Config) { c.Login.Success = &Success{JSONPathEquals: &JSONEquals{Path: "[x]", Value: "ok"}} }), "login.success.json_path_equals.path"},
		{"json_path_equals bad value", mut(func(c *Config) {
			c.Login.Success = &Success{JSONPathEquals: &JSONEquals{Path: "status", Value: []any{1}}}
		}), "login.success.json_path_equals.value"},
		{"status out of range", mut(func(c *Config) { c.Login.Success = &Success{Statuses: []int{99}} }), "login.success.statuses"},
		{"body_contains too long", mut(func(c *Config) { c.Login.Success = &Success{BodyContains: strings.Repeat("x", 201)} }), "login.success.body_contains"},
		{"headers with form", mut(func(c *Config) { c.Headers = map[string]string{"X-Key": "abcd1234"} }), "headers"},
		{"login with header type", Config{Type: TypeHeader, Login: formCfg().Login, Headers: map[string]string{"X-Key": "abcd1234"}}, "login"},
		{"header type without headers", Config{Type: TypeHeader}, "headers"},
		{"CRLF in header value", Config{Type: TypeHeader, Headers: map[string]string{"X-Key": "abcd\r\nX-Evil: 1"}}, "headers"},
		{"LF in header value", Config{Type: TypeHeader, Headers: map[string]string{"X-Key": "abcd\nefgh"}}, "headers"},
		{"CRLF in header name", Config{Type: TypeHeader, Headers: map[string]string{"X-Key\r\nX-Evil": "abcd1234"}}, "headers"},
		{"header name with space", Config{Type: TypeHeader, Headers: map[string]string{"X Key": "abcd1234"}}, "headers"},
		{"Host header", Config{Type: TypeHeader, Headers: map[string]string{"host": "evil.example.net"}}, "headers"},
		{"Cookie header", Config{Type: TypeHeader, Headers: map[string]string{"Cookie": "a=bcdef"}}, "headers"},
		{"duplicate header (case)", Config{Type: TypeHeader, Headers: map[string]string{"X-Key": "abcd1234", "x-key": "abcd1234"}}, "headers"},
		{"empty header value", Config{Type: TypeHeader, Headers: map[string]string{"X-Key": ""}}, "headers"},
		{"header value 4 KiB + 1", Config{Type: TypeHeader, Headers: map[string]string{"X-Key": long}}, "headers"},
		{"cookie with semicolon", Config{Type: TypeHeader, Cookies: map[string]string{"sid": "abcd;efgh"}}, "cookies"},
		{"cookie with CRLF", Config{Type: TypeHeader, Cookies: map[string]string{"sid": "abcd\r\nefgh"}}, "cookies"},
		{"bad cookie name", Config{Type: TypeHeader, Cookies: map[string]string{"s=id": "abcd1234"}}, "cookies"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Validate(c.cfg, base)
			if err == nil {
				t.Fatal("accepted")
			}
			if got := field(t, err); got != c.field && !strings.HasPrefix(got, c.field+".") && !strings.HasPrefix(got, c.field+"[") {
				t.Fatalf("field %q, want %q (%v)", got, c.field, err)
			}
		})
	}
	// More than 10 headers.
	h := map[string]string{}
	for i := 0; i < 11; i++ {
		h["X-H"+strings.Repeat("a", i)] = "abcd1234"
	}
	if _, err := Validate(Config{Type: TypeHeader, Headers: h}, base); err == nil {
		t.Fatal("11 headers accepted")
	}
	delete(h, "X-H")
	if _, err := Validate(Config{Type: TypeHeader, Headers: h}, base); err != nil {
		t.Fatalf("10 headers: %v", err)
	}
	// Total size above 16 KiB: five 4 KiB values.
	big := map[string]string{}
	for i := 0; i < 5; i++ {
		big["X-Big"+strings.Repeat("a", i)] = strings.Repeat("v", 4096)
	}
	if _, err := Validate(Config{Type: TypeHeader, Headers: big}, base); err == nil || !strings.Contains(err.Error(), "16 KiB") {
		t.Fatalf("total size: %v", err)
	}
}

func TestMergeKeepsBlankSecretsOfTheSameName(t *testing.T) {
	prev := Config{Type: TypeFormHeader, Login: &Login{Password: "old-pass", ExtraFields: map[string]string{"otp": "old-otp"}},
		Headers: map[string]string{"Authorization": "Bearer old-token"}, Cookies: map[string]string{"sid": "old-cookie"}}
	in := Config{Type: TypeFormHeader, Login: &Login{URL: "x", ExtraFields: map[string]string{"otp": "", "new": ""}},
		Headers: map[string]string{"authorization": "", "X-New": ""}, Cookies: map[string]string{"sid": "", "other": "fresh-value"}}
	out := Merge(in, &prev)
	if out.Login.Password != "old-pass" || out.Login.ExtraFields["otp"] != "old-otp" || out.Login.ExtraFields["new"] != "" ||
		out.Headers["authorization"] != "Bearer old-token" || out.Headers["X-New"] != "" || out.Cookies["sid"] != "old-cookie" || out.Cookies["other"] != "fresh-value" {
		t.Fatalf("%+v %+v", out.Login, out)
	}
	if in.Login.Password != "" || in.Headers["authorization"] != "" {
		t.Fatal("Merge must not modify its input")
	}
	// A new value wins.
	in.Login.Password = "typed-now"
	if Merge(in, &prev).Login.Password != "typed-now" {
		t.Fatal("typed password must win")
	}
	// Without a stored config a blank secret stays blank (and validation rejects it).
	if Merge(in, nil).Headers["X-New"] != "" {
		t.Fatal("no previous value")
	}
}

func TestMetaAndViewCarryNoSecrets(t *testing.T) {
	cfg := Config{Type: TypeFormHeader, Login: &Login{URL: base + "/login", Method: "POST", BodyFormat: "json", UsernameField: "u", PasswordField: "p",
		Username: "tester", Password: "TOP-SECRET-pw", ExtraFields: map[string]string{"otp": "SECRET-OTP-1"},
		CSRF:    &CSRF{Source: "html_input", Name: "_csrf", SendAs: "field"},
		Success: &Success{Statuses: []int{200}, CookieSet: "sid"}},
		Headers: map[string]string{"Authorization": "Bearer SECRET-TOKEN-1"}, Cookies: map[string]string{"sid": "SECRET-COOKIE-1"}}
	raw, _ := json.Marshal(MetaOf(cfg, time.Date(2026, 10, 28, 1, 2, 3, 0, time.UTC), map[string]any{"id": 1, "username": "adm"}))
	view, _ := json.Marshal(View(TypeFormHeader, true, raw))
	for _, out := range []string{string(raw), string(view)} {
		for _, sec := range []string{"TOP-SECRET-pw", "SECRET-OTP-1", "SECRET-TOKEN-1", "SECRET-COOKIE-1"} {
			if strings.Contains(out, sec) {
				t.Fatalf("secret %q in %s", sec, out)
			}
		}
	}
	var v map[string]any
	_ = json.Unmarshal(view, &v)
	if v["has_secret"] != true || v["username"] != "tester" || v["login_url"] != base+"/login" || v["updated_at"] != "2026-10-28T01:02:03Z" {
		t.Fatalf("view: %s", view)
	}
	// Type none has every key, null or empty.
	var n map[string]any
	nb, _ := json.Marshal(View(TypeNone, false, nil))
	_ = json.Unmarshal(nb, &n)
	if len(n) != 16 || n["login_url"] != nil || n["has_secret"] != false {
		t.Fatalf("none: %s", nb)
	}
}

func TestEngineFileMatchesTheContract(t *testing.T) {
	cfg := Config{Type: TypeFormHeader, Login: &Login{URL: base + "/login", Method: "POST", BodyFormat: "json", UsernameField: "u", PasswordField: "p",
		Username: "tester", Password: "pw-123456", ExtraFields: map[string]string{"remember": "1"},
		CSRF:    &CSRF{Source: "header", Name: "X-CSRF", SendAs: "header", HeaderName: "X-CSRF-Token"},
		Success: &Success{Statuses: []int{200, 302}, CookieSet: "sid", BodyContains: "Welcome", BodyNotContains: "Invalid", RedirectNotTo: "/login"}},
		Headers: map[string]string{"Authorization": "Bearer abcdef"}, Cookies: map[string]string{"sid": "v1v1v1"}}
	b, err := EngineFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	l := doc["login"].(map[string]any)
	for k, want := range map[string]any{"type": "form", "url": base + "/login", "method": "POST", "body_format": "json", "username_field": "u",
		"password_field": "p", "username": "tester", "password": "pw-123456"} {
		if l[k] != want {
			t.Errorf("login.%s = %v, want %v", k, l[k], want)
		}
	}
	csrf, succ := l["csrf"].(map[string]any), l["success"].(map[string]any)
	if csrf["source"] != "header" || csrf["name"] != "X-CSRF" || csrf["send_as"] != "header" || csrf["header_name"] != "X-CSRF-Token" ||
		succ["cookie_set"] != "sid" || succ["body_contains"] != "Welcome" || succ["body_not_contains"] != "Invalid" || succ["redirect_not_to"] != "/login" ||
		len(succ["statuses"].([]any)) != 2 || doc["version"].(float64) != 1 || l["extra_fields"].(map[string]any)["remember"] != "1" {
		t.Fatalf("%s", b)
	}
	// header/cookie only: no login key.
	b2, _ := EngineFile(Config{Type: TypeHeader, Headers: map[string]string{"X-Key": "abcd1234"}})
	if strings.Contains(string(b2), `"login"`) || !strings.Contains(string(b2), `"version":1`) {
		t.Fatalf("%s", b2)
	}
}

func TestSecretsCoverValuesAndTheirEncodings(t *testing.T) {
	cfg := Config{Type: TypeFormHeader, Login: &Login{Username: "tester", Password: `p"w&x y/1`, ExtraFields: map[string]string{"otp": "123456", "r": "1"}},
		Headers: map[string]string{"Authorization": "Bearer tok-ABCDEF"}, Cookies: map[string]string{"sid": "cookie-value"}}
	sec := Secrets(cfg)
	has := func(s string) bool {
		for _, x := range sec {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, want := range []string{`p"w&x y/1`, `p\"w&x y/1`, "p%22w%26x+y%2F1", "123456", "Bearer tok-ABCDEF", "tok-ABCDEF", "cookie-value",
		base64.StdEncoding.EncodeToString([]byte("tester:" + `p"w&x y/1`))} {
		if !has(want) {
			t.Errorf("Secrets lacks %q", want)
		}
	}
	if has("1") || has("") {
		t.Error("values shorter than 4 characters must not be listed")
	}
	// Longest first: a header value is replaced as a whole, not only its token part.
	got := Redact("Authorization: Bearer tok-ABCDEF done", sec)
	if got != "Authorization: [REDACTED] done" {
		t.Fatalf("%q", got)
	}
	if Redact("nothing here", sec) != "nothing here" {
		t.Fatal("unrelated text changed")
	}
}

func TestValidateExclude(t *testing.T) {
	ok, err := ValidateExclude([]string{`^/admin`, `\.(pdf|zip)$`, ` /logout `})
	if err != nil || len(ok) != 3 || ok[2] != "/logout" {
		t.Fatalf("%v %v", ok, err)
	}
	if out, err := ValidateExclude(nil); err != nil || out == nil || len(out) != 0 {
		t.Fatalf("nil list must give an empty, non-nil list: %v %v", out, err)
	}
	many := make([]string, 21)
	for i := range many {
		many[i] = "a"
	}
	for name, in := range map[string][]string{
		"21 patterns":   many,
		"201 chars":     {strings.Repeat("a", 201)},
		"empty":         {"  "},
		"unclosed":      {"(abc"},
		"lookahead":     {"(?=x)"},
		"backreference": {`(a)\1`},
		"huge repeat":   {"a{1001}"},
		"nested repeat": {"((a{100}){100}){100}"},
		"control char":  {"a\x00b"},
		"newline":       {"a\nb"},
	} {
		if _, err := ValidateExclude(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Exactly 200 characters and exactly 20 patterns are fine.
	if _, err := ValidateExclude([]string{strings.Repeat("a", 200)}); err != nil {
		t.Errorf("200 chars: %v", err)
	}
	if _, err := ValidateExclude(many[:20]); err != nil {
		t.Errorf("20 patterns: %v", err)
	}
}

func TestOriginComparison(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"https://shop.example.com", "https://SHOP.example.com/login", true},
		{"https://shop.example.com:443/a", "https://shop.example.com/b", true},
		{"http://shop.example.com:80", "http://shop.example.com/", true},
		{"https://shop.example.com", "http://shop.example.com", false},
		{"https://shop.example.com", "https://shop.example.com:8443", false},
		{"https://shop.example.com", "https://shop2.example.com", false},
		{"https://shop.example.com", "https://shop.example.com.evil.net", false},
		{"https://shop.example.com", "ftp://shop.example.com", false},
	} {
		if SameOrigin(c.a, c.b) != c.same {
			t.Errorf("SameOrigin(%q, %q) != %v", c.a, c.b, c.same)
		}
	}
}

func TestValidateReportsAllFields(t *testing.T) {
	cfg := Config{Type: TypeFormHeader,
		Login: &Login{URL: "https://other.example.net/login", UsernameField: "", PasswordField: "p", Username: "", Password: "",
			Success: &Success{Statuses: []int{200, 999, 42}, CookieSet: "bad name"}},
		Headers: map[string]string{"X-Ok": "abcd1234", "Host": "evil", "X-Short": "ab"},
		Cookies: map[string]string{"sid": ""}}
	_, err := Validate(cfg, base)
	ae, ok := apierr.As(err)
	if !ok || ae.Status != 422 || ae.Code != "validation_failed" {
		t.Fatalf("got %v", err)
	}
	got := map[string]string{}
	for _, f := range apierr.FieldsOf(ae) {
		got[f.Field] = f.Message
	}
	for _, want := range []string{"login.url", "login.username_field", "login.username", "login.password",
		"login.success.statuses[1]", "login.success.statuses[2]", "login.success.cookie_set", "headers.Host", "headers.X-Short", "cookies.sid"} {
		if got[want] == "" {
			t.Errorf("missing field error %q in %v", want, got)
		}
	}
	if _, bad := got["headers.X-Ok"]; bad {
		t.Errorf("valid header reported: %v", got)
	}
	if got["login.password"] != "login.password is required." {
		t.Errorf("message %q", got["login.password"])
	}
	if apierr.FieldOf(ae) != apierr.FieldsOf(ae)[0].Field || ae.Message != apierr.FieldsOf(ae)[0].Message {
		t.Errorf("details.field/message must mirror the first error: %v", ae)
	}
}

func TestValidateExcludeReportsEachRow(t *testing.T) {
	_, err := ValidateExclude([]string{`^/ok`, `(`, ``, `[a-`})
	ae, ok := apierr.As(err)
	if !ok {
		t.Fatalf("got %v", err)
	}
	var fields []string
	for _, f := range apierr.FieldsOf(ae) {
		fields = append(fields, f.Field)
	}
	if strings.Join(fields, ",") != "dast_crawl_exclude[1],dast_crawl_exclude[2],dast_crawl_exclude[3]" {
		t.Fatalf("fields %v", fields)
	}
}
