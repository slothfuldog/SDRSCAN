// Package dastauth models the authentication of authenticated DAST scans: the configuration that
// is stored encrypted (secrets included), its validation, the non-secret view for the API and the
// UI, the JSON file handed to sdrscan-dast (--auth-file) and the list of values that must never
// reach logs.
//
// Secrets (passwords, tokens, header and cookie values, extra login field values) live only in
// Config. Everything that is shown, logged or audited is derived through Meta/View, which carry
// names and other non-secret settings only.
package dastauth

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
)

// Limits of the configuration.
const (
	MaxHeaders    = 10
	MaxCookies    = 10
	MaxExtra      = 20
	MaxValueBytes = 4 << 10  // one header/cookie value
	MaxTotalBytes = 16 << 10 // the whole configuration as JSON
	MinSecretLen  = 4        // shorter secrets could not be redacted reliably
	MaxStatuses   = 10
)

// Types of authentication.
const (
	TypeNone       = "none"
	TypeForm       = "form"
	TypeHeader     = "header"
	TypeFormHeader = "form+header"
)

// Config is the full authentication configuration (this is what is encrypted at rest and what the
// PUT endpoint accepts).
type Config struct {
	Type    string            `json:"type"`
	Login   *Login            `json:"login,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
}

// Login describes a form or JSON login.
type Login struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	BodyFormat    string            `json:"body_format"`
	UsernameField string            `json:"username_field"`
	PasswordField string            `json:"password_field"`
	Username      string            `json:"username"`
	Password      string            `json:"password"`
	ExtraFields   map[string]string `json:"extra_fields,omitempty"`
	CSRF          *CSRF             `json:"csrf,omitempty"`
	Token         *Token            `json:"token,omitempty"`
	Success       *Success          `json:"success,omitempty"`
}

// Token tells the engine to read a token from the login response (a JSON body or a response
// header) and to send it with every later request to the target origin. The token itself is
// dynamic: it is never stored, only where to find it and how to send it.
type Token struct {
	From       string  `json:"from,omitempty"`        // json | header
	Path       string  `json:"path"`                  // dotted JSON path (items[0].token) or response header name
	SendAs     string  `json:"send_as,omitempty"`     // header | cookie
	HeaderName string  `json:"header_name,omitempty"` // request header (send_as header), default Authorization
	Prefix     *string `json:"prefix,omitempty"`      // value prefix (send_as header); nil = default, "" = none
	CookieName string  `json:"cookie_name,omitempty"` // request cookie (send_as cookie)
}

// JSONEquals asserts that the JSON value at Path equals Value (string, number or boolean).
type JSONEquals struct {
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// CSRF tells the engine where to read an anti-CSRF token and how to send it back.
type CSRF struct {
	Source     string `json:"source"`  // html_input | cookie | header
	Name       string `json:"name"`    // input / cookie / header name to read
	SendAs     string `json:"send_as"` // field | header
	HeaderName string `json:"header_name,omitempty"`
}

// Success are the indicators that a login worked.
type Success struct {
	Statuses        []int  `json:"statuses,omitempty"`
	CookieSet       string `json:"cookie_set,omitempty"`
	BodyContains    string `json:"body_contains,omitempty"`
	BodyNotContains string `json:"body_not_contains,omitempty"`
	RedirectNotTo   string `json:"redirect_not_to,omitempty"`
	// JSONPathExists / JSONPathEquals check the JSON body of the login response.
	JSONPathExists string      `json:"json_path_exists,omitempty"`
	JSONPathEquals *JSONEquals `json:"json_path_equals,omitempty"`
}

// Active reports whether any authentication is configured.
func (c Config) Active() bool { return c.Type != "" && c.Type != TypeNone }

func bad(field, msg string) error {
	return apierr.ValidationField(field, msg)
}

var (
	fieldNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]{1,100}$`)
	// RFC 9110 token: header and cookie names.
	tokenRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
)

// forbiddenHeaders are never configurable: they would break the request framing or the origin
// binding, or have their own mechanism (cookies).
var forbiddenHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "cookie": true,
	"upgrade": true, "te": true, "trailer": true, "keep-alive": true, "expect": true,
	"proxy-authorization": true, "proxy-connection": true, "x-forwarded-host": true,
}

func hasCtl(s string, allowTab bool) bool {
	for _, r := range s {
		if r == '\t' && allowTab {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// Origin returns scheme://host:port of an absolute http(s) URL in a normalised form for comparison.
func Origin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port, true
}

// SameOrigin reports whether a and b share scheme, host and port.
func SameOrigin(a, b string) bool {
	oa, ok1 := Origin(a)
	ob, ok2 := Origin(b)
	return ok1 && ok2 && oa == ob
}

// Merge fills blank secrets of in from prev (same field names), so that non-secret settings can be
// edited without re-entering the write-only values. Blank means "keep"; a value that is not stored
// stays blank and fails validation (except extra field values, which may legitimately be empty).
func Merge(in Config, prev *Config) Config {
	if prev == nil {
		return in
	}
	out := in
	if in.Login != nil {
		l := *in.Login
		if prev.Login != nil {
			if l.Password == "" {
				l.Password = prev.Login.Password
			}
			if len(l.ExtraFields) > 0 {
				ef := make(map[string]string, len(l.ExtraFields))
				for k, v := range l.ExtraFields {
					if v == "" {
						v = prev.Login.ExtraFields[k]
					}
					ef[k] = v
				}
				l.ExtraFields = ef
			}
		}
		out.Login = &l
	}
	fill := func(cur, old map[string]string, fold bool) map[string]string {
		if len(cur) == 0 {
			return cur
		}
		m := make(map[string]string, len(cur))
		for k, v := range cur {
			if v == "" {
				for ok, ov := range old {
					if ok == k || (fold && strings.EqualFold(ok, k)) {
						v = ov
						break
					}
				}
			}
			m[k] = v
		}
		return m
	}
	out.Headers = fill(in.Headers, prev.Headers, true)
	out.Cookies = fill(in.Cookies, prev.Cookies, false)
	return out
}

// Validate checks and normalises c for the target base URL. It does not touch the network; the
// caller applies the network policy to the login host separately. Every failing field is reported
// (details.fields) instead of only the first one.
func Validate(c Config, baseURL string) (Config, error) {
	var fe apierr.FieldErrors
	switch c.Type {
	case TypeForm, TypeHeader, TypeFormHeader:
	case TypeNone, "":
		return c, bad("type", "Use DELETE to remove the authentication; type must be form, header or form+header.")
	default:
		return c, bad("type", "type must be form, header or form+header.")
	}
	wantLogin := c.Type == TypeForm || c.Type == TypeFormHeader
	wantHeaders := c.Type == TypeHeader || c.Type == TypeFormHeader
	if wantLogin {
		if c.Login == nil {
			fe.Add("login", "login is required for this type.")
		} else {
			l := validateLogin(*c.Login, baseURL, &fe)
			c.Login = &l
		}
	} else if c.Login != nil {
		fe.Add("login", "login is not allowed for type "+c.Type+".")
	}
	if wantHeaders {
		if len(c.Headers)+len(c.Cookies) == 0 {
			fe.Add("headers", "At least one header or cookie is required for this type.")
		}
		validateHeaders(c.Headers, &fe)
		validateCookies(c.Cookies, &fe)
	} else if len(c.Headers) > 0 || len(c.Cookies) > 0 {
		fe.Add("headers", "headers and cookies are not allowed for type "+c.Type+".")
	}
	if err := fe.Err(); err != nil {
		return c, err
	}
	b, err := json.Marshal(c)
	if err != nil || len(b) > MaxTotalBytes {
		return c, bad("type", "The authentication configuration is too large (maximum 16 KiB).")
	}
	return c, nil
}

func validateLogin(l Login, baseURL string, fe *apierr.FieldErrors) Login {
	l.URL = strings.TrimSpace(l.URL)
	if msg := checkLoginURL(l.URL, baseURL); msg != "" {
		fe.Add("login.url", msg)
	}
	l.Method = strings.ToUpper(strings.TrimSpace(l.Method))
	if l.Method == "" {
		l.Method = "POST"
	}
	if l.Method != "POST" && l.Method != "PUT" && l.Method != "PATCH" {
		fe.Add("login.method", "login.method must be POST, PUT or PATCH.")
	}
	if l.BodyFormat == "" {
		l.BodyFormat = "form"
	}
	if l.BodyFormat != "form" && l.BodyFormat != "json" {
		fe.Add("login.body_format", "login.body_format must be form or json.")
	}
	if !fieldNameRe.MatchString(l.UsernameField) {
		fe.Add("login.username_field", "login.username_field is required (letters, digits and _ . : [ ] -, at most 100).")
	}
	if !fieldNameRe.MatchString(l.PasswordField) {
		fe.Add("login.password_field", "login.password_field is required (letters, digits and _ . : [ ] -, at most 100).")
	} else if l.UsernameField == l.PasswordField {
		fe.Add("login.password_field", "login.username_field and login.password_field must differ.")
	}
	if n := utf8.RuneCountInString(l.Username); n < 1 {
		fe.Add("login.username", "login.username is required.")
	} else if n > 256 || hasCtl(l.Username, false) {
		fe.Add("login.username", "login.username must be at most 256 characters without control characters.")
	}
	switch {
	case l.Password == "":
		fe.Add("login.password", "login.password is required.")
	case len(l.Password) < MinSecretLen || len(l.Password) > 1024 || hasCtl(l.Password, false):
		fe.Add("login.password", "login.password must be 4 to 1024 characters without control characters.")
	}
	if len(l.ExtraFields) > MaxExtra {
		fe.Add("login.extra_fields", "At most 20 extra fields are allowed.")
	}
	for _, k := range sortedKeys(l.ExtraFields) {
		v := l.ExtraFields[k]
		path := "login.extra_fields." + k
		switch {
		case !fieldNameRe.MatchString(k):
			fe.Add("login.extra_fields", "Extra field name "+strconv.Quote(clip(k, 40))+" may contain only letters, digits and _ . : [ ] - (at most 100).")
		case k == l.UsernameField || k == l.PasswordField:
			fe.Add(path, "An extra field must not repeat the username or password field.")
		case len(v) > 1024 || hasCtl(v, false):
			fe.Add(path, "Extra field values must be at most 1024 characters without control characters.")
		}
	}
	if l.CSRF != nil {
		c := *l.CSRF
		switch c.Source {
		case "html_input", "cookie", "header":
		default:
			fe.Add("login.csrf.source", "login.csrf.source must be html_input, cookie or header.")
		}
		if !fieldNameRe.MatchString(c.Name) && !tokenRe.MatchString(c.Name) {
			fe.Add("login.csrf.name", "login.csrf.name is required (at most 100 characters).")
		}
		if c.SendAs == "" { // the engine's defaults: field for html_input, header for cookie and header sources
			c.SendAs = "header"
			if c.Source == "html_input" {
				c.SendAs = "field"
			}
		}
		switch c.SendAs {
		case "field":
			c.HeaderName = ""
		case "header":
			if c.HeaderName == "" {
				c.HeaderName = "X-CSRF-Token"
			}
			if !tokenRe.MatchString(c.HeaderName) || forbiddenHeaders[strings.ToLower(c.HeaderName)] {
				fe.Add("login.csrf.header_name", "login.csrf.header_name must be a valid header name when send_as is header.")
			}
		default:
			fe.Add("login.csrf.send_as", "login.csrf.send_as must be field or header.")
		}
		l.CSRF = &c
	}
	if l.Token != nil {
		t := validateToken(*l.Token, fe)
		l.Token = &t
	}
	if l.Success != nil {
		s := *l.Success
		if len(s.Statuses) > MaxStatuses {
			fe.Add("login.success.statuses", "At most 10 status codes are allowed.")
		}
		seen := map[int]bool{}
		var sts []int
		for i, c := range s.Statuses {
			if c < 100 || c > 599 {
				fe.Add("login.success.statuses["+strconv.Itoa(i)+"]", "Status codes must be between 100 and 599.")
				continue
			}
			if !seen[c] {
				seen[c] = true
				sts = append(sts, c)
			}
		}
		sort.Ints(sts)
		s.Statuses = sts
		if s.CookieSet != "" && !tokenRe.MatchString(s.CookieSet) {
			fe.Add("login.success.cookie_set", "login.success.cookie_set must be a valid cookie name.")
		}
		for _, p := range []struct{ name, v string }{{"body_contains", s.BodyContains}, {"body_not_contains", s.BodyNotContains}, {"redirect_not_to", s.RedirectNotTo}} {
			if utf8.RuneCountInString(p.v) > 200 || hasCtl(p.v, false) {
				fe.Add("login.success."+p.name, "login.success."+p.name+" must be at most 200 characters without control characters.")
			}
		}
		s.JSONPathExists = strings.TrimSpace(s.JSONPathExists)
		if s.JSONPathExists != "" && !ValidJSONPath(s.JSONPathExists) {
			fe.Add("login.success.json_path_exists", jsonPathMsg("login.success.json_path_exists"))
		}
		if e := s.JSONPathEquals; e != nil {
			e2 := *e
			e2.Path = strings.TrimSpace(e2.Path)
			if !ValidJSONPath(e2.Path) {
				fe.Add("login.success.json_path_equals.path", jsonPathMsg("login.success.json_path_equals.path"))
			}
			switch v := e2.Value.(type) {
			case string:
				if utf8.RuneCountInString(v) > 200 || hasCtl(v, false) {
					fe.Add("login.success.json_path_equals.value", "login.success.json_path_equals.value must be at most 200 characters without control characters.")
				}
			case float64, bool:
			default:
				fe.Add("login.success.json_path_equals.value", "login.success.json_path_equals.value must be a string, number or boolean.")
			}
			s.JSONPathEquals = &e2
		}
		l.Success = &s
	}
	return l
}

// MaxJSONPath is the longest JSON path accepted.
const MaxJSONPath = 200

func jsonPathMsg(field string) string {
	return field + " must be a dotted JSON path such as data.access_token or items[0].token (at most 200 characters)."
}

// ValidJSONPath mirrors the engine's path syntax: dot-separated keys, each optionally followed by
// [n] indexes; a path may start with [n] (a root array). No wildcards or filters.
func ValidJSONPath(p string) bool {
	if p == "" || len(p) > MaxJSONPath {
		return false
	}
	n := 0
	for i, part := range strings.Split(p, ".") {
		name, rest := part, ""
		if j := strings.IndexByte(part, '['); j >= 0 {
			name, rest = part[:j], part[j:]
		}
		if strings.Contains(name, "]") || hasCtl(name, false) {
			return false
		}
		if name == "" {
			if i != 0 || rest == "" {
				return false
			}
		} else {
			n++
		}
		for rest != "" {
			if rest[0] != '[' {
				return false
			}
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return false
			}
			d := rest[1:end]
			if d == "" || len(d) > 6 {
				return false
			}
			for _, c := range d {
				if c < '0' || c > '9' {
					return false
				}
			}
			n++
			rest = rest[end+1:]
		}
	}
	return n > 0 && n <= 32
}

func validateToken(t Token, fe *apierr.FieldErrors) Token {
	if t.From == "" {
		t.From = "json"
	}
	t.Path = strings.TrimSpace(t.Path)
	switch t.From {
	case "json":
		if !ValidJSONPath(t.Path) {
			fe.Add("login.token.path", jsonPathMsg("login.token.path"))
		}
	case "header":
		if !tokenRe.MatchString(t.Path) {
			fe.Add("login.token.path", "login.token.path must be a valid response header name when from is header.")
		}
	default:
		fe.Add("login.token.from", "login.token.from must be json or header.")
	}
	if t.SendAs == "" {
		t.SendAs = "header"
	}
	switch t.SendAs {
	case "header":
		t.CookieName = ""
		if t.HeaderName == "" {
			t.HeaderName = "Authorization"
		}
		if !tokenRe.MatchString(t.HeaderName) || forbiddenHeaders[strings.ToLower(t.HeaderName)] ||
			strings.HasPrefix(strings.ToLower(t.HeaderName), "proxy-") || strings.HasPrefix(strings.ToLower(t.HeaderName), "sec-") {
			fe.Add("login.token.header_name", "login.token.header_name must be a valid header name that can be configured (not Host, Cookie, Content-Length and similar).")
		}
		if t.Prefix == nil && strings.EqualFold(t.HeaderName, "Authorization") {
			p := "Bearer "
			t.Prefix = &p
		}
		if t.Prefix != nil {
			p := *t.Prefix
			if utf8.RuneCountInString(p) > 32 || hasCtl(p, false) || !isASCII(p) {
				fe.Add("login.token.prefix", "login.token.prefix must be at most 32 ASCII characters without control characters (CR/LF).")
			}
		}
	case "cookie":
		t.HeaderName, t.Prefix = "", nil
		if !tokenRe.MatchString(t.CookieName) {
			fe.Add("login.token.cookie_name", "login.token.cookie_name is required (a valid cookie name) when send_as is cookie.")
		}
	default:
		fe.Add("login.token.send_as", "login.token.send_as must be header or cookie.")
	}
	return t
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// checkLoginURL validates the login URL; msg is "" when it is fine.
func checkLoginURL(raw, baseURL string) string {
	if raw == "" {
		return "login.url is required."
	}
	if len(raw) > 2000 || hasCtl(raw, false) || strings.ContainsAny(raw, " \\") {
		return "login.url must be an absolute http(s) URL."
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "login.url must be an absolute http(s) URL."
	}
	if u.User != nil {
		return "login.url must not contain credentials."
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return "login.url must not contain a fragment."
	}
	if !SameOrigin(raw, baseURL) {
		return "login.url must have the same origin (scheme, host and port) as the target base URL."
	}
	return ""
}

// clip shortens s for use in a message.
func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

func validateHeaders(h map[string]string, fe *apierr.FieldErrors) {
	if len(h) > MaxHeaders {
		fe.Add("headers", "At most 10 headers are allowed.")
	}
	seen := map[string]bool{}
	for _, k := range sortedKeys(h) {
		v := h[k]
		path := "headers." + k
		if !tokenRe.MatchString(k) {
			fe.Add("headers", "Header name "+strconv.Quote(clip(k, 40))+" is not a valid HTTP token (letters, digits and !#$%&'*+.^_`|~-, at most 100 characters).")
			continue
		}
		lk := strings.ToLower(k)
		if forbiddenHeaders[lk] || strings.HasPrefix(lk, "proxy-") || strings.HasPrefix(lk, "sec-") {
			fe.Add(path, "The header "+k+" cannot be configured.")
			continue
		}
		if seen[lk] {
			fe.Add(path, "Header names must be unique (case-insensitive).")
			continue
		}
		seen[lk] = true
		switch {
		case v == "":
			fe.Add(path, "The header "+k+" needs a value.")
		case strings.ContainsAny(v, "\r\n\x00") || hasCtl(v, true):
			fe.Add(path, "Header values must not contain CR, LF or control characters.")
		case len(v) > MaxValueBytes:
			fe.Add(path, "A header value must be at most 4 KiB.")
		case len(v) < MinSecretLen:
			fe.Add(path, "A header value must be at least 4 characters.")
		}
	}
}

func validateCookies(c map[string]string, fe *apierr.FieldErrors) {
	if len(c) > MaxCookies {
		fe.Add("cookies", "At most 10 cookies are allowed.")
	}
	for _, k := range sortedKeys(c) {
		v := c[k]
		path := "cookies." + k
		switch {
		case !tokenRe.MatchString(k):
			fe.Add("cookies", "Cookie name "+strconv.Quote(clip(k, 40))+" is not a valid token (at most 100 characters).")
		case v == "" || len(v) < MinSecretLen:
			fe.Add(path, "The cookie "+k+" needs a value of at least 4 characters.")
		case len(v) > MaxValueBytes || strings.ContainsAny(v, ";,\r\n\x00 ") || hasCtl(v, false):
			fe.Add(path, "Cookie values must be at most 4 KiB without spaces, ';', ',' or control characters.")
		}
	}
}

// ----- non-secret view -----

// Meta is the non-secret description stored beside the ciphertext and shown by the API.
type Meta map[string]any

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MetaOf builds the non-secret description of c. updatedBy is {id, username}.
func MetaOf(c Config, now time.Time, updatedBy map[string]any) Meta {
	m := Meta{
		"login_url": nil, "method": nil, "body_format": nil, "username_field": nil, "password_field": nil,
		"username": nil, "extra_field_names": []string{}, "csrf": nil, "token": nil, "success": nil,
		"header_names": sortedKeys(c.Headers), "cookie_names": sortedKeys(c.Cookies),
		"updated_at": now.UTC().Format(time.RFC3339), "updated_by": updatedBy,
	}
	if l := c.Login; l != nil {
		m["login_url"], m["method"], m["body_format"] = l.URL, l.Method, l.BodyFormat
		m["username_field"], m["password_field"], m["username"] = l.UsernameField, l.PasswordField, l.Username
		m["extra_field_names"] = sortedKeys(l.ExtraFields)
		if l.CSRF != nil {
			m["csrf"] = map[string]any{"source": l.CSRF.Source, "name": l.CSRF.Name, "send_as": l.CSRF.SendAs, "header_name": nilIfEmpty(l.CSRF.HeaderName)}
		}
		if t := l.Token; t != nil {
			tm := map[string]any{"from": t.From, "path": t.Path, "send_as": t.SendAs, "header_name": nilIfEmpty(t.HeaderName), "prefix": nil, "cookie_name": nilIfEmpty(t.CookieName)}
			if t.Prefix != nil {
				tm["prefix"] = *t.Prefix
			}
			m["token"] = tm
		}
		if s := l.Success; s != nil {
			sts := s.Statuses
			if sts == nil {
				sts = []int{}
			}
			m["success"] = map[string]any{"statuses": sts, "cookie_set": nilIfEmpty(s.CookieSet), "body_contains": nilIfEmpty(s.BodyContains),
				"body_not_contains": nilIfEmpty(s.BodyNotContains), "redirect_not_to": nilIfEmpty(s.RedirectNotTo),
				"json_path_exists": nilIfEmpty(s.JSONPathExists), "json_path_equals": nil}
			if e := s.JSONPathEquals; e != nil {
				m["success"].(map[string]any)["json_path_equals"] = map[string]any{"path": e.Path, "value": e.Value}
			}
		}
	}
	return m
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// metaKeys are the keys a view always carries (null when they do not apply).
var metaKeys = []string{"login_url", "method", "body_format", "username_field", "password_field", "username",
	"extra_field_names", "csrf", "token", "success", "header_names", "cookie_names", "updated_at", "updated_by"}

// View is the API object `dast_auth`: {type, has_secret, <meta keys>}. It never contains a secret.
// raw is the stored meta JSON (may be empty for type none).
func View(typ string, hasSecret bool, raw []byte) map[string]any {
	v := map[string]any{"type": typ, "has_secret": hasSecret}
	var stored map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &stored)
	}
	for _, k := range metaKeys {
		val, ok := stored[k]
		if !ok {
			switch k {
			case "extra_field_names", "header_names", "cookie_names":
				val = []any{}
			default:
				val = nil
			}
		}
		v[k] = val
	}
	return v
}

// ----- engine file and redaction -----

type engineLogin struct {
	Type          string            `json:"type"`
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	BodyFormat    string            `json:"body_format"`
	UsernameField string            `json:"username_field"`
	PasswordField string            `json:"password_field"`
	Username      string            `json:"username"`
	Password      string            `json:"password"`
	ExtraFields   map[string]string `json:"extra_fields,omitempty"`
	CSRF          *CSRF             `json:"csrf,omitempty"`
	Token         *Token            `json:"token,omitempty"`
	Success       *Success          `json:"success,omitempty"`
}

// EngineFile renders the JSON document for `sdrscan-dast --auth-file` (version 1).
func EngineFile(c Config) ([]byte, error) {
	doc := struct {
		Version int               `json:"version"`
		Login   *engineLogin      `json:"login,omitempty"`
		Headers map[string]string `json:"headers,omitempty"`
		Cookies map[string]string `json:"cookies,omitempty"`
	}{Version: 1, Headers: c.Headers, Cookies: c.Cookies}
	if l := c.Login; l != nil {
		doc.Login = &engineLogin{Type: "form", URL: l.URL, Method: l.Method, BodyFormat: l.BodyFormat,
			UsernameField: l.UsernameField, PasswordField: l.PasswordField, Username: l.Username, Password: l.Password,
			ExtraFields: l.ExtraFields, CSRF: l.CSRF, Token: l.Token, Success: l.Success}
	}
	return json.Marshal(doc)
}

// Secrets lists every value (and common encodings of it) that must be replaced by [REDACTED] in
// anything that is logged or stored: passwords, header and cookie values, extra field values, the
// token part of "Scheme token" header values and the Basic-auth encoding of the login.
func Secrets(c Config) []string {
	set := map[string]bool{}
	add := func(s string) {
		if len(s) < MinSecretLen {
			return
		}
		set[s] = true
		if j, err := json.Marshal(s); err == nil && len(j) > 2 { // Go escapes &, <, > as \u00XX
			set[string(j[1:len(j)-1])] = true
		}
		var sb strings.Builder
		enc := json.NewEncoder(&sb) // other JSON writers (serde_json, ...) do not
		enc.SetEscapeHTML(false)
		if enc.Encode(s) == nil {
			if j := strings.TrimSpace(sb.String()); len(j) > 2 {
				set[j[1:len(j)-1]] = true
			}
		}
		set[url.QueryEscape(s)] = true
		set[url.PathEscape(s)] = true
		set[base64.StdEncoding.EncodeToString([]byte(s))] = true
	}
	if l := c.Login; l != nil {
		add(l.Password)
		for _, v := range l.ExtraFields {
			add(v)
		}
		if l.Password != "" {
			set[base64.StdEncoding.EncodeToString([]byte(l.Username+":"+l.Password))] = true
		}
	}
	for _, v := range c.Headers {
		add(v)
		if i := strings.IndexByte(v, ' '); i > 0 {
			add(strings.TrimSpace(v[i+1:]))
		}
	}
	for _, v := range c.Cookies {
		add(v)
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	// Longest first so that a value containing another is replaced as a whole.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

var (
	// bearerRe matches "Bearer <token>" (also with a token the engine never printed).
	bearerRe = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)
	// jwtRe matches a JSON Web Token: three base64url parts, the first being a JSON header ("eyJ...").
	jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)
)

// RedactTokens masks values that look like tokens obtained at login (Bearer ... and JWTs). Such
// tokens are dynamic, so they cannot be listed in Secrets; the engine never prints them, this is
// the second line of defence.
func RedactTokens(text string) string {
	text = jwtRe.ReplaceAllString(text, "[REDACTED]")
	return bearerRe.ReplaceAllString(text, "${1}[REDACTED]")
}

// Redact replaces every secret in text with [REDACTED], then masks token-looking values.
func Redact(text string, secrets []string) string {
	for _, s := range secrets {
		if len(s) >= MinSecretLen {
			text = strings.ReplaceAll(text, s, "[REDACTED]")
		}
	}
	return RedactTokens(text)
}

// ----- crawl settings -----

// Crawl limits.
const (
	MaxExclude       = 20
	MaxExcludeLen    = 200
	DefaultMaxDepth  = 3
	DefaultMaxPages  = 50
	MaxCrawlDepthCap = 10
	MaxCrawlPagesCap = 500
)

// ValidateExclude checks the exclude patterns: at most 20, each 1..200 characters, no control
// characters, and each must compile as a regular expression (RE2 syntax: linear time, so a
// hostile pattern cannot cause catastrophic backtracking; unsupported constructs such as
// look-around or back-references are rejected).
func ValidateExclude(in []string) ([]string, error) {
	var fe apierr.FieldErrors
	if len(in) > MaxExclude {
		fe.Add("dast_crawl_exclude", "At most 20 exclusion patterns are allowed.")
	}
	out := make([]string, 0, len(in))
	for i, p := range in {
		path := "dast_crawl_exclude[" + strconv.Itoa(i) + "]"
		p = strings.TrimSpace(p)
		switch {
		case p == "":
			fe.Add(path, "Pattern "+strconv.Itoa(i+1)+" is empty; enter a regular expression or remove the row.")
		case utf8.RuneCountInString(p) > MaxExcludeLen || len(p) > 4*MaxExcludeLen || hasCtl(p, false):
			fe.Add(path, "Pattern "+strconv.Itoa(i+1)+" must be 1 to 200 characters without control characters.")
		default:
			if _, err := regexp.Compile(p); err != nil {
				fe.Add(path, "Pattern "+strconv.Itoa(i+1)+" is not a valid regular expression: "+strconv.Quote(p)+".")
				continue
			}
			out = append(out, p)
		}
	}
	if err := fe.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
