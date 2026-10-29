package httpapi_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
	"github.com/sdrscan/sdrscan/backend/internal/vulndb"
)

// fieldCase is one invalid request and the per-field error contract it must produce:
// details.field is the first failing field and, when several fail, details.fields lists all of them.
type fieldCase struct {
	name   string
	body   map[string]any
	status int
	code   string   // error.code; "" = validation_failed
	field  string   // details.field
	fields []string // details.fields (nil = single error, no list)
	msg    string   // substring of error.message ("" = not checked)
}

func runFieldCases(t *testing.T, c *testutil.Client, method, path string, cases []fieldCase) {
	t.Helper()
	for _, tc := range cases {
		r := c.Do(method, path, tc.body)
		code := tc.code
		if code == "" {
			code = "validation_failed"
		}
		if r.Status != tc.status || r.ErrCode() != code {
			t.Errorf("%s: %d %s, want %d %s", tc.name, r.Status, r.Body, tc.status, code)
			continue
		}
		if f := r.ErrField(); f != tc.field {
			t.Errorf("%s: details.field %q, want %q (%s)", tc.name, f, tc.field, r.Body)
		}
		if got := r.ErrFields(); !reflect.DeepEqual(got, tc.fields) {
			t.Errorf("%s: details.fields %v, want %v (%s)", tc.name, got, tc.fields, r.Body)
		}
		if tc.msg != "" && !strings.Contains(r.ErrMessage(), tc.msg) {
			t.Errorf("%s: message %q does not contain %q", tc.name, r.ErrMessage(), tc.msg)
		}
		if len(tc.fields) > 0 { // message mirrors the first entry; every entry has a message
			list := r.ErrDetails()["fields"].([]any)
			first := list[0].(map[string]any)
			if first["message"] != r.ErrMessage() {
				t.Errorf("%s: message %q must equal the first field message %q", tc.name, r.ErrMessage(), first["message"])
			}
			for _, it := range list {
				if m, _ := it.(map[string]any)["message"].(string); m == "" {
					t.Errorf("%s: empty field message in %s", tc.name, r.Body)
				}
			}
		}
	}
}

func TestFieldErrorsLoginAndPassword(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	runFieldCases(t, w.anon, "POST", "/api/v1/auth/login", []fieldCase{
		{name: "empty", body: map[string]any{}, status: 422, field: "username", fields: []string{"username", "password"}, msg: "Username is required."},
		{name: "no password", body: map[string]any{"username": "admin"}, status: 422, field: "password", msg: "Password is required."},
		{name: "blank username", body: map[string]any{"username": "  ", "password": "x"}, status: 422, field: "username"},
		{name: "wrong credentials stay 401", body: map[string]any{"username": "admin", "password": "wrong"}, status: 401, code: "invalid_credentials"},
	})
	pw := "/api/v1/auth/password"
	runFieldCases(t, w.member, "POST", pw, []fieldCase{
		{name: "empty", body: map[string]any{}, status: 422, field: "current_password", fields: []string{"current_password", "new_password"}},
		{name: "wrong current and short new", body: map[string]any{"current_password": "nope", "new_password": "short"}, status: 422,
			field: "current_password", fields: []string{"current_password", "new_password"}, msg: "Current password is incorrect."},
		{name: "short new", body: map[string]any{"current_password": testutil.Password, "new_password": "short"}, status: 422,
			field: "new_password", msg: "Password must be at least 12 characters."},
		{name: "same as current", body: map[string]any{"current_password": testutil.Password, "new_password": testutil.Password}, status: 422,
			field: "new_password", msg: "different from the current password"},
		{name: "new equals username", body: map[string]any{"current_password": testutil.Password, "new_password": "MEMBER"}, status: 422, field: "new_password"},
	})
}

func TestFieldErrorsUsers(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	runFieldCases(t, w.admin, "POST", "/api/v1/users", []fieldCase{
		{name: "empty", body: map[string]any{}, status: 422, field: "username", fields: []string{"username", "password"}},
		{name: "bad everything", body: map[string]any{"username": "a b", "password": "short", "role": "root"}, status: 422,
			field: "username", fields: []string{"username", "role", "password"}},
		{name: "bad username only", body: map[string]any{"username": "x", "password": "long-enough-password"}, status: 422, field: "username", msg: "3 to 64 characters"},
		{name: "short password", body: map[string]any{"username": "newbie", "password": "short"}, status: 422, field: "password", msg: "Password must be at least 12 characters."},
		{name: "bad role", body: map[string]any{"username": "newbie", "password": "long-enough-password", "role": "root"}, status: 422, field: "role"},
		{name: "taken", body: map[string]any{"username": "MEMBER", "password": "long-enough-password"}, status: 409, code: "username_taken", field: "username"},
	})
	uid := testutil.MustID(t, w.admin.Get("/api/v1/users").JSON()["items"].([]any)[0].(map[string]any), "id")
	runFieldCases(t, w.admin, "POST", fmt.Sprintf("/api/v1/users/%d/reset-password", uid), []fieldCase{
		{name: "empty", body: map[string]any{}, status: 422, field: "new_password", msg: "New password is required."},
		{name: "short", body: map[string]any{"new_password": "short"}, status: 422, field: "new_password", msg: "at least 12"},
	})
	runFieldCases(t, w.admin, "PATCH", fmt.Sprintf("/api/v1/users/%d", uid), []fieldCase{
		{name: "bad role", body: map[string]any{"role": "root"}, status: 422, field: "role"},
	})
}

func TestFieldErrorsTokensAndProjects(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	runFieldCases(t, w.admin, "POST", "/api/v1/ingest-tokens", []fieldCase{
		{name: "no name", body: map[string]any{}, status: 422, field: "name", msg: "name is required."},
		{name: "name and project", body: map[string]any{"name": "", "project_id": -3}, status: 422, field: "name", fields: []string{"name", "project_id"}},
		{name: "unknown project", body: map[string]any{"name": "ci", "project_id": 987654}, status: 422, field: "project_id", msg: "does not exist"},
		{name: "long name", body: map[string]any{"name": strings.Repeat("n", 101)}, status: 422, field: "name", msg: "at most 100"},
	})
	runFieldCases(t, w.admin, "POST", "/api/v1/projects", []fieldCase{
		{name: "empty", body: map[string]any{}, status: 422, field: "name", msg: "name is required."},
		{name: "name and description", body: map[string]any{"name": "", "description": strings.Repeat("d", 1001)}, status: 422,
			field: "name", fields: []string{"name", "description"}},
		{name: "control chars", body: map[string]any{"name": "a\x01b"}, status: 422, field: "name"},
		{name: "taken", body: map[string]any{"name": "online shop"}, status: 409, code: "name_taken", field: "name"},
	})
	runFieldCases(t, w.admin, "PATCH", fmt.Sprintf("/api/v1/projects/%d", w.projectID), []fieldCase{
		{name: "blank name", body: map[string]any{"name": " "}, status: 422, field: "name"},
		{name: "both", body: map[string]any{"name": "", "description": strings.Repeat("d", 1001)}, status: 422, field: "name", fields: []string{"name", "description"}},
	})
	runFieldCases(t, w.admin, "DELETE", fmt.Sprintf("/api/v1/projects/%d", w.projectID), []fieldCase{
		{name: "no confirm", status: 422, code: "confirmation_required", field: "confirm"},
	})
}

func TestFieldErrorsCodebaseCreate(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	path := fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID)
	repo := func(m map[string]any) map[string]any {
		b := map[string]any{"name": "cb", "target_type": "repo", "repo_url": "https://git.example.com/x.git"}
		for k, v := range m {
			if v == nil {
				delete(b, k)
			} else {
				b[k] = v
			}
		}
		return b
	}
	runFieldCases(t, w.admin, "POST", path, []fieldCase{
		{name: "no target type", body: map[string]any{"name": "cb"}, status: 422, field: "target_type", msg: "target_type is required"},
		{name: "bad target type", body: map[string]any{"name": "cb", "target_type": "svn"}, status: 422, field: "target_type"},
		{name: "empty repo", body: map[string]any{"target_type": "repo"}, status: 422, field: "name", fields: []string{"name", "repo_url"}},
		{name: "missing repo_url", body: repo(map[string]any{"repo_url": nil}), status: 422, field: "repo_url", msg: "repo_url is required."},
		{name: "http repo_url", body: repo(map[string]any{"repo_url": "http://git.example.com/x"}), status: 422, field: "repo_url"},
		{name: "private repo host", body: repo(map[string]any{"repo_url": "https://10.0.0.8/x.git"}), status: 422, code: "address_not_allowed", field: "repo_url"},
		{name: "bad branch", body: repo(map[string]any{"branch": "-x;rm"}), status: 422, field: "branch", msg: "branch must match"},
		{name: "bad subdirectory", body: repo(map[string]any{"subdirectory": "../x"}), status: 422, field: "subdirectory"},
		{name: "bad auth kind", body: repo(map[string]any{"git_auth_kind": "magic"}), status: 422, field: "git_auth_kind"},
		{name: "missing secret", body: repo(map[string]any{"git_auth_kind": "https_token"}), status: 422, field: "git_secret", msg: "git_secret is required"},
		{name: "bad cron", body: repo(map[string]any{"schedule_cron": "every day"}), status: 422, code: "invalid_cron", field: "schedule_cron"},
		{name: "too frequent", body: repo(map[string]any{"schedule_cron": "* * * * *"}), status: 422, code: "schedule_too_frequent", field: "schedule_cron"},
		{name: "many at once", body: repo(map[string]any{"name": "", "repo_url": "ftp://x", "branch": "bad branch", "subdirectory": "/abs", "git_auth_kind": "ssh_key", "schedule_cron": nil}),
			status: 422, field: "name", fields: []string{"name", "repo_url", "branch", "subdirectory", "git_secret"}},
		{name: "private base_url", body: map[string]any{"name": "a", "target_type": "url", "base_url": "http://192.168.1.10/"}, status: 422, code: "address_not_allowed", field: "base_url"},
		{name: "missing base_url", body: map[string]any{"name": "a", "target_type": "url"}, status: 422, field: "base_url", msg: "base_url is required"},
		{name: "url target many", body: map[string]any{"name": "", "target_type": "url", "base_url": "ftp://x", "dast_max_rps": 500}, status: 422,
			field: "name", fields: []string{"name", "base_url", "dast_max_rps"}},
	})
	// A member without DAST access gets 403 for a URL target instead of field errors.
	if r := w.member.Do("POST", path, map[string]any{"name": "", "target_type": "url"}); r.Status != 403 {
		t.Errorf("member url target: %d %s", r.Status, r.Body)
	}
	w.repo(t, w.admin, "taken-name")
	runFieldCases(t, w.admin, "POST", path, []fieldCase{
		{name: "taken", body: repo(map[string]any{"name": "TAKEN-NAME"}), status: 409, code: "name_taken", field: "name"},
	})
}

func TestFieldErrorsCodebaseUpdate(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	rid := w.repo(t, w.admin, "repo-one")
	uid := w.urlTarget(t, w.dastUser, "live", "https://shop.example.com")
	rp, up := fmt.Sprintf("/api/v1/codebases/%d", rid), fmt.Sprintf("/api/v1/codebases/%d", uid)
	runFieldCases(t, w.admin, "PATCH", rp, []fieldCase{
		{name: "blank name", body: map[string]any{"name": " "}, status: 422, field: "name"},
		{name: "blank repo_url", body: map[string]any{"repo_url": ""}, status: 422, field: "repo_url", msg: "repo_url is required."},
		{name: "bad branch", body: map[string]any{"branch": "a b"}, status: 422, field: "branch"},
		{name: "name type", body: map[string]any{"name": 5}, status: 422, field: "name", msg: "must be a string"},
		{name: "kind needs secret", body: map[string]any{"git_auth_kind": "ssh_key"}, status: 422, field: "git_secret"},
		{name: "schedule via patch", body: map[string]any{"schedule_cron": "0 1 * * *"}, status: 422, field: "schedule_cron"},
		{name: "url field on repo", body: map[string]any{"base_url": "https://x.example.com"}, status: 422, field: "base_url"},
		{name: "unknown project", body: map[string]any{"project_id": 98765}, status: 422, field: "project_id"},
		{name: "many", body: map[string]any{"name": "", "repo_url": "", "branch": "x y", "subdirectory": "../a", "project_id": 0}, status: 422,
			field: "name", fields: []string{"name", "project_id", "repo_url", "branch", "subdirectory"}},
	})
	w.repo(t, w.admin, "repo-two")
	runFieldCases(t, w.admin, "PATCH", rp, []fieldCase{
		{name: "taken", body: map[string]any{"name": "repo-two"}, status: 409, code: "name_taken", field: "name"},
	})
	runFieldCases(t, w.dastUser, "PATCH", up, []fieldCase{
		{name: "bad base_url", body: map[string]any{"base_url": "ftp://x"}, status: 422, field: "base_url"},
		{name: "private base_url", body: map[string]any{"base_url": "http://10.1.1.1"}, status: 422, code: "address_not_allowed", field: "base_url"},
		{name: "rps", body: map[string]any{"dast_max_rps": 0}, status: 422, field: "dast_max_rps"},
		{name: "repo field on url", body: map[string]any{"repo_url": "https://x.example.com"}, status: 422, field: "repo_url"},
		{name: "crawl numbers", body: map[string]any{"dast_crawl_max_depth": 0, "dast_crawl_max_pages": 100000}, status: 422,
			field: "dast_crawl_max_depth", fields: []string{"dast_crawl_max_depth", "dast_crawl_max_pages"}},
		{name: "crawl exclude rows", body: map[string]any{"dast_crawl_exclude": []string{"^/ok", "(", "", "[a-"}}, status: 422,
			field: "dast_crawl_exclude[1]", fields: []string{"dast_crawl_exclude[1]", "dast_crawl_exclude[2]", "dast_crawl_exclude[3]"}},
		{name: "crawl exclude single row", body: map[string]any{"dast_crawl_exclude": []string{"(unclosed"}}, status: 422, field: "dast_crawl_exclude[0]", msg: "not a valid regular expression"},
		{name: "crawl everything", body: map[string]any{"dast_max_rps": 101, "dast_crawl_max_pages": 0, "dast_crawl_exclude": []string{"("}}, status: 422,
			field: "dast_max_rps", fields: []string{"dast_max_rps", "dast_crawl_max_pages", "dast_crawl_exclude[0]"}},
	})
}

func TestFieldErrorsDastAuthPut(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	id := w.urlTarget(t, w.dastUser, "live", target)
	body := map[string]any{"type": "form+header",
		"login": map[string]any{"url": "https://other.example.net/login", "method": "GET", "username_field": "", "password_field": "p", "username": "", "password": "",
			"success": map[string]any{"statuses": []int{200, 700}}},
		"headers": map[string]string{"Host": "evil", "X-Short": "ab", "Authorization": "Bearer abcdefgh"},
		"cookies": map[string]string{"sid": ""}}
	r := w.dastUser.Do("PUT", authPath(id), body)
	if r.Status != 422 || r.ErrCode() != "validation_failed" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	want := []string{"login.url", "login.method", "login.username_field", "login.username", "login.password", "login.success.statuses[1]", "headers.Host", "headers.X-Short", "cookies.sid"}
	if got := r.ErrFields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields %v, want %v", got, want)
	}
	if r.ErrField() != "login.url" {
		t.Errorf("details.field %q", r.ErrField())
	}
	runFieldCases(t, w.dastUser, "PUT", authPath(id), []fieldCase{
		{name: "no type", body: map[string]any{}, status: 422, field: "type"},
		{name: "login missing", body: map[string]any{"type": "form"}, status: 422, field: "login"},
		{name: "no headers", body: map[string]any{"type": "header"}, status: 422, field: "headers"},
		{name: "blank password and extra", body: map[string]any{"type": "form", "login": map[string]any{"url": target + "/login", "username_field": "u",
			"password_field": "p", "username": "x"}}, status: 422, field: "login.password", msg: "login.password is required."},
		{name: "csrf", body: map[string]any{"type": "form", "login": map[string]any{"url": target + "/login", "username_field": "u", "password_field": "p",
			"username": "x", "password": "abcdef", "csrf": map[string]any{"source": "magic", "name": ""}}}, status: 422,
			field: "login.csrf.source", fields: []string{"login.csrf.source", "login.csrf.name"}},
		{name: "cookie value", body: map[string]any{"type": "header", "cookies": map[string]string{"sid": "ab;cd1234"}}, status: 422, field: "cookies.sid"},
	})
	if r := w.dastUser.Do("PUT", authPath(id), body); strings.Contains(string(r.Body), "evil") && strings.Contains(string(r.Body), "abcdefgh") {
		t.Errorf("error body leaks values: %s", r.Body)
	}
}

func TestFieldErrorsSchedulesScansAndMisc(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	rid := w.repo(t, w.member, "sched")
	sp := fmt.Sprintf("/api/v1/codebases/%d/schedule", rid)
	runFieldCases(t, w.member, "PUT", sp, []fieldCase{
		{name: "empty", body: map[string]any{}, status: 422, code: "invalid_cron", field: "cron", msg: "cron is required"},
		{name: "garbage", body: map[string]any{"cron": "garbage"}, status: 422, code: "invalid_cron", field: "cron"},
		{name: "too frequent", body: map[string]any{"cron": "*/5 * * * *"}, status: 422, code: "schedule_too_frequent", field: "cron"},
	})
	runFieldCases(t, w.member, "POST", "/api/v1/scans", []fieldCase{
		{name: "no codebase", body: map[string]any{}, status: 422, field: "codebase_id", msg: "codebase_id is required."},
	})
	uid := w.urlTarget(t, w.dastUser, "live", target)
	runFieldCases(t, w.admin, "POST", fmt.Sprintf("/api/v1/codebases/%d/confirm-authorization", uid), []fieldCase{
		{name: "not accepted", body: map[string]any{"statement_accepted": false}, status: 422, field: "statement_accepted"},
	})
	if r := w.admin.Get("/api/v1/projects?page_size=500"); r.Status != 400 || r.ErrField() != "page_size" {
		t.Errorf("page_size: %d %s", r.Status, r.Body)
	}
	if r := w.admin.Get(fmt.Sprintf("/api/v1/codebases/%d/findings?kind=nope", rid)); r.Status != 400 || r.ErrField() != "kind" {
		t.Errorf("kind filter: %d %s", r.Status, r.Body)
	}
}

func TestFieldErrorsVulnDBEcosystems(t *testing.T) {
	v := newVulnWorld(t, testutil.FakeVuln{}, vulndb.Config{})
	runFieldCases(t, v.admin, "POST", "/api/v1/system/vulndb/update", []fieldCase{
		{name: "unknown", body: map[string]any{"ecosystems": []string{"npm", "Cobol"}}, status: 422, field: "ecosystems[1]", msg: "Allowed:"},
		{name: "two unknown", body: map[string]any{"ecosystems": []string{"x", "npm", "y"}}, status: 422, field: "ecosystems[0]", fields: []string{"ecosystems[0]", "ecosystems[2]"}},
	})
}
