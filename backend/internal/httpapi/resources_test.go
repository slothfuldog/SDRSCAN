package httpapi_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func TestProjectCRUDAndValidation(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	c := w.member
	if r := c.Do("POST", "/api/v1/projects", map[string]any{"name": "online shop"}); r.Status != 409 || r.ErrCode() != "name_taken" {
		t.Fatalf("duplicate (case-insensitive): %d %s", r.Status, r.Body)
	}
	for name, body := range map[string]map[string]any{
		"empty name":       {"name": "  "},
		"long name":        {"name": strings.Repeat("a", 101)},
		"control chars":    {"name": "a\x00b"},
		"long description": {"name": "ok", "description": strings.Repeat("d", 1001)},
	} {
		if r := c.Do("POST", "/api/v1/projects", body); r.Status != 422 || r.ErrCode() != "validation_failed" {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	r := c.Do("POST", "/api/v1/projects", map[string]any{"name": "  Second  ", "description": "d"})
	if r.Status != 201 || r.JSON()["name"] != "Second" {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	id := testutil.MustID(t, r.JSON(), "id")
	if r := c.Do("PATCH", fmt.Sprintf("/api/v1/projects/%d", id), map[string]any{"name": "Online Shop"}); r.Status != 409 {
		t.Fatalf("rename to taken: %d", r.Status)
	}
	if r := c.Do("PATCH", fmt.Sprintf("/api/v1/projects/%d", id), map[string]any{"description": "new"}); r.Status != 200 || r.JSON()["description"] != "new" {
		t.Fatalf("patch: %d %s", r.Status, r.Body)
	}
	if r := c.Get("/api/v1/projects/abc"); r.Status != 400 {
		t.Fatalf("non-integer id: %d", r.Status)
	}
	if r := c.Get("/api/v1/projects/424242"); r.Status != 404 {
		t.Fatalf("missing: %d", r.Status)
	}
	// Pagination.
	for i := 0; i < 4; i++ {
		c.Do("POST", "/api/v1/projects", map[string]any{"name": fmt.Sprintf("P%d", i)})
	}
	l := c.Get("/api/v1/projects?page=2&page_size=2").JSON()
	if l["total"].(float64) != 6 || l["page"].(float64) != 2 || l["page_size"].(float64) != 2 || len(l["items"].([]any)) != 2 {
		t.Fatalf("pagination: %v", l)
	}
	if r := c.Get("/api/v1/projects?page_size=500"); r.Status != 400 {
		t.Fatalf("page_size limit: %d", r.Status)
	}
	if r := c.Get("/api/v1/projects?page=0"); r.Status != 400 {
		t.Fatalf("page 0: %d", r.Status)
	}
}

func TestCodebaseValidationAndFriendlyNetworkErrors(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	path := fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID)
	bad := []struct {
		name string
		body map[string]any
		msg  string
		code string
	}{
		{"file url", map[string]any{"name": "a", "target_type": "repo", "repo_url": "file:///etc"}, "", ""},
		{"local path", map[string]any{"name": "a", "target_type": "repo", "repo_url": "/tmp/repo"}, "", ""},
		{"http", map[string]any{"name": "a", "target_type": "repo", "repo_url": "http://git.example.com/x"}, "", ""},
		{"git proto", map[string]any{"name": "a", "target_type": "repo", "repo_url": "git://git.example.com/x"}, "", ""},
		{"ext", map[string]any{"name": "a", "target_type": "repo", "repo_url": "ext::sh -c id"}, "", ""},
		{"dash", map[string]any{"name": "a", "target_type": "repo", "repo_url": "--upload-pack=id"}, "", ""},
		{"userinfo", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://u:p@git.example.com/x"}, "", ""},
		{"private repo host", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://10.0.0.8/x.git"}, "Private network addresses are not allowed", "address_not_allowed"},
		{"loopback repo host", map[string]any{"name": "a", "target_type": "repo", "repo_url": "ssh://git@127.0.0.1/x.git"}, "Private network addresses are not allowed", "address_not_allowed"},
		{"bad branch", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://git.example.com/x", "branch": "-x;rm"}, "", ""},
		{"dotdot subdir", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://git.example.com/x", "subdirectory": "../x"}, "", ""},
		{"abs subdir", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://git.example.com/x", "subdirectory": "/etc"}, "", ""},
		{"bad target type", map[string]any{"name": "a", "target_type": "svn"}, "", ""},
		{"missing secret", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://git.example.com/x", "git_auth_kind": "https_token"}, "", ""},
		{"bad cron", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://git.example.com/x", "schedule_cron": "every day"}, "", "invalid_cron"},
		{"private base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "http://192.168.1.10/"}, "Private network addresses are not allowed", "address_not_allowed"},
		{"loopback base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "http://127.0.0.1:8080"}, "Private network addresses are not allowed", "address_not_allowed"},
		{"metadata base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "http://169.254.169.254/latest"}, "Private network addresses are not allowed", "address_not_allowed"},
		{"cgnat base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "http://100.64.1.1"}, "Private network addresses are not allowed", "address_not_allowed"},
		{"ula base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "http://[fd00::1]/"}, "Private network addresses are not allowed", "address_not_allowed"},
		{"userinfo base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "https://u:p@shop.example.com"}, "", ""},
		{"query base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "https://shop.example.com/?a=1"}, "", ""},
		{"ftp base_url", map[string]any{"name": "a", "target_type": "url", "base_url": "ftp://shop.example.com"}, "", ""},
	}
	for _, c := range bad {
		want := c.code
		if want == "" {
			want = "validation_failed"
		}
		r := w.admin.Do("POST", path, c.body)
		if r.Status != 422 || r.ErrCode() != want {
			t.Errorf("%s: %d %s", c.name, r.Status, r.Body)
			continue
		}
		if c.msg != "" && !strings.Contains(string(r.Body), c.msg) {
			t.Errorf("%s: message lacks %q: %s", c.name, c.msg, r.Body)
		}
	}
	if r := w.admin.Do("POST", "/api/v1/projects/99999/codebases", map[string]any{"name": "a", "target_type": "repo", "repo_url": "https://git.example.com/x"}); r.Status != 404 {
		t.Fatalf("unknown project: %d", r.Status)
	}
	w.repo(t, w.admin, "dup")
	if r := w.admin.Do("POST", path, map[string]any{"name": "DUP", "target_type": "repo", "repo_url": "https://git.example.com/x"}); r.Status != 409 || r.ErrCode() != "name_taken" {
		t.Fatalf("duplicate codebase name: %d %s", r.Status, r.Body)
	}
	// A scan of a DAST target whose name resolves to a private address is refused with the friendly message.
	// Saving a name that resolves to a private address is refused; so is a host with one private record among public ones.
	for _, host := range []string{"internal.example", "rebind.example"} {
		r := w.admin.Do("POST", path, map[string]any{"name": "x-" + host, "target_type": "url", "base_url": "https://" + host})
		if r.Status != 422 || r.ErrCode() != "address_not_allowed" || !strings.Contains(string(r.Body), "Private network addresses are not allowed") {
			t.Fatalf("%s at save time: %d %s", host, r.Status, r.Body)
		}
		r = w.admin.Do("POST", path, map[string]any{"name": "g-" + host, "target_type": "repo", "repo_url": "https://" + host + "/x.git"})
		if r.Status != 422 || r.ErrCode() != "address_not_allowed" {
			t.Fatalf("repo %s at save time: %d %s", host, r.Status, r.Body)
		}
	}
	if r := w.admin.Do("POST", path, map[string]any{"name": "nx", "target_type": "url", "base_url": "https://nxdomain.example"}); r.Status != 422 {
		t.Fatalf("unresolvable host: %d", r.Status)
	}
	// The DNS answer can change after saving: POST /scans resolves again.
	id := w.urlTarget(t, w.admin, "later", "https://shop.example.com")
	w.confirm(t, id)
	_, _ = w.env.Pool.Exec(context.Background(), `UPDATE codebases SET base_url = 'https://internal.example' WHERE id = $1`, id)
	r := w.admin.Do("POST", "/api/v1/scans", map[string]any{"codebase_id": id})
	if r.Status != 422 || r.ErrCode() != "address_not_allowed" {
		t.Fatalf("private resolution at scan time: %d %s", r.Status, r.Body)
	}
}

func TestGitCredentialsAreEncryptedAndNeverReturned(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	const secret = "ghp_THISISAVERYSECRETTOKEN0123456789"
	path := fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID)
	r := w.member.Do("POST", path, map[string]any{"name": "private", "target_type": "repo", "repo_url": "https://git.example.com/priv.git",
		"git_auth_kind": "https_token", "git_username": "x-access-token", "git_secret": secret})
	if r.Status != 201 {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	if bytes.Contains(r.Body, []byte(secret)) || r.JSON()["has_credential"] != true || r.JSON()["git_username"] != "x-access-token" {
		t.Fatalf("response: %s", r.Body)
	}
	id := testutil.MustID(t, r.JSON(), "id")
	cp := fmt.Sprintf("/api/v1/codebases/%d", id)
	for _, p := range []string{cp, fmt.Sprintf("/api/v1/projects/%d", w.projectID)} {
		if g := w.admin.Get(p); bytes.Contains(g.Body, []byte(secret)) || bytes.Contains(g.Body, []byte("git_secret")) {
			t.Fatalf("secret leaked from %s: %s", p, g.Body)
		}
	}
	var enc []byte
	if err := w.env.Pool.QueryRow(context.Background(), `SELECT git_secret_enc FROM codebases WHERE id = $1`, id).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if len(enc) < 28 || bytes.Contains(enc, []byte(secret)) {
		t.Fatalf("stored credential is not encrypted (%d bytes)", len(enc))
	}
	plain, err := w.env.Box.Open(enc)
	if err != nil || string(plain) != secret {
		t.Fatalf("round trip: %q %v", plain, err)
	}
	// A new secret overwrites the old one; switching to none clears it.
	if r := w.member.Do("PATCH", cp, map[string]any{"git_secret": "ghp_another_value_0123456789"}); r.Status != 200 {
		t.Fatalf("patch secret: %d %s", r.Status, r.Body)
	}
	var enc2 []byte
	_ = w.env.Pool.QueryRow(context.Background(), `SELECT git_secret_enc FROM codebases WHERE id = $1`, id).Scan(&enc2)
	if bytes.Equal(enc, enc2) {
		t.Fatal("secret not overwritten")
	}
	if r := w.member.Do("PATCH", cp, map[string]any{"git_auth_kind": "none"}); r.Status != 200 || r.JSON()["has_credential"] != false {
		t.Fatalf("switch to none: %d %s", r.Status, r.Body)
	}
	// Without SDRSCAN_SECRET_KEY credentials are refused rather than stored in clear.
	w2 := newWorld(t, testutil.EnvOptions{NoKey: true})
	r = w2.member.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", w2.projectID), map[string]any{"name": "p", "target_type": "repo",
		"repo_url": "https://git.example.com/priv.git", "git_auth_kind": "https_token", "git_secret": secret})
	if r.Status != 503 || r.ErrCode() != "credentials_unavailable" {
		t.Fatalf("no key: %d %s", r.Status, r.Body)
	}
}

func TestCodebaseMoveAndDashboard(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	a := w.repo(t, w.member, "storefront")
	u := w.urlTarget(t, w.admin, "storefront (live)", "https://shop.example.com")
	r := w.dastUser.Get(fmt.Sprintf("/api/v1/projects/%d", w.projectID))
	j := r.JSON()
	totals := j["totals"].(map[string]any)
	if r.Status != 200 || totals["highest_severity"] != nil || totals["high"].(float64) != 0 {
		t.Fatalf("dashboard totals: %s", r.Body)
	}
	cbs := j["codebases"].([]any)
	if len(cbs) != 2 {
		t.Fatalf("codebases: %s", r.Body)
	}
	for _, x := range cbs {
		m := x.(map[string]any)
		if m["summary"] != nil || m["state"] != nil || m["latest_scan"] != nil {
			t.Fatalf("unscanned codebase must report null summary: %v", m)
		}
		if m["target_type"] == "url" && m["dast"].(map[string]any)["status"] != "pending_confirmation" {
			t.Fatalf("url entry: %v", m)
		}
	}
	if got := len(w.member.Get(fmt.Sprintf("/api/v1/projects/%d", w.projectID)).JSON()["codebases"].([]any)); got != 1 {
		t.Fatalf("a member without DAST access must see only the repo codebase, got %d", got)
	}
	// Move to another project keeps the id and history.
	p2 := w.member.Do("POST", "/api/v1/projects", map[string]any{"name": "Other"})
	p2id := testutil.MustID(t, p2.JSON(), "id")
	r = w.member.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", a), map[string]any{"project_id": p2id})
	if r.Status != 200 || int64(r.JSON()["project"].(map[string]any)["id"].(float64)) != p2id {
		t.Fatalf("move: %d %s", r.Status, r.Body)
	}
	// Name clash in the destination.
	w.admin.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", p2id), map[string]any{"name": "clash", "target_type": "repo", "repo_url": "https://git.example.com/c.git"})
	b := w.repo(t, w.member, "clash")
	if r := w.member.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", b), map[string]any{"project_id": p2id}); r.Status != 409 {
		t.Fatalf("move into a name clash: %d", r.Status)
	}
	if r := w.member.Do("PATCH", fmt.Sprintf("/api/v1/codebases/%d", b), map[string]any{"project_id": 99999}); r.Status != 422 {
		t.Fatalf("move to unknown project: %d", r.Status)
	}
	_ = u
}

func TestSystemInfoAndHealth(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	r := w.member.Get("/api/v1/system/info")
	j := r.JSON()
	if r.Status != 200 || j["version"] != "test" || j["queue"].(map[string]any)["queued"].(float64) != 0 {
		t.Fatalf("system info: %d %s", r.Status, r.Body)
	}
	if _, ok := j["engines"].(map[string]any); !ok {
		t.Fatalf("engines missing: %s", r.Body)
	}
}

func TestUsersAPI(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	for name, body := range map[string]map[string]any{
		"short username": {"username": "ab", "password": "long-enough-password"},
		"bad characters": {"username": "a b c", "password": "long-enough-password"},
		"short password": {"username": "carol", "password": "short"},
		"bad role":       {"username": "carol", "password": "long-enough-password", "role": "root"},
	} {
		if r := w.admin.Do("POST", "/api/v1/users", body); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	if r := w.admin.Do("POST", "/api/v1/users", map[string]any{"username": "MEMBER", "password": "long-enough-password"}); r.Status != 409 || r.ErrCode() != "username_taken" {
		t.Fatalf("duplicate username: %d %s", r.Status, r.Body)
	}
	r := w.admin.Do("POST", "/api/v1/users", map[string]any{"username": "carol", "password": "long-enough-password", "can_run_dast": true})
	j := r.JSON()
	if r.Status != 201 || j["role"] != "member" || j["can_run_dast"] != true || bytes.Contains(r.Body, []byte("argon2")) {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	l := w.admin.Get("/api/v1/users")
	if l.Status != 200 || l.JSON()["total"].(float64) != 4 || bytes.Contains(l.Body, []byte("password")) && bytes.Contains(l.Body, []byte("argon2")) {
		t.Fatalf("list: %s", l.Body)
	}
	id := testutil.MustID(t, j, "id")
	pr := w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", id), map[string]any{"role": "admin", "can_run_dast": false})
	if pr.Status != 200 || pr.JSON()["role"] != "admin" || pr.JSON()["can_run_dast"] != false {
		t.Fatalf("patch: %d %s", pr.Status, pr.Body)
	}
	if r := w.admin.Do("PATCH", fmt.Sprintf("/api/v1/users/%d", id), map[string]any{"role": "wizard"}); r.Status != 422 {
		t.Fatalf("bad role patch: %d", r.Status)
	}
	if r := w.admin.Do("PATCH", "/api/v1/users/99999", map[string]any{"role": "member"}); r.Status != 404 {
		t.Fatalf("unknown user: %d", r.Status)
	}
	a := w.admin.Get("/api/v1/audit-log")
	if a.Status != 200 {
		t.Fatal(a.Status)
	}
	var actions []string
	for _, it := range a.JSON()["items"].([]any) {
		actions = append(actions, it.(map[string]any)["action"].(string))
	}
	joined := strings.Join(actions, ",")
	for _, want := range []string{"user_created", "user_role_changed", "user_dast_access_changed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %s: %s", want, joined)
		}
	}
	if bytes.Contains(a.Body, []byte("long-enough-password")) {
		t.Fatal("password in audit log")
	}
}
