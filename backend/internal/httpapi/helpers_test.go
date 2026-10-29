package httpapi_test

import (
	"fmt"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

type world struct {
	env       *testutil.Env
	admin     *testutil.Client
	member    *testutil.Client // member without DAST access
	dastUser  *testutil.Client // member with can_run_dast
	anon      *testutil.Client
	projectID int64
}

func newWorld(t *testing.T, eo testutil.EnvOptions) *world {
	t.Helper()
	env := testutil.NewEnv(t, eo)
	w := &world{env: env}
	w.admin = env.Login(env.CreateUser("admin", "admin", false))
	w.member = env.Login(env.CreateUser("member", "member", false))
	w.dastUser = env.Login(env.CreateUser("dastuser", "member", true))
	w.anon = env.Anonymous()
	r := w.admin.Do("POST", "/api/v1/projects", map[string]any{"name": "Online Shop", "description": "Web and API"})
	if r.Status != 201 {
		t.Fatalf("create project: %d %s", r.Status, r.Body)
	}
	w.projectID = testutil.MustID(t, r.JSON(), "id")
	return w
}

func (w *world) repo(t *testing.T, c *testutil.Client, name string) int64 {
	t.Helper()
	r := c.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID), map[string]any{
		"name": name, "target_type": "repo", "repo_url": "https://git.example.com/shop.git", "language": "php"})
	if r.Status != 201 {
		t.Fatalf("create repo codebase: %d %s", r.Status, r.Body)
	}
	return testutil.MustID(t, r.JSON(), "id")
}

func (w *world) urlTarget(t *testing.T, c *testutil.Client, name, base string) int64 {
	t.Helper()
	r := c.Do("POST", fmt.Sprintf("/api/v1/projects/%d/codebases", w.projectID), map[string]any{
		"name": name, "target_type": "url", "base_url": base})
	if r.Status != 201 {
		t.Fatalf("create url codebase: %d %s", r.Status, r.Body)
	}
	return testutil.MustID(t, r.JSON(), "id")
}

func (w *world) confirm(t *testing.T, id int64) {
	t.Helper()
	r := w.admin.Do("POST", fmt.Sprintf("/api/v1/codebases/%d/confirm-authorization", id), map[string]any{"statement_accepted": true})
	if r.Status != 200 {
		t.Fatalf("confirm: %d %s", r.Status, r.Body)
	}
}

func (w *world) token(t *testing.T, name string, projectID *int64) string {
	t.Helper()
	body := map[string]any{"name": name}
	if projectID != nil {
		body["project_id"] = *projectID
	}
	r := w.admin.Do("POST", "/api/v1/ingest-tokens", body)
	if r.Status != 201 {
		t.Fatalf("create token: %d %s", r.Status, r.Body)
	}
	tok, _ := r.JSON()["secret"].(string)
	if tok == "" {
		t.Fatal("secret missing from the create response")
	}
	return tok
}
