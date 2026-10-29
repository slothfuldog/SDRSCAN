package scanner_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/netguard"
	"github.com/sdrscan/sdrscan/backend/internal/scanner"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func gitEnv() []string {
	return append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// makeRepo creates a local git repository with the given files and returns its path.
func makeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "init")
	return dir
}

func copyFixture(t *testing.T, root, fixture string) map[string]string {
	t.Helper()
	files := map[string]string{}
	dir := filepath.Join(root, "tests", "fixtures", "php", fixture)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".php") {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			files[e.Name()] = string(b)
		}
	}
	return files
}

// fakeEngine writes an executable shell script and returns its path.
func fakeEngine(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "engine.sh")
	script := "#!/bin/sh\nout=\"\"\nwhile [ $# -gt 0 ]; do case \"$1\" in --output) out=\"$2\"; shift;; esac; shift; done\n" + body
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeSarif(t *testing.T, d testutil.Doc) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture.sarif")
	if err := os.WriteFile(p, d.Build(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

type rig struct {
	t    *testing.T
	env  *testutil.Env
	work string
	proj store.Project
	adm  store.User
}

type rigOpts struct {
	guard  *netguard.Guard
	runner scanner.Config
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	work := filepath.Join(t.TempDir(), "work")
	if o.runner.Workdir == "" {
		o.runner.Workdir = work
	}
	if o.runner.PollInterval == 0 {
		o.runner.PollInterval = 50 * time.Millisecond
	}
	if o.runner.CancelPoll == 0 {
		o.runner.CancelPoll = 100 * time.Millisecond
	}
	if o.runner.KillGrace == 0 {
		o.runner.KillGrace = time.Second
	}
	env := testutil.NewEnv(t, testutil.EnvOptions{Guard: o.guard, Runner: o.runner})
	adm := env.CreateUser("root", "admin", false)
	p, err := env.Store.CreateProject(context.Background(), "P", "")
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: env, work: o.runner.Workdir, proj: p, adm: adm}
}

func (r *rig) repoCB(name, url string) store.Codebase {
	r.t.Helper()
	br := "main"
	cb, err := r.env.Store.CreateCodebase(context.Background(), store.NewCodebase{ProjectID: r.proj.ID, Name: name, TargetType: "repo", RepoURL: &url, Branch: &br, GitAuthKind: "none"})
	if err != nil {
		r.t.Fatal(err)
	}
	return cb
}

func (r *rig) enqueue(cb store.Codebase) store.Scan {
	r.t.Helper()
	typ := "sast"
	if cb.TargetType == "url" {
		typ = "dast"
	}
	sc, err := r.env.Store.CreateJob(context.Background(), cb.ID, typ, "manual", &r.adm.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return sc
}

// run processes exactly one queued job synchronously and returns the finished scan.
func (r *rig) run(sc store.Scan) store.Scan {
	r.t.Helper()
	ok, err := r.env.Runner.RunOnce(context.Background())
	if err != nil || !ok {
		r.t.Fatalf("RunOnce: %v %v", ok, err)
	}
	got, err := r.env.Store.GetScan(context.Background(), sc.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}

func (r *rig) assertWorkdirClean() {
	r.t.Helper()
	entries, _ := os.ReadDir(r.work)
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != 0 {
		r.t.Fatalf("work directory not cleaned: %v", left)
	}
}

func logOf(s store.Scan) string {
	if s.LogTail == nil {
		return ""
	}
	return *s.LogTail
}

func codeOf(s store.Scan) string {
	if s.ErrorCode == nil {
		return ""
	}
	return *s.ErrorCode
}

func (r *rig) countFindings(cbID int64) int {
	var n int
	_ = r.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM findings WHERE codebase_id = $1 AND is_current`, cbID).Scan(&n)
	return n
}

func local() *netguard.Guard {
	return &netguard.Guard{AllowLocalRepos: true, Resolver: testutil.DefaultResolver()}
}

var _ = fmt.Sprint
