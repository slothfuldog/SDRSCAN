package httpapi_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
	"github.com/sdrscan/sdrscan/backend/internal/vulndb"
)

const statusJSON = testutil.RealStatusJSON

type vulnWorld struct {
	*world
	dir, bin, calls, envFile string
}

// newVulnWorld has an installed database (a directory with meta.json, as sdrscan-vuln writes it);
// newVulnWorldEmpty has none.
func newVulnWorld(t *testing.T, f testutil.FakeVuln, cfg vulndb.Config) *vulnWorld {
	t.Helper()
	return newVulnWorldOpt(t, f, cfg, true)
}

func newVulnWorldEmpty(t *testing.T, f testutil.FakeVuln, cfg vulndb.Config) *vulnWorld {
	t.Helper()
	return newVulnWorldOpt(t, f, cfg, false)
}

func newVulnWorldOpt(t *testing.T, f testutil.FakeVuln, cfg vulndb.Config, installed bool) *vulnWorld {
	t.Helper()
	v := &vulnWorld{}
	v.bin, v.calls, v.envFile = testutil.FakeVulnTool(t, f)
	v.dir = filepath.Join(t.TempDir(), "vulndb")
	if cfg.Dir == "" {
		cfg.Dir = v.dir
	}
	if installed {
		if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.Dir, "meta.json"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Bin = v.bin
	cfg.ScaEnabled = true
	if cfg.KillGrace == 0 {
		cfg.KillGrace = time.Second
	}
	v.world = newWorld(t, testutil.EnvOptions{VulnDB: cfg})
	return v
}

func (v *vulnWorld) get(t *testing.T) map[string]any {
	t.Helper()
	r := v.admin.Get("/api/v1/system/vulndb")
	if r.Status != 200 {
		t.Fatalf("GET /system/vulndb: %d %s", r.Status, r.Body)
	}
	return r.JSON()
}

func (v *vulnWorld) waitState(t *testing.T, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		j := v.get(t)
		if u, _ := j["update"].(map[string]any); u != nil && u["state"] == want {
			return u
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("update never reached %q: %v", want, v.get(t)["update"])
	return nil
}

func TestVulnDBEndpointsAreAdminOnly(t *testing.T) {
	v := newVulnWorld(t, testutil.FakeVuln{StatusJSON: statusJSON}, vulndb.Config{})
	for _, c := range []struct {
		name string
		cl   *testutil.Client
		want int
	}{{"member", v.member, 403}, {"member+dast", v.dastUser, 403}, {"anonymous", v.anon, 401}} {
		for _, rt := range [][2]string{{"GET", "/api/v1/system/vulndb"}, {"POST", "/api/v1/system/vulndb/update"}, {"POST", "/api/v1/system/vulndb/update/cancel"}} {
			var body any
			if rt[0] == "POST" {
				body = map[string]any{}
			}
			if r := c.cl.Do(rt[0], rt[1], body); r.Status != c.want {
				t.Errorf("%s %s %s: %d (want %d)", c.name, rt[0], rt[1], r.Status, c.want)
			}
		}
	}
	if n := len(testutil.Calls(t, v.calls)); n != 0 {
		t.Fatalf("the tool must not run for non-admins: %d calls", n)
	}
}

func TestVulnDBNotConfigured(t *testing.T) {
	w := newWorld(t, testutil.EnvOptions{})
	j := w.admin.Get("/api/v1/system/vulndb").JSON()
	if j["configured"] != false || j["status"] != nil || j["db_path"] != nil || j["update"] != nil || j["db_present"] != false {
		t.Fatalf("%v", j)
	}
	if eco := j["ecosystems"].([]any); len(eco) != 4 || eco[0] != "Packagist" {
		t.Fatalf("ecosystems: %v", eco)
	}
	r := w.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{})
	if r.Status != 409 || r.ErrCode() != "vulndb_not_configured" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r := w.admin.Do("POST", "/api/v1/system/vulndb/update/cancel", map[string]any{}); r.Status != 409 || r.ErrCode() != "no_update_running" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestVulnDBStatusReadsTheRealCLIShape(t *testing.T) {
	v := newVulnWorld(t, testutil.FakeVuln{StatusJSON: statusJSON}, vulndb.Config{})
	j := v.get(t)
	st := j["status"].(map[string]any)
	if j["configured"] != true || j["sca_enabled"] != true || j["tool"].(map[string]any)["available"] != true || j["db_present"] != true || j["status_error"] != nil {
		t.Fatalf("%v", j)
	}
	if st["installed"] != true || st["advisory_count"].(float64) != 13 || st["updated_at"] != "2026-10-20T00:00:00Z" ||
		st["age_days"].(float64) != 8 || st["max_age_days"].(float64) != 7 || st["format_version"].(float64) != 1 {
		t.Fatalf("status: %v", st)
	}
	if _, has := st["raw"]; has {
		t.Fatal("no raw text any more")
	}
	src := st["sources"].([]any)
	if len(src) != 5 {
		t.Fatalf("sources (4 OSV ecosystems + NVD): %v", src)
	}
	by := map[string]map[string]any{}
	for _, x := range src {
		m := x.(map[string]any)
		key := m["name"].(string)
		if e, ok := m["ecosystem"].(string); ok {
			key += "/" + e
		}
		by[key] = m
	}
	if g := by["osv/Packagist"]; g == nil || g["advisories"].(float64) != 4 || g["age_days"].(float64) != 8 || g["updated_at"] != "2026-10-20T00:00:00Z" || len(g["products"].([]any)) != 0 {
		t.Fatalf("osv/Packagist: %v", g)
	}
	if n := by["nvd"]; n == nil || n["ecosystem"] != nil || n["advisories"].(float64) != 4 || len(n["products"].([]any)) != 3 || n["products"].([]any)[1] != "cpe:2.3:a:nginx:nginx" {
		t.Fatalf("nvd: %v", n)
	}
	if by["osv/crates.io"] == nil || by["osv/Go"] == nil || by["osv/npm"] == nil {
		t.Fatalf("ecosystems: %v", by)
	}
	if j["stale"] != true || j["stale_after_days"].(float64) != 7 {
		t.Fatalf("stale comes from the CLI: %v %v", j["stale"], j["stale_after_days"])
	}
	// The backend passes its threshold to the CLI.
	if c := testutil.Calls(t, v.calls); len(c) != 1 || !strings.HasPrefix(c[0], "status --json --db "+v.dir+" --max-age-days 7") {
		t.Fatalf("calls: %v", c)
	}
	// Fresh data: stale false as reported by the CLI; a partial install has no NVD source.
	fresh := newVulnWorld(t, testutil.FakeVuln{StatusJSON: `{"advisory_count": 5, "age_days": 1, "format_version": 1, "max_age_days": 7, "stale": false,
		"updated_at": "2026-10-27T00:00:00Z", "osv": {"npm": {"advisories": 5, "age_days": 1, "updated_at": "2026-10-27T00:00:00Z"}}}`}, vulndb.Config{})
	fj := fresh.get(t)
	if fj["stale"] != false || len(fj["status"].(map[string]any)["sources"].([]any)) != 1 {
		t.Fatalf("fresh: %v", fj)
	}
}

func TestVulnDBNotInstalledAndErrors(t *testing.T) {
	// No meta.json: not installed, answered without running the tool (no 500, no error).
	v := newVulnWorldEmpty(t, testutil.FakeVuln{StatusJSON: statusJSON}, vulndb.Config{})
	j := v.get(t)
	st := j["status"].(map[string]any)
	if j["configured"] != true || j["db_present"] != false || st["installed"] != false || st["advisory_count"].(float64) != 0 ||
		len(st["sources"].([]any)) != 0 || st["updated_at"] != nil || j["status_error"] != nil || j["stale"] != false {
		t.Fatalf("not installed: %v", j)
	}
	if n := len(testutil.Calls(t, v.calls)); n != 0 {
		t.Fatalf("the tool must not run for a missing database: %d calls", n)
	}
	// An empty directory (created, no meta.json) is the same.
	v2 := newVulnWorldEmpty(t, testutil.FakeVuln{StatusJSON: statusJSON}, vulndb.Config{})
	_ = os.MkdirAll(v2.dir, 0o755)
	if j := v2.get(t); j["db_present"] != true || j["status"].(map[string]any)["installed"] != false {
		t.Fatalf("empty dir: %v", j)
	}
	// status failing (e.g. a corrupt meta.json) -> status_error, still a 200.
	v3 := newVulnWorld(t, testutil.FakeVuln{StatusExit: 2}, vulndb.Config{})
	if j := v3.get(t); j["status"] != nil || !strings.Contains(j["status_error"].(string), "status failed") {
		t.Fatalf("failing status: %v", j)
	}
	// Output that is not JSON.
	v4 := newVulnWorld(t, testutil.FakeVuln{StatusJSON: "Database: ok"}, vulndb.Config{})
	if j := v4.get(t); j["status"] != nil || j["status_error"] == nil {
		t.Fatalf("not JSON: %v", j)
	}
	// Tool missing.
	v6 := newVulnWorld(t, testutil.FakeVuln{StatusJSON: statusJSON}, vulndb.Config{})
	_ = os.Remove(v6.bin)
	j6 := v6.get(t)
	if j6["tool"].(map[string]any)["available"] != false || j6["status_error"] == nil || j6["status"] != nil {
		t.Fatalf("missing tool: %v", j6)
	}
	if r := v6.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{}); r.Status != 409 || r.ErrCode() != "vuln_tool_unavailable" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestVulnDBUpdateRunsTheToolWithoutShellAndCleanEnv(t *testing.T) {
	t.Setenv("SDRSCAN_SECRET_KEY", "super-secret-key-value")
	t.Setenv("DATABASE_URL", "postgres://u:pw@db/x")
	t.Setenv("HTTPS_PROXY", "http://proxy.internal:3128")
	t.Setenv("NVD_API_KEY", "nvd-key-1")
	v := newVulnWorld(t, testutil.FakeVuln{StatusJSON: statusJSON, UpdateScript: `echo "fetching https://user:pw@feed.example/osv.zip"; echo "warn: slow" >&2; printf '\033[31mred\033[0m\n'`}, vulndb.Config{})
	r := v.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{"ecosystems": []string{"npm", "go", "NPM"}, "nvd": true})
	if r.Status != 202 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	u := r.JSON()["update"].(map[string]any)
	if u["state"] != "running" || u["trigger"] != "manual" || u["requested_by"] != "admin" || u["nvd"] != true {
		t.Fatalf("started: %v", u)
	}
	if eco := u["ecosystems"].([]any); len(eco) != 2 || eco[0] != "npm" || eco[1] != "Go" {
		t.Fatalf("ecosystems canonicalised and de-duplicated: %v", eco)
	}
	done := v.waitState(t, "succeeded")
	if done["exit_code"].(float64) != 0 || done["error_code"] != nil || done["finished_at"] == nil {
		t.Fatalf("done: %v", done)
	}
	logTail := done["log_tail"].(string)
	for _, want := range []string{"fetching https://feed.example/osv.zip", "warn: slow", "red", "update finished"} {
		if !strings.Contains(logTail, want) {
			t.Errorf("log lacks %q:\n%s", want, logTail)
		}
	}
	if strings.Contains(logTail, "pw@") || strings.Contains(logTail, "\x1b") {
		t.Errorf("userinfo / control sequences must be stripped:\n%q", logTail)
	}
	calls := testutil.Calls(t, v.calls)
	var upd string
	for _, c := range calls {
		if strings.HasPrefix(c, "update ") {
			upd = c
		}
	}
	if upd != "update --db "+v.dir+" --ecosystems npm,Go --nvd" {
		t.Fatalf("update argv: %q (calls %v)", upd, calls)
	}
	if st, err := os.Stat(v.dir); err != nil || !st.IsDir() {
		t.Fatalf("the database directory is created: %v", err)
	}
	env, _ := os.ReadFile(v.envFile)
	for _, leak := range []string{"super-secret-key-value", "postgres://u:pw@db/x", "DATABASE_URL", "SDRSCAN_SECRET_KEY"} {
		if strings.Contains(string(env), leak) {
			t.Errorf("tool environment leaks %s", leak)
		}
	}
	for _, want := range []string{"SDRSCAN_VULN_DB=" + v.dir, "HTTPS_PROXY=http://proxy.internal:3128", "NVD_API_KEY=nvd-key-1", "PATH=/usr/bin:/bin:/usr/local/bin"} {
		if !strings.Contains(string(env), want) {
			t.Errorf("tool environment lacks %s:\n%s", want, env)
		}
	}
	// The result is visible in GET and the audit log.
	if u := v.get(t)["update"].(map[string]any); u["state"] != "succeeded" || u["id"].(float64) != 1 {
		t.Fatalf("GET: %v", u)
	}
	var actions []string
	rows, err := v.env.Pool.Query(context.Background(), `SELECT action FROM audit_log WHERE action LIKE 'vulndb_%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	if strings.Join(actions, ",") != "vulndb_update_started,vulndb_update_finished" {
		t.Fatalf("audit: %v", actions)
	}
	var target, actor string
	_ = v.env.Pool.QueryRow(context.Background(), `SELECT target, actor_name FROM audit_log WHERE action = 'vulndb_update_started'`).Scan(&target, &actor)
	if actor != "admin" || !strings.Contains(target, "npm,Go") {
		t.Fatalf("audit target: %q by %q", target, actor)
	}
	// Defaults: no body / no ecosystems = all ecosystems, no flags.
	if r := v.admin.Do("POST", "/api/v1/system/vulndb/update", nil); r.Status != 202 {
		t.Fatalf("empty body: %d %s", r.Status, r.Body)
	}
	v.waitState(t, "succeeded")
	calls = testutil.Calls(t, v.calls)
	last := ""
	for _, c := range calls {
		if strings.HasPrefix(c, "update ") {
			last = c
		}
	}
	if last != "update --db "+v.dir {
		t.Fatalf("default update argv: %q", last)
	}
}

func TestVulnDBUpdateValidation(t *testing.T) {
	v := newVulnWorld(t, testutil.FakeVuln{}, vulndb.Config{})
	for _, body := range []map[string]any{{"ecosystems": []string{"npm;rm -rf /"}}, {"ecosystems": []string{"PyPI"}}, {"ecosystems": []string{"--db=/etc"}}, {"ecosystems": []string{""}}} {
		r := v.admin.Do("POST", "/api/v1/system/vulndb/update", body)
		if r.Status != 422 || r.ErrCode() != "validation_failed" {
			t.Errorf("%v: %d %s", body, r.Status, r.Body)
		}
	}
	if r := v.admin.Raw("POST", "/api/v1/system/vulndb/update", strings.NewReader("{nope"), map[string]string{"Content-Type": "application/json"}); r.Status != 400 {
		t.Errorf("bad JSON: %d", r.Status)
	}
	if n := len(testutil.Calls(t, v.calls)); n != 0 {
		t.Fatalf("nothing may run for invalid input: %d calls", n)
	}
}

func TestVulnDBOneUpdateAtATimeAndCancel(t *testing.T) {
	v := newVulnWorld(t, testutil.FakeVuln{UpdateScript: `echo started; sleep 30; echo never`}, vulndb.Config{})
	if r := v.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{}); r.Status != 202 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	r := v.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{})
	if r.Status != 409 || r.ErrCode() != "update_in_progress" {
		t.Fatalf("second update: %d %s", r.Status, r.Body)
	}
	// The log of the running job is readable.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(v.get(t)["update"].(map[string]any)["log_tail"].(string), "started") {
		if time.Now().After(deadline) {
			t.Fatal("no log while running")
		}
		time.Sleep(50 * time.Millisecond)
	}
	start := time.Now()
	c := v.admin.Do("POST", "/api/v1/system/vulndb/update/cancel", map[string]any{})
	if c.Status != 202 {
		t.Fatalf("cancel: %d %s", c.Status, c.Body)
	}
	u := v.waitState(t, "cancelled")
	if u["error_code"] != "cancelled" || time.Since(start) > 15*time.Second {
		t.Fatalf("cancelled job: %v after %s", u, time.Since(start))
	}
	if c := v.admin.Do("POST", "/api/v1/system/vulndb/update/cancel", map[string]any{}); c.Status != 409 || c.ErrCode() != "no_update_running" {
		t.Fatalf("cancel when idle: %d %s", c.Status, c.Body)
	}
	// A new update can start after the cancelled one.
	if r := v.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{"ecosystems": []string{"Go"}}); r.Status != 202 {
		t.Fatalf("after cancel: %d %s", r.Status, r.Body)
	}
	var cancelled int
	_ = v.env.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'vulndb_update_cancelled'`).Scan(&cancelled)
	if cancelled != 1 {
		t.Fatalf("audit cancelled rows: %d", cancelled)
	}
}

func TestVulnDBUpdateFailureTimeoutAndCrossInstanceLock(t *testing.T) {
	// Non-zero exit.
	v := newVulnWorld(t, testutil.FakeVuln{UpdateScript: `echo "network down" >&2; exit 3`}, vulndb.Config{})
	v.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{})
	u := v.waitState(t, "failed")
	if u["error_code"] != "update_failed" || u["exit_code"].(float64) != 3 || !strings.Contains(u["log_tail"].(string), "network down") {
		t.Fatalf("failed: %v", u)
	}
	// Timeout.
	v2 := newVulnWorld(t, testutil.FakeVuln{UpdateScript: `sleep 30`}, vulndb.Config{Timeout: time.Second})
	v2.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{})
	if u := v2.waitState(t, "failed"); u["error_code"] != "timeout" {
		t.Fatalf("timeout: %v", u)
	}
	// Another backend instance holds the advisory lock: one update at a time overall.
	v3 := newVulnWorld(t, testutil.FakeVuln{}, vulndb.Config{})
	conn, err := v3.env.Pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	const key int64 = 0x5344525643564c
	if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock($1)`, key); err != nil {
		t.Fatal(err)
	}
	r := v3.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{})
	if r.Status != 409 || r.ErrCode() != "update_in_progress" {
		t.Fatalf("cross-instance: %d %s", r.Status, r.Body)
	}
	_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
	if r := v3.admin.Do("POST", "/api/v1/system/vulndb/update", map[string]any{}); r.Status != 202 {
		t.Fatalf("after unlock: %d %s", r.Status, r.Body)
	}
}

func TestVulnDBScheduledUpdateRunsOncePerSlot(t *testing.T) {
	v := newVulnWorld(t, testutil.FakeVuln{}, vulndb.Config{Cron: "30 3 * * *"})
	slot := time.Date(2026, 5, 6, 3, 30, 0, 0, time.UTC)
	v.env.VulnDB.ScheduledTick(slot.Add(-time.Minute)) // not due
	if v.get(t)["update"] != nil {
		t.Fatal("started before the slot")
	}
	v.env.VulnDB.ScheduledTick(slot.Add(5 * time.Second))
	u := v.waitState(t, "succeeded")
	if u["trigger"] != "schedule" || u["requested_by"] != nil || u["id"].(float64) != 1 {
		t.Fatalf("scheduled job: %v", u)
	}
	v.env.VulnDB.ScheduledTick(slot.Add(65 * time.Second)) // same slot, next tick
	if v.get(t)["update"].(map[string]any)["id"].(float64) != 1 {
		t.Fatal("the slot ran twice")
	}
	v.env.VulnDB.ScheduledTick(slot.Add(24*time.Hour + time.Second)) // next day's slot
	deadline := time.Now().Add(10 * time.Second)
	for v.get(t)["update"].(map[string]any)["id"].(float64) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("next slot did not run")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if v.get(t)["update_cron"] != "30 3 * * *" {
		t.Fatalf("update_cron: %v", v.get(t)["update_cron"])
	}
	// No cron configured: never.
	w := newVulnWorld(t, testutil.FakeVuln{}, vulndb.Config{})
	w.env.VulnDB.ScheduledTick(slot)
	if w.get(t)["update"] != nil {
		t.Fatal("scheduled without a cron")
	}
}

// The real sdrscan-vuln (dist/) on the repository fixture: `status` only, never `update`.
func TestVulnDBStatusWithTheRealTool(t *testing.T) {
	vf := testutil.RealVulnFixtures(t)
	w := newWorld(t, testutil.EnvOptions{VulnDB: vulndb.Config{Dir: vf.DB, Bin: vf.VulnBin, ScaEnabled: true}})
	j := w.admin.Get("/api/v1/system/vulndb").JSON()
	st, _ := j["status"].(map[string]any)
	if st == nil {
		t.Fatalf("no status: %v", j)
	}
	if st["installed"] != true || st["advisory_count"].(float64) != 13 || st["format_version"].(float64) != 1 || st["max_age_days"].(float64) != 7 ||
		st["updated_at"] != "2026-10-20T00:00:00Z" || len(st["sources"].([]any)) != 5 || j["status_error"] != nil {
		t.Fatalf("status: %v", st)
	}
	// The fixture is dated; whether it is stale depends on today's date, and the CLI decides.
	age := st["age_days"].(float64)
	if (age > 7) != (j["stale"] == true) {
		t.Fatalf("stale=%v with age_days=%v", j["stale"], age)
	}
	nvd := map[string]any{}
	for _, s := range st["sources"].([]any) {
		if m := s.(map[string]any); m["name"] == "nvd" {
			nvd = m
		}
	}
	if nvd["advisories"].(float64) != 4 || len(nvd["products"].([]any)) != 3 {
		t.Fatalf("nvd: %v", nvd)
	}
	// An empty directory and a broken meta.json.
	empty := t.TempDir()
	w2 := newWorld(t, testutil.EnvOptions{VulnDB: vulndb.Config{Dir: empty, Bin: vf.VulnBin}})
	if j := w2.admin.Get("/api/v1/system/vulndb").JSON(); j["status"].(map[string]any)["installed"] != false || j["status_error"] != nil {
		t.Fatalf("empty dir: %v", j)
	}
	if err := os.WriteFile(filepath.Join(empty, "meta.json"), []byte("{bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	j3 := w2.admin.Get("/api/v1/system/vulndb").JSON()
	if j3["status"] != nil || !strings.Contains(j3["status_error"].(string), "meta.json") {
		t.Fatalf("broken meta.json: %v", j3)
	}
}
