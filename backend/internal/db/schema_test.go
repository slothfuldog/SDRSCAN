package db_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func TestSchemaConstraints(t *testing.T) {
	pool := testutil.NewDB(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	must := func(sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	mustFail := func(why, sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err == nil {
			t.Errorf("%s: statement was accepted", why)
		}
	}
	must(`INSERT INTO users (username, password_hash, role) VALUES ('admin1','x','admin')`)
	mustFail("duplicate username (case-insensitive)", `INSERT INTO users (username, password_hash) VALUES ('ADMIN1','x')`)
	mustFail("bad role", `INSERT INTO users (username, password_hash, role) VALUES ('bob12','x','root')`)
	mustFail("bad username", `INSERT INTO users (username, password_hash) VALUES ('a b','x')`)
	must(`INSERT INTO projects (name) VALUES ('Shop')`)
	mustFail("duplicate project name", `INSERT INTO projects (name) VALUES ('shop')`)
	must(`INSERT INTO codebases (project_id, name, target_type, repo_url) VALUES (1,'api','repo','https://h/x.git')`)
	mustFail("duplicate codebase name in project", `INSERT INTO codebases (project_id, name, target_type, repo_url) VALUES (1,'API','repo','https://h/y.git')`)
	mustFail("repo without repo_url", `INSERT INTO codebases (project_id, name, target_type) VALUES (1,'r2','repo')`)
	mustFail("repo with base_url", `INSERT INTO codebases (project_id, name, target_type, repo_url, base_url) VALUES (1,'r3','repo','https://h/x','https://x')`)
	mustFail("url without dast_status", `INSERT INTO codebases (project_id, name, target_type, base_url) VALUES (1,'u1','url','https://x')`)
	mustFail("url with repo_url", `INSERT INTO codebases (project_id, name, target_type, base_url, repo_url, dast_status) VALUES (1,'u2','url','https://x','https://h/x','pending_confirmation')`)
	mustFail("bad target_type", `INSERT INTO codebases (project_id, name, target_type, repo_url) VALUES (1,'r4','svn','x')`)
	mustFail("confirmed without trail", `INSERT INTO codebases (project_id, name, target_type, base_url, dast_status) VALUES (1,'u3','url','https://x','confirmed')`)
	mustFail("pending with trail", `INSERT INTO codebases (project_id, name, target_type, base_url, dast_status, dast_confirmed_by, dast_confirmed_at, dast_confirmation_text)
		VALUES (1,'u4','url','https://x','pending_confirmation',1,now(),'t')`)
	must(`INSERT INTO codebases (project_id, name, target_type, base_url, dast_status) VALUES (1,'u5','url','https://x','pending_confirmation')`)
	must(`UPDATE codebases SET dast_status='confirmed', dast_confirmed_by=1, dast_confirmed_at=now(), dast_confirmation_text='ok' WHERE name='u5'`)

	must(`INSERT INTO scans (codebase_id, type, trigger, status) VALUES (1,'sast','manual','queued')`)
	mustFail("second active runner job on a codebase", `INSERT INTO scans (codebase_id, type, trigger, status) VALUES (1,'sast','manual','running')`)
	must(`INSERT INTO scans (codebase_id, type, trigger, status) VALUES (1,'sast','ci','succeeded')`)
	must(`INSERT INTO scans (codebase_id, type, trigger, status) VALUES (1,'sast','ci','succeeded')`)
	mustFail("bad scan status", `INSERT INTO scans (codebase_id, type, trigger, status) VALUES (1,'sast','ci','weird')`)
	mustFail("partial scan from the web", `INSERT INTO scans (codebase_id, type, coverage, trigger, status) VALUES (1,'sast','partial','manual','succeeded')`)
	must(`INSERT INTO scans (codebase_id, type, coverage, trigger, status) VALUES (1,'sast','partial','ci','succeeded')`)

	var sA, sB int
	if err := pool.QueryRow(ctx, `SELECT min(id), max(id) FROM scans WHERE trigger = 'ci' AND coverage = 'full'`).Scan(&sA, &sB); err != nil {
		t.Fatal(err)
	}
	finding := func(scan, cb int, kind string, path, url any, sev string, rank int, fp string) error {
		return exec(`INSERT INTO findings (scan_id, codebase_id, rule_id, severity, severity_rank, message, location_kind, path, url, fingerprint)
			VALUES ($1,$2,'r',$3,$4,'m',$5,$6,$7,$8)`, scan, cb, sev, rank, kind, path, url, fp)
	}
	if err := finding(sA, 1, "file", "a.php", nil, "high", 3, "fp1"); err != nil {
		t.Fatal(err)
	}
	if finding(sA, 1, "file", nil, nil, "high", 3, "fp2") == nil {
		t.Error("file finding without path accepted")
	}
	if finding(sA, 1, "url", nil, nil, "high", 3, "fp3") == nil {
		t.Error("url finding without url accepted")
	}
	if finding(sA, 1, "ftp", "a", nil, "high", 3, "fp4") == nil {
		t.Error("bad location kind accepted")
	}
	if finding(sA, 1, "file", "a.php", nil, "high", 4, "fp5") == nil {
		t.Error("severity_rank inconsistent with severity accepted")
	}
	if finding(sA, 1, "file", "a.php", nil, "severe", 3, "fp6") == nil {
		t.Error("bad severity accepted")
	}
	if finding(sB, 1, "file", "a.php", nil, "high", 3, "fp7") != nil {
		t.Error("valid finding on another scan rejected")
	}
	// Composite FK: a finding cannot claim a codebase the scan does not belong to.
	if finding(sA, 2, "file", "a.php", nil, "high", 3, "fp8") == nil {
		t.Error("finding with a codebase that differs from its scan accepted")
	}
	// Identity uniqueness.
	if finding(sA, 1, "file", "a.php", nil, "high", 3, "fp1") == nil {
		t.Error("duplicate (scan, fingerprint, occurrence) accepted")
	}

	// Cascades: deleting the project removes everything below it.
	must(`DELETE FROM projects WHERE id = 1`)
	for _, tbl := range []string{"codebases", "scans", "findings", "scan_files"} {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+tbl).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s not emptied by cascade (%d, %v)", tbl, n, err)
		}
	}
	// Users referenced as DAST confirmer cannot be deleted (RESTRICT).
	must(`INSERT INTO projects (name) VALUES ('P2')`)
	must(`INSERT INTO codebases (project_id, name, target_type, base_url, dast_status, dast_confirmed_by, dast_confirmed_at, dast_confirmation_text)
		VALUES ((SELECT id FROM projects WHERE name='P2'),'u','url','https://x','confirmed',(SELECT id FROM users LIMIT 1),now(),'ok')`)
	err := exec(`DELETE FROM users`)
	if err == nil || !strings.Contains(err.Error(), "foreign key") {
		t.Errorf("deleting a confirmer must be restricted, got %v", err)
	}
}

func TestScheduleColumnsShape(t *testing.T) {
	pool := testutil.NewDB(t)
	ctx := context.Background()
	exec := func(sql string) error { _, err := pool.Exec(ctx, sql); return err }
	if err := exec(`INSERT INTO users (username, password_hash, role) VALUES ('admin1','x','admin')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO projects (name) VALUES ('P')`); err != nil {
		t.Fatal(err)
	}
	base := `INSERT INTO codebases (project_id, name, target_type, repo_url, %s) VALUES ((SELECT id FROM projects LIMIT 1), '%s', 'repo', 'https://h/x.git', %s)`
	ins := func(name, cols, vals string) error { return exec(fmt.Sprintf(base, cols, name, vals)) }
	owner := `(SELECT id FROM users LIMIT 1)`
	if err := ins("ok-active", "schedule_cron, schedule_owner_id, schedule_status", `'0 3 * * *', `+owner+`, 'active'`); err != nil {
		t.Fatalf("valid active schedule: %v", err)
	}
	if err := ins("ok-susp", "schedule_cron, schedule_owner_id, schedule_status, schedule_suspended_reason, schedule_suspended_at",
		`'0 3 * * *', `+owner+`, 'suspended', 'owner_deactivated', now()`); err != nil {
		t.Fatalf("valid suspended schedule: %v", err)
	}
	for name, c := range map[string][2]string{
		"cron without owner":         {"schedule_cron, schedule_status", `'0 3 * * *', 'active'`},
		"cron without status":        {"schedule_cron, schedule_owner_id", `'0 3 * * *', ` + owner},
		"owner without cron":         {"schedule_owner_id, schedule_status", owner + `, 'active'`},
		"suspended without reason":   {"schedule_cron, schedule_owner_id, schedule_status", `'0 3 * * *', ` + owner + `, 'suspended'`},
		"active with a reason":       {"schedule_cron, schedule_owner_id, schedule_status, schedule_suspended_reason, schedule_suspended_at", `'0 3 * * *', ` + owner + `, 'active', 'owner_deactivated', now()`},
		"unknown reason":             {"schedule_cron, schedule_owner_id, schedule_status, schedule_suspended_reason, schedule_suspended_at", `'0 3 * * *', ` + owner + `, 'suspended', 'because', now()`},
		"last_enqueued without cron": {"schedule_last_enqueued_at", `now()`},
	} {
		if err := ins("bad-"+strings.ReplaceAll(name, " ", "-"), c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
