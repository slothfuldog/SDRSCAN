package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/sdrscan/sdrscan/backend/internal/db"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
	"github.com/sdrscan/sdrscan/backend/migrations"
)

// TestMigrationDastActiveScanning applies the schema up to 0004 (dast_auth), seeds a confirmed URL
// target, a repo and a scan, then migrates to the current schema: the new active-scanning-
// authorization and OpenAPI spec columns on codebases and the active/active_timing columns on scans
// appear with safe defaults, their CHECK constraints hold, and down/up stay clean.
func TestMigrationDastActiveScanning(t *testing.T) {
	pool, _ := testutil.NewEmptyDB(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 4); err != nil {
		t.Fatal(err)
	}
	var has bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'codebases' AND column_name = 'dast_active_authorized_at')`).Scan(&has)
	if has {
		t.Fatal("dast_active_authorized_at must not exist before 0005")
	}
	for _, q := range []string{
		`INSERT INTO users (username, password_hash, role) VALUES ('admin1', 'x', 'admin')`,
		`INSERT INTO projects (name) VALUES ('P')`,
		`INSERT INTO codebases (project_id, name, target_type, base_url, dast_status, dast_registered_by, dast_confirmed_by, dast_confirmed_at, dast_confirmation_text)
			VALUES (1, 'live', 'url', 'https://h.example', 'confirmed', 1, 1, now(), 'I confirm')`,
		`INSERT INTO codebases (project_id, name, target_type, repo_url) VALUES (1, 'repo', 'repo', 'https://h/x.git')`,
		`INSERT INTO scans (codebase_id, type, trigger, status) VALUES (1, 'dast', 'manual', 'queued')`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var authorizedAt any
	var active, activeTiming bool
	var openapi any
	if err := pool.QueryRow(ctx, `SELECT dast_active_authorized_at, dast_openapi_spec_url FROM codebases WHERE id = 1`).Scan(&authorizedAt, &openapi); err != nil {
		t.Fatal(err)
	}
	if authorizedAt != nil || openapi != nil {
		t.Fatalf("defaults must be null: authorized_at=%v openapi=%v", authorizedAt, openapi)
	}
	if err := pool.QueryRow(ctx, `SELECT active, active_timing FROM scans WHERE id = 1`).Scan(&active, &activeTiming); err != nil {
		t.Fatal(err)
	}
	if active || activeTiming {
		t.Fatalf("scans.active/active_timing must default false, got %v %v", active, activeTiming)
	}

	for name, q := range map[string]string{
		"authorized_at without by/statement": `UPDATE codebases SET dast_active_authorized_at = now() WHERE id = 1`,
		"authorized_by without the rest":     `UPDATE codebases SET dast_active_authorized_by = 1 WHERE id = 1`,
		"active authorization on a repo": `UPDATE codebases SET dast_active_authorized_at = now(), dast_active_authorized_by = 1,
			dast_active_statement = 's' WHERE id = 2`,
		"openapi spec url on a repo": `UPDATE codebases SET dast_openapi_spec_url = 'https://h.example/spec.json' WHERE id = 2`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, q := range map[string]string{
		"full active authorization": `UPDATE codebases SET dast_active_authorized_at = now(), dast_active_authorized_by = 1,
			dast_active_statement = 'I confirm ... live' WHERE id = 1`,
		"openapi spec url on a url target": `UPDATE codebases SET dast_openapi_spec_url = 'https://h.example/openapi.json' WHERE id = 1`,
		"revoke back to null": `UPDATE codebases SET dast_active_authorized_at = NULL, dast_active_authorized_by = NULL,
			dast_active_statement = NULL, dast_openapi_spec_url = NULL WHERE id = 1`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE scans SET active = true, active_timing = true WHERE id = 1`); err != nil {
		t.Fatalf("set active flags: %v", err)
	}

	// Down (to 0004, past these migrations): columns go away, rows stay.
	if _, err := p.DownTo(ctx, 4); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM codebases`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("codebases after down: %d %v", n, err)
	}
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'codebases' AND column_name IN ('dast_active_authorized_at', 'dast_active_authorized_by', 'dast_active_statement', 'dast_openapi_spec_url'))`).Scan(&has)
	if has {
		t.Fatal("down must drop the codebases columns")
	}
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'scans' AND column_name IN ('active', 'active_timing'))`).Scan(&has)
	if has {
		t.Fatal("down must drop the scans columns")
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}
