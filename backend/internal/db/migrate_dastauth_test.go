package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/sdrscan/sdrscan/backend/internal/db"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
	"github.com/sdrscan/sdrscan/backend/migrations"
)

// TestMigrationDastAuth migrates a schema without DAST authentication: existing targets get type
// none and the default crawl limits, the new constraints hold, and down/up are clean.
func TestMigrationDastAuth(t *testing.T) {
	pool, _ := testutil.NewEmptyDB(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	cols := func() int {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'codebases' AND column_name LIKE 'dast\_auth\_%' OR (table_name = 'codebases' AND column_name LIKE 'dast\_crawl\_%')`).Scan(&n)
		return n
	}
	if cols() != 0 {
		t.Fatal("DAST auth columns must not exist before 0004")
	}
	for _, q := range []string{
		`INSERT INTO users (username, password_hash, role) VALUES ('admin1', 'x', 'admin')`,
		`INSERT INTO projects (name) VALUES ('P')`,
		`INSERT INTO codebases (project_id, name, target_type, base_url, dast_status, dast_registered_by) VALUES (1, 'live', 'url', 'https://h.example', 'pending_confirmation', 1)`,
		`INSERT INTO codebases (project_id, name, target_type, repo_url) VALUES (1, 'repo', 'repo', 'https://h/x.git')`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if cols() != 7 {
		t.Fatalf("expected 7 new columns, got %d", cols())
	}
	var typ string
	var enabled bool
	var depth, pages, nex int
	if err := pool.QueryRow(ctx, `SELECT dast_auth_type, dast_crawl_enabled, dast_crawl_max_depth, dast_crawl_max_pages, cardinality(dast_crawl_exclude) FROM codebases WHERE id = 1`).
		Scan(&typ, &enabled, &depth, &pages, &nex); err != nil {
		t.Fatal(err)
	}
	if typ != "none" || enabled || depth != 3 || pages != 50 || nex != 0 {
		t.Fatalf("defaults: %s %v %d %d %d", typ, enabled, depth, pages, nex)
	}
	twentyOne := "ARRAY[" + strings.TrimSuffix(strings.Repeat("'a',", 21), ",") + "]"
	long := "ARRAY['" + strings.Repeat("a", 4100) + "']"
	for name, q := range map[string]string{
		"unknown type":              `UPDATE codebases SET dast_auth_type = 'oauth' WHERE id = 1`,
		"type without ciphertext":   `UPDATE codebases SET dast_auth_type = 'form', dast_auth_meta = '{}' WHERE id = 1`,
		"ciphertext with none":      `UPDATE codebases SET dast_auth_enc = '\x00' WHERE id = 1`,
		"auth on a repo":            `UPDATE codebases SET dast_auth_type = 'header', dast_auth_enc = '\x00', dast_auth_meta = '{}' WHERE id = 2`,
		"depth 0":                   `UPDATE codebases SET dast_crawl_max_depth = 0 WHERE id = 1`,
		"depth 11":                  `UPDATE codebases SET dast_crawl_max_depth = 11 WHERE id = 1`,
		"pages 0":                   `UPDATE codebases SET dast_crawl_max_pages = 0 WHERE id = 1`,
		"pages 501":                 `UPDATE codebases SET dast_crawl_max_pages = 501 WHERE id = 1`,
		"21 exclude patterns":       `UPDATE codebases SET dast_crawl_exclude = ` + twentyOne + ` WHERE id = 1`,
		"oversized exclude pattern": `UPDATE codebases SET dast_crawl_exclude = ` + long + ` WHERE id = 1`,
		"crawl on a repo":           `UPDATE codebases SET dast_crawl_enabled = true WHERE id = 2`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, q := range map[string]string{
		"valid auth":   `UPDATE codebases SET dast_auth_type = 'form+header', dast_auth_enc = '\x0102', dast_auth_meta = '{"login_url":"x"}' WHERE id = 1`,
		"valid crawl":  `UPDATE codebases SET dast_crawl_enabled = true, dast_crawl_max_depth = 10, dast_crawl_max_pages = 500, dast_crawl_exclude = ARRAY['^/a','b'] WHERE id = 1`,
		"back to none": `UPDATE codebases SET dast_auth_type = 'none', dast_auth_enc = NULL, dast_auth_meta = NULL WHERE id = 1`,
		"min crawl":    `UPDATE codebases SET dast_crawl_max_depth = 1, dast_crawl_max_pages = 1 WHERE id = 1`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Down drops the columns (and keeps the codebases); up again is clean. DownTo(3) rather than a
	// single Down() step, so this still isolates migration 0004 once later migrations are added on top.
	if _, err := p.DownTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM codebases`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("codebases after down: %d %v", n, err)
	}
	if cols() != 0 {
		t.Fatal("down must drop the columns")
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}
