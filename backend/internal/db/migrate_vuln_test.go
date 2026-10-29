package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/sdrscan/sdrscan/backend/internal/db"
	"github.com/sdrscan/sdrscan/backend/internal/store"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
	"github.com/sdrscan/sdrscan/backend/migrations"
)

// TestMigrationFromTheSchemaWithoutVulnerabilities applies 0001 and 0002, stores findings the old
// way, then migrates to the current schema: old rows stay valid code findings and the new column,
// constraint and indexes work. The down migration drops the columns and keeps the findings.
func TestMigrationFromTheSchemaWithoutVulnerabilities(t *testing.T) {
	pool, _ := testutil.NewEmptyDB(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	var has bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'findings' AND column_name = 'vulnerability')`).Scan(&has)
	if has {
		t.Fatal("the vulnerability column must not exist before 0003")
	}
	for _, q := range []string{
		`INSERT INTO projects (name) VALUES ('P')`,
		`INSERT INTO codebases (project_id, name, target_type, repo_url) VALUES (1, 'c', 'repo', 'https://h/x.git')`,
		`INSERT INTO scans (codebase_id, type, trigger, status) VALUES (1, 'sast', 'ci', 'succeeded')`,
		`INSERT INTO findings (scan_id, codebase_id, is_current, rule_id, severity, severity_rank, message, location_kind, path, fingerprint)
			VALUES (1, 1, true, 'php-xss-echo', 'high', 3, 'm', 'file', 'a.php', 'fp1')`,
		`INSERT INTO findings (scan_id, codebase_id, is_current, rule_id, severity, severity_rank, confidence, message, location_kind, path, fingerprint)
			VALUES (1, 1, true, 'php-info', 'low', 1, 'low', 'm', 'file', 'b.php', 'fp2')`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := db.Migrate(ctx, store.New(pool).Pool); err != nil {
		t.Fatal(err)
	}
	var nullVuln, emptyIDs, total int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE vulnerability IS NULL), count(*) FILTER (WHERE vuln_ids = '{}'), count(*) FROM findings`).Scan(&nullVuln, &emptyIDs, &total); err != nil {
		t.Fatal(err)
	}
	if total != 2 || nullVuln != 2 || emptyIDs != 2 {
		t.Fatalf("old rows after migration: total=%d null=%d empty=%d", total, nullVuln, emptyIDs)
	}
	// The store reads old rows as code findings, and the facets/filters work on them.
	st := store.New(pool)
	fs, n, err := st.ListFindings(ctx, store.FindingFilter{CodebaseID: 1, IncludeLow: true}, store.Page{Page: 1, Size: 10})
	if err != nil || n != 2 || fs[0].Kind() != "code" || fs[0].Vulnerability != nil {
		t.Fatalf("old findings: %+v %d %v", fs, n, err)
	}
	if fc, err := st.FindingFacets(ctx, store.FindingFilter{CodebaseID: 1, IncludeLow: true}); err != nil || fc.Kind.Code != 2 || fc.Kind.Vulnerability != 0 {
		t.Fatalf("facets: %+v %v", fc, err)
	}
	// New rows: a CVE finding, and the shape constraint.
	ins := func(vuln, ids, fp string) error {
		_, err := pool.Exec(ctx, `INSERT INTO findings (scan_id, codebase_id, rule_id, severity, severity_rank, message, location_kind, path, fingerprint, vulnerability, vuln_ids)
			VALUES (1, 1, 'CVE-2021-1111', 'high', 3, 'm', 'file', 'composer.lock', $1, $2::jsonb, $3::text[])`, fp, nilIfEmpty(vuln), ids)
		return err
	}
	if err := ins(`{"ids":["CVE-2021-1111"]}`, `{CVE-2021-1111}`, "v1"); err != nil {
		t.Fatalf("valid CVE row: %v", err)
	}
	for name, c := range map[string][3]string{
		"vulnerability without ids":   {`{"ids":[]}`, `{}`, "v2"},
		"ids without vulnerability":   {``, `{CVE-2021-1111}`, "v3"},
		"vulnerability not an object": {`["x"]`, `{CVE-2021-1111}`, "v4"},
	} {
		if err := ins(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	var viaIndex int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE vuln_ids @> ARRAY['CVE-2021-1111']::text[]`).Scan(&viaIndex); err != nil || viaIndex != 1 {
		t.Fatalf("search by id: %d %v", viaIndex, err)
	}
	// Down (to 0002, past later migrations): columns go away, findings stay.
	if _, err := p.DownTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM findings`).Scan(&total); err != nil || total != 3 {
		t.Fatalf("findings after down: %d %v", total, err)
	}
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'findings' AND column_name IN ('vulnerability','vuln_ids'))`).Scan(&has)
	if has {
		t.Fatal("down must drop the columns")
	}
	// And up again is clean.
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
