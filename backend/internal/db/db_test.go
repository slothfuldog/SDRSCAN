package db_test

import (
	"context"
	"testing"

	"github.com/sdrscan/sdrscan/backend/internal/db"
	"github.com/sdrscan/sdrscan/backend/internal/testutil"
)

func TestMigrateFromEmptyAndIdempotent(t *testing.T) {
	pool := testutil.NewDB(t)
	ctx := context.Background()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
		WHERE table_schema='public' AND table_name IN
		('users','projects','codebases','scans','scan_files','findings','ingest_digest','ingest_tokens','sessions','audit_log')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("expected 10 tables, got %d", n)
	}
}
