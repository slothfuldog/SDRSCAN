// Package testutil provides helpers shared by tests: a throw-away PostgreSQL
// database per test, built from the real migrations.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sdrscan/sdrscan/backend/internal/db"
)

// DefaultTestDatabaseURL is the local development database from the docs; it is
// used only to create and drop sdrscan_test_* databases.
const DefaultTestDatabaseURL = "postgres://sdrscan:sdrscan_dev@127.0.0.1:5433/sdrscan?sslmode=disable"

// BaseURL returns the admin connection URL used to create test databases.
func BaseURL() string {
	if v := os.Getenv("SDRSCAN_TEST_DATABASE_URL"); v != "" {
		return v
	}
	return DefaultTestDatabaseURL
}

// NewDB creates an empty migrated database for the test and drops it afterwards.
func NewDB(t testing.TB) *pgxpool.Pool {
	pool, _ := NewDBWithURL(t)
	return pool
}

// NewDBWithURL is NewDB that also returns the connection URL of the new database.
func NewDBWithURL(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	return newDB(t, true)
}

// NewEmptyDB creates a database without any migration applied (for migration tests).
func NewEmptyDB(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	return newDB(t, false)
}

func newDB(t testing.TB, migrate bool) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	base := BaseURL()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Skipf("PostgreSQL not reachable for tests (%v); set SDRSCAN_TEST_DATABASE_URL", err)
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	name := "sdrscan_test_" + hex.EncodeToString(rnd[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create test database: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse test database url: %v", err)
	}
	u.Path = "/" + name
	testURL := u.String()
	pool, err := db.Connect(ctx, testURL, false)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	if migrate {
		if err := db.Migrate(ctx, pool); err != nil {
			t.Fatalf("migrate test database: %v", err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = admin.Exec(c, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close(c)
	})
	return pool, testURL
}
