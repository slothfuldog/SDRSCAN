// Package db opens the PostgreSQL pool and runs goose migrations.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/sdrscan/sdrscan/backend/migrations"
)

// Connect opens a pgx pool and verifies connectivity, retrying like the TRD
// asks (5 attempts, 2 s apart) when retries is true.
func Connect(ctx context.Context, url string, retries bool) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", errors.New("invalid connection string"))
	}
	cfg.MaxConns = 20
	attempts := 1
	if retries {
		attempts = 5
	}
	var last error
	for i := 0; i < attempts; i++ {
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = pool.Ping(pctx)
			cancel()
			if err == nil {
				return pool, nil
			}
			pool.Close()
		}
		last = err
		if i < attempts-1 {
			slog.Warn("database not reachable, retrying", "attempt", i+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil, fmt.Errorf("database unreachable: %w", last)
}

func provider(sqlDB *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS, goose.WithSessionLocker(locker))
}

// Migrate applies all pending migrations. It refuses to run when the database
// schema is newer than this binary.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := provider(sqlDB)
	if err != nil {
		return err
	}
	cur, err := p.GetDBVersion(ctx)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	var latest int64
	for _, s := range p.ListSources() {
		if s.Version > latest {
			latest = s.Version
		}
	}
	if cur > latest {
		return fmt.Errorf("database schema version %d is newer than this binary (%d)", cur, latest)
	}
	res, err := p.Up(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for _, r := range res {
		slog.Debug("migration applied", "version", r.Source.Version, "path", r.Source.Path)
	}
	return nil
}
