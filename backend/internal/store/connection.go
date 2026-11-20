package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"guardian/internal/config"
	"guardian/migrations"
)

var (
	database *sql.DB
	once     sync.Once
)

// Open connects to PostgreSQL and applies pending migrations. It waits and retries until the database is
// reachable, so Guardian can start before its database does; cancelling ctx stops the wait. Only the
// first call has an effect.
func Open(ctx context.Context, cfg config.Database) (*sql.DB, error) {
	var err error
	once.Do(func() {
		var db *sql.DB
		if db, err = connect(ctx, cfg); err != nil {
			return
		}
		if err = initializeDB(ctx, db, cfg.Migrate != "wait"); err != nil {
			db.Close()
			return
		}
		database = db
	})
	if err != nil {
		return nil, err
	}
	if database == nil {
		return nil, errors.New("store: an earlier Open failed")
	}
	return database, nil
}

// GetDatabaseConnection returns the pool opened by Open.
func GetDatabaseConnection() *sql.DB {
	if database == nil {
		panic("store: GetDatabaseConnection called before Open")
	}
	return database
}

func connect(ctx context.Context, cfg config.Database) (*sql.DB, error) {
	for {
		db, err := sql.Open("pgx", cfg.DSN())
		if err == nil {
			err = db.PingContext(ctx)
		}
		if err == nil {
			configurePool(db, cfg.MaxConns)
			slog.Info("connected to the database", "host", cfg.Host, "port", cfg.Port, "database", cfg.Name)
			return db, nil
		}
		if db != nil {
			db.Close()
		}
		slog.Warn("database not reachable, retrying in 3 seconds", "error", err)
		if err := wait(ctx, 3*time.Second); err != nil {
			return nil, fmt.Errorf("gave up waiting for the database: %w", err)
		}
	}
}

func initializeDB(ctx context.Context, db *sql.DB, migrate bool) error {
	if !migrate {
		// DB_MIGRATE=wait: a migration Job applies the schema; wait until it has (an upgrade's Job runs before
		// the new pods, an install's alongside them).
		for {
			err := VerifySchemaRevision(ctx, db)
			if err == nil || !errors.Is(err, ErrSchemaRevision) {
				return err
			}
			slog.Info("waiting for the migration job to apply the database schema", "detail", err.Error())
			if err := wait(ctx, 3*time.Second); err != nil {
				return fmt.Errorf("gave up waiting for the database schema: %w", err)
			}
		}
	}
	for {
		err := Migrate(ctx, db)
		if err == nil {
			return VerifySchemaRevision(ctx, db)
		}
		slog.Warn("database migration failed, retrying in 3 seconds", "error", err)
		if err := wait(ctx, 3*time.Second); err != nil {
			return fmt.Errorf("gave up migrating the database: %w", err)
		}
	}
}

// ErrSchemaRevision means the database was created by another revision of migration 1.
var ErrSchemaRevision = errors.New("this database was created by a different development version of Guardian. " +
	"Until Guardian 1.0 the first migration is still edited in place, so the database cannot be upgraded: " +
	"recreate it (with the compose setup: docker compose down -v), or restore a backup into a new one")

// VerifySchemaRevision checks that the database was created by the migration 1 that this binary ships
// with (see SCHEMA REVISION in migrations/00001_init.sql). Without it, a database from an older
// development version would start fine and then fail on the first query that needs a newer table.
func VerifySchemaRevision(ctx context.Context, db *sql.DB) error {
	var stored string
	err := db.QueryRowContext(ctx, `SELECT fingerprint FROM schema_revision LIMIT 1`).Scan(&stored)
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, sql.ErrNoRows), errors.As(err, &pgErr) && pgErr.Code == "42P01": // no row, or no such table
		return ErrSchemaRevision
	case err != nil:
		return err
	case stored != migrations.InitFingerprint:
		return fmt.Errorf("%w (database revision %s, expected %s)", ErrSchemaRevision, stored, migrations.InitFingerprint)
	}
	return nil
}

// Migrate applies every migration that the database has not seen yet, in order. Each migration runs in
// its own transaction. A Postgres session lock makes replicas that start together take turns, so a
// migration never runs twice.
func Migrate(ctx context.Context, db *sql.DB) error {
	// Ask for the lock once a second, for up to five minutes. goose's default asks every five seconds,
	// which delays every replica that starts while another one holds the lock.
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockTimeout(1, 300))
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		if r.Error == nil {
			slog.Info("applied database migration", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration.String())
		}
	}
	return err
}

// wait pauses for d, or returns early with the context's error when it is cancelled.
func wait(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// configurePool bounds connections per pod. Total = replicas x DB_MAX_CONNS must stay below
// Postgres max_connections (put PgBouncer in front if you scale beyond that).
func configurePool(db *sql.DB, maxConns int) {
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxLifetime(30 * time.Minute)
}
