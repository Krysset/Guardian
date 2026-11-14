package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"guardian/internal/config"
	"guardian/migrations"
)

var (
	database *sql.DB
	once     sync.Once
)

// Open connects to PostgreSQL and runs the schema script. It waits and retries until the database is
// reachable, so Guardian can start before its database does; cancelling ctx stops the wait. Only the
// first call has an effect.
func Open(ctx context.Context, cfg config.Database) (*sql.DB, error) {
	var err error
	once.Do(func() {
		var db *sql.DB
		if db, err = connect(ctx, cfg); err != nil {
			return
		}
		if err = initializeDB(ctx, db); err != nil {
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
		db, err := sql.Open("postgres", cfg.DSN())
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

func initializeDB(ctx context.Context, db *sql.DB) error {
	for {
		err := runSchema(db, migrations.InitSQL)
		if err == nil {
			return nil
		}
		slog.Warn("schema script failed, retrying in 3 seconds", "error", err)
		if err := wait(ctx, 3*time.Second); err != nil {
			return fmt.Errorf("gave up running the schema script: %w", err)
		}
	}
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

// runSchema executes the init script on one dedicated connection. The script manages its own
// transaction (BEGIN ... COMMIT), so after a failure we must ROLLBACK before the connection
// goes back to the pool, otherwise it would stay stuck in an aborted transaction.
func runSchema(db *sql.DB, script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, script); err != nil {
		conn.ExecContext(context.Background(), "ROLLBACK")
		return err
	}
	return nil
}

// configurePool bounds connections per pod. Total = replicas x DB_MAX_CONNS must stay below
// Postgres max_connections (put PgBouncer in front if you scale beyond that).
func configurePool(db *sql.DB, maxConns int) {
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxLifetime(30 * time.Minute)
}
