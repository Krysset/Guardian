package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var (
	database *sql.DB
	once     sync.Once
)

// GetDatabaseConnection connects and runs the init script on first use.
func GetDatabaseConnection() *sql.DB {
	once.Do(func() {
		database = connect()
		initializeDB(database)
	})
	return database
}

func connect() *sql.DB {
	port, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		log.Println("DB_PORT is missing or invalid, using 5432")
		port = 5432
	}
	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"), port, os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), sslmode)

	for {
		db, err := sql.Open("postgres", dsn)
		if err == nil {
			err = db.Ping()
		}
		if err == nil {
			configurePool(db)
			log.Println("Connected to DB")
			return db
		}
		log.Printf("DB not reachable (%v). Retrying in 3 seconds...", err)
		if db != nil {
			db.Close()
		}
		time.Sleep(3 * time.Second)
	}
}

func initializeDB(db *sql.DB) {
	path := os.Getenv("SCHEMA_PATH")
	if path == "" {
		path = "/schema.sql"
	}
	script, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", path, err)
	}
	for {
		err := runSchema(db, string(script))
		if err == nil {
			return
		}
		log.Printf("Failed to run schema script (%v). Retrying in 3 seconds...", err)
		time.Sleep(3 * time.Second)
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
func configurePool(db *sql.DB) {
	maxConns := 20
	if v, err := strconv.Atoi(os.Getenv("DB_MAX_CONNS")); err == nil && v > 0 {
		maxConns = v
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxLifetime(30 * time.Minute)
}
