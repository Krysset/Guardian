// Package testutil holds helpers for tests that need a real PostgreSQL database.
//
// Database tests are opt-in and refuse to touch anything but a dedicated test database, because Reset
// truncates every table:
//
//	createdb guardian_test
//	export GUARDIAN_TEST_DB=1 DB_HOST=localhost DB_PORT=5432 DB_USER=... DB_PASSWORD=... DB_NAME=guardian_test
//	go test ./...
//
// Without those variables the database tests skip themselves and only the unit tests run.
// Test processes (one per package) take a Postgres advisory lock, so `go test ./...` is safe to run in parallel.
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"

	"guardian/auth"
	db "guardian/database"
)

// DefaultPassword is the password of every account made by CreateAccount.
const DefaultPassword = "correct-horse-battery"

// Enabled reports whether database tests may run (explicit opt-in + a database named *_test).
func Enabled() bool {
	return os.Getenv("GUARDIAN_TEST_DB") == "1" && strings.HasSuffix(os.Getenv("DB_NAME"), "_test")
}

var (
	setupOnce  sync.Once
	setupErr   error
	lockConn   *sql.Conn // holds the cross-process advisory lock for the lifetime of the test process
	schemaPath string

	hashOnce sync.Once
	hashVal  string
)

// Setup connects (running the schema script) and serializes this process against other test processes.
// It is idempotent. Use it from TestMain; tests should call RequireTestDB instead.
func Setup() error {
	setupOnce.Do(func() {
		if !Enabled() {
			setupErr = fmt.Errorf("database tests need GUARDIAN_TEST_DB=1 and DB_NAME ending in _test")
			return
		}
		path, err := findSchema()
		if err != nil {
			setupErr = err
			return
		}
		schemaPath = path
		os.Setenv("SCHEMA_PATH", path)

		// GetDatabaseConnection retries forever; fail fast instead if nothing is listening.
		addr := net.JoinHostPort(os.Getenv("DB_HOST"), envOr("DB_PORT", "5432"))
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			setupErr = fmt.Errorf("cannot reach test database at %s: %w", addr, err)
			return
		}
		c.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		conn := db.GetDatabaseConnection()
		if lockConn, err = conn.Conn(ctx); err != nil {
			setupErr = err
			return
		}
		if _, err = lockConn.ExecContext(ctx, `SELECT pg_advisory_lock(727300)`); err != nil {
			setupErr = err
		}
	})
	return setupErr
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func findSchema() (string, error) {
	if p := os.Getenv("SCHEMA_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, "schema.sql")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("schema.sql not found above %s (set SCHEMA_PATH)", dir)
		}
		dir = parent
	}
}

// RequireTestDB skips the test unless database tests are enabled, and fails it if the setup is broken.
func RequireTestDB(t testing.TB) {
	t.Helper()
	if !Enabled() {
		t.Skip("database test: set GUARDIAN_TEST_DB=1 and DB_NAME=<name>_test (plus DB_HOST/DB_PORT/DB_USER/DB_PASSWORD)")
	}
	if err := Setup(); err != nil {
		t.Fatalf("test database setup: %v", err)
	}
}

// Reset empties every table (except signing keys) and re-runs the schema script, which re-seeds the
// scopes, the guardian app, the admin role and the admin account. Call it first in each database test.
func Reset(t testing.TB) {
	t.Helper()
	RequireTestDB(t)
	conn := db.GetDatabaseConnection()
	rows, err := conn.Query(`SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename <> 'signing_key'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, pq.QuoteIdentifier(name))
	}
	rows.Close()
	if len(tables) > 0 {
		if _, err := conn.Exec(`TRUNCATE ` + strings.Join(tables, ", ") + ` CASCADE`); err != nil {
			t.Fatal(err)
		}
	}
	RunSchema(t)
}

// RunSchemaErr executes the schema script the way the application does at startup.
func RunSchemaErr() error {
	script, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := db.GetDatabaseConnection().Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, string(script)); err != nil {
		c.ExecContext(context.Background(), "ROLLBACK")
		return err
	}
	return nil
}

func RunSchema(t testing.TB) {
	t.Helper()
	if err := RunSchemaErr(); err != nil {
		t.Fatalf("schema script: %v", err)
	}
}

func DeleteSigningKeys() {
	db.GetDatabaseConnection().Exec(`DELETE FROM signing_key`)
}

// Exec runs raw SQL (to set up edge cases such as expired or revoked rows).
func Exec(t testing.TB, query string, args ...any) {
	t.Helper()
	if _, err := db.GetDatabaseConnection().Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// Count runs a `SELECT count(*)`-style query.
func Count(t testing.TB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.GetDatabaseConnection().QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func defaultHash() string {
	hashOnce.Do(func() {
		h, err := auth.HashPassword(DefaultPassword)
		if err != nil {
			panic(err)
		}
		hashVal = h
	})
	return hashVal
}

// CreateAccount makes an active account whose password is DefaultPassword.
func CreateAccount(t testing.TB, username string) db.Account {
	t.Helper()
	acct, err := db.CreateAccount(username, defaultHash())
	if err != nil {
		t.Fatalf("create account %s: %v", username, err)
	}
	return acct
}

type AppOptions struct {
	Public         bool
	FirstParty     bool // skips the consent screen
	RedirectURIs   []string
	PostLogoutURIs []string
	BackchannelURI string
	Scopes         []string
	TTLSeconds     int
}

// CreateApp registers an app and returns it with its plaintext client secret ("" for public apps).
// Defaults: confidential, redirect https://<name>.test/callback, scopes openid profile email offline_access.
func CreateApp(t testing.TB, name string, o AppOptions) (db.App, string) {
	t.Helper()
	if o.RedirectURIs == nil {
		o.RedirectURIs = []string{"https://" + name + ".test/callback"}
	}
	if o.PostLogoutURIs == nil {
		o.PostLogoutURIs = []string{"https://" + name + ".test/"}
	}
	if o.Scopes == nil {
		o.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	clientType, secret, secretHash := "confidential", "", ""
	if o.Public {
		clientType = "public"
	} else {
		s, err := auth.RandomToken(32)
		if err != nil {
			t.Fatal(err)
		}
		secret, secretHash = s, auth.HashToken(s)
	}
	app, err := db.AddApp(db.App{
		Name: name, PrettyName: "App " + name, Description: "test app", ClientType: clientType,
		RedirectURIs: o.RedirectURIs, PostLogoutRedirectURIs: o.PostLogoutURIs,
		BackchannelLogoutURI: o.BackchannelURI, IsFirstParty: o.FirstParty, AccessTokenTTL: o.TTLSeconds,
	}, o.Scopes, secretHash)
	if err != nil {
		t.Fatalf("create app %s: %v", name, err)
	}
	return app, secret
}

func RoleID(t testing.TB, name string) string {
	t.Helper()
	roles, err := db.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.Name == name {
			return r.ID
		}
	}
	t.Fatalf("role %q not found", name)
	return ""
}

// AdminAccount creates an account holding the built-in catchall admin role.
func AdminAccount(t testing.TB, username string) db.Account {
	t.Helper()
	acct := CreateAccount(t, username)
	if err := db.GrantRole(acct.ID, RoleID(t, "admin"), "", nil); err != nil {
		t.Fatal(err)
	}
	return acct
}

func Permission(t testing.TB, appID, name string) string {
	t.Helper()
	id, err := db.CreateAppPermission(appID, name, name, "test permission")
	if err != nil {
		t.Fatalf("create permission %s: %v", name, err)
	}
	return id
}

func Role(t testing.TB, name string, allPermissions bool, permissionIDs ...string) string {
	t.Helper()
	id, err := db.CreateRole(name, name, "test role", allPermissions, permissionIDs)
	if err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	return id
}

// Session creates an SSO session directly and returns it with the raw cookie value.
func Session(t testing.TB, accountID string) (db.Session, string) {
	t.Helper()
	cookie, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	s, err := db.CreateSession(accountID, auth.HashToken(cookie), "", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return s, cookie
}

// Token stores an opaque access token directly and returns the plaintext token. A negative ttl makes it
// already expired; an empty sessionID makes it session-less.
func Token(t testing.TB, app db.App, accountID, sessionID string, ttl time.Duration, scopes ...string) string {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveAccessToken(auth.HashToken(token), app.ID, accountID, sessionID, scopes, time.Now().Add(ttl)); err != nil {
		t.Fatal(err)
	}
	return token
}
