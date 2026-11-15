// Package config reads Guardian's configuration from environment variables, in one place, and validates it
// before anything else starts. Load reports every problem at once, so a broken deployment shows the whole
// list instead of failing on one variable at a time.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is everything Guardian needs to start.
type Config struct {
	// PublicAddr serves browsers and apps (sign-in pages, OIDC endpoints, /api/v1). It sits behind the ingress.
	PublicAddr string
	// InternalAddr serves /metrics, /healthz and /readyz. It must only be reachable in the cluster.
	InternalAddr string

	// IssuerURL is the public base URL of Guardian as browsers see it, without a trailing slash.
	// https:// turns on Secure and __Host- cookies.
	IssuerURL string
	// AllowedOrigins are extra browser origins allowed to send state-changing requests to /api.
	// IssuerURL is always allowed.
	AllowedOrigins []string
	// TrustedProxyHops is how many reverse proxies in front of Guardian append to X-Forwarded-For.
	// 0 ignores the header.
	TrustedProxyHops int
	// SessionIdleTimeout ends a sign-in session that has not been used for this long. Using Guardian's
	// pages or refreshing an app's tokens counts as use.
	SessionIdleTimeout time.Duration
	// SessionMaxLifetime ends a sign-in session this long after sign-in, however active it is.
	SessionMaxLifetime time.Duration

	// KeyEncryptionKey is the 32-byte AES key that encrypts signing keys at rest.
	KeyEncryptionKey []byte
	// AdminInitialPassword sets the seeded admin's first password. Empty means: generate one and log it once.
	AdminInitialPassword string

	DB  Database
	Log Log
}

// Database is how to reach PostgreSQL.
type Database struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLMode  string
	// MaxConns bounds the connection pool of this process. Replicas times MaxConns must stay below
	// Postgres max_connections.
	MaxConns int
}

// Log controls log output.
type Log struct {
	// Format is "json" (default) or "text".
	Format string
	// Level is "debug", "info" (default), "warn" or "error".
	Level string
}

// DSN returns the connection string in libpq keyword/value form, which the pgx driver accepts.
func (d Database) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		quoteDSN(d.Host), d.Port, quoteDSN(d.User), quoteDSN(d.Password), quoteDSN(d.Name), d.SSLMode)
}

// quoteDSN quotes a value for a key=value connection string, so spaces and quotes in a password are safe.
func quoteDSN(v string) string {
	if v != "" && !strings.ContainsAny(v, ` '\`) {
		return v
	}
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// Load reads and validates the whole configuration. On failure the error lists every problem found.
// The returned Config always has usable Log settings, so the caller can report the error in the right format.
func Load() (Config, error) {
	var problems []error
	fail := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }

	cfg := Config{
		PublicAddr:           envOr("PUBLIC_ADDR", ":3001"),
		InternalAddr:         envOr("INTERNAL_ADDR", ":3002"),
		AdminInitialPassword: os.Getenv("ADMIN_INITIAL_PASSWORD"),
		SessionIdleTimeout:   7 * 24 * time.Hour,
		SessionMaxLifetime:   30 * 24 * time.Hour,
	}

	var err error
	if cfg.Log, err = loadLog(); err != nil {
		problems = append(problems, err)
	}
	if cfg.DB, err = LoadDatabase(); err != nil {
		problems = append(problems, err)
	}

	cfg.IssuerURL = strings.TrimRight(os.Getenv("ISSUER_URL"), "/")
	switch u, err := url.Parse(cfg.IssuerURL); {
	case cfg.IssuerURL == "":
		fail("ISSUER_URL is not set (for example https://auth.example.com, or http://localhost:3001 for development)")
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		fail("ISSUER_URL must be an http:// or https:// URL, got %q", cfg.IssuerURL)
	case u.RawQuery != "" || u.Fragment != "":
		fail("ISSUER_URL must not contain a query or a fragment, got %q", cfg.IssuerURL)
	}

	for _, o := range strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			cfg.AllowedOrigins = append(cfg.AllowedOrigins, o)
		}
	}

	duration := func(key string, into *time.Duration) {
		if v := os.Getenv(key); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				fail("%s must be a positive Go duration such as 168h, got %q", key, v)
			} else {
				*into = d
			}
		}
	}
	duration("SESSION_IDLE_TIMEOUT", &cfg.SessionIdleTimeout)
	duration("SESSION_MAX_LIFETIME", &cfg.SessionMaxLifetime)
	if cfg.SessionIdleTimeout > cfg.SessionMaxLifetime {
		fail("SESSION_IDLE_TIMEOUT (%s) must not be longer than SESSION_MAX_LIFETIME (%s)", cfg.SessionIdleTimeout, cfg.SessionMaxLifetime)
	}

	if v := os.Getenv("TRUSTED_PROXY_HOPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			fail("TRUSTED_PROXY_HOPS must be a non-negative whole number, got %q", v)
		} else {
			cfg.TrustedProxyHops = n
		}
	}

	if cfg.KeyEncryptionKey, err = ParseEncryptionKey(os.Getenv("KEY_ENCRYPTION_KEY")); err != nil {
		problems = append(problems, err)
	}

	return cfg, errors.Join(problems...)
}

// LoadDatabase reads and validates only the database settings. Tests use it to connect without the rest
// of the configuration.
func LoadDatabase() (Database, error) {
	var problems []error
	fail := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }

	d := Database{
		Host:     os.Getenv("DB_HOST"),
		Port:     5432,
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		Name:     os.Getenv("DB_NAME"),
		SSLMode:  envOr("DB_SSLMODE", "disable"),
		MaxConns: 20,
	}
	for key, value := range map[string]string{"DB_HOST": d.Host, "DB_USER": d.User, "DB_NAME": d.Name} {
		if value == "" {
			fail("%s is not set", key)
		}
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			fail("DB_PORT must be a port number between 1 and 65535, got %q", v)
		} else {
			d.Port = n
		}
	}
	switch d.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		fail("DB_SSLMODE must be one of disable, allow, prefer, require, verify-ca or verify-full, got %q", d.SSLMode)
	}
	if v := os.Getenv("DB_MAX_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			fail("DB_MAX_CONNS must be a positive whole number, got %q", v)
		} else {
			d.MaxConns = n
		}
	}
	return d, errors.Join(problems...)
}

// ParseEncryptionKey decodes KEY_ENCRYPTION_KEY: 32 bytes, base64 encoded.
func ParseEncryptionKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("KEY_ENCRYPTION_KEY is not set (generate one with: openssl rand -base64 32)")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("KEY_ENCRYPTION_KEY must be 32 bytes, base64 encoded (generate one with: openssl rand -base64 32)")
	}
	return key, nil
}

func loadLog() (Log, error) {
	l := Log{Format: strings.ToLower(envOr("LOG_FORMAT", "json")), Level: strings.ToLower(envOr("LOG_LEVEL", "info"))}
	var problems []error
	if l.Format != "json" && l.Format != "text" {
		problems = append(problems, fmt.Errorf("LOG_FORMAT must be json or text, got %q", l.Format))
		l.Format = "json"
	}
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, fmt.Errorf("LOG_LEVEL must be debug, info, warn or error, got %q", l.Level))
		l.Level = "info"
	}
	return l, errors.Join(problems...)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
