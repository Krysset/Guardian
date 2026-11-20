// Package config reads Guardian's configuration from environment variables, in one place, and validates it
// before anything else starts. Load reports every problem at once, so a broken deployment shows the whole
// list instead of failing on one variable at a time.
package config

import (
	"errors"
	"fmt"
	"net/mail"
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
	// DeletionGrace is how long a deleted account waits before it is erased; an administrator can restore
	// it until then.
	DeletionGrace time.Duration

	// HelpURL and PrivacyURL are the Help and Privacy links in the footer of the sign-in pages.
	// Each link is left out when its address is empty.
	HelpURL    string
	PrivacyURL string

	// Keyring is the text of the encryption keyring ("k2:<base64>,k1:<base64>"), from KEY_ENCRYPTION_KEYS_FILE
	// or KEY_ENCRYPTION_KEYS. The auth package parses it (auth.ParseKeyring).
	Keyring string
	// KeyringFile is KEY_ENCRYPTION_KEYS_FILE; Guardian reloads it every minute. Empty when the keyring
	// came from KEY_ENCRYPTION_KEYS, which cannot change while Guardian runs.
	KeyringFile string
	// SigningKeyLifetime is how long a signing key signs before the next one takes over.
	SigningKeyLifetime time.Duration
	// AdminInitialPassword sets the seeded admin's first password. Empty means: generate one and log it once.
	AdminInitialPassword string

	DB   Database
	Log  Log
	Mail Mail
}

// Mail is how Guardian sends email. Without SMTP_HOST, email is off: sign-up has no email field and only
// an administrator can reset a forgotten password.
type Mail struct {
	Host     string // SMTP_HOST
	Port     int    // SMTP_PORT, default 587
	Username string // SMTP_USERNAME; empty means no authentication
	Password string // SMTP_PASSWORD
	// Security is starttls (default), tls or none (only for a local mail catcher).
	Security string // SMTP_SECURITY
	// From is the sender, such as "Hyrule Guardian <no-reply@auth.example.com>". Its name is also the name
	// the emails use for this Guardian.
	From *mail.Address // MAIL_FROM
	// RequireEmail makes an email address mandatory at sign-up.
	RequireEmail bool // REQUIRE_EMAIL
}

// Enabled reports whether email is configured.
func (m Mail) Enabled() bool { return m.Host != "" }

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
		DeletionGrace:        30 * 24 * time.Hour,
		SigningKeyLifetime:   90 * 24 * time.Hour,
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

	for _, s := range []struct {
		key  string
		into *string
	}{{"HELP_URL", &cfg.HelpURL}, {"PRIVACY_URL", &cfg.PrivacyURL}} {
		key, into := s.key, s.into
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			continue
		}
		if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			fail("%s must be an http:// or https:// URL, got %q", key, v)
			continue
		}
		*into = v
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
	duration("DELETION_GRACE_PERIOD", &cfg.DeletionGrace)
	duration("SIGNING_KEY_LIFETIME", &cfg.SigningKeyLifetime)
	if cfg.SigningKeyLifetime < 24*time.Hour {
		fail("SIGNING_KEY_LIFETIME must be at least 24h, got %s", cfg.SigningKeyLifetime)
	}
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

	if cfg.Mail, err = loadMail(); err != nil {
		problems = append(problems, err)
	}

	cfg.KeyringFile = strings.TrimSpace(os.Getenv("KEY_ENCRYPTION_KEYS_FILE"))
	inline := os.Getenv("KEY_ENCRYPTION_KEYS")
	switch {
	case cfg.KeyringFile != "" && inline != "":
		fail("set KEY_ENCRYPTION_KEYS_FILE or KEY_ENCRYPTION_KEYS, not both")
	case cfg.KeyringFile != "":
		if b, err := os.ReadFile(cfg.KeyringFile); err != nil {
			fail("KEY_ENCRYPTION_KEYS_FILE: %v", err)
		} else {
			cfg.Keyring = string(b)
		}
	case inline != "":
		cfg.Keyring = inline
	case os.Getenv("KEY_ENCRYPTION_KEY") != "":
		fail("KEY_ENCRYPTION_KEY was replaced by the keyring: set KEY_ENCRYPTION_KEYS=k1:<the same base64 key>")
	default:
		fail("KEY_ENCRYPTION_KEYS_FILE or KEY_ENCRYPTION_KEYS is not set (a keyring such as k1:<base64>; generate the key with: openssl rand -base64 32)")
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

func loadMail() (Mail, error) {
	var problems []error
	fail := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }
	m := Mail{
		Host:     strings.TrimSpace(os.Getenv("SMTP_HOST")),
		Port:     587,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		Security: strings.ToLower(envOr("SMTP_SECURITY", "starttls")),
	}
	switch v := strings.ToLower(os.Getenv("REQUIRE_EMAIL")); v {
	case "", "false", "0", "no":
	case "true", "1", "yes":
		m.RequireEmail = true
	default:
		fail("REQUIRE_EMAIL must be true or false, got %q", v)
	}
	if m.Host == "" {
		if m.RequireEmail {
			fail("REQUIRE_EMAIL needs email: set SMTP_HOST and MAIL_FROM")
		}
		return m, errors.Join(problems...)
	}
	if v := os.Getenv("SMTP_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			fail("SMTP_PORT must be a port number between 1 and 65535, got %q", v)
		} else {
			m.Port = n
		}
	}
	switch m.Security {
	case "starttls", "tls", "none":
	default:
		fail("SMTP_SECURITY must be starttls, tls or none, got %q", m.Security)
	}
	if v := os.Getenv("MAIL_FROM"); v == "" {
		fail("MAIL_FROM is not set (the sender of Guardian's emails, such as \"Guardian <no-reply@auth.example.com>\")")
	} else if a, err := mail.ParseAddress(v); err != nil {
		fail("MAIL_FROM must be an email address, optionally with a name, got %q", v)
	} else {
		m.From = a
	}
	return m, errors.Join(problems...)
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
