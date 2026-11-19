package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var validKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

// setValid sets the smallest configuration that Load accepts and clears every optional variable.
func setValid(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"DB_HOST": "db", "DB_USER": "guardian", "DB_NAME": "guardian", "DB_PASSWORD": "",
		"DB_PORT": "", "DB_SSLMODE": "", "DB_MAX_CONNS": "",
		"ISSUER_URL": "https://auth.example.com", "KEY_ENCRYPTION_KEY": validKey,
		"PUBLIC_ADDR": "", "INTERNAL_ADDR": "", "ALLOWED_ORIGINS": "",
		"SESSION_IDLE_TIMEOUT": "", "SESSION_MAX_LIFETIME": "",
		"TRUSTED_PROXY_HOPS": "", "ADMIN_INITIAL_PASSWORD": "",
		"LOG_FORMAT": "", "LOG_LEVEL": "",
		"SMTP_HOST": "", "SMTP_PORT": "", "SMTP_USERNAME": "", "SMTP_PASSWORD": "", "SMTP_SECURITY": "",
		"MAIL_FROM": "", "REQUIRE_EMAIL": "",
	} {
		t.Setenv(k, v)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	setValid(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PublicAddr != ":3001" || cfg.InternalAddr != ":3002" {
		t.Errorf("addresses = %q, %q", cfg.PublicAddr, cfg.InternalAddr)
	}
	if cfg.SessionIdleTimeout != 7*24*time.Hour || cfg.SessionMaxLifetime != 30*24*time.Hour || cfg.TrustedProxyHops != 0 {
		t.Errorf("session idle = %v, max = %v, hops = %d", cfg.SessionIdleTimeout, cfg.SessionMaxLifetime, cfg.TrustedProxyHops)
	}
	if cfg.DB.Port != 5432 || cfg.DB.SSLMode != "disable" || cfg.DB.MaxConns != 20 {
		t.Errorf("db = %+v", cfg.DB)
	}
	if cfg.Log.Format != "json" || cfg.Log.Level != "info" {
		t.Errorf("log = %+v", cfg.Log)
	}
	if len(cfg.KeyEncryptionKey) != 32 {
		t.Errorf("key length = %d", len(cfg.KeyEncryptionKey))
	}
}

func TestLoadReadsEveryVariable(t *testing.T) {
	setValid(t)
	for k, v := range map[string]string{
		"PUBLIC_ADDR": ":8080", "INTERNAL_ADDR": ":8081", "ISSUER_URL": "https://auth.example.com/",
		"ALLOWED_ORIGINS":      " https://a.example/ , ,https://b.example",
		"SESSION_IDLE_TIMEOUT": "2h", "SESSION_MAX_LIFETIME": "12h", "TRUSTED_PROXY_HOPS": "2", "ADMIN_INITIAL_PASSWORD": "pw",
		"DB_PORT": "6543", "DB_SSLMODE": "require", "DB_MAX_CONNS": "5", "DB_PASSWORD": "secret",
		"LOG_FORMAT": "TEXT", "LOG_LEVEL": "Debug",
		"HELP_URL": "https://example.com/help", "PRIVACY_URL": " https://example.com/privacy ",
	} {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.IssuerURL != "https://auth.example.com" {
		t.Errorf("issuer = %q, the trailing slash must be removed", cfg.IssuerURL)
	}
	if got := strings.Join(cfg.AllowedOrigins, "|"); got != "https://a.example|https://b.example" {
		t.Errorf("origins = %q", got)
	}
	if cfg.PublicAddr != ":8080" || cfg.InternalAddr != ":8081" || cfg.SessionIdleTimeout != 2*time.Hour ||
		cfg.SessionMaxLifetime != 12*time.Hour || cfg.TrustedProxyHops != 2 || cfg.AdminInitialPassword != "pw" {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.DB.Port != 6543 || cfg.DB.SSLMode != "require" || cfg.DB.MaxConns != 5 || cfg.DB.Password != "secret" {
		t.Errorf("db = %+v", cfg.DB)
	}
	if cfg.Log.Format != "text" || cfg.Log.Level != "debug" {
		t.Errorf("log = %+v", cfg.Log)
	}
	if cfg.HelpURL != "https://example.com/help" || cfg.PrivacyURL != "https://example.com/privacy" {
		t.Errorf("footer links = %q, %q", cfg.HelpURL, cfg.PrivacyURL)
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	setValid(t)
	for k, v := range map[string]string{
		"DB_HOST": "", "DB_PORT": "abc", "DB_SSLMODE": "maybe", "DB_MAX_CONNS": "0",
		"ISSUER_URL": "", "KEY_ENCRYPTION_KEY": "", "SESSION_IDLE_TIMEOUT": "soon", "SESSION_MAX_LIFETIME": "-1h",
		"TRUSTED_PROXY_HOPS": "-1", "LOG_FORMAT": "xml", "LOG_LEVEL": "loud",
		"HELP_URL": "javascript:alert(1)", "PRIVACY_URL": "/privacy",
	} {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err == nil {
		t.Fatal("Load accepted a broken configuration")
	}
	for _, name := range []string{"DB_HOST", "DB_PORT", "DB_SSLMODE", "DB_MAX_CONNS", "ISSUER_URL",
		"KEY_ENCRYPTION_KEY", "SESSION_IDLE_TIMEOUT", "SESSION_MAX_LIFETIME",
		"TRUSTED_PROXY_HOPS", "LOG_FORMAT", "LOG_LEVEL", "HELP_URL", "PRIVACY_URL"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not mention %s:\n%v", name, err)
		}
	}
	if cfg.Log.Format != "json" || cfg.Log.Level != "info" {
		t.Errorf("log settings must stay usable when invalid, got %+v", cfg.Log)
	}
}

func TestIdleTimeoutCannotExceedTheMaximumLifetime(t *testing.T) {
	setValid(t)
	t.Setenv("SESSION_IDLE_TIMEOUT", "48h")
	t.Setenv("SESSION_MAX_LIFETIME", "24h")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must not be longer") {
		t.Errorf("idle longer than the maximum: %v", err)
	}
	t.Setenv("SESSION_IDLE_TIMEOUT", "24h")
	if _, err := Load(); err != nil {
		t.Errorf("idle equal to the maximum must be accepted: %v", err)
	}
}

func TestIssuerURLMustBeAPlainHTTPURL(t *testing.T) {
	for _, bad := range []string{"auth.example.com", "ftp://auth.example.com", "https://", "https://a.example?x=1", "https://a.example#f"} {
		setValid(t)
		t.Setenv("ISSUER_URL", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ISSUER_URL") {
			t.Errorf("ISSUER_URL=%q: err = %v, want an ISSUER_URL error", bad, err)
		}
	}
	for _, good := range []string{"http://localhost:3001", "https://example.com/auth"} {
		setValid(t)
		t.Setenv("ISSUER_URL", good)
		if _, err := Load(); err != nil {
			t.Errorf("ISSUER_URL=%q: %v", good, err)
		}
	}
}

func TestParseEncryptionKey(t *testing.T) {
	if key, err := ParseEncryptionKey(validKey); err != nil || len(key) != 32 {
		t.Fatalf("valid key: len %d, err %v", len(key), err)
	}
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	for name, raw := range map[string]string{"empty": "", "not base64": "%%%", "16 bytes": short} {
		if _, err := ParseEncryptionKey(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDSNQuotesAwkwardValues(t *testing.T) {
	d := Database{Host: "db", Port: 5432, User: "guardian", Password: `p w'd\`, Name: "guardian", SSLMode: "disable"}
	want := `host=db port=5432 user=guardian password='p w\'d\\' dbname=guardian sslmode=disable`
	if got := d.DSN(); got != want {
		t.Errorf("DSN = %s\nwant  %s", got, want)
	}
	d.Password = ""
	if got := d.DSN(); !strings.Contains(got, "password='' ") {
		t.Errorf("an empty password must be quoted, got %s", got)
	}
}

func TestMailIsOffWithoutAHostAndCheckedWithOne(t *testing.T) {
	setValid(t)
	cfg, err := Load()
	if err != nil || cfg.Mail.Enabled() {
		t.Fatalf("mail without SMTP_HOST: enabled=%v, err=%v", cfg.Mail.Enabled(), err)
	}

	t.Setenv("REQUIRE_EMAIL", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REQUIRE_EMAIL needs email") {
		t.Errorf("REQUIRE_EMAIL without mail: %v", err)
	}

	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("MAIL_FROM", "Hyrule Guardian <no-reply@auth.example.com>")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Mail
	if !m.Enabled() || !m.RequireEmail || m.Port != 587 || m.Security != "starttls" || m.From.Name != "Hyrule Guardian" ||
		m.From.Address != "no-reply@auth.example.com" {
		t.Errorf("mail = %+v", m)
	}

	t.Setenv("SMTP_PORT", "70000")
	t.Setenv("SMTP_SECURITY", "ssl")
	t.Setenv("MAIL_FROM", "not an address")
	t.Setenv("REQUIRE_EMAIL", "maybe")
	_, err = Load()
	for _, want := range []string{"SMTP_PORT", "SMTP_SECURITY", "MAIL_FROM", "REQUIRE_EMAIL"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("no complaint about %s: %v", want, err)
		}
	}
}
