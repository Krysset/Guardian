-- =============================================================================
-- Guardian: account service with OIDC provider + per-app permissions
-- Target: PostgreSQL 13+ (gen_random_uuid() is built in)
--
-- Runs at EVERY startup. Rules:
--   * Only creates what is missing (IF NOT EXISTS). Never ALTERs or DROPs.
--     Changes to existing tables belong in migration scripts.
--   * Seed data is inserted only when its table is empty (first run), so rows
--     that were later edited or deleted are never recreated or overwritten.
--   * Whole script is one transaction behind an advisory lock, so several
--     instances starting at once don't race each other.
--
-- Conventions: TIMESTAMPTZ everywhere, secrets/tokens stored as hashes,
--              TEXT + CHECK instead of enums (easier to migrate).
-- =============================================================================

BEGIN;
SELECT pg_advisory_xact_lock(727274);   -- arbitrary constant, released at COMMIT

-- -----------------------------------------------------------------------------
-- ACCOUNTS
-- Doubles as the OIDC "subject": account.id is the stable `sub` claim.
-- Profile columns map 1:1 to OIDC standard claims so scope -> claim is trivial.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account (
	id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	username             TEXT NOT NULL,                 -- preferred_username
	password_hash        TEXT,                          -- argon2id; NULL = passwordless / federated only
	must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
	status               TEXT NOT NULL DEFAULT 'active'
	                     CHECK (status IN ('pending', 'active', 'disabled', 'locked')),

	-- Profile (OIDC scope: profile)
	display_name         TEXT,                          -- name
	given_name           TEXT,
	family_name          TEXT,
	picture_url          TEXT,                          -- picture
	locale               TEXT,                          -- e.g. 'sv-SE'
	zoneinfo             TEXT,                          -- e.g. 'Europe/Stockholm'
	birthdate            DATE,

	-- Email (OIDC scope: email)
	email                TEXT,
	email_verified_at    TIMESTAMPTZ,

	-- Phone (OIDC scope: phone) - store E.164
	phone_number         TEXT,
	phone_verified_at    TIMESTAMPTZ,

	created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- OIDC `updated_at`
	last_login_at        TIMESTAMPTZ,
	deleted_at           TIMESTAMPTZ                    -- soft delete / GDPR grace period
);
-- Case-insensitive uniqueness (no citext extension needed)
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_username ON account (lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_email    ON account (lower(email))  WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_phone    ON account (phone_number)  WHERE phone_number IS NOT NULL;

-- -----------------------------------------------------------------------------
-- APPS (= OIDC clients)
-- client_id replaces app_key as the public identifier. Secrets live in app_secret
-- so they can be rotated with overlap and are never stored in plaintext.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app (
	id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	name                        TEXT NOT NULL UNIQUE,   -- machine name, e.g. 'guardian'
	pretty_name                 TEXT NOT NULL,
	description                 TEXT NOT NULL,
	logo_url                    TEXT,
	homepage_url                TEXT,

	client_id                   UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
	client_type                 TEXT NOT NULL DEFAULT 'confidential'
	                            CHECK (client_type IN ('confidential', 'public')),   -- public = SPA/mobile (PKCE only)
	token_endpoint_auth_method  TEXT NOT NULL DEFAULT 'client_secret_basic'
	                            CHECK (token_endpoint_auth_method IN
	                                   ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none')),
	grant_types                 TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token'],
	redirect_uris               TEXT[] NOT NULL DEFAULT '{}',   -- exact match only
	post_logout_redirect_uris   TEXT[] NOT NULL DEFAULT '{}',
	backchannel_logout_uri      TEXT,
	jwks                        JSONB,                          -- for private_key_jwt auth

	require_pkce                BOOLEAN NOT NULL DEFAULT TRUE,
	is_first_party              BOOLEAN NOT NULL DEFAULT FALSE, -- skips the consent screen
	access_token_ttl_seconds    INT NOT NULL DEFAULT 900,
	refresh_token_ttl_seconds   INT NOT NULL DEFAULT 2592000,
	enabled                     BOOLEAN NOT NULL DEFAULT TRUE,
	created_at                  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Multiple active secrets per app => zero-downtime rotation. "Regenerate" = add new, revoke old later.
CREATE TABLE IF NOT EXISTS app_secret (
	id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	app_id       UUID NOT NULL REFERENCES app(id) ON DELETE CASCADE,
	secret_hash  TEXT NOT NULL,
	label        TEXT,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at   TIMESTAMPTZ,
	revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_app_secret_app ON app_secret (app_id);

-- -----------------------------------------------------------------------------
-- OIDC SCOPES  (what an app may *ask to know* about / do on behalf of a user)
-- Standard scopes: openid, profile, email, phone, address, offline_access.
-- Custom scopes belong to an app (app_id set), e.g. 'photos:read'.
-- `claims` lists the claims released by the scope.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scope (
	name         TEXT PRIMARY KEY,
	app_id       UUID REFERENCES app(id) ON DELETE CASCADE,   -- NULL = standard / global
	description  TEXT NOT NULL,                               -- shown on the consent screen
	claims       TEXT[] NOT NULL DEFAULT '{}'
);

-- Which scopes each app is *allowed* to request (replaces old app_permission semantics)
CREATE TABLE IF NOT EXISTS app_scope (
	app_id      UUID NOT NULL REFERENCES app(id)    ON DELETE CASCADE,
	scope_name  TEXT NOT NULL REFERENCES scope(name) ON DELETE CASCADE,
	PRIMARY KEY (app_id, scope_name)
);

-- What a user has actually agreed to share with an app
CREATE TABLE IF NOT EXISTS account_consent (
	account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	app_id      UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	scopes      TEXT[] NOT NULL,
	granted_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at  TIMESTAMPTZ,
	PRIMARY KEY (account_id, app_id)
);

-- -----------------------------------------------------------------------------
-- AUTHORIZATION: per-app permissions, cross-app roles, and per-account grants
-- Permission names are opaque to Guardian; the app decides what they mean.
-- `attributes` on a grant carries app-specific parameters (limits, resource ids, ...).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_permission (
	id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	app_id       UUID NOT NULL REFERENCES app(id) ON DELETE CASCADE,
	name         TEXT NOT NULL,                 -- e.g. 'invoices.approve'
	pretty_name  TEXT NOT NULL,
	description  TEXT NOT NULL,
	UNIQUE (app_id, name)
);

-- Roles: named, reassignable sets of permissions. A role is NOT tied to one app;
-- it can bundle permissions from any number of apps (e.g. 'support' = read access
-- in app A + refund permission in app B).
-- all_permissions = catchall: the role implicitly holds EVERY permission of EVERY
-- app, including apps/permissions created later, with no role_permission rows needed.
CREATE TABLE IF NOT EXISTS role (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	name             TEXT NOT NULL UNIQUE,
	pretty_name      TEXT NOT NULL,
	description      TEXT NOT NULL,
	all_permissions  BOOLEAN NOT NULL DEFAULT FALSE,
	is_system        BOOLEAN NOT NULL DEFAULT FALSE,    -- built-in; the app should refuse to delete/rename it
	created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_permission (
	role_id        UUID NOT NULL REFERENCES role(id)           ON DELETE CASCADE,
	permission_id  UUID NOT NULL REFERENCES app_permission(id) ON DELETE CASCADE,
	PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS account_role (
	account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	role_id     UUID NOT NULL REFERENCES role(id)    ON DELETE CASCADE,
	granted_by  UUID REFERENCES account(id) ON DELETE SET NULL,
	granted_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at  TIMESTAMPTZ,
	PRIMARY KEY (account_id, role_id)
);
CREATE INDEX IF NOT EXISTS ix_role_permission_perm ON role_permission (permission_id);

-- Direct grants (for one-off permissions that don't belong in a role)
CREATE TABLE IF NOT EXISTS account_app_permission (
	account_id     UUID NOT NULL REFERENCES account(id)        ON DELETE CASCADE,
	permission_id  UUID NOT NULL REFERENCES app_permission(id) ON DELETE CASCADE,
	attributes     JSONB NOT NULL DEFAULT '{}',
	granted_by     UUID REFERENCES account(id) ON DELETE SET NULL,
	granted_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at     TIMESTAMPTZ,
	PRIMARY KEY (account_id, permission_id)
);

-- -----------------------------------------------------------------------------
-- SESSIONS & OIDC TOKEN STATE
-- -----------------------------------------------------------------------------
-- SSO session (the cookie on Guardian's own domain)
CREATE TABLE IF NOT EXISTS session (
	id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	session_hash      TEXT NOT NULL UNIQUE,
	account_id        UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	auth_time         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,   -- OIDC auth_time
	amr               TEXT[] NOT NULL DEFAULT ARRAY['pwd'],             -- OIDC amr, e.g. {pwd,otp}
	ip_address        INET,
	user_agent        TEXT,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at        TIMESTAMPTZ NOT NULL,
	revoked_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_session_account ON session (account_id);

-- Short-lived (~60s), single use
CREATE TABLE IF NOT EXISTS authorization_code (
	code_hash              TEXT PRIMARY KEY,
	app_id                 UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	account_id             UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	session_id             UUID REFERENCES session(id) ON DELETE CASCADE,
	redirect_uri           TEXT NOT NULL,
	scopes                 TEXT[] NOT NULL,
	nonce                  TEXT,
	code_challenge         TEXT,
	code_challenge_method  TEXT CHECK (code_challenge_method IN ('S256')),
	auth_time              TIMESTAMPTZ NOT NULL,
	expires_at             TIMESTAMPTZ NOT NULL,
	used_at                TIMESTAMPTZ
);

-- Rotating refresh tokens. If a rotated token is reused, revoke the whole family.
CREATE TABLE IF NOT EXISTS refresh_token (
	id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	token_hash  TEXT NOT NULL UNIQUE,
	family_id   UUID NOT NULL,
	app_id      UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	session_id  UUID REFERENCES session(id) ON DELETE SET NULL,
	scopes      TEXT[] NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at  TIMESTAMPTZ NOT NULL,
	rotated_at  TIMESTAMPTZ,
	revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_refresh_family  ON refresh_token (family_id);
CREATE INDEX IF NOT EXISTS ix_refresh_account ON refresh_token (account_id);

-- Opaque access tokens. Only the hash is stored. A token is valid only while this row is live AND its
-- account is active AND its session is not revoked, so logout / disable / app-disable kill tokens at once.
CREATE TABLE IF NOT EXISTS access_token (
	id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	token_hash  TEXT NOT NULL UNIQUE,
	app_id      UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	session_id  UUID REFERENCES session(id) ON DELETE CASCADE,
	scopes      TEXT[] NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at  TIMESTAMPTZ NOT NULL,
	revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_access_token_session ON access_token (session_id);
CREATE INDEX IF NOT EXISTS ix_access_token_expires ON access_token (expires_at);

-- Fixed-window counters for rate limiting (login attempts, sign-ups). UNLOGGED = no WAL, much cheaper,
-- and losing the counters in a database crash is harmless. Shared by all Guardian replicas.
CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit (
	key           TEXT NOT NULL,
	window_start  TIMESTAMPTZ NOT NULL,
	hits          INT NOT NULL DEFAULT 0,
	PRIMARY KEY (key, window_start)
);

-- Apps that received tokens under an SSO session. Used to fan out back-channel logout.
CREATE TABLE IF NOT EXISTS session_app (
	session_id     UUID NOT NULL REFERENCES session(id) ON DELETE CASCADE,
	app_id         UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (session_id, app_id)
);

-- Keys for signing ID/access tokens; public half is served at /jwks.json
CREATE TABLE IF NOT EXISTS signing_key (
	kid                    TEXT PRIMARY KEY,
	alg                    TEXT NOT NULL DEFAULT 'RS256',
	public_jwk             JSONB NOT NULL,
	private_key_encrypted  TEXT NOT NULL,              -- encrypt with a KMS/env key, never plaintext
	status                 TEXT NOT NULL DEFAULT 'active'
	                       CHECK (status IN ('active', 'retiring', 'retired')),  -- retiring = still published, no longer signs
	created_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	retire_at              TIMESTAMPTZ
);

-- -----------------------------------------------------------------------------
-- ONE-TIME TOKENS (replaces password_reset_code + account_access_token)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account_token (
	id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	purpose     TEXT NOT NULL
	            CHECK (purpose IN ('password_reset', 'email_verify', 'phone_verify', 'reauth', 'invite')),
	token_hash  TEXT NOT NULL,
	metadata    JSONB NOT NULL DEFAULT '{}',          -- e.g. the new email being verified
	created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at  TIMESTAMPTZ NOT NULL,
	used_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_account_token_lookup ON account_token (token_hash);

-- -----------------------------------------------------------------------------
-- MFA
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account_mfa (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	account_id     UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	type           TEXT NOT NULL CHECK (type IN ('totp', 'webauthn', 'recovery_code')),
	name           TEXT,                                -- "YubiKey", "Phone"
	secret         TEXT,                                -- encrypted TOTP secret, or hashed recovery code
	credential_id  BYTEA,                               -- webauthn
	public_key     BYTEA,                               -- webauthn
	sign_count     BIGINT,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_used_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_account_mfa_account ON account_mfa (account_id);

-- -----------------------------------------------------------------------------
-- AUDIT LOG (append-only)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
	id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	occurred_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	event_type        TEXT NOT NULL,                    -- 'login.success', 'login.failure', 'permission.granted', ...
	actor_account_id  UUID,                             -- no FK on purpose: logs outlive accounts
	actor_app_id      UUID,
	target_type       TEXT,
	target_id         TEXT,
	ip_address        INET,
	metadata          JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit_log (actor_account_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_event ON audit_log (event_type, occurred_at DESC);

-- =============================================================================
-- EFFECTIVE PERMISSIONS: the single definition of "what may this account do".
-- Combines catchall roles, role permissions and direct grants, and ignores expired grants.
-- It is a plain view (no caching): every read sees the latest committed state, so a revoke is
-- effective for the very next query on every replica. Created only if missing; later changes
-- to the view belong in a migration.
-- =============================================================================
DO $$
BEGIN
	IF to_regclass('account_effective_permission') IS NULL THEN
		CREATE VIEW account_effective_permission AS
			SELECT ar.account_id, p.id AS permission_id, p.app_id, p.name
			FROM account_role ar
			JOIN role r ON r.id = ar.role_id AND r.all_permissions
			CROSS JOIN app_permission p
			WHERE ar.expires_at IS NULL OR ar.expires_at > now()
			UNION
			SELECT ar.account_id, p.id, p.app_id, p.name
			FROM account_role ar
			JOIN role_permission rp ON rp.role_id = ar.role_id
			JOIN app_permission p ON p.id = rp.permission_id
			WHERE ar.expires_at IS NULL OR ar.expires_at > now()
			UNION
			SELECT g.account_id, p.id, p.app_id, p.name
			FROM account_app_permission g
			JOIN app_permission p ON p.id = g.permission_id
			WHERE g.expires_at IS NULL OR g.expires_at > now();
	END IF;
END $$;

-- =============================================================================
-- SEED DATA - each block runs only if its table is empty.
-- The admin's password is NOT set here (SQL can't produce your app's hash and we
-- don't ship default passwords). The admin is created with password_hash NULL
-- and must_change_password = TRUE; the app must set an initial password on
-- startup when it finds an account without one (e.g. from an env var, or a
-- random one logged once). Until then the account cannot log in.
-- =============================================================================

-- Standard OIDC scopes
DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM scope) THEN
		INSERT INTO scope (name, description, claims) VALUES
			('openid',         'Verify your identity',                    ARRAY['sub']),
			('profile',        'Your name, username and profile picture', ARRAY['name','given_name','family_name','preferred_username','picture','locale','zoneinfo','birthdate','updated_at']),
			('email',          'Your email address',                      ARRAY['email','email_verified']),
			('phone',          'Your phone number',                       ARRAY['phone_number','phone_number_verified']),
			('offline_access', 'Stay signed in / access when you are away', ARRAY[]::TEXT[]);
	END IF;
END $$;

-- Guardian app, its permissions and allowed scopes
-- TODO: tighten guardian's scopes to only what it needs
DO $$
DECLARE
	v_app_id UUID;
BEGIN
	IF NOT EXISTS (SELECT 1 FROM app) THEN
		INSERT INTO app (name, pretty_name, description, is_first_party)
		VALUES ('guardian', 'Guardian', 'Service for managing accounts and app permissions', TRUE)
		RETURNING id INTO v_app_id;

		INSERT INTO app_permission (app_id, name, pretty_name, description) VALUES
			(v_app_id, 'accounts.read',      'Read accounts',      'View accounts and their profiles'),
			(v_app_id, 'accounts.write',     'Manage accounts',    'Create, edit, disable and delete accounts'),
			(v_app_id, 'apps.manage',        'Manage apps',        'Create apps, rotate secrets, edit redirect URIs'),
			(v_app_id, 'permissions.manage', 'Manage permissions', 'Define permissions/roles and grant them to accounts');

		INSERT INTO app_scope (app_id, scope_name)
		SELECT v_app_id, name FROM scope WHERE app_id IS NULL;
	END IF;
END $$;

-- Built-in admin role: catchall, holds every permission of every app (no role_permission rows)
DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM role) THEN
		INSERT INTO role (name, pretty_name, description, all_permissions, is_system)
		VALUES ('admin', 'Administrator', 'Holds all permissions in all apps', TRUE, TRUE);
	END IF;
END $$;

-- Initial admin account (no password yet, see note above) with the admin role
DO $$
DECLARE
	v_account_id UUID;
	v_role_id    UUID;
BEGIN
	IF NOT EXISTS (SELECT 1 FROM account) THEN
		SELECT id INTO v_role_id FROM role WHERE name = 'admin';

		INSERT INTO account (username, display_name, must_change_password)
		VALUES ('admin', 'Admin', TRUE)
		RETURNING id INTO v_account_id;

		IF v_role_id IS NOT NULL THEN
			INSERT INTO account_role (account_id, role_id) VALUES (v_account_id, v_role_id);
		END IF;
	END IF;
END $$;

COMMIT;
