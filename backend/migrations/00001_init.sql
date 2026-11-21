-- =============================================================================
-- Guardian: account service with OIDC provider + groups
-- Target: PostgreSQL 13+ (gen_random_uuid() is built in)
--
-- This is migration 1. goose runs it once per database, inside a transaction, and records it in
-- goose_db_version. Until Guardian 1.0 this file is still edited in place: a database that already ran
-- it does not pick up later edits, so recreate development databases after a schema change. Guardian
-- notices the difference at startup and says so (see SCHEMA REVISION below).
--
-- Rules:
--   * Only creates what is missing (IF NOT EXISTS). Never ALTERs or DROPs. That keeps it safe on a
--     database that was created before goose was introduced, and lets the tests run it repeatedly.
--   * Seed data is inserted only when its table is empty, so rows that were later edited or deleted
--     are never recreated or overwritten.
--   * It takes a transaction-level advisory lock, so two runs at the same time do not race.
--
-- Conventions: TIMESTAMPTZ everywhere, secrets/tokens stored as hashes,
--              TEXT + CHECK instead of enums (easier to migrate).
-- =============================================================================

-- +goose Up
-- +goose StatementBegin
SELECT pg_advisory_xact_lock(727274);   -- arbitrary constant, released when the transaction ends

-- -----------------------------------------------------------------------------
-- SCHEMA REVISION
-- Remembers which revision of this file created the database. Guardian fills in the placeholder below
-- before it runs the script, and at every start compares the stored value with the file it ships with.
-- A database made by another revision is refused with an explanation, instead of failing on a missing
-- table later. The row is only written into a database that has no Guardian tables yet, so running the
-- script again on an existing database can never mark it as current.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_revision (
	fingerprint  TEXT NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO schema_revision (fingerprint)
SELECT '@@INIT_FINGERPRINT@@'
WHERE to_regclass('account') IS NULL AND NOT EXISTS (SELECT 1 FROM schema_revision);

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

	-- Email (OIDC scope: email)
	email                TEXT,
	email_verified_at    TIMESTAMPTZ,

	created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- OIDC `updated_at`
	last_login_at        TIMESTAMPTZ,

	-- Deletion: the account is disabled at once and erased (deleted, ids into deletion_log) after the
	-- grace period, during which an administrator can restore it.
	deleted_at           TIMESTAMPTZ,
	deleted_by           UUID,                          -- who deleted it (itself or an admin); no FK
	erase_after          TIMESTAMPTZ,                   -- when maintenance erases it
	held_memberships     JSONB                          -- its group memberships, given back on restore
);
-- Case-insensitive uniqueness (no citext extension needed)
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_username ON account (lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_email    ON account (lower(email))  WHERE email IS NOT NULL;

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
	-- 'client_credentials' here gives the app its own tokens for Guardian's read-only machine API.
	grant_types                 TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token'],
	-- How the app gets refresh tokens. 'stable': one refresh token per sign-in, valid as long as the
	-- session is (for apps with a secret). 'none': no refresh tokens (for apps without a secret).
	-- Rotating refresh tokens for apps without a secret are planned; add 'rotating' here then.
	refresh_mode                TEXT NOT NULL DEFAULT 'stable'
	                            CHECK (refresh_mode IN ('stable', 'none')),
	redirect_uris               TEXT[] NOT NULL DEFAULT '{}',   -- exact match only
	post_logout_redirect_uris   TEXT[] NOT NULL DEFAULT '{}',
	backchannel_logout_uri      TEXT,
	jwks                        JSONB,                          -- for private_key_jwt auth

	require_pkce                BOOLEAN NOT NULL DEFAULT TRUE,
	is_first_party              BOOLEAN NOT NULL DEFAULT FALSE, -- skips the consent screen
	-- Lifetime of access and ID tokens. It is also how stale an app's view of a user can get: group
	-- changes, logout and disabling reach the app when it next refreshes.
	access_token_ttl_seconds    INT NOT NULL DEFAULT 300
	                            CHECK (access_token_ttl_seconds BETWEEN 15 AND 86400),
	enabled                     BOOLEAN NOT NULL DEFAULT TRUE,
	-- Who may sign in to this app. 'groups': only members of a group linked to it (app_group).
	-- 'anyone': every account. The default denies, so a new app is closed until it is opened on purpose.
	access_rule                 TEXT NOT NULL DEFAULT 'groups'
	                            CHECK (access_rule IN ('groups', 'anyone')),
	-- Signing in to this app needs two-factor. Guardian asks for it, or has it set up, before the code.
	require_mfa                 BOOLEAN NOT NULL DEFAULT FALSE,
	-- The algorithm of the app's tokens (ID, access and logout tokens). RS256 is what OIDC apps expect when
	-- they say nothing; ES256 is smaller and faster, for apps whose library handles it.
	signing_alg                 TEXT NOT NULL DEFAULT 'RS256'
	                            CHECK (signing_alg IN ('RS256', 'ES256')),
	-- App admins: the active members of this group may edit the app, rotate its secret, disable it, read its
	-- audit entries, and link to it only groups they own. Set by Guardian admins.
	owner_group_id              UUID,
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
-- Standard scopes: openid, profile, email, offline_access. Guardian adds: groups.
-- Custom scopes belong to an app (app_id set), e.g. 'photos:read'.
-- `claims` lists the claims released by the scope.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scope (
	name         TEXT PRIMARY KEY,
	app_id       UUID REFERENCES app(id) ON DELETE CASCADE,   -- NULL = standard / global
	description  TEXT NOT NULL,                               -- shown on the consent screen
	claims       TEXT[] NOT NULL DEFAULT '{}'
);

-- Which scopes each app is *allowed* to request
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
-- GROUPS
-- Guardian knows which groups an account is in; each app decides what a group means.
-- Groups are flat (no groups inside groups). "group" is a reserved word, hence user_group.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_group (
	id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	key             TEXT NOT NULL UNIQUE,          -- immutable; the value apps see in the "groups" claim
	display_name    TEXT NOT NULL,                 -- editable
	description     TEXT NOT NULL DEFAULT '',
	is_system       BOOLEAN NOT NULL DEFAULT FALSE, -- built-in: cannot be deleted, renamed or given an owner
	-- Members of the owner group may add and remove members of this group. One level only.
	owner_group_id  UUID REFERENCES user_group(id) ON DELETE SET NULL,
	created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	-- Single-app groups: bound_at is set when the group is bound to one app, for good. It can then only
	-- be linked to that app. When the app is deleted, bound_app_id becomes NULL and bound_app_deleted_at
	-- records when, so the group can never be linked again and is cleaned up after audit retention (0.5).
	bound_app_id          UUID REFERENCES app(id) ON DELETE SET NULL,
	bound_at              TIMESTAMPTZ,
	bound_app_deleted_at  TIMESTAMPTZ,
	-- hidden: left out of its members' own group list (apps still get it in tokens).
	-- requestable: people outside it may ask to join; its owners (or Guardian admins) decide.
	-- join_by_default: every new account joins it.
	hidden                BOOLEAN NOT NULL DEFAULT FALSE,
	requestable           BOOLEAN NOT NULL DEFAULT FALSE,
	join_by_default       BOOLEAN NOT NULL DEFAULT FALSE,
	CHECK (owner_group_id IS DISTINCT FROM id),
	CHECK (bound_app_id IS NULL OR bound_at IS NOT NULL),
	CHECK (NOT (is_system AND bound_at IS NOT NULL)),
	CHECK (NOT (is_system AND (hidden OR requestable OR join_by_default))),
	CHECK (NOT (hidden AND requestable))
);
CREATE INDEX IF NOT EXISTS ix_user_group_owner ON user_group (owner_group_id);
-- The app's owner group (declared above, before user_group existed). Deleting the group leaves the app
-- without app admins.
DO $$ BEGIN
	ALTER TABLE app ADD CONSTRAINT app_owner_group_fk FOREIGN KEY (owner_group_id) REFERENCES user_group(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE INDEX IF NOT EXISTS ix_app_owner_group ON app (owner_group_id);

-- Membership. A row with expires_at in the past no longer counts.
CREATE TABLE IF NOT EXISTS group_member (
	group_id    UUID NOT NULL REFERENCES user_group(id) ON DELETE CASCADE,
	account_id  UUID NOT NULL REFERENCES account(id)    ON DELETE CASCADE,
	added_by    UUID REFERENCES account(id) ON DELETE SET NULL,
	added_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at  TIMESTAMPTZ,
	PRIMARY KEY (group_id, account_id)
);
CREATE INDEX IF NOT EXISTS ix_group_member_account ON group_member (account_id);

-- Requests to join a requestable group. One open request per account and group; a decided one is kept for
-- 30 days so its requester can see the answer, then removed by maintenance.
CREATE TABLE IF NOT EXISTS group_request (
	id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	group_id    UUID NOT NULL REFERENCES user_group(id) ON DELETE CASCADE,
	account_id  UUID NOT NULL REFERENCES account(id)    ON DELETE CASCADE,
	message     TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	decision    TEXT CHECK (decision IN ('approved', 'denied', 'withdrawn')),
	decided_by  UUID REFERENCES account(id) ON DELETE SET NULL,
	decided_at  TIMESTAMPTZ,
	CHECK ((decision IS NULL) = (decided_at IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_group_request_open ON group_request (group_id, account_id) WHERE decision IS NULL;
CREATE INDEX IF NOT EXISTS ix_group_request_account ON group_request (account_id);

-- Which groups an app is told about. An app only ever sees the groups linked to it, and with
-- access_rule = 'groups' only their members may sign in to it.
CREATE TABLE IF NOT EXISTS app_group (
	app_id    UUID NOT NULL REFERENCES app(id)        ON DELETE CASCADE,
	group_id  UUID NOT NULL REFERENCES user_group(id) ON DELETE CASCADE,
	PRIMARY KEY (app_id, group_id)
);
CREATE INDEX IF NOT EXISTS ix_app_group_group ON app_group (group_id);

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
	last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,   -- activity; the idle timeout counts from here
	expires_at        TIMESTAMPTZ NOT NULL,                             -- absolute end, whatever the activity
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

-- Refresh tokens. An app gets one per sign-in and keeps using it: it is not replaced at each refresh.
-- It is only usable with the app's secret, and only while its session is alive, so it ends with logout,
-- disabling and the session timeouts. Only the hash is stored.
-- family_id is unused for now: it is kept for rotating refresh tokens (apps without a secret), where
-- every token that descends from one sign-in shares a family.
CREATE TABLE IF NOT EXISTS refresh_token (
	id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	token_hash  TEXT NOT NULL UNIQUE,
	family_id   UUID NOT NULL DEFAULT gen_random_uuid(),
	app_id      UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	session_id  UUID NOT NULL REFERENCES session(id) ON DELETE CASCADE,
	scopes      TEXT[] NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_refresh_session ON refresh_token (session_id);
CREATE INDEX IF NOT EXISTS ix_refresh_account ON refresh_token (account_id);

-- Access tokens are signed JWTs and are not stored anywhere.

-- Fixed-window counters for rate limiting (login attempts, sign-ups). UNLOGGED = no WAL, much cheaper,
-- and losing the counters in a database crash is harmless. Shared by all Guardian replicas.
CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit (
	key           TEXT NOT NULL,
	window_start  TIMESTAMPTZ NOT NULL,
	hits          INT NOT NULL DEFAULT 0,
	PRIMARY KEY (key, window_start)
);

-- WebAuthn challenges already answered, so an answer cannot be sent twice. Kept until the challenge
-- expires; maintenance removes them after.
CREATE TABLE IF NOT EXISTS used_challenge (
	challenge   TEXT PRIMARY KEY,
	expires_at  TIMESTAMPTZ NOT NULL
);

-- Accounts that have signed in to an app at least once. The machine API lets an app look up these
-- accounts, and members of its linked groups, but nobody else.
CREATE TABLE IF NOT EXISTS app_user (
	app_id               UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	account_id           UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	first_signed_in_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_signed_in_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (app_id, account_id)
);
CREATE INDEX IF NOT EXISTS ix_app_user_account ON app_user (account_id);

-- Apps that received tokens under an SSO session. Used to fan out back-channel logout.
CREATE TABLE IF NOT EXISTS session_app (
	session_id     UUID NOT NULL REFERENCES session(id) ON DELETE CASCADE,
	app_id         UUID NOT NULL REFERENCES app(id)     ON DELETE CASCADE,
	first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (session_id, app_id)
);

-- Keys for signing ID/access tokens; public half is served at /jwks.json
-- Each algorithm (RS256, ES256) has its own active key and rotation; an app's tokens use its signing_alg.
-- Signing keys move through pending (published, not signing yet, so apps learn the key before it signs),
-- active (exactly one signs), retiring (published until tokens it signed have expired) and retired (no
-- longer published; the private key is wiped).
CREATE TABLE IF NOT EXISTS signing_key (
	kid                    TEXT PRIMARY KEY,
	alg                    TEXT NOT NULL DEFAULT 'RS256' CHECK (alg IN ('RS256', 'ES256')),
	public_jwk             JSONB NOT NULL,
	private_key_encrypted  TEXT,                       -- keyring value (v1:<key id>:...); NULL once retired
	status                 TEXT NOT NULL DEFAULT 'active'
	                       CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
	created_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	activated_at           TIMESTAMPTZ,
	retire_at              TIMESTAMPTZ,                -- retiring: when it stops being published
	retired_at             TIMESTAMPTZ,
	CHECK ((status = 'retired') = (private_key_encrypted IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_signing_key_active ON signing_key (alg) WHERE status = 'active';

-- -----------------------------------------------------------------------------
-- ONE-TIME TOKENS (password reset, email verification, re-authentication, invites)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account_token (
	id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
	purpose     TEXT NOT NULL
	            CHECK (purpose IN ('password_reset', 'email_verify', 'reauth', 'invite')),
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
	credential_id  BYTEA,                               -- webauthn: the credential's id
	credential     JSONB,                               -- webauthn: the stored credential (public key, flags, transports)
	sign_count     BIGINT,                              -- webauthn counter, or the last TOTP time step used
	created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_used_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_account_mfa_account ON account_mfa (account_id);
-- One authenticator app per account.
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_mfa_totp ON account_mfa (account_id) WHERE type = 'totp';
-- A security key or passkey belongs to one account; a passkey sign-in finds it by its id.
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_mfa_credential ON account_mfa (credential_id) WHERE type = 'webauthn';

-- -----------------------------------------------------------------------------
-- AUDIT LOG (append-only)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
	id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	occurred_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	event_type        TEXT NOT NULL,                    -- 'login.success', 'login.failure', 'group.member_added', ...
	actor_account_id  UUID,                             -- no FK on purpose: logs outlive accounts
	actor_app_id      UUID,
	target_type       TEXT,
	target_id         TEXT,
	ip_address        INET,
	metadata          JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit_log (actor_account_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_event ON audit_log (event_type, occurred_at DESC);

-- -----------------------------------------------------------------------------
-- DELETION LOG: the ids of erased accounts, and nothing else. Backups carry it, and a restore can apply a
-- newer one (`guardian restore --apply-deletions`), so an erased account stays erased.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS deletion_log (
	account_id  UUID PRIMARY KEY,
	erased_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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
			('profile',        'Your name, username and profile picture', ARRAY['name','given_name','family_name','preferred_username','picture','locale','zoneinfo','updated_at']),
			('email',          'Your email address',                      ARRAY['email','email_verified']),
			('groups',         'Which of this app''s groups you are in',    ARRAY['groups']),
			-- Accepted so that apps which always ask for it keep working. It changes nothing: refresh
			-- tokens never outlive the sign-in session.
			('offline_access', 'Stay signed in while your session lasts', ARRAY[]::TEXT[]);
	END IF;
END $$;

-- Built-in administrators group. Its members may do everything in Guardian.
DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM user_group) THEN
		INSERT INTO user_group (key, display_name, description, is_system)
		VALUES ('guardian-admins', 'Guardian administrators', 'Members can manage accounts, apps and groups in Guardian', TRUE);
	END IF;
END $$;

-- Initial admin account (no password yet, see note above), a member of the administrators group
DO $$
DECLARE
	v_account_id UUID;
	v_group_id   UUID;
BEGIN
	IF NOT EXISTS (SELECT 1 FROM account) THEN
		SELECT id INTO v_group_id FROM user_group WHERE key = 'guardian-admins';

		INSERT INTO account (username, display_name, must_change_password)
		VALUES ('admin', 'Admin', TRUE)
		RETURNING id INTO v_account_id;

		IF v_group_id IS NOT NULL THEN
			INSERT INTO group_member (group_id, account_id) VALUES (v_group_id, v_account_id);
		END IF;
	END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Guardian only migrates forward. To go back, restore a backup.
