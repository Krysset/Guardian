# Guardian roadmap to 1.0

Status: agreed plan, consolidated 2026-11-13 after a full design review and revised since (see the change log at the bottom). 0.1 is done; 0.2 is next. Change this document when a decision changes, and say so in the change log. `Agents.md` has working notes for agents.

## 1. What Guardian 1.0 is

- **An OIDC provider and account service** for apps that mostly run in the same Kubernetes cluster.
- **The single source of truth for accounts and group membership.** Apps map groups to their own permissions.
- **Installed with one Helm chart.** It works with plain Helm and with Argo CD.
- **A compatibility promise from 1.0 on:** the OIDC endpoints, the token claims and `/api/v1` only change in backwards-compatible ways within a major version.

**Scope boundary.** Guardian handles identity, sign-in, MFA, sessions and group membership. Apps decide what a group means, and they own any rules about individual records (for example "may open invoice 42"). Groups are deliberately coarse.

## 2. Core design

### Tokens and staleness
- **Access tokens are short-lived signed JWTs.**
  - They are lean: `sub`, `aud` (client_id), `scope`, `sid`, `amr` and `groups`. They carry no profile data.
  - The header type is `at+jwt`, so an ID token can never be accepted as an access token or the reverse.
  - They are not stored in the database.
- **Profile data** lives in the ID token, which is re-issued at every refresh, and in `/userinfo`.
- **The `groups` scope** puts the `groups` claim in the ID token, `/userinfo` and the access token.
  - It lists only the groups linked to the app.
  - Its values are immutable group keys, never display names.
- **Apps identify users by `sub`,** never by username or email, because both can change.
- **Lifetime** is the app's `access_token_ttl_seconds`, minimum **15 seconds**. That lifetime is the app's staleness window.
  - The docs recommend 60 seconds or more. Very short tokens are fragile when clocks differ by a few seconds, and an app's own leeway setting adds to the real window.
- **Refresh is where revocation happens.** Every refresh re-checks the session, account status, the app's enabled flag, the access rule and group membership, and issues fresh claims.
  - Logout, disabling an account and removing someone from a group therefore reach an app within one window.
  - A refresh token is issued whenever the app is allowed the `refresh_token` grant.
  - All refresh tokens are bound to the Guardian session. There are no refresh tokens that outlive it in 1.0.
- **Refresh tokens are stable for apps with a client secret.**
  - A confidential app gets one refresh token per sign-in. It is not replaced on each refresh, so parallel refreshes and retries all succeed and no grace window is needed.
  - It ends with the session: logout, "sign out everywhere", disabling, or the idle and absolute timeouts.
  - A refresh writes nothing to the database, apart from the occasional session activity stamp.
  - The trade-off is that automatic theft detection is gone. A stolen refresh token is useless without the client secret.
- **Apps without a client secret get no refresh tokens in 1.0.** They can sign users in, and should use a small backend to hold tokens.
- **Rotation returns in 1.x for public clients,** because the owner plans a mobile app. The 1.0 code is built for it:
  - each app has a refresh mode setting, with `stable` and `none` in 1.0 and `rotating` reserved;
  - issuing the next refresh token goes through one function, so a second mode is a local change;
  - the refresh token table keeps a family id column, unused in 1.0.
- **Session lifetime:** an idle timeout of 7 days, extended by activity including refreshes, and an absolute maximum of 30 days. Both are configurable.
- **Membership removal and disabling send a back-channel logout** to the apps that user is signed in to.
- **Apps that neither refresh nor implement back-channel logout** are as stale as their own session. `INTEGRATION.md` says so.
  - Planned off-the-shelf apps are Grafana and SonarQube; their real behaviour is checked when they are integrated.
  - Argo CD stays outside Guardian on purpose, so a Guardian outage cannot lock the owner out of the cluster.
- **Back-channel logout** makes logout and disabling immediate for apps that implement it.
- **No per-request calls to Guardian.** `/introspect` and the `access_token` table are removed.
  - RFC 7009 revocation covers refresh tokens.
  - The internal listener `:3002` serves only `/metrics`, `/healthz` and `/readyz`.
- **Outage behaviour for apps** (documented in `INTEGRATION.md`):
  - Apps keep validating JWTs locally while Guardian is down.
  - On `invalid_grant`, the app logs the user out.
  - On a network error or 5xx, the app keeps the session and retries for about one more token lifetime.

### Groups, apps and access
- **Groups are flat.** Membership can expire. Grants carry no attributes.
- **Each group has an immutable key and an editable display name.** The key is set at creation and is what tokens carry.
- **System group `guardian-admins`** holds all admin rights in Guardian.
  - It always has at least one active member. Guardian refuses to remove, disable or delete the last one.
  - There is no break-glass command. Recovery for a locked-out sole admin is a documented SQL statement, run by someone with database access.
  - The admin area warns when there is only one admin. MFA setup makes the user confirm a recovery code before it finishes.
- **Apps only see the groups linked to them** (`app_group`).
- **Tables:** `user_group` ("group" is a reserved word in SQL), `group_member` and `app_group`.
- **Per-app access rule:**
  - **"Members of linked groups only"** is the default. Guardian refuses everyone else at sign-in with a clear message, and no code is issued.
  - **"Anyone with an account"** is the alternative.
- **Per-app "require MFA" setting.** Guardian enforces it during sign-in, either with the second-factor prompt or by walking the user through setting one up.
- **Group owners (delegation):**
  - Owners add members by typing an exact username or email. There are no suggestions, and the only answers are "No user found" or "User added".
  - Owners see which apps their groups are linked to, and users see the groups they are in.
  - A group can name an owner group, whose members manage the owned group's membership.
  - Only global admins change system groups or ownership.
  - Apps, and linking groups to apps, are global-admin only in 1.0.
  - Every delegated action is audited, recording which ownership was used.
- **Single-app groups:** a group can be bound to one named app, permanently. It can never be linked to another app; when its app is deleted it stays, bound to nothing, until the clean-up after audit retention removes it. New groups ask whether they are for one app only, with no preselected answer.
- **Machine access for apps:**
  - The `client_credentials` grant.
  - A read-only API (`/api/v1/apps/self/...`), limited to the calling app, for its linked groups, their members, and user lookup by id.
  - All changes are made in Guardian.

### Accounts and sign-in
- **Sign-up** is open and auto-approved. It needs a username and password; email is optional.
  - The new user is signed in and continues to the app they came from. When they gave an email, sign-up completes only once it is confirmed.
  - Every new or changed password is typed twice.
  - Sign-up reports a taken username or email plainly.
  - Its defences are a honeypot field and per-IP limits.
  - **Notices on the sign-up page:**
    - Without an email, a forgotten password can only be reset by an admin.
    - Guardian is a hobby project under active development.
    - Use a unique password and do not reuse one from another site.
- **Security notices by email,** when the account has one, for password changes and for MFA being added or removed.
- **Email is never stored unverified.**
  - An entered address waits as a pending `account_token` until its link is clicked, so `account.email` is always verified or empty.
  - Addresses set by an admin count as verified.
  - `REQUIRE_EMAIL` (default off) makes an email mandatory at sign-up.
- **Sign-in** uses a username or the account's email. Login and password reset never reveal whether an account exists.
- **Email handling:** addresses are compared case-insensitively and otherwise exactly. Changing the address notifies the old one, and the new address only takes effect once verified.
- **Password resets** only go to the account's email. They change only the password; MFA still applies afterwards.
- **MFA:**
  - TOTP plus 10 single-use recovery codes.
  - WebAuthn security keys and passkeys (WebAuthn Level 3), including passwordless sign-in. Passkey-only accounts are allowed, with a warning before the user removes their last recovery option.
  - **Mandatory** for `guardian-admins` members and group owners.
  - **Recovery ladder:** another factor, then a recovery code, then an audited admin reset that requires a reason and notifies the user by email.
- **Re-authentication before protected changes:**
  - Protected changes: username, email, password, MFA, recovery codes, account deletion, sessions and connected apps.
  - The API answers `403 reauth_required` unless the session was re-authenticated within the last 5 minutes.
  - The management UI shows one shared dialog and retries the save automatically.
- **Abuse protection:**
  - Login failures are counted per username *and* IP together: 5 in 15 minutes blocks that IP for that account.
  - A separate per-IP limit applies across all accounts.
  - Accounts are never locked automatically.

### Keys and secrets
- **Signing keys:** RS256 with RSA-2048.
  - Keys move through four stages: `pending` → `active` → `retiring` → `retired`.
    - **pending:** published but not signing, for 1 hour.
    - **active:** exactly one per algorithm signs.
    - **retiring:** published until the longest token lifetime plus clock skew has passed.
  - Replicas reload keys every 60 seconds. JWKS is served with `max-age=900`.
  - Rotation is automatic every 90 days. `guardian keys rotate` rotates by hand; `--now --revoke-current` is the emergency path.
  - **Limit of the emergency path:** apps cache Guardian's public keys, so tokens signed with a revoked key are still accepted until each app's cache expires. The runbook includes restarting or refreshing the apps.
  - The code is algorithm-agnostic, with a per-app algorithm setting. ES256 is a stretch goal before 1.0, otherwise 1.x.
- **Encryption keyring:**
  - It replaces `KEY_ENCRYPTION_KEY`. It is read from `KEY_ENCRYPTION_KEYS_FILE` (`k2:<b64>,k1:<b64>`) and reloaded every 60 seconds.
  - **Format:** values are tagged `v1:<key id>:...`, encrypted with AES-256-GCM, with the table, column and row as associated data.
  - **Adding a key:** a new key is added decrypt-only, then promoted. Re-encryption runs in the background, with a metric counting the values left per key.
  - **Safety:** Guardian refuses to start when a needed key is missing.
- **Secrets:**
  - The chart generates none. The database password, keyring, backup public key and admin password all come from operator-provided Secrets. The owner fills them from Bitwarden.
  - `values.schema.json` fails the install when one is missing.
  - There is no KMS integration.

### Operations
- **Versioning:**
  - **0.x:** the schema may change (`00001_init.sql` is edited), and upgrades go through backup and restore, or a reinstall.
  - **From 1.0, patch and minor releases** follow expand/contract and are always safe as a rolling upgrade. This is enforced in CI by running the previous minor's end-to-end tests against the new schema.
  - **From 1.0, major releases** require a backup first, then the upgrade with downtime, starting from the last minor of the previous major. CI checks that a backup from that minor restores into the new major.
  - Migrations only go forward. Recovery means restoring a backup.
- **Migrations** use goose with embedded SQL.
  - `migrations.mode: startup` (the default) runs them in the backend under an advisory lock.
  - **`job` mode:**
    - It is a Helm hook, plus an Argo CD Sync hook ordered by waves: bundled Postgres in wave -2, the Job in -1, the apps in 0.
    - In this mode the backend waits for the expected schema version before it reports ready.
- **Backup and restore** via `kubectl exec`.
  - **`guardian backup`:**
    - It writes Guardian's own versioned format to stdout, taken from one database snapshot.
    - It is always encrypted with an `age` public key; the private key stays offline in Bitwarden.
    - It contains accounts, groups, apps, consents, MFA, signing keys (still keyring-encrypted), the deletion log and, optionally, the audit log. Sessions, tokens and counters are left out.
  - **`guardian restore`:**
    - It only restores into an empty database, in one transaction.
    - It accepts backups from the same major version or the previous one.
    - `--apply-deletions <file>` applies a newer deletion log; `guardian deletions export` writes one.
  - **After restoring an older backup,** security changes made since are reverted: removed admins, changed passwords and revoked app secrets come back. The runbook has a post-restore checklist.
  - **Scheduled backups:** a CronJob writes backups, plus the matching deletion log, to its own disk claim and storage class, and keeps the last N. S3 comes in 1.x.
  - **Backup manifest:**
    - Each backup starts with an unencrypted manifest with no personal data: format and schema version, time, issuer, row counts per table, and the id of the key-encryption key it needs. The size and SHA-256 of the encrypted part close the file, because the backup is streamed and they are known only at the end. One file instead of a sidecar, so `kubectl exec ... > file` captures all of it.
    - `guardian backup verify` checks a file against its manifest without the private key; with the key it also counts the rows.
    - Metrics report the time of the last successful backup (`guardian_backup_last_success_timestamp_seconds`, read from the audit log); the counts are in the backup's audit entry.
    - A restore drill with the private key is documented, because only a real restore proves a backup works.
- **Rules for destructive commands** (key revoke, `mfa reset-totp --all`, restore):
  - They exist only as CLI commands, so Kubernetes RBAC on `pods/exec` decides who can run them.
  - They do a dry run by default. To execute they need `--execute`, `--reason`, and the issuer host typed back (or `--confirm=<host>`).
  - Each run is audited. (A metric per run is not possible: the commands run in their own process, not in the server that Prometheus scrapes. The audit log is the record.)
  - They are idempotent: either a single transaction, or resumable batches.
  - Backup itself needs `--execute` and `--reason`, and is audited.
- **Bundled Postgres** (`database.mode: bundled`, the default; `external` is the alternative):
  - A single instance with the major version pinned. Changing the major is a backup-and-restore procedure.
  - Its disk is kept on uninstall.
  - Options: image tag within the major, resources, storage size and class or an existing claim, placement, a Postgres settings map, and the security context.
  - Password rotation is manual, by runbook (`ALTER ROLE`, then update the Secret).
  - It is documented as meant for development and small setups. Production should use an external HA Postgres such as CloudNativePG.
- **Scaling:**
  - No feature may depend on the number of backend replicas or on which cluster a replica runs in. Backends in several clusters can share one Postgres.
  - The chart defaults to 2 replicas plus a PDB.
  - Target: refresh p99 under 100 ms.
- **Routing:**
  - One hostname. `/account`, `/admin` and `/_app` (the management UI's script and style files) go to the frontend; everything else goes to the backend.
  - The chart offers an optional standard `Ingress` (with `className`) and an optional Gateway API `HTTPRoute` (with `parentRefs`). It never creates a Gateway, and contains nothing Traefik-specific.
  - The NetworkPolicy ingress source is a value. HTTPS is required unless a dev flag is set. `TRUSTED_PROXY_HOPS` is a value, default 1.

### Data protection (GDPR)
- **Account deletion:**
  - Self-service in the account area, as a protected change.
  - The account is disabled at once and hard-deleted after a 30-day grace period (configurable), during which an admin can restore it.
  - Admins can also delete, with an "erase now" option.
  - Hard-deleted ids go into the deletion log, which holds ids only, no personal data.
- **Audit log** retention is **6 months** by default. When an account is erased, the IP address and personal details are removed from its audit entries.
- **"Download my data"** gives the user a JSON export.
- **Less data collected:** `phone_number`, `birthdate` and the `phone` scope are removed.
- **Logs** contain account ids at most, never emails, IP addresses, names or tokens.
- **Backups** keep data until their own retention ends. Erasure is re-applied on restore.
- `docs/DATA-PROTECTION.md` documents all of the above.

## 3. Tech stack

- **Backend:**
  - Go (current stable) with chi.
  - `database/sql` with `jackc/pgx/v5/stdlib`.
  - goose for migrations; `log/slog` (JSON) for logging; Prometheus client for metrics.
  - `golang-jwt` for tokens, `go-webauthn/webauthn` for WebAuthn, `rsc.io/qr` for the setup QR code (TOTP itself is Guardian's own code), `filippo.io/age` for backup encryption, and `net/smtp` behind a `Mailer` interface.
  - Everything is embedded (migrations, templates, static files).
  - The image is distroless, non-root, with a read-only root filesystem.
- **Sign-in pages** (login, sign-up, consent, logout, reset, MFA) and the 0.1 Home: server-rendered Go `html/template` in the approved Guardian design (dark only), with embedded styles and scripts and a strict Content-Security-Policy. They work without JavaScript, except for the security-key prompt.
- **Management UI** (the account area `/account` and the admin area `/admin`; called the "console" before 2026-11-15). Admins do all everyday work here; the CLI is only for cluster operations:
  - Svelte 5 + SvelteKit (`adapter-static`) + TypeScript.
  - Plain CSS with tokens shared with the sign-in pages.
  - Types generated from `docs/openapi.yaml`.
  - Served by `nginx-unprivileged` as its own deployment, on the same origin, using Guardian's session cookie.
- **Chart:** Helm, usable with plain Helm and Argo CD.

## 4. Repository layout (target)

```
guardian/
├── Agents.md                      # hand-off notes; read first
├── README.md, Makefile, docker-compose.yml (postgres, mailpit, backend, frontend dev)
├── .github/workflows/             # backend.yml, frontend.yml, chart.yml, release.yml
├── backend/
│   ├── cmd/guardian/main.go       # serve | migrate | backup | restore | deletions | keys | mfa
│   ├── migrations/                # 00001_init.sql (editable until 1.0)
│   ├── internal/
│   │   ├── config/  store/  auth/  oidc/  api/  internalapi/  web/  mail/  httpx/  backup/  testutil/
│   ├── e2e/
│   └── Dockerfile
├── frontend/                      # SvelteKit management UI, Dockerfile, nginx.conf
├── charts/guardian/               # see Agents.md for the template list
└── docs/
    ├── ROADMAP.md, ARCHITECTURE.md, INTEGRATION.md, TESTING.md, USERS.md, PAGES.md, LOCAL-GRAFANA.md
    └── INSTALL.md (incl. runbooks), DATA-PROTECTION.md, openapi.yaml
```

## 5. Release plan

Everything runs in a staging environment with test data until 1.0. Guardian is not opened for public sign-up before then.

### 0.1: it runs locally (done 2026-11-19)
- **M0: make it run. Done 2026-11-14.**
  - CI moved to the root `.github/`; the Dockerfile and `docker-compose.yml` were fixed.
  - The backend builds, and all 102 tests pass against PostgreSQL 16. One bug was found and fixed.
- **M1: restructure. Done 2026-11-14.** No change to features.
  - Part 1: move to `cmd/` and `internal/`, add the config package with validation, structured logging with slog, and the schema embedded in the binary.
  - Part 2: goose migrations and the pgx driver, plus a `guardian migrate` command.
  - The split of `internal/api` into `oidc`, `web`, `httpx` and `internalapi` was moved to the groups and JWT step below.
- **Groups and JWT:**
  - **Done 2026-11-14:** groups with keys (`user_group`, `group_member`, `app_group`), group owners, the per-app access rule enforced at sign-in, the last-administrator rule, and `/api/groups`.
  - **Done 2026-11-15:** lean JWT access tokens, the `groups` scope, stable refresh tokens for confidential apps with re-checks at every refresh, session idle and absolute timeouts, back-channel logout on leaving a group, `/revoke`, removal of `/introspect`, phone and birthdate.
  - Still to come in `00001_init.sql`, each with its feature: the require-MFA flag, key stages, keyring tags and the deletion log.
  - **Done 2026-11-15:** `client_credentials` and the read-only machine API at `/api/v1/apps/self`.
  - **Done 2026-11-15:** the split of `internal/api` into `httpx`, `web`, `oidc`, `internalapi` and `api`. No change to behaviour.
- **API and pages:**
  - **Done 2026-11-15:** `/api/v1` with REST routes and `docs/openapi.yaml` (kept in step with the router by a test); admin checks through `guardian-admins`; account search, disabling and admin-set passwords; app edits and secret rotation; the audit log.
  - **Done 2026-11-19:** the sign-in pages in the approved design (S1-S9 on the design board): login (username or email), sign-up with its notices and honeypot, consent, no access, sign out and signed out, already signed in, the error pages, and the forced password change after an admin-set password. Templates and static files are embedded; the Content-Security-Policy allows no inline styles or scripts.
  - **Done 2026-11-19:** single-app groups in the backend (`docs/USERS.md` A27): `bound_app_id` on `POST /groups` and `POST /groups/{group}/bind`; a bound group is linked to its app and can be linked to no other (`group_bound`); a binding never moves (`already_bound`) and needs the group to be linked nowhere else (`linked_elsewhere`); deleting the app leaves the group bound to nothing, with `bound_app_deleted_at` for the clean-up in 0.5.
- **Done when:** with docker-compose, a test app and Grafana sign in through OIDC and receive the right groups. **Done 2026-11-19:** the end-to-end tests cover the test app; the owner ran the Grafana check (`docs/LOCAL-GRAFANA.md`, Grafana behind the `grafana` profile in `docker-compose.yml`), including roles from groups, refusal without a group and sign-out.

### 0.2: it runs in the cluster
- A minimal chart: backend, bundled or external Postgres, Ingress/HTTPRoute, required Secrets, startup migrations.
  - **Built 2026-11-19, not yet installed:** `charts/guardian` with the backend Deployment, both Services, a PDB, the bundled Postgres StatefulSet, HTTPRoute and Ingress, `values.schema.json`, CI values, and `docs/INSTALL.md`. A `chart` CI workflow lints, renders and validates it. The image comes from the owner's own registry until the release workflow (0.5).
- `guardian backup` and `guardian restore`, with the manifest and the rules for destructive commands.
  - **Built 2026-11-19, tested locally:** `internal/backup` and the `backup`, `backup verify`, `backup decrypt` and `restore` commands (`docs/INSTALL.md`, "Backup and restore"). A restore only goes into a new installation, needs the same schema revision and key-encryption key, and is rehearsed in a rolled-back transaction by the dry run. The deletion log moved to 0.3, where account deletion creates it.
- **Done when:** installed via Argo CD in the staging cluster, and a backup restores into a fresh install.

### 0.3: accounts
Built in parts, in this order: (1) email, (2) re-authentication, (3) two-factor, (4) account deletion and the deletion log, (5) signing keys and the keyring, (6) abuse protection.
- Mailer, email verification and change, password reset, `REQUIRE_EMAIL`, and security notices.
  - **Built 2026-11-19 (part 1):** `internal/mail` (SMTP with STARTTLS or TLS, a background queue with retries, the E1, E2, E3 and E5 emails), the S2 email field, S2b, S10, S11 and S12, and `PUT /api/v1/me/email`. Mailpit catches the emails locally. Email is off without `SMTP_HOST`. The chart's settings for email wait with the other chart features.
- TOTP, recovery codes, the MFA challenge, the recovery ladder, admin MFA reset.
- **Mandatory MFA for admins and group owners, and enforcement of the per-app "require MFA" setting.**
  - **Built 2026-11-20 (part 3):** TOTP written in Guardian itself (RFC 6238, about 30 lines, so no `pquerna/otp`), each code usable once; 10 recovery codes stored as hashes; S13, S15 and S16; the API for setting up, removing and renewing (`/api/v1/me/mfa/...`, protected changes) and the admin reset with a reason (`POST /accounts/{id}/mfa/reset`, E6); E4 notices; `require_mfa` on apps, enforced at `/authorize` with a step-up. Administrators and group owners set it up at sign-in, and their rights need a session that passed two-factor (`403 mfa_required`). `POST /me/reauth` also takes a code. The QR code comes from `rsc.io/qr`. The `mfa reset-totp --all` command moves to part 5, with the keyring it exists for.
- Re-authentication and the protected-change list.
  - **Built 2026-11-19 (part 2):** `POST /api/v1/me/reauth` (password; two-factor codes join with part 3) moves the session's `auth_time`; protected changes answer `403 reauth_required` when it is more than 5 minutes old. Signing in counts. Enforced today on the username, email and password; the other protected changes enforce it as they arrive. `PUT /me/password` no longer takes the current password: re-authentication replaces it.
- Account deletion with the grace period and hard delete, and "download my data". The deletion log arrives with it, in backups too, with `--apply-deletions` and `guardian deletions export`.
  - **Built 2026-11-20 (part 4):** `DELETE /api/v1/me` (protected, the username typed back) and the admin's `DELETE /accounts/{id}` wait out `DELETION_GRACE_PERIOD` (30 days); `GET /accounts/deleted`, `POST /accounts/{id}/restore` (memberships come back where their groups still exist) and `POST /accounts/{id}/erase` ("erase now", the username typed back). Maintenance erases due accounts. Erasing deletes the account and what hangs off it, strips IP addresses and personal details from its audit entries, and writes its id to `deletion_log`. `GET /api/v1/me/export` is "download my data". Backups carry the deletion log; `guardian deletions export` and `guardian restore --apply-deletions` keep erased accounts erased. Audit retention (6 months) is not enforced yet: it comes with the clean-up in 0.5.
- **Built 2026-11-20 (part 5):** AD11 Audit log: filter by event (grouped, in words) and by account (an exact username: what it did and what was done to it, also during its deletion grace period), or by app from an app's page; 50 entries a page with Next and Previous; each row opens its details with links to the account, app and group. Entries carry the names of the account, app and group they are about while those exist (`target_username`, `app_name`, `group_name`), and `GET /audit?username=`. A browser pass over every page of the management UI at desktop and phone width, and the sign-in pages at phone width: no sideways scrolling, no console errors.
- The signing-key lifecycle with automatic rotation, the encryption keyring with re-encryption, and the runbook commands.
  - **Built 2026-11-20 (part 5):** signing keys move pending (1 hour) → active → retiring (longest token lifetime + 5 minutes) → retired (private key wiped), every 90 days (`SIGNING_KEY_LIFETIME`), on a schedule every replica runs each minute under an advisory lock; replicas reload the keys every minute; JWKS `max-age=900`. The keyring (`KEY_ENCRYPTION_KEYS_FILE`, or `KEY_ENCRYPTION_KEYS` for local use) replaces `KEY_ENCRYPTION_KEY`: `v1:<key id>:...` values with the table, column and row as associated data, reread every minute, refused when it lacks a key in use, re-encrypted in the background, `guardian_keyring_values`. Commands: `guardian keys list`, `keys rotate` (and `--now --revoke-current`), `keys reencrypt`, `mfa reset-totp --all`. Backups name the keyring keys they need (id and fingerprint). The chart mounts the keyring from the Secret key `key-encryption-keys`. ES256 and a per-app algorithm stay open (stretch goal before 1.0).
- Abuse protection (login limits and the honeypot).
  - **Built 2026-11-20 (part 6):** sign-in failures count per account *and* address (`login:account:<id>:ip:<ip>`; an unknown login counts under its lowercased name, so the answer reveals nothing): 5 in 15 minutes refuse that account from that address, with a dummy hash so the timing matches. Every address has 50 failures per 15 minutes across all accounts. A success clears the account's counter. The limits are settings (`LOGIN_FAILURE_WINDOW`, `LOGIN_MAX_FAILURES_PER_ACCOUNT_IP`, `LOGIN_MAX_FAILURES_PER_IP`; in the chart `config.loginLimits`). No account is ever locked, so a stranger cannot lock out its owner. Sign-up and forgot-password carry a honeypot; a hit answers as usual, does nothing, is audited (`honeypot`) and counted in `guardian_rate_limited_total{endpoint="honeypot"}`.
- **Done when:** end-to-end tests cover reset, verification, MFA sign-in, re-authentication, deletion, and key and keyring rotation.

### 0.4: management UI (built 2026-11-20; the image and the chart wait for the cluster)
Built in parts, in this order: (1) foundation (the project, the frame, the API client, the "Confirm it's you" dialog, the font), (2) Home and the account area, including the group owner's page, (3) the admin area's overview and accounts (with the statistics API, the one-administrator warning, and a two-factor step-up: an administrator whose session has not passed two-factor confirms with a code and continues, the way apps that require two-factor already ask, instead of signing out and in again; decided 2026-11-20), (4) the admin area's groups and apps, (5) the audit log, a browser pass over every page, and the docs. The nginx image and the chart's frontend wait for the cluster.
- **Built 2026-11-20 (part 1):** `frontend/` with SvelteKit 3, Svelte 5, Vite 8, TypeScript 6 and `adapter-static` (a single-page app with the fallback `200.html` and a hash-based CSP); API types generated from `docs/openapi.yaml` (`npm run api`); the F2 frame; AC8 with the retry; the error page; AC1's "About you" and username. Figtree is bundled (30 KB, latin and latin-ext) in the backend's `/static/` and used by both UIs. Sign-in now returns to `/account` and `/admin` pages. Local development: `npm run dev` on :3000 forwards everything else to the backend.
- **Built 2026-11-20 (part 2):** H0 Home and the account area, AC1 to AC7, in design F. New API routes: `GET /me/home`, `GET|DELETE /me/sessions` and `DELETE /me/sessions/{session}`, `GET /me/apps` and `DELETE /me/apps/{app}` ("Remove access": consent, refresh tokens, the machine API's right to look the user up, and a back-channel logout), `GET /me/groups` (groups the user is in and groups they manage, with the linked apps' names), `DELETE /me/email` and `DELETE /me/email/pending`, `POST /groups/{group}/members` (add by exact username or email: "No user found" or the member). `GET /me` gains `email_settings` (sending on, address required, the pending address) and `mfa.required_reason`. Sessions, connected apps and the email address are protected changes. Home is the management UI's page at `/` (the ingress sends exactly `/` to the frontend once the chart has it); the backend's simple Home stays as the fallback until then. An account with a temporary password is sent to the new-password page first.
- **Built 2026-11-20 (part 3):** AD13 Overview (`GET /overview`: figures only; refused requests are counted per endpoint and hour in the `rate_limit` table by `httpx.CountRefused`, so the last 24 hours cover every replica), AD1 Accounts (search, status filter including "must change password", paging with a total), AD3 New account, AD2 Account (profile and email masked until shown, sign out everywhere with the new `DELETE /accounts/{account}/sessions`, temporary password, two-factor reset with a reason, disable or enable, groups with expiry, recent activity from `GET /audit?about=`), AD12 Deleted accounts (restore, erase after typing the username), and the one-administrator warning (A23) across the admin area. The two-factor step-up: `/mfa/stepup?return_to=` asks a session that has not passed two-factor for a code (or sets it up) and returns to the management UI; the UI goes there on any `403 mfa_required`. Fixed: an account an administrator creates now must choose its own password at the first sign-in (A3 said so; the API did not), and a duplicate username or email answers `username_taken` or `email_taken`.
- **Built 2026-11-20 (part 4):** AD4 Groups (built-in and bound badges), AD6 New group (the key rule checked as it is typed, "Is this group for one app only?" with neither answer preselected), AD5 Group (details and owner group, members with search and expiry, binding to its one app, delete after typing the key; built-in groups are read-only), AD7 Apps, AD9 New app (the other settings folded away), AD8 App (setup values to copy: client id, issuer, discovery URL; settings; access with linked groups and the machine API; secret rotation with a grace period; recent activity; disable, enable, delete after typing the name), and AD10, the secret shown once: Done turns on after Copy or ticking "I have stored it", and Escape does not close it. The group owner's page shares the members card with AD5, without suggestions (O3). New API: `GET /scopes` (the standard scopes an app may ask for) and `GET /audit?app=` (entries by the app or about it).
- The SvelteKit management UI (pages in `docs/PAGES.md`):
  - Home (`/`): connected and available apps, actions needed, the way to both areas; no personal details. It replaces the simple 0.1 Home;
  - `/account`: opens on the profile (email masked until shown); security, sessions, connected apps, groups, data export, deletion;
  - `/admin`: an overview of aggregated figures as the start page (no personal data on it), accounts (including signing an account out everywhere), apps, groups, audit log.
- Group owners and their scoped admin view.
- **Done when:** everything in the management UI list can be done without curl.

### 0.5: complete
Built in parts: (1) audit retention and the clean-up of single-app groups, (2) security keys and passkeys, (3) the release workflow and SonarQube, (4) the parts that need the cluster: the full chart with the frontend, scheduled backups and migration job mode.
- **Built 2026-11-20 (part 1):** audit entries older than `AUDIT_RETENTION` (default 4392h, about 6 months; chart `config.auditRetention`) are deleted every hour in batches; single-app groups whose app was deleted longer ago go too, audited as `group.deleted` by the schedule. The deletion log is never pruned. The audit log page says how long entries are kept (`audit_retention_days` in `GET /overview`).
- **Built 2026-11-20 (part 2):** security keys and passkeys with `go-webauthn/webauthn` (v0.18.2). A key is a second factor after the password (S14), a passkey signs in on its own from "Sign in with a passkey" or the browser's suggestions in the username field (the authenticator must verify the user, and the session counts as two-factor: amr `hwk`, `user`), and a key confirms it's you (AC8). Keys are added in the account area or in the required setup (S15), listed, renamed and removed; the first two-factor method of either kind brings the recovery codes, typed back before anything is saved; the recovery codes go with the last method; an account that must use two-factor keeps one. The relying party is the issuer's host name; the management UI's origin counts when it is served elsewhere (`ALLOWED_ORIGINS`). Each challenge travels sealed and is answered once (`used_challenge`); a key whose counter goes backwards is refused. No attestation is asked for. Passwordless accounts (no password at all) are not offered: the password stays.
- WebAuthn and passkeys, including passwordless sign-in.
- Scheduled backups, audit retention, and migration job mode (Helm hooks and Argo CD waves).
- Clean-up of single-app groups whose app was deleted longer ago than the audit retention period.
- The full chart: frontend deployment, HPA, PDB, NetworkPolicy, ServiceMonitor, `ci/` values tested with chart-testing on kind.
- Release workflow (images to GHCR, chart as OCI).
- SonarQube integrated and its staleness behaviour documented.
- **Done when:** every 1.0 feature is in place and a clean `helm install` works with both bundled and external Postgres.

### 0.6: test and requirement review
- Every requirement in `docs/USERS.md` is implemented and named by at least one test; a table maps each requirement to its tests, and gaps are filled.
- The tests are reviewed: slow or overlapping tests are made faster or merged, flaky ones fixed, and missing cases added (error paths, permissions, limits).
- **Done when:** the requirement table has no gaps and the suite runs green and reasonably fast.

### 1.0: release
- **M7 hardening:**
  - a real browser over TLS;
  - SIGTERM handling and readiness when the database is down;
  - proxy hops;
  - a refresh load test against the p99 target;
  - multi-replica and multi-cluster behaviour;
  - a security review.
- **Docs:** `INSTALL.md` (with runbooks), `INTEGRATION.md`, `ARCHITECTURE.md`, `DATA-PROTECTION.md`, `openapi.yaml`, `CHANGELOG.md`.
  - **Reminder:** recreate the app-to-Guardian communication diagrams (how an app talks to Guardian: sign-in, refresh, logout, back-channel logout, machine API). The old yUML versions described the removed introspection design and were deleted in 0.1.
- **ES256** only if it doesn't delay the release.
- **After tagging,** `00001_init.sql` is frozen and the compatibility rules apply. Until then nothing is deployed, so removed or renamed settings are simply dropped: no warnings or refusals for legacy options.

### Release checklist for v1.0.0
- [ ] CI is green, including end-to-end tests against Postgres and the chart-testing install.
- [ ] Removing a user from a group, or disabling them, reaches a refreshing app within its `access_token_ttl_seconds`, and sends a back-channel logout that reaches an app implementing it.
- [ ] Parallel refreshes with the same token all succeed, and the token stops working the moment its session ends.
- [ ] A backup restores into a fresh install, and `--apply-deletions` keeps erased accounts erased.
- [ ] Signing-key rotation and keyring rotation run on a live multi-replica install without errors at the apps.
- [ ] A sample app integrates by following only `INTEGRATION.md`.
- [ ] No secrets or personal data in logs. The images run as non-root with read-only root filesystems.
- [ ] All docs listed above are current, including the recreated app-to-Guardian communication diagrams.

## 6. After 1.0 (1.x candidates)

- **App owners:** an owner group edits its app and links only groups it owns.
- **Copying a group** with its members, as a new, unrelated group (`docs/USERS.md` A29).
- **Hidden groups,** left out of a member's own group list, only if a need arises (`docs/USERS.md` A26).
- **Access requests:** requests to join a group, and a "request access" screen when an app's access rule denies sign-in.
- **Rotating refresh tokens for public clients** (mobile apps and backend-less SPAs), with reuse detection.
- **`acr_values`:** apps can demand MFA for a single sign-in.
- **ES256** (if it didn't make 1.0).
- **Proof-of-work challenges** (ALTCHA-style) on sign-up and on login under attack.
- **S3-compatible backup storage.**
- **A bundled CloudNativePG option.**
- **Invites,** default groups, and sign-up approval or closed modes, only if needed.
- **Not planned:** federated login, LDAP, SCIM, phone/SMS, `private_key_jwt`, dynamic client registration, multi-tenancy, third-party CAPTCHAs, KMS integration, theming beyond the built-in design, translations (strings are kept in one place so these can be added later).

## Change log
- 2026-11-13: first plan, then a full review settled 15 topics: groups and JWT, signing keys, the encryption keyring, migrations and backups, bundled Postgres, console hosting, delegation, email, recovery and MFA, access for new accounts, the scope boundary, GDPR, abuse protection, routing, and the release plan. This document was then consolidated.
- 2026-11-14: second review. Replaced refresh rotation with stable refresh tokens for confidential apps (public clients get none until 1.x). Added groups in the ID token and userinfo, logout on membership removal, lean access tokens, group keys, session timeouts, the last-admin rule, sign-up notices, the honest limit of emergency key revocation, the post-restore checklist and the backup manifest. Split the first release in two (0.1 local, 0.2 cluster), giving 0.1 to 0.5 before 1.0. Access-rule enforcement moved to 0.1.
- 2026-11-15: no legacy-option warnings before 1.0 (the `SESSION_TTL` refusal was removed). The old yUML diagrams were deleted, with a reminder to recreate that documentation before 1.0. The split of `internal/api` was done before the review of parts 2 and 3.
- 2026-11-15: `/api/v1` replaced the old routes without aliases. Users set their own email only once verification exists (0.3); emails set by administrators count as verified.
- 2026-11-15: the "console" is now called the management UI (account area and admin area), and the hosted pages the sign-in pages. `docs/USERS.md` lists the users and their requirements, `docs/PAGES.md` the pages. Decided: users see their groups, owners see linked apps and add members by exact username or email, admins can sign an account out everywhere. App admins stay in 1.x but their part is documented. Proposed, not yet decided: hidden groups and single-app groups.
- 2026-11-15: hidden groups moved to the 1.x candidates. The admin area opens on an overview with aggregated figures only; pages with personal data are opened deliberately.
- 2026-11-15: single-app groups decided (backend in 0.1, clean-up with audit retention in 0.5). Copying groups added to the 1.x candidates. Personal data appears only where someone went to see it: the account area also opens on a start page without personal details, and the profile masks the email until shown.
- 2026-11-15: page contents reviewed: passwords typed twice, sign-up signs the user in, session IPs masked like emails, admin-created accounts change their password at first sign-in, temporary passwords typed by the admin (a generate button in 0.5).
- 2026-11-19: Home (`/`, H0) replaces the account area start page; it arrives with the management UI in 0.4, and until then a simple Home in the sign-in page style lists the user's apps. The sign-in pages of 0.1 are built; optional `HELP_URL` and `PRIVACY_URL` fill their footer.
- 2026-11-19: 0.1 done. Single-app groups built in the backend. The sign-in pages are dark only; light mode is not planned for now. The owner checked the whole flow with Grafana; `docker-compose.yml` renames Grafana's built-in user and gives accounts without an email a placeholder address for Grafana.
- 2026-11-19: backup and restore built (0.2). The manifest sits at the start of the backup file instead of in a sidecar, with the checksum at the end. The deletion log moved to 0.3, with account deletion. Destructive commands are audited instead of counted in a metric, since they run outside the server. Chart features wait until the cluster is ready; local development continues.
- 2026-11-19: 0.3 started with email (part 1). Decided while building: the email queue is in memory (a lost email means asking for a new link); a confirmation link signs in only in the browser that signed up, so mail scanners cannot; an unconfirmed sign-up is removed after 48 hours; the first account to confirm an address gets it.
- 2026-11-19: re-authentication built (0.3 part 2). It moves the session's OIDC `auth_time` instead of keeping a separate time, so apps see the newer sign-in too. The password change no longer asks for the current password; the re-authentication window replaces it.
- 2026-11-20: two-factor built (0.3 part 3). TOTP is Guardian's own code instead of `pquerna/otp`; the QR code uses `rsc.io/qr`. Between the password and the second factor there is no session, only a sealed flow cookie; a setup is carried in a sealed token, so nothing is saved until it is finished. An administrator's or group owner's session without two-factor cannot use their rights.
- 2026-11-20: account deletion built (0.3 part 4). A deleted account keeps its group memberships aside and gets them back on restore. "Erase now" also works on an account that is not deleted yet. Audit retention moves to 0.5, with the clean-up of single-app groups that depends on it.
- 2026-11-20: signing keys and the keyring built (0.3 part 5). The first keyring key encrypts and every key decrypts, so adding a key at the end and promoting it later is a reorder of the Secret. `KEY_ENCRYPTION_KEYS` (inline) is kept beside the file for local development and tests. The chart mounts the keyring as a file, so a rotation needs no restart.
- 2026-11-20: management UI built (0.4). The audit log filters by an exact username on the server (`?username=`), which also finds an account in its deletion grace period; entries name the account, app and group they are about. Disabling or enabling an app or account shows as such in activity lists, from the recorded details.
- 2026-11-20: 0.5 split into four parts. A 0.6 step added before 1.0 (owner's request): review the tests and make sure every requirement is implemented and has at least one test. A passkey signs in on its own, with no further step, and counts as two-factor.
- 2026-11-20: security keys and passkeys built (0.5 part 2). The sign-in pages run the key dialogs with plain form posts (the options in the page, the answer in a form field), so their CSP stays without `connect-src`. Removing the password from an account is not part of 0.5.
