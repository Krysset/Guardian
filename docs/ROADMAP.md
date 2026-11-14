# Guardian roadmap to 1.0

Status: agreed plan, consolidated 2026-11-13 after a full design review and revised 2026-11-14 after a second review. `Agents.md` has the short version. Change this document when a decision changes, and say so in the change log at the bottom.

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
  - The console warns when there is only one admin. MFA setup makes the user confirm a recovery code before it finishes.
- **Apps only see the groups linked to them** (`app_group`).
- **Per-app access rule:**
  - **"Members of linked groups only"** is the default. Guardian refuses everyone else at sign-in with a clear message, and no code is issued.
  - **"Anyone with an account"** is the alternative.
- **Per-app "require MFA" setting.** Guardian enforces it during sign-in, either with the second-factor prompt or by walking the user through setting one up.
- **Group owners (delegation):**
  - A group can name an owner group, whose members manage the owned group's membership.
  - Only global admins change system groups or ownership.
  - Apps, and linking groups to apps, are global-admin only in 1.0.
  - Every delegated action is audited, recording which ownership was used.
- **Machine access for apps:**
  - The `client_credentials` grant.
  - A read-only API (`/api/v1/apps/self/...`), limited to the calling app, for its linked groups, their members, and user lookup by id.
  - All changes are made in Guardian.

### Accounts and sign-in
- **Sign-up** is open and auto-approved. It needs a username and password; email is optional.
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
  - The console shows one shared dialog and retries the save automatically.
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
    - Each backup gets an unencrypted sidecar file with no personal data: format and schema version, time, row counts per table, the size and SHA-256 of the encrypted file, and the keyring key id it needs.
    - `guardian backup verify` checks a file against its manifest without the private key.
    - Metrics report the time and counts of the last successful backup.
    - A restore drill with the private key is documented, because only a real restore proves a backup works.
- **Rules for destructive commands** (key revoke, `mfa reset-totp --all`, restore):
  - They exist only as CLI commands, so Kubernetes RBAC on `pods/exec` decides who can run them.
  - They do a dry run by default. To execute they need `--execute`, `--reason`, and the issuer host typed back (or `--confirm=<host>`).
  - Each run is audited and increments a metric.
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
  - One hostname. `/account`, `/admin` and `/_app` (the console's script and style files) go to the frontend; everything else goes to the backend.
  - The chart offers an optional standard `Ingress` (with `className`) and an optional Gateway API `HTTPRoute` (with `parentRefs`). It never creates a Gateway, and contains nothing Traefik-specific.
  - The NetworkPolicy ingress source is a value. HTTPS is required unless a dev flag is set. `TRUSTED_PROXY_HOPS` is a value, default 1.

### Data protection (GDPR)
- **Account deletion:**
  - Self-service in the console, as a protected change.
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
  - `golang-jwt` for tokens, `go-webauthn/webauthn` for WebAuthn, `pquerna/otp` for TOTP, `filippo.io/age` for backup encryption, and `net/smtp` behind a `Mailer` interface.
  - Everything is embedded (migrations, templates, static files).
  - The image is distroless, non-root, with a read-only root filesystem.
- **Hosted pages** (login, sign-up, consent, logout, reset, MFA): server-rendered Go `html/template` in the approved Guardian design. They work without JavaScript, except for the security-key prompt.
- **Console** (`/account`, `/admin`):
  - Svelte 5 + SvelteKit (`adapter-static`) + TypeScript.
  - Plain CSS with tokens shared with the hosted pages.
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
├── frontend/                      # SvelteKit console, Dockerfile, nginx.conf
├── charts/guardian/               # see Agents.md for the template list
└── docs/
    ├── ROADMAP.md, ARCHITECTURE.md, INTEGRATION.md, TESTING.md
    ├── INSTALL.md (incl. runbooks), DATA-PROTECTION.md, openapi.yaml
    └── design/                    # login mockup, logo, background
```

## 5. Release plan

Everything runs in a staging environment with test data until 1.0. Guardian is not opened for public sign-up before then.

### 0.1: it runs locally
- **M0: make it run. Done 2026-11-14.**
  - CI moved to the root `.github/`; the Dockerfile and `docker-compose.yml` were fixed.
  - The backend builds, and all 102 tests pass against PostgreSQL 16. One bug was found and fixed.
  - Still to do by the owner: check `docker compose up --build`, push, and merge `oidc-refactor` into `dev`.
- **M1: restructure.** Move to `cmd/` and `internal/`, add the config package with validation, goose, slog, pgx and embedded assets. No behaviour changes.
- **Groups and JWT:**
  - Rewrite `00001_init.sql`: groups with keys, `app_group`, group owners, the per-app access rule and require-MFA flag, key stages, keyring tags, the deletion log; no phone or birthdate.
  - Lean JWT access tokens, the `groups` scope, refresh re-checks with stable refresh tokens for confidential apps, and session idle and absolute timeouts.
  - `client_credentials` and the machine API.
  - Remove `/introspect`.
  - **Enforce the per-app access rule** and the last-admin rule.
- **API and pages:**
  - `/api/v1` with REST routes and `openapi.yaml`; admin checks through `guardian-admins`.
  - The hosted login, sign-up (with its notices), consent, logout and error pages in the approved design.
- **Done when:** with docker-compose, a test app and Grafana sign in through OIDC and receive the right groups.

### 0.2: it runs in the cluster
- A minimal chart: backend, bundled or external Postgres, Ingress/HTTPRoute, required Secrets, startup migrations.
- `guardian backup` and `guardian restore`, with the deletion log, the manifest and the rules for destructive commands.
- **Done when:** installed via Argo CD in the staging cluster, and a backup restores into a fresh install.

### 0.3: accounts
- Mailer, email verification and change, password reset, `REQUIRE_EMAIL`, and security notices.
- TOTP, recovery codes, the MFA challenge, the recovery ladder, admin MFA reset.
- **Mandatory MFA for admins and group owners, and enforcement of the per-app "require MFA" setting.**
- Re-authentication and the protected-change list.
- Account deletion with the grace period and hard delete, and "download my data".
- The signing-key lifecycle with automatic rotation, the encryption keyring with re-encryption, and the runbook commands.
- Abuse protection (login limits and the honeypot).
- **Done when:** end-to-end tests cover reset, verification, MFA sign-in, re-authentication, deletion, and key and keyring rotation.

### 0.4: console
- The SvelteKit console:
  - `/account`: profile, security, sessions, connected apps, data export, deletion;
  - `/admin`: accounts, apps, groups, audit log.
- Group owners and their scoped admin view.
- **Done when:** everything in the console list can be done without curl.

### 0.5: complete
- WebAuthn and passkeys, including passwordless sign-in.
- Scheduled backups, audit retention, and migration job mode (Helm hooks and Argo CD waves).
- The full chart: frontend deployment, HPA, PDB, NetworkPolicy, ServiceMonitor, `ci/` values tested with chart-testing on kind.
- Release workflow (images to GHCR, chart as OCI).
- SonarQube integrated and its staleness behaviour documented.
- **Done when:** every 1.0 feature is in place and a clean `helm install` works with both bundled and external Postgres.

### 1.0: release
- **M7 hardening:**
  - a real browser over TLS;
  - SIGTERM handling and readiness when the database is down;
  - proxy hops;
  - a refresh load test against the p99 target;
  - multi-replica and multi-cluster behaviour;
  - a security review.
- **Docs:** `INSTALL.md` (with runbooks), `INTEGRATION.md`, `ARCHITECTURE.md`, `DATA-PROTECTION.md`, `openapi.yaml`, `CHANGELOG.md`.
- **ES256** only if it doesn't delay the release.
- **After tagging,** `00001_init.sql` is frozen and the compatibility rules apply.

### Release checklist for v1.0.0
- [ ] CI is green, including end-to-end tests against Postgres and the chart-testing install.
- [ ] Removing a user from a group, or disabling them, reaches a refreshing app within its `access_token_ttl_seconds`, and sends a back-channel logout that reaches an app implementing it.
- [ ] Parallel refreshes with the same token all succeed, and the token stops working the moment its session ends.
- [ ] A backup restores into a fresh install, and `--apply-deletions` keeps erased accounts erased.
- [ ] Signing-key rotation and keyring rotation run on a live multi-replica install without errors at the apps.
- [ ] A sample app integrates by following only `INTEGRATION.md`.
- [ ] No secrets or personal data in logs. The images run as non-root with read-only root filesystems.
- [ ] All docs listed above are current.

## 6. After 1.0 (1.x candidates)

- **App owners:** an owner group edits its app and links only groups it owns.
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
