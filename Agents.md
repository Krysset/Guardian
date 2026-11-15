# Agents.md — Guardian

Hand-off notes for AI agents (and humans). Read this first in a new session, then `docs/ROADMAP.md`. Update both when decisions change.

## What Guardian is
- OIDC provider and account service with per-app permissions, similar in function to Authentik. It is meant to be the single source of truth for users and for what they may do in each app.
- Named after the Guardian enemies in *Zelda: Breath of the Wild*; the visual identity follows from that.
- Deployed to Kubernetes as one Helm release (frontend, backend, Postgres connection). Other services, usually in the same cluster, call it over HTTP.

## Hard requirements (do not trade these away)
- Open sign-up, rate limited.
- **Bounded staleness** (changed 2026-11-13; earlier docs said "immediate"):
  - Group changes, logout and disabling reach an app within its `access_token_ttl_seconds`. This is configurable per app, with a floor of 15 seconds.
  - Every refresh re-checks session, account, app and groups.
  - Back-channel logout makes logout and disabling immediate for apps that implement it.
- **Do not overload Guardian:** there is no per-request call from apps. Apps validate JWT access tokens locally and only call Guardian to refresh.
- **Integration is just "use any OIDC library and read the `groups` claim"**, plus an optional read-only machine API via `client_credentials`.
- Prometheus metrics from the backend.
- Helm chart with Traefik as an ingress option (not nginx).

## Environment
- Owner works on Windows; repo is at `D:\Projekt\Guardian`.
- Branches: `main`, `dev`, `oidc-refactor`. Work happens on `oidc-refactor`. Nothing has been pushed or merged by an agent; the owner decides when.
- **Where things can run (checked 2026-11-14):**
  - **The cloud workspace** has PostgreSQL 16 (start it as the `postgres` user with `initdb` and `pg_ctl`) and gofmt, but no network. Go 1.24 is preinstalled, which is too old for the repo; unpack the Go 1.26 toolchain from `.tools/` instead. Go modules cannot be downloaded there.
  - **The shell on the owner's PC** (`device_bash`, a Linux VM with the repo mounted at `$HOME/mnt/Guardian`) has git, python3, tar and gcc, but no Go, no Postgres, no Docker and no network.
  - **Go dependencies** therefore come from `backend/vendor/` (the owner runs `go mod vendor` on Windows; the folder is git-ignored). Access to the owner's Go module cache folder was denied by policy; do not ask again.
  - **Docker cannot run in either place.** The image and compose setup are verified by the owner, or by the `image` job in CI.
- **Moving files between the two:**
  - PC to cloud: `git archive` or `tar` in the VM into the repo folder, then `device_stage_files` on that one file. Delete the transfer file afterwards.
  - Cloud to PC: write patches (`git diff --no-renames --binary`), tar them into `/mnt/user-data/outputs/`, send with `device_commit_files`, check the SHA-256 in the VM, then `git apply --index`.
  - Renames that only change letter case (for example `dockerfile` to `Dockerfile`) fail in a patch on the Windows disk. Use `git mv` through a temporary name.
- **Git in the VM:**
  - Always pass `-c core.autocrlf=true`. The owner's Windows checkout has CRLF files, and without it they show as modified.
  - The VM has no git identity. Commit with the author of the latest commit: `-c user.name="$(git log -1 --format=%an)" -c user.email="$(git log -1 --format=%ae)"`.
  - Deleting files, including git's own lock files, needs `device_request_delete_permission` once per session.
- After writing single files to the PC with `device_commit_files`, check size or checksum. It has several times written the *previous* version of a file; committing again with `force` fixed it.

## Repository map (current)
- `backend/` — Go module `guardian` (Go 1.26): chi, pgx, goose, golang-jwt, prometheus. About 3,300 lines plus a large test suite.
  - `cmd/guardian/main.go` — the entry point: loads `.env` if present, loads and validates the configuration, sets up logging, runs the server.
  - `internal/config/` — every environment variable in one place, validated at startup; all problems are reported at once.
  - `internal/server/` — wiring: opens the database, loads keys, builds the two routers, runs both listeners and shuts down cleanly.
    - Public `:3001`: OIDC, hosted pages, `/api`.
    - Internal `:3002`: `/metrics`, `/healthz`, `/readyz`.
  - `internal/api/` — HTTP handlers, still one package:
    - `oidc.go` — discovery, authorize, token, userinfo, jwks, consent.
    - `login.go` — login/logout and back-channel logout.
    - `account.go`, `app.go`, `groups.go` — `/api/account`, `/api/service`, `/api/groups` (REST style).
    - `machine.go` — the machine API at `/api/v1/apps/self` (Bearer `client_credentials` tokens) and the client_credentials grant.
    - `internal.go` — internal router (metrics and probes).
    - `templates.go` — inline hosted-page HTML.
    - `middleware.go` — session, CSRF, `Authenticate`, `RequireAdmin` (member of `guardian-admins`), `RequireSameOrigin`.
  - `internal/auth/` — argon2id, AES key encryption, RSA signing keys and JWKS.
  - `internal/store/` — queries (imported as `db`); `connection.go` connects and applies migrations with goose at startup.
  - `migrations/00001_init.sql` — the full data model, described below. It is embedded into the binary.
  - `internal/testutil/` — helpers for tests that need Postgres.
  - `e2e/` — end-to-end tests over HTTP against both routers.
  - Tests: 124, all passing (`docs/TESTING.md`).
- `charts/guardian/` — only an empty `Chart.yaml` and empty `helper/` and `images/` folders so far.
- `frontend/` — empty.
- `docs/` — `ARCHITECTURE.md` (design decisions, load, mermaid diagrams), `INTEGRATION.md`, `TESTING.md`, `ROADMAP.md`. The old yUML diagrams were deleted (2026-11-15); recreating app-to-Guardian communication diagrams is a 1.0 docs item in `docs/ROADMAP.md`.

## Data model (backend/migrations/00001_init.sql)
- `account` — the OIDC subject; profile columns map 1:1 to standard claims. Status is pending, active, disabled or locked. Soft delete via `deleted_at`.
- `app` — an OIDC client: public or confidential, redirect URIs, PKCE, first-party (skips consent), TTLs. `app_secret` allows several active secrets, so rotation can overlap.
- `scope`, `app_scope`, `account_consent` — standard and custom scopes, and the scopes a user has consented to.
- **Groups** (the old roles, permissions and the effective-permission view are gone):
  - `user_group` — the group itself ("group" is a reserved word). It has an immutable `key` (what apps see), an editable `display_name`, `is_system`, and an optional `owner_group_id`.
  - `group_member` — membership, with optional `expires_at`. Expired rows do not count.
  - `app_group` — which groups an app is told about.
  - `app.access_rule` — `groups` (the default: only members of a linked group may sign in) or `anyone`.
- Session and token tables: `session` (SSO; `last_seen_at` drives the idle timeout, `expires_at` is the absolute end), `authorization_code`, `refresh_token` (one stable token per sign-in and app, bound to the session; `family_id` unused, kept for rotation later), `session_app` (for back-channel logout), `signing_key`. Access tokens are signed JWTs and are not stored.
- `account_token` — one-time tokens for reset, verification, re-authentication and invites. `account_mfa` holds TOTP, WebAuthn and recovery codes. Both are unused so far.
- `rate_limit` (UNLOGGED) and `audit_log` (append-only).
- Seed data: standard scopes; the system group `guardian-admins`; and an `admin` account in that group with no password, set at startup from `ADMIN_INITIAL_PASSWORD` or logged once. No app is seeded.

## Agreed chart layout
```
charts/guardian/
├── Chart.yaml                 # version = chart semver, appVersion = image tag for both images
├── values.yaml
├── values.schema.json         # fails early on missing host, DB, or secret
├── ci/                        # chart-testing values: default, ha, external-db
├── templates/
│   ├── _helpers.tpl, NOTES.txt, serviceaccount.yaml, configmap.yaml
│   ├── ingress.yaml           # optional standard Ingress; one host, path routing (/account, /admin -> frontend; rest -> backend)
│   ├── httproute.yaml         # optional Gateway API HTTPRoute, same routing, attaches to an existing Gateway
│   ├── networkpolicy.yaml
│   ├── postgres/ statefulset, service, secret   # only when database.mode=bundled
│   ├── backend/  deployment, service (public), service-internal, hpa, pdb, servicemonitor
│   ├── frontend/ deployment, service, hpa, pdb
│   └── tests/test-connection.yaml
```

## Decisions (2026-11-13; see ROADMAP.md for the reasoning)
- **Groups replace per-app permissions.** Apps only see the groups linked to them; groups are flat; grants carry no attributes.
- **Access tokens are short-lived signed JWTs.**
  - Lifetime is the app's `access_token_ttl_seconds`, minimum 15 seconds.
  - Claims: `sub`, `aud`, `scope`, `sid`, `groups` and the profile claims for the granted scopes.
  - They are not stored in the database.
- **`/introspect` is removed.**
  - The internal `:3002` listener keeps only `/metrics`, `/healthz` and `/readyz`.
  - RFC 7009 revocation covers refresh tokens.
- **Machine access for apps:** the `client_credentials` grant, plus a read-only API limited to the calling app (its linked groups, their members, user lookup by id).
- **Signing keys:**
  - Four stages: pending (published but not signing, 1 h), active (one per algorithm), retiring (until the longest token lifetime plus skew has passed), retired.
  - Replicas reload every 60 seconds; JWKS is served with `max-age=900`.
  - Automatic rotation every 90 days; `guardian keys rotate`, plus `--now --revoke-current` for emergencies.
  - **RS256 / RSA-2048 for 1.0.** Never hardcode the algorithm: there is an app-level signing-alg setting.
  - ES256 is a late stretch goal before 1.0, otherwise 1.x.
- **Encryption keyring:**
  - Read from `KEY_ENCRYPTION_KEYS_FILE` and reloaded every 60 seconds; values are tagged with their key id; the row is bound as associated data.
  - New keys are added decrypt-only, then promoted; background re-encryption follows.
  - Guardian refuses to start when a key is missing.
  - Secrets come via `existingSecret`, filled by Bitwarden (owner's choice). No KMS integration.
- **Versioning:**
  - In 0.x the schema may change; edit `00001_init.sql`; upgrades go through backup and restore.
  - From 1.0: minor releases use expand/contract with a CI compatibility check; major releases mean back up, then upgrade, starting from the last previous minor.
  - Forward-only: recovery is a restore, never a down migration.
- **Migrations:** goose; `migrations.mode: startup` (default) or `job` (Helm hook and Argo CD Sync hook with waves: Postgres -2, Job -1, apps 0). In job mode the backend waits for the expected schema version. The owner uses Argo CD; plain Helm must keep working.
- **Backup and restore:** `guardian backup` and `guardian restore` via `kubectl exec`.
  - Guardian's own versioned format, `age`-encrypted to a public key (private key in Bitwarden). Sessions and tokens are excluded.
  - Restore only into an empty database; a deletion log keeps erased accounts erased.
  - Must exist in the first real install.
- **Secrets:** the chart generates none, because Argo CD renders without `lookup`. Everything comes from operator-provided Secrets, and the schema fails the install when one is missing.
- **Bundled Postgres:**
  - Single instance with the major version pinned; the disk is kept on uninstall.
  - Basic options: tag, resources, storage, placement, Postgres settings, security context.
  - Password rotation is manual, by runbook; there is no sync sidecar (owner's decision).
- **Availability:**
  - The backend must work with any replica count (default 2 plus a PDB).
  - Production should use an external HA Postgres.
  - Apps treat `invalid_grant` as a logout, but keep the session through Guardian network errors for about one token lifetime.
- **Scheduled backups:** a CronJob writes to its own disk claim in 1.0; S3 comes in 1.x.
- **Console hosting:** the same hostname with path routing (`/account` and `/admin` to the frontend, the rest to the backend); the console uses Guardian's session cookie. The owner wants replica control and multi-cluster support. Backends in several clusters share one Postgres, with no cluster-local state.
- **Delegation:**
  - 1.0 has group owners: an owner group manages an owned group's members. Only global admins touch system groups, and owners can't change their own ownership. Delegated actions are audited.
  - Apps and their group links are global-admin only in 1.0. App owners come in 1.x.
- **Recovery and MFA:**
  - A reset changes only the password; MFA still applies.
  - Recovery ladder: another factor, then a recovery code, then an audited admin reset.
  - Protected changes need re-authentication at save (`reauth_required` → console dialog → retry), with a 5-minute grace period.
  - MFA is mandatory for global admins and group owners.
  - Tokens carry `amr`. A per-app "require MFA" setting is enforced at sign-in; `acr_values` comes in 1.x.
  - Passkey-only accounts are allowed.
- **App access rule:** "linked groups only" (the default, enforced by Guardian at sign-in) or "anyone with an account". Sign-up is always open and auto-approved, with no default groups. A "request access" screen comes in 1.x.
- **Scope boundary:** Guardian does identity and groups only; apps own per-record authorization. Keep the docs on this short.
- **GDPR:**
  - Deletion: 30-day grace period, then a hard-delete job, with the id added to the deletion log.
  - Audit log retention is 6 months by default; personal details are removed from the entries of erased accounts.
  - "Download my data" export in the console.
  - `phone_number`, `birthdate` and the `phone` scope are removed.
  - Logs hold account ids only. `docs/DATA-PROTECTION.md` documents it all.
  - A restore re-applies the deletion log; `--apply-deletions` handles restoring an older backup.
- **Abuse protection:** login limits per username+IP and per IP, never an automatic lock; a sign-up honeypot; no third-party CAPTCHA. Proof-of-work comes in 1.x.
- **Routing:** an optional standard `Ingress` and an optional Gateway API `HTTPRoute`; nothing Traefik-specific. The NetworkPolicy ingress source is configurable, HTTPS is required, and `TRUSTED_PROXY_HOPS` is a value (default 1).
- **Destructive commands** (emergency key revoke, `mfa reset-totp --all`):
  - CLI only, gated by Kubernetes RBAC.
  - Dry run by default; they need `--execute`, `--reason` and the issuer host typed back.
  - Audited and counted in a metric.
  - Idempotent: single-step commands run in one transaction, and re-encryption resumes where it stopped.
- Hosted auth pages (login, sign-up, consent, logout, reset, MFA) stay **server-rendered Go templates**: they work without JavaScript, allow a strict CSP and share the session cookie's origin.
- The account and admin console is **Svelte 5 + SvelteKit (adapter-static) + TypeScript**, styled with plain CSS tokens; no Tailwind in 1.0. It runs on the same origin and uses the session cookie, so it needs no OIDC client of its own.
- Migrations will use goose with embedded SQL; `schema.sql` becomes `00001_init.sql`. The driver moves to pgx (stdlib); logging to slog.
- The API moves to `/api/v1` with REST verbs and Guardian-permission checks (not role-name checks), documented in `docs/openapi.yaml`.
- WebAuthn security keys and passkeys are **in 1.0**, built on the latest spec and library (go-webauthn), alongside TOTP and recovery codes. The login page's "Use a security key" button stays.
- The frontend is its **own deployment**, so it can scale and be hosted separately; it is not embedded in the Go binary.
- **Email is optional at sign-up and never stored unverified.**
  - An entered address waits in `account_token` until its link is clicked.
  - `account.email` is always verified or NULL.
  - Login works with a username or that email; resets only go there.
  - `REQUIRE_EMAIL` (default off) makes an email mandatory at sign-up.
  - Sign-up reports a taken username or email plainly; login and reset never reveal whether an account exists.
- The chart supports `database.mode: bundled | external`.
  - Bundled is the default: a single-instance Postgres StatefulSet using the official image, with its PVC kept on uninstall.
  - External is for managed or HA databases.
  - A CloudNativePG option is planned for after 1.0.

## M0: done (2026-11-14)
- **Build and tests:** `go build ./...` and `go vet ./...` pass. All 102 tests pass with `-race` against PostgreSQL 16, with none skipped. The tests had never been run before.
- **One real bug found and fixed:** registering an app without `post_logout_redirect_uris` failed, because a missing list was stored as NULL in a NOT NULL column. `database.strArray` now binds a nil slice as an empty array.
- **Smoke test:** the static binary starts against Postgres, serves discovery, JWKS, the login page, health and metrics, and the admin can sign in and register an app.
- **Infrastructure:**
  - gofmt on all Go code.
  - A multi-stage distroless `backend/Dockerfile` (renamed from `dockerfile`) and `.dockerignore`.
  - `docker-compose.yml` with the right `DB_*` names, ports 3001/3002, a dev key, Postgres 16 with a health check, and Mailpit.
  - CI at `.github/workflows/backend.yml` (format check, vet, tests against Postgres, image build).
  - `.gitattributes`, `.gitignore`, `README.md` and `TESTING.md` updates.
- **No tests were deleted in M0.** The tests for introspection and the old permission model were replaced in the groups and tokens work.
- **Not verified:** the Docker image build and `docker compose up` (no Docker available to the agent), and the CI workflow (nothing has been pushed).
- **Left to the owner:** pushing, and merging `oidc-refactor` into `dev`.
- **Fixed since, in the groups work:** admin routes used to mix `OnlyAdmin` and `RequirePermission`, and any signed-in user could list all apps.

## Login page design (approved)
Mockup: claude.ai artifact "Guardian – login page" (https://claude.ai/artifact/TCheh3oE3wEhtFxMxKY59J). It is to be implemented in the Go templates (milestone M3).
- Full-screen background: BotW screenshot of the wall with the destroyed Guardians, `cover`.
- Left bar `min(460px, 100%)`, full height, translucent white `rgba(255,255,255,.80)` with `backdrop-filter: blur(14px)`. On phones under 560px it is full width.
- The logo (white SVG, viewBox `0 0 275.52 282.11`) is **cut out of the bar** with a CSS mask (`mask-composite: exclude`), so the background shows through it. A small script aligns the mask to an empty `.logo-slot` element.
- Logo is centered horizontally above the form (168px, or 128px on mobile). Logo, "Sign in" heading and fields form one vertically centered group.
- Footer pinned to the bottom: Help, Privacy, "Powered by Guardian".
- Copy: the heading is just "Sign in", with no "continue to <app>" line (the owner removed it). Fields are "Username or email" and "Password", with "Forgot password?" on the password label row. Buttons are "Sign in", an "or" divider, and "Use a security key" (WebAuthn/passkey, in 1.0).
- Tokens:
  - Sheikah teal `#0b6f7c` (hover `#085b66`; dark mode `#4fd1e0`).
  - Ink `#1b2a2e`, muted `#4d6469`, lines `#9db4b8`, 6px radius.
  - Font: Figtree.
  - Dark panel: `rgba(14,26,30,.78)`.
- Unused idea: Guardian-beam orange/red as a bolder accent.

## Second review (2026-11-14)
- **Tokens:**
  - Access tokens are lean (`sub`, `aud`, `scope`, `sid`, `amr`, `groups`) with type `at+jwt`. Profile data is in the ID token (re-issued at refresh) and `/userinfo`.
  - The `groups` scope puts group keys in the ID token, userinfo and access token. Apps key users on `sub`.
  - The docs recommend a lifetime of 60 seconds or more; the floor stays at 15.
- **Refresh tokens (confirmed):**
  - Stable, non-rotating, for apps with a client secret. There is no grace window and no reuse detection.
  - Apps without a secret get none in 1.0.
  - The owner needs a mobile app later, so rotation for public clients returns in 1.x. Keep the per-app refresh mode setting (`stable`, `none`, reserved `rotating`), a single issuing function, and the family id column.
- **Sessions:** idle timeout 7 days, absolute 30 days, configurable. Refresh tokens never outlive the session.
- **Membership removal and disabling send a back-channel logout.** Apps that neither refresh nor support it are as stale as their own session.
- **Planned off-the-shelf apps:** Grafana and SonarQube. Argo CD deliberately does not use Guardian, to avoid lock-out.
- **Groups have an immutable key** (in tokens) and an editable display name.
- **Last admin:** `guardian-admins` always keeps one active member. The owner wants **no break-glass command**; recovery is a documented SQL statement.
- **Sign-up page notices:** no email means admin-only password reset; hobby project under active development; use a unique password.
- **Security notices by email** for password and MFA changes.
- **Emergency key revoke:** the runbook admits apps keep accepting old-key tokens until their key cache expires, and tells the operator to restart them.
- **Restore:** a post-restore checklist, because an older backup reverts security changes.
- **Backup manifest (confirmed):** an unencrypted sidecar with counts and checksum, `guardian backup verify`, metrics, and a restore drill.
- **Routing:** `/_app` also goes to the frontend.
- **Staging only until 1.0;** all data before then is test data.

## Status and next step (2026-11-14)
- **Two design reviews are complete.** `docs/ROADMAP.md` is the source of truth; if this file disagrees, it wins.
- **No open confirmations.**
- **Release plan:**
  - **0.1 local:** M0, M1, groups and JWT, access-rule enforcement, `/api/v1`, hosted pages including sign-up; runs with docker-compose.
  - **0.2 cluster:** minimal chart, backup and restore, install via Argo CD in staging.
  - **0.3 accounts:** email, TOTP, mandatory admin MFA, require-MFA enforcement, re-authentication, GDPR deletion and export, key and keyring rotation, abuse limits.
  - **0.4 console:** account and admin console, group owners.
  - **0.5 complete:** WebAuthn and passkeys, scheduled backups, job migrations, the full chart, the release workflow.
  - **1.0:** hardening, docs, and ES256 if time allows.
- **M1 is done** (2026-11-14), on branch `implement-m1`. The owner reviews changes before anything is committed: **do not commit on the owner's branches unless asked**; leave changes staged.
  - **Part 1:** the move to `cmd/guardian`, `internal/{api,auth,store,server,config}`, `e2e/` and `migrations/`; the config package with validation; structured logging with `log/slog` (`LOG_FORMAT`, `LOG_LEVEL`); the schema embedded in the binary.
  - **Part 2:** goose migrations and the pgx driver.
    - `migrations/00001_init.sql` is a goose migration: `-- +goose Up` with one statement block and no `BEGIN`/`COMMIT` of its own. It still takes its advisory lock and stays idempotent.
    - `store.Migrate` runs goose with a Postgres session lock, asking for the lock once a second; `store.Open` calls it. `guardian migrate` applies migrations and exits.
    - The driver is `pgx/v5/stdlib` (pgx 5.13, goose 3.30). Arrays are scanned through `store.scanArray` and passed with `store.strArray`. Unique violations are detected with `pgconn.PgError`.
  - **Verified with Go 1.26.11 and PostgreSQL 16:** build, vet, gofmt, and all 110 tests with `-race`. The binary was also run against a fresh database, against a database created before goose (it adopts it and keeps edited rows), and with `guardian migrate`.
  - **Not verified:** the Docker image build and CI.
  - **Deliberately not in M1:** splitting `internal/api` into `oidc`, `web`, `httpx` and `internalapi`. Those handlers are rewritten in the groups and JWT step, so the split happens there.
- **Groups and JWT work of 0.1, in parts** (on branch `dev`; leave changes staged for the owner's review):
  - **Part 1, groups: done and tested, staged for review (2026-11-14).**
    - Schema: `user_group`, `group_member`, `app_group`, `app.access_rule`. Roles, permissions and the seeded `guardian` app are removed.
    - Store: `internal/store/groups.go`. The last-administrator rule lives there: one active account must always be in `guardian-admins` through a membership without an expiry. It is enforced on member removal, on adding an expiry and on account deletion, under a row lock on the administrators group.
    - API: `/api/groups` (REST). Administrators do everything; a group's owners (members of its owner group) may only list, add and remove its members. `/api/service` is now administrators only, with `POST /api/service/access` for the access rule and linked groups.
    - Sign-in: `/authorize` enforces the app's access rule; refused accounts get a 403 page, or `access_denied` with `prompt=none`.
    - **Schema revision check:** `00001_init.sql` records a fingerprint of itself (table `schema_revision`; comments and blank lines do not count) when it creates a database. `store.VerifySchemaRevision` compares it at every start and refuses a database made by another revision, with a message that says to recreate it. So after any edit to `00001_init.sql`, existing development databases must be recreated (`docker compose down -v`); tell the owner when a change needs that.
  - **Part 2, tokens: done and tested, staged for review (2026-11-15).**
    - Access tokens are signed JWTs (`typ: at+jwt`) with `sub`, `aud`, `client_id`, `scope`, `sid`, `amr`, `jti` and, with the `groups` scope, `groups`. No profile data. Not stored. The ID token carries profile claims and `groups`, and is issued again at every refresh.
    - `api.issueTokens` is the single place that decides whether a user may (still) have tokens for an app. Every code exchange and every refresh goes through it and re-checks live data: session (idle and absolute), account, the app's access rule, groups.
    - Refresh tokens: `refresh_mode` per app, `stable` (confidential apps; one token per sign-in, never replaced, valid while the session lives) or `none` (public apps). A refresh returns no new refresh token. `offline_access` is accepted but changes nothing.
    - `POST /revoke` (RFC 7009) for refresh tokens, confidential apps only, always 200.
    - `/userinfo` verifies the access token (rejects ID tokens by `typ`) and checks session, account and app live; returns current groups.
    - Sessions: `SESSION_IDLE_TIMEOUT` (default 168h) and `SESSION_MAX_LIFETIME` (default 720h) replace `SESSION_TTL` (removed; no warning for it). Refreshes and userinfo count as use.
    - Back-channel logout also on account deletion and on leaving a group (only apps linked to that group).
    - Removed: `/introspect`, the `access_token` table, `INTROSPECTION_URL`, `phone_number`, `birthdate`, the `phone` scope. Token lifetime 15-86400 seconds (database CHECK), default 300.
    - Metric `guardian_token_requests_total{grant,result}` replaces the introspection counter.
    - `docs/INTEGRATION.md` is rewritten for the new design.
  - **Part 3, machine API: done and tested, staged for review (2026-11-15).**
    - `client_credentials` grant for confidential apps that have it in `grant_types`; turned on and off with `"machine_api"` on `POST /api/service/access` (checked before anything changes). Token: `at+jwt`, `sub` = `client_id` = the app's client id, `aud` = the issuer, no `sid`, lifetime `access_token_ttl_seconds`, no refresh token.
    - `GET /api/v1/apps/self`, `/groups`, `/groups/{key}/members`, `/users/{sub}`. Read-only. Mounted outside the cookie API, so no same-origin check.
    - Every request re-checks that the app is enabled and still has the grant, so turning access off stops existing tokens at once. User access tokens are refused (audience and `sid`).
    - Visibility: linked groups only; accounts that are active members of a linked group, or that have signed in to the app (new table `app_user`, written when an authorization code is exchanged). Anything else is the same 404 as an unknown account. Claims follow the app's allowed scopes.
    - The owner was away and asked for work to continue and be reviewed together: part 2 and part 3 are staged together on `dev`. Separate diffs are in `.tools/review/` (git-ignored).
  - **Part 4:** split `internal/api` into `oidc`, `web`, `httpx` and `internalapi`.
  - Columns for later features (require-MFA flag, key stages, keyring tags, deletion log) are added to `00001_init.sql` when their feature is built, not before.
- **How to build and test in the cloud workspace:**
  - Go: stage `.tools/go1.26.11.linux-amd64.tar.gz` from the repo, check its SHA-256 (`9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec`), unpack it and put its `bin` first on `PATH`. The preinstalled Go 1.24 is too old.
  - Modules: tar `backend/vendor` in the VM and unpack it in the cloud copy. When dependencies change, the code that imports them must exist first, then the owner runs `go get`, `go mod tidy` and `go mod vendor` in `backend`.
  - Use `GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local` with `GUARDIAN_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=postgres DB_NAME=guardian_test`.
  - Postgres in the cloud workspace is killed between turns; restart it at the start of each command that needs it.
- `docs/ARCHITECTURE.md` was rewritten for the current design on 2026-11-15 (staged with parts 2 and 3). Its four mermaid diagrams render with `mmdc`; keep them in sync when the design changes.

## Working conventions
- Keep this file and `docs/ROADMAP.md` current; they are the hand-off between sessions.
- Never let staleness exceed the app's configured `access_token_ttl_seconds`; every refresh must re-check session, account, app and groups.
- No feature may depend on the number of backend replicas, or on which cluster a replica runs in.
- Secrets and tokens are stored only as hashes or encrypted values; never log query strings on OIDC routes.
- No warnings or refusals for legacy or removed settings before 1.0: nothing is deployed until then, so old options are simply dropped.
