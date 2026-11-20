# Agents.md — Guardian

Hand-off notes for AI agents (and humans). Read this first in a new session. `docs/ROADMAP.md` is the source
of truth for design decisions and the release plan; if this file disagrees with it, the roadmap wins. Keep both
current: they are the hand-off between sessions.

## What Guardian is
- An OIDC provider and account service, similar in function to Authentik: the single source of truth for
  accounts and group membership. Apps map groups to their own permissions.
- Named after the Guardians in *Zelda: Breath of the Wild*; the visual identity follows from that.
- Deployed to Kubernetes as one Helm release (frontend, backend, Postgres). Apps, usually in the same cluster,
  use it over HTTP.

## Hard requirements (do not trade these away)
- Open sign-up, rate limited.
- **Bounded staleness:** group changes, logout and disabling reach an app within its `access_token_ttl_seconds`
  (per app, at least 15 seconds). Every refresh re-checks session, account, app and groups. Back-channel logout
  makes it immediate for apps that support it.
- **No per-request calls from apps:** they validate JWT access tokens locally and call Guardian only to refresh.
- **Integration is "any OIDC library plus the `groups` claim"**, with an optional read-only machine API.
- Prometheus metrics. Helm chart with standard Ingress or Gateway API routing (works with Traefik; nothing
  Traefik-specific).

## Working with the owner
- Leave changes **uncommitted (staged)** so the owner can review them; the owner commits. Do not push or merge.
- Number questions so the owner can answer by number.
- Words: **sign-in pages** (served by the backend), **management UI** (the SvelteKit frontend) with the
  **account area** (`/account`) and the **admin area** (`/admin`), **Home** (`/`). Never "console": the owner
  read that as a terminal. The **CLI** (`guardian ...` via `kubectl exec`) is only for cluster operations.
- No warnings or refusals for legacy or removed settings before 1.0: nothing is deployed until then.
- Light mode is not wanted for now: don't build anything for it.

## Environment
- Owner works on Windows; repo at `D:\Projekt\Guardian`, branch `dev` (`main`, `implement-m1` and
  `oidc-refactor` are older).
- **Where things can run:**
  - **Cloud workspace:** PostgreSQL 16 (start it as the `postgres` user with `initdb` and `pg_ctl`; it is killed
    between turns, so restart it in each command that needs it), gofmt, Chromium with Playwright for
    screenshots. Node 22 and npm. No network except package registries (since 2026-11-20): npm reaches
    registry.npmjs.org only through the agent proxy, so clear the proxy bypass first:
    `export NO_PROXY= no_proxy= npm_config_noproxy=`. The preinstalled Go is too old: unpack `.tools/go1.26.11.linux-amd64.tar.gz`
    (SHA-256 `9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec`) and put its `bin` first on `PATH`.
  - **Owner's PC shell** (`device_bash`, a Linux VM with the repo at `$HOME/mnt/Guardian`): git, python3, tar,
    gcc. No Go, Postgres, Docker or network.
  - **Docker runs only on the owner's PC.** The owner checks the image, compose and the Grafana flow.
- **Go modules** come from `backend/vendor/` (git-ignored; the owner runs `go mod vendor` on Windows). Tar it in
  the VM and unpack it in the cloud copy. When dependencies change, write the code that imports them first, then
  the owner runs `go get`, `go mod tidy` and `go mod vendor` in `backend`. Access to the owner's Go module cache
  was denied by policy; do not ask again.
- **Build and test in the cloud:** `GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local`, and for database tests
  `GUARDIAN_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=postgres DB_NAME=guardian_test`; run with `-race -p 1`.
- **Moving files:**
  - PC to cloud: `git archive` (or `tar`) into a file in the repo, `device_stage_files` it, delete it afterwards.
  - Cloud to PC: `git diff --no-renames --binary` into `/mnt/user-data/outputs/`, `device_commit_files`, check
    the SHA-256 in the VM, then `git -c core.autocrlf=true apply --index`. Check size or checksum after every
    `device_commit_files`: it has written a *previous* version of a file before.
  - Renames that only change letter case fail in a patch on the Windows disk; use `git mv` through a temporary
    name.
- **Git in the VM:** always `-c core.autocrlf=true` (the checkout has CRLF files). Deleting files, including
  git's lock and temporary files, needs `device_request_delete_permission` once per session. To commit (only
  when asked), use the latest commit's author: `-c user.name="$(git log -1 --format=%an)" -c
  user.email="$(git log -1 --format=%ae)"`.
- Review diffs for the owner go in `.tools/review/` (git-ignored); delete them once the work is committed.

## Status (2026-11-20)
- **0.1 is done.** Everything up to and including the sign-in pages, Home, single-app groups and the Grafana
  check is committed (`632a0d4`). The owner ran the Grafana flow with Docker: admin signs in as Grafana Admin, an
  account without groups is refused, a `grafana-viewers` member signs in as Viewer, removal from the group
  refuses the next sign-in, and Grafana's sign-out goes through Guardian's.
- **0.2 is built and committed (`d3ec55a`)** but not installed: the cluster is not ready. Decided 2026-11-19:
  the image comes from the owner's own registry (no publishing until 0.5); staging uses a Gateway API HTTPRoute
  and the bundled Postgres.
  - **Part 1, the chart.** `charts/guardian` (see `docs/INSTALL.md`). There is no `helm` in
    either workspace: templates were checked with a scratch renderer (Go templates plus the few sprig functions
    the chart uses; not in the repo), the schema with Python `jsonschema`. `.github/workflows/chart.yml` runs
    the real `helm lint`, `helm template` and kubeconform. Keep the chart to the functions it uses now, or check
    new ones carefully.
  - **Part 2, backup and restore.** `internal/backup` (format, dump, restore, verify,
    decrypt) and `cmd/guardian/backup.go`; documented in `docs/INSTALL.md`, "Backup and restore". Encryption with
    `filippo.io/age` (vendored 2026-11-19); a backup's payload decrypts with the `age` CLI too.
  - **The cluster is not ready (2026-11-19):** carry on with local development; chart features beyond part 1
    (including the email settings) wait until the owner's cluster is.
- **0.5 in progress**, in four parts (`docs/ROADMAP.md`): (1) audit retention and single-app group clean-up,
  (2) security keys and passkeys (`github.com/go-webauthn/webauthn` v0.18.2, vendored 2026-11-20), (3) release
  workflow and SonarQube, (4) the cluster parts. Then 0.6: a review of the tests, and every requirement
  implemented with at least one test (owner's request, 2026-11-20).
  - **Passkeys (decided 2026-11-20):** a passkey signs in on its own, with no further step, and counts as
    two-factor (apps with `require_mfa` and administrators' rights accept it).
  - **Part 4, the full chart (locally, no cluster yet): built, uncommitted.** Frontend image `frontend/Dockerfile`
    (nginx-unprivileged 1.27, `frontend/nginx/default.conf` + `headers.conf`, probe `/_ui/health`, read-only with
    `/tmp` emptyDir). Chart: `templates/frontend/*`, routing split in `httproute.yaml`/`ingress.yaml`,
    `backend/hpa.yaml`, `backend/servicemonitor.yaml` (internal Service labelled `guardian.dev/service: internal`),
    `networkpolicy.yaml` (pods that may reach the bundled Postgres carry `guardian.dev/database-client`),
    `jobs/migrate.yaml` (hook; `fail`s unless `database.mode: external`; env from `guardian.commandEnv`, not the
    ConfigMap), `jobs/backup.yaml` (CronJob + PVC with `helm.sh/resource-policy: keep`), mail and other settings
    in the ConfigMap. Backend: `DB_MIGRATE=startup|wait` (`config.Database.Migrate`; `guardian migrate` always
    migrates), `guardian backup --out-dir DIR --keep N` (`pruneBackups`). Compose: `--profile ui` builds the
    frontend image and puts `docker/gateway.conf` (nginx) on :3008 routing like the chart. CI: chart.yml `install`
    job on kind (bundled + UI, upgrade + backup by hand, second release with the Job against external Postgres);
    frontend.yml builds the image; release.yml publishes both images. **No helm here:** `helm`, `kind` and
    image registries are blocked in the cloud container (Docker runs but cannot pull). Check the chart with the
    stand-in renderer `scratchpad/minihelm` (Go text/template + the few Sprig functions the chart uses;
    `check.py` renders every `ci/` file and asserts routing, Job, CronJob, policies) and the schema with
    `jsonschema`; the real `helm` runs in CI. SonarQube paused by the owner (2026-11-20).
  - **Part 3, release workflow, SonarQube, Generate: built, uncommitted.** `.github/workflows/release.yml` (tag
    `vX.Y.Z` → checks via `workflow_call` of backend/frontend/chart workflows → `ghcr.io/krysset/guardian-backend`
    amd64+arm64, chart `oci://ghcr.io/krysset/charts/guardian`, GitHub release). Dockerfile cross-compiles
    (`--platform=$BUILDPLATFORM`) and takes `VERSION`; `server.Version` via ldflags, `guardian version`,
    `guardian_build_info`. SonarQube: `docker compose --profile sonarqube` (oauth2-proxy v7.15.5 on :3006 in
    front of SonarQube 26.11 community, HTTP header sign-in; SonarQube has no port of its own),
    `docs/LOCAL-SONARQUBE.md`, proxy pattern in INTEGRATION.md. The owner runs it and fills in the measured
    staleness. Frontend: `lib/password.ts` (`generatePassword`, `copyText`), `PasswordField` has a bindable
    `show`. Passkey-only accounts are a 1.x candidate (owner, 2026-11-20).
  - **Part 2, security keys and passkeys: committed (`b123232`, with part 1).** `internal/passkey` (relying party = issuer host,
    origins = issuer + `ALLOWED_ORIGINS`; ceremonies sealed in tokens with kind and account; `used_challenge`
    makes each answer count once; clone warning refused). `store/webauthn.go` (`account_mfa` type `webauthn`
    with `credential_id` + `credential` JSONB; `RemoveFactor` keeps the last method when required and drops
    the codes with the last one). Web: `/login/passkey`, `/mfa?key` (S14), `/mfa/setup?method=key`; the pages
    post forms, `guardian.js` runs the dialogs (`data-webauthn` = create, get, passkey). amr: passkey
    `hwk,user`, password+key `pwd,hwk`; `httpx.TwoFactor(amr)` replaces checks for "otp". API: `/me/mfa/keys`,
    `/me/mfa/keys/finish`, `PATCH|DELETE /me/mfa/keys/{key}`, `/me/mfa/finish` (was `/me/mfa/totp/finish`),
    `/me/reauth/key` + `key` in `POST /me/reauth`. Tests: `testutil.Authenticator` (software key, own CBOR),
    `e2e/passkey_test.go`; browser check `scratchpad/ui04/passkeys.js` uses Chromium's CDP virtual
    authenticator (it answers conditional mediation at once, so the script turns suggestions off for the
    button and S14 paths). **Schema changed** (`credential` column, `used_challenge`): recreate local databases.
  - **Part 1, retention: committed (`b123232`).** `AUDIT_RETENTION` (config `AuditRetention`, `store.AuditRetention`,
    chart `config.auditRetention`); `store.PruneAudit` (batches of 5000) and `RemoveOrphanedSingleAppGroups`
    run in the hourly `cleanup`. `GET /overview` has `audit_retention_days`.
- Go modules cannot be fetched in the cloud: `proxy.golang.org` is refused by the agent proxy (npm works with
  `NO_PROXY=` cleared). New modules always come from the owner's `go mod vendor`.
- **0.4 built** (committed `d0e64af`; the nginx image and the chart's frontend wait for the cluster), in five parts (`docs/ROADMAP.md`): (1) foundation, (2) Home and the account area,
  (3) admin accounts and overview, with a two-factor step-up for the management UI (a session without
  two-factor gets `/mfa` with `return_to` instead of "sign out and in again"; decided 2026-11-20), (4) admin groups and apps, (5) audit log, a browser pass, docs.
  - **Part 5, audit log and the browser pass: committed (`d0e64af`).** `/admin/audit` (AD11): filters in the address
    (`event`, `username`, `app`, `cursor`), 50 a page, Previous via a stack of cursors, a row opens its details
    (links to the account, app and group, the raw metadata). On a phone the rows become stacked cards. API:
    AuditEntry gains `target_username`, `app_name`, `group_name` (joined through `uuidOrNull`, so metadata that
    is not an id never breaks the query); `?username=` resolves an account (also one in its grace period) to
    `about`, 404 `account_not_found` if none. `lib/events.ts`: `eventWords(type, metadata)` (says "App
    disabled" etc.), `summary(entry)`, `who(entry)`, `eventGroups` for the filter. `[...rest]` is gone; unknown
    admin paths get the 404 page. Browser pass: `scratchpad/ui04/part5.js` (every page at 1280 and 390 wide).
  - **Part 4, admin groups and apps: committed (`5dcebd6`).** Pages `/admin/groups` (AD4), `/admin/groups/new`
    (AD6), `/admin/groups/[group]` (AD5), `/admin/apps` (AD7), `/admin/apps/new` (AD9), `/admin/apps/[app]`
    (AD8, with AD10). Components: `CopyField`, `UriList` (https, localhost or a custom scheme, no fragment;
    `required` keeps the last one), `SecretDialog` (AD10), `GroupMembers` (shared by AC6 and AD5; `search`
    turns on suggestions for admins only), `AppSettings`, `AccessFields`. API: `GET /scopes`
    (`store.ListScopes`), audit filter `app` (actor app or metadata `app`). `POST /apps` answers
    `{app, client_secret}`. `/admin/[...rest]` still stands in for `/admin/audit` until part 5.
    Browser check: `scratchpad/ui04/part4.js` (session-local).
  - **Part 3, admin overview and accounts: committed (`e207a35`).** Pages `/admin` (AD13), `/admin/accounts`
    (AD1), `/admin/accounts/new` (AD3), `/admin/accounts/[account]` (AD2), `/admin/deleted` (AD12); the admin
    layout loads `/overview` once (`depends('guardian:overview')`) for the start page and the A23 warning.
    API: `api/overview.go` (`GET /overview`, `DELETE /accounts/{account}/sessions`), `store/overview.go`,
    `CountAccounts`, audit `about` (actor, or metadata `account`/`target`) with `actor_username`,
    `deleted_by_username`, AccountDetail `is_admin` and `mfa`. Web: `GET /mfa/stepup` in `web/mfa.go`. The API
    client sends `403 mfa_required` there. `askConfirm` takes `typeToConfirm`. `lib/events.ts` words audit
    events; `lib/locales.ts` has the language and time zone choices. e2e: `e2e/admin_area_test.go`.
    Load files may only export `load` and Kit's options; other exports need a `_` prefix (`_pageSize`).
  - **Part 2, Home and the account area: committed (`e3aee9c`).** Pages `/` (H0), `/account` (AC1),
    `/account/security|sessions|apps|groups|data`, `/account/groups/[group]` (AC6). API: `api/me.go` (home,
    sessions, connected apps, groups, email removal and cancel, add a member by login) on `store/me.go`;
    `api/useragent.go` ("Firefox on Windows"). e2e: `e2e/account_area_test.go`.
  - **Part 1, foundation: committed (`b836b22`).** See "Management UI" below.
- **0.3 is built**, in six parts (`docs/ROADMAP.md`): (1) email, (2) re-authentication, (3) two-factor,
  (4) account deletion and the deletion log, (5) signing keys and the keyring, (6) abuse protection.
  - **Part 1, email: committed (`17f8ad0`).** See "Email" below.
  - **Part 6, abuse protection: committed (`20fd053`).** `web/login.go`: the account is looked up first;
    failures count under `login:account:<id or lowercased login>:ip:<ip>` (5 per 15 minutes) and `login:ip:<ip>`
    (50); a refusal runs `auth.DummyVerify`. The numbers are `config.LoginLimits` (`LOGIN_FAILURE_WINDOW`,
    `LOGIN_MAX_FAILURES_PER_ACCOUNT_IP`, `LOGIN_MAX_FAILURES_PER_IP`; chart `config.loginLimits`), applied by
    `web.Configure`; a zero value keeps `config.DefaultLoginLimits`. `honeypotHit(r, form)` in `web/signup.go` (audit `honeypot`, metric
    label `honeypot`), used by sign-up and `/forgot`. e2e: `TRUSTED_PROXY_HOPS=1`, and `browser.ip` is sent as
    `X-Forwarded-For` to act from another address.
  - **Part 5, keys: committed (`c453ea7`).** `auth/crypto.go` is the keyring (`ParseKeyring`, `SetKeyring`,
    `Encrypt`/`Decrypt` with `AAD(table, column, row)`, `Seal`/`Open` for browser-held tokens). `auth/keys.go`:
    `Keys` reloads (`Reload`, `ActiveKID`). `auth/maintenance.go`: `MaintainKeys` (reread the keyring file,
    `db.AdvanceSigningKeys`, reload keys, `Reencrypt`, metric) every minute. `store/signingkeys.go`: the stages
    and `EmergencyRotate`; `store/keyring.go`: the encrypted values. `cmd/guardian/keys.go`: `keys list|rotate|
    reencrypt`, `mfa reset-totp --all`. `server.UseKeyring(cfg)`. Config: `KEY_ENCRYPTION_KEYS_FILE` or
    `KEY_ENCRYPTION_KEYS`, `SIGNING_KEY_LIFETIME`. Backups: `Manifest.KeyringKeys` ("id:fingerprint").
    Schema changed (signing_key stages). Tests set keyrings with `auth.SetEncryptionKey` (one key "k1").
  - **Part 4, account deletion: committed (`131cc81`).** `store/deletion.go` (`SoftDeleteAccount(id, by)` sets
    `deleted_by`, `erase_after`, `held_memberships`; `RestoreAccount`; `EraseAccount`/`EraseAccountTx` delete the
    row, scrub the audit entries (`personalKeys`, IP) and log the id in `deletion_log`; `EraseDueAccounts` runs in
    maintenance; `ExportAccountData`). `api/deletion.go`: `DELETE /me`, `GET /me/export`, `GET /accounts/deleted`,
    `POST /accounts/{id}/restore`, `POST /accounts/{id}/erase`. `backup/deletions.go`: the deletion log file
    (`GUARDIAN-DELETIONS 1` + JSON lines), `guardian deletions export`, `restore --apply-deletions`. Config
    `DELETION_GRACE_PERIOD` (720h). Schema changed again (account columns, `deletion_log`).
  - **Part 3, two-factor: committed (`9d95287`).** See "Two-factor" below. `rsc.io/qr` vendored 2026-11-20.
  - **Part 2, re-authentication: committed.** `httpx.RequireReauth(w, r)` in a handler answers
    `403 reauth_required` unless the session's `auth_time` is under 5 minutes old (`httpx.ReauthWindow`);
    `Authenticate` puts `auth_time` in the context. `POST /api/v1/me/reauth` (`api/account.go`) checks the
    password (5 failures per 15 minutes per account) and moves `auth_time` (`db.Reauthenticate`). Protected
    today: username (`PATCH /me` only when `username` is in the body), email, password. **Every new protected
    change (two-factor, recovery codes, sessions, connected apps, deletion) must call `RequireReauth`.**
- Tests: 206, all passing with `-race` (`docs/TESTING.md`).

## Repository map
- `backend/` — Go module `guardian` (Go 1.26): chi, pgx, goose, golang-jwt, prometheus.
  - `cmd/guardian/main.go` — entry point (`serve`, `migrate`): loads `.env` if present, validates the
    configuration, sets up logging, runs the server. `backup.go` — `backup`, `backup verify`, `backup decrypt`
    and `restore`: data on stdout, everything else (logs too) on stderr; `verify` and `decrypt` need no
    configuration.
  - `internal/backup/` — the backup file (`format.go`: magic line, manifest in the clear, age payload of
    gzipped JSON rows, size and SHA-256 trailer), `database.go` (the table list in restore order, the tables
    left out, snapshot dump, restore into a fresh database with `json_populate_recordset`), `commands.go` (dry
    runs, the destructive-command rules, audit entries). A new table must go into `tables` or `notBackedUp`;
    `TestEveryTableIsBackedUpOrLeftOutOnPurpose` fails otherwise.
  - `internal/config/` — every environment variable in one place, validated at startup; all problems reported
    at once. `backend/.env.example` lists them.
  - `internal/server/` — wiring: database, keys, the two routers, both listeners, clean shutdown.
    `server.Configure(cfg, keys)` configures `httpx`, `web` and `oidc`; the e2e tests call it too.
    - Public `:3001`: Home, sign-in pages, OIDC, `/api/v1`, `/static/`. Unknown paths get the HTML 404 page.
    - Internal `:3002`: `/metrics`, `/healthz`, `/readyz`.
  - HTTP packages; dependencies point one way: `httpx` <- `web` <- `oidc` <- `api`; `internalapi` uses only
    `httpx`.
    - `internal/httpx/` — settings (`Issuer`, session timeouts, cookie names), JSON responses and errors
      (`Error`, `ErrorCode`, `DecodeJSON`), `ClientIP`, `SafeReturnTo` (only `/authorize?...`),
      `ValidRedirectURI`, session cookie and CSRF helpers, `Authenticate`, `AdminOnly`, `RequireSameOrigin`,
      request metrics, `RateLimited`.
    - `internal/web/` — Home and the sign-in pages (see "Sign-in pages" below).
    - `internal/oidc/` — `oidc.go` (discovery, JWKS), `authorize.go` (authorize, consent, no-access, the
      temporary-password check), `token.go` (`/token`, `issueTokens` — the one place that decides whether a user
      may have tokens — `/revoke`), `userinfo.go`, `client.go` (client_credentials), `logout.go` (RP-initiated
      logout with `return_to` for "switch account", back-channel logout).
    - `internal/api/` — `/api/v1`, described in `docs/openapi.yaml`; `TestOpenAPIDescribesEveryRoute` fails when
      they drift apart. `account.go`, `groups.go`, `app.go`, `audit.go`, `machine.go` (`/apps/self`).
    - `internal/internalapi/` — `/metrics`, `/healthz`, `/readyz`.
  - `internal/auth/` — argon2id, the encryption keyring, RSA signing keys and their schedule, JWKS, TOTP.
  - `internal/store/` — queries (imported as `db`); goose migrations at startup.
  - `migrations/00001_init.sql` — the whole data model, embedded. Edited in place until 1.0; it records a
    fingerprint of itself and Guardian refuses a database made by another revision, so **after any edit, existing
    development databases must be recreated (`docker compose down -v`); tell the owner.** Columns for later
    features (require-MFA flag, key stages, keyring tags, deletion log) are added with their feature, not before.
  - `internal/testutil/` (helpers for database tests), `e2e/` (HTTP tests against both routers).
- `charts/guardian/` — the Helm chart (0.2): backend Deployment, Services, PDB, bundled Postgres, HTTPRoute,
  Ingress; `ci/*.yaml` are the values CI renders. `docs/INSTALL.md` explains it.
- `frontend/` — the management UI (0.4): SvelteKit 3 (config lives in `vite.config.ts`; there is no
  `svelte.config.js`), Svelte 5 runes, Vite 8, TypeScript 6, `adapter-static` with the fallback `200.html`.
  See "Management UI" below.
- `docker-compose.yml` — backend, Postgres 16, Mailpit, and Grafana behind the `grafana` profile.
- `.github/workflows/backend.yml` — format check, vet, tests against Postgres, image build;
  `chart.yml` — helm lint, helm template and kubeconform for every `charts/guardian/ci/*.yaml`.
- `docs/` — see `README.md` for the list.

## Data model (`00001_init.sql`)
- `account` — the OIDC subject; profile columns map to standard claims. `email` is always confirmed or NULL.
  `must_change_password` is set by admin-set passwords and on the seeded admin. Soft delete via `deleted_at`.
- `app` — an OIDC client: public or confidential, redirect URIs, PKCE, first-party (skips consent), token
  lifetime, `refresh_mode` (`stable` or `none`), `access_rule` (`groups` or `anyone`), homepage. `app_secret`
  holds several secrets, so rotation can overlap.
- `scope`, `app_scope`, `account_consent`; `app_user` (accounts that have signed in to an app).
- **Groups:** `user_group` (immutable `key`, editable `display_name`, `is_system`, optional `owner_group_id`;
  single-app groups have `bound_at`, `bound_app_id` and, once the app is deleted, `bound_app_deleted_at`),
  `group_member` (optional `expires_at`), `app_group` (which groups an app is told about).
- `session` (SSO; idle and absolute timeouts), `authorization_code`, `refresh_token` (one stable token per
  sign-in and app; `family_id` kept for rotation later), `session_app` (for back-channel logout), `signing_key`.
  Access tokens are not stored.
- `account_token`, `account_mfa` — for 0.3, unused so far. `rate_limit` (UNLOGGED), `audit_log` (append-only).
- Seed: standard scopes; the group `guardian-admins`; an `admin` account in it, whose password comes from
  `ADMIN_INITIAL_PASSWORD` (or is generated and logged once) and must be changed at its first sign-in.
- The last-administrator rule lives in the store: one active account always stays in `guardian-admins` through a
  membership without expiry.

## Sign-in pages and Home (`internal/web`)
- `templates/*.html`: `layout.html` plus one file per page (each defines `content`, optionally `bar`).
  `static/`: `guardian.css`, `guardian.js`, `background.jpg`, `logo-mask.svg`, `favicon.svg`. All embedded and
  served from `/static/<name>?v=<content hash>`, cached for a year.
- `templates.go`: `Render`, `Page`, `Error(w, kind)` for the error pages, `ScopeLines` (consent wording),
  `Configure` (the optional `HELP_URL` and `PRIVACY_URL` footer links). `login.go`, `signup.go`, `password.go`
  (the forced new password after a temporary one), `home.go`, `account.go` (username and password rules and
  `CreateAccount`, shared with `POST /api/v1/signup`).
- **No inline styles or scripts:** the CSP is `default-src 'none'; style-src 'self'; script-src 'self'`, enforced
  by `TestPagesHaveNoInlineStylesOrScripts`. A side effect: `fetch` from the browser console fails on these pages
  (use a JSON page such as `/api/v1/me`).
- `guardian.js` adds the password show buttons and centres the bar's content vertically, moving the logo
  cut-out with it (`--logo-y`). Without JavaScript the content sits at the top. The consent page is not centred.
- **Dark only.** The favicon is the head logo, black on light browser tabs and white on dark ones. The owner's
  logo files: "dark" means a black icon, "light" a white one; full, mid and head variants.
- Error notices shake once per page load (not with reduced motion).
- Parts of later releases (security key, "go to your account") stay out until they work. The email field,
  "Forgot password?" and `/forgot` appear only when email is configured (`mail` template function). `/` is a simple Home (connected and available apps) until the management UI's Home in 0.4.
- The background image is the 640×360 one from the design board; a full-size one would look sharper.

## Email (0.3 part 1)
- `internal/mail`: `SMTP` sender (starttls, tls or none), `Compose` (multipart text and HTML, quoted-printable),
  an in-memory background queue with retries (`Enqueue`; lost on restart, by decision), `Capture` for tests.
  The emails (E1 confirm, E2 reset, E3 password changed, E5 email changing) render from one `email` value
  through `templates/email.html` and `email.txt`; inline styles, light colours. Times in the account's
  `zoneinfo` (`time/tzdata` is in the binary). `Mask` hides addresses (`a•••@example.com`).
- Config: `SMTP_HOST` (empty = email off), `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_SECURITY`,
  `MAIL_FROM` (its name is the site name in emails), `REQUIRE_EMAIL`. Compose sends to Mailpit (port 3003 UI).
- `internal/web/email.go`: S2b `/signup/inbox` (resend, change address), S12 `/confirm`, S10 `/forgot`, S11
  `/reset`. Links are `account_token` rows (hash only; `store/tokens.go`); a new link replaces the account's
  unused ones of the same purpose; 5 links per account per hour. Sign-up with an address creates a `pending`
  account plus a `guardian_signup` cookie whose hash is in the token: the link signs in only in that browser.
  Pending accounts go after 48 hours (maintenance). `ConfirmEmail` gives the address to the first account that
  confirms it (`ErrEmailTaken` for the rest). `ResetPassword` ends every session.
- `PUT /api/v1/me/email` sends E1 to the new address and E5 to the old one; it needs re-authentication (part 2
  added it). Password changes send E3 (S3, `PUT /me/password`, reset).
- The cloud workspace tests real SMTP against a tiny Python sink (scratchpad `mailsink/sink.py`, port 2525).

## Two-factor (0.3 part 3)
- `auth/totp.go`: TOTP (RFC 6238, SHA-1, 6 digits, 30 s, one step of drift), recovery codes (`xxxx-xxxx`,
  alphabet without i l o u, hashed with the account id). `auth.Seal`/`Open` encrypt with the key encryption key.
- `store/mfa.go`: `account_mfa` rows: one `totp` (sealed secret; `sign_count` = last used time step, so a code
  works once) and `recovery_code` rows (hash; deleted when used). `MFARequirement` (admins, owners).
  `StepUpSession` adds `otp` to the session's `amr`. Schema: `app.require_mfa`, a unique TOTP per account.
- `web/mfa.go`: after the password, `mfaAfterPassword` decides: the code (S13 `/mfa`), the required setup
  (S15/S16 `/mfa/setup`), or straight in. The waiting state is the sealed `guardian_mfa` cookie (`mfaFlow`;
  `signin` or `stepup`). `StepUp` is used by `/authorize` for apps with `require_mfa`. The setup logic
  (`NewTOTPSetup`, `ConfirmTOTPSetup`, `FinishTOTPSetup`, recovery-code renewal) is shared with the API; its
  state is a sealed setup token. 5 wrong codes per 15 minutes per account.
- `api/mfa.go`: `/me/mfa/totp` (+ `/confirm`, `/finish`, DELETE), `/me/mfa/recovery-codes` (+ `/finish`),
  `/accounts/{id}/mfa/reset`. `httpx.RequireMFASession` in `AdminOnly` and `groupAccess`.
- Tests: `testutil.AdminAccount` gets an authenticator app (`EnableTOTP`); `testutil.TOTPCode` gives a current
  code and forgets used steps; e2e `mustLoginWith` passes `/mfa` and sets up on `/mfa/setup` by itself;
  `testutil.Session` makes `pwd otp` sessions. Sealed tokens in HTML are entity-escaped (`&#43;`): unescape.
- **Schema changed** (fingerprint differs): the owner's local database must be recreated.

## Management UI (`frontend/`, 0.4)
- **Run it:** the backend on :3001 (docker compose), then `npm install` and `npm run dev` in `frontend/`, and open
  http://localhost:3000. Vite serves `/account`, `/admin` and its own paths, and forwards everything else (sign-in
  pages, `/api`, `/static`, OIDC) to the backend (`GUARDIAN_BACKEND`, default http://localhost:3001), so one origin
  and one session cookie. The backend needs `ALLOWED_ORIGINS=http://localhost:3000` (set in compose).
- **Checks:** `npm run check` (svelte-check, types) and `npm run build`. After changing `docs/openapi.yaml`, run
  `npm run api` to regenerate `src/lib/api/schema.d.ts` (committed).
- **SvelteKit 3, not 2:** imports use `#lib/...` with file extensions (`#lib/api/client.ts`), page state comes
  from `$app/state` (`page`, not `$page`), `refreshAll` replaced `invalidateAll`.
- **Single-page app:** `ssr = false` in the root layout; the root load fetches `/me` for every page. The CSP is a
  `<meta>` tag with the hash of Kit's start script (`csp` in `vite.config.ts`); no inline styles.
- **Files:** `src/lib/api/client.ts` (typed `api.get('/me')` etc.; 401 goes to `/login?return_to=`;
  `403 reauth_required` opens AC8 and retries once; failures are `ApiError` with the API's code; `loadFailed(e)`
  in load functions), `src/lib/reauth.svelte.ts` + `components/ReauthDialog.svelte` (AC8, a native `<dialog>`),
  `components/Frame.svelte` (F2: top bar, area switch for admins, side nav, `banner` slot for A23),
  `components/Icon.svelte`, `styles/app.css` (design F's dark tokens and shared classes), `routes/+error.svelte`
  (404, 403, `mfa_required`).
- **Shared with the sign-in pages:** the font (Figtree, `figtree-latin*.woff2`, OFL in `figtree-OFL.txt`), the
  background and the logo are the backend's `/static/` files; the UI links to them, it does not copy them.
- **Shared parts (part 2):** `confirm.svelte.ts` + `ConfirmDialog.svelte` (`askConfirm({title, message, confirm,
  danger})` before anything that cannot be undone), `format.ts` (dates, `maskIP`, `maskEmail`, `endOfDay` for date
  inputs, `messageOf`), `AppLogo.svelte`, `PasswordField.svelte`, `RecoveryCodes.svelte` (S16's codes: copy,
  download, type one back). Global classes in `app.css` include `.visually-hidden` and `.scroll` (positioned, so
  hidden table headers stay inside it).
- **Home is `/` in the UI** (the dev proxy keeps exactly `/` with Vite). The backend's `/` Home stays as the
  fallback until the chart routes `/` to the frontend.
- Sign-in returns to the UI: `httpx.SafeReturnTo` accepts `/account...` and `/admin...` paths (printable ASCII,
  no `//`, `..`, backslash or `#`) besides `/authorize?`.
- Screenshots: take full-page ones only after `scrollTo(0, 0)`. Taken while scrolled, they draw the sticky top bar
  in the middle of the page and cut off the fixed background, which looks like a bug but is not. Check sticky
  parts with viewport screenshots at several scroll positions.
- Browser check: the Playwright flow signs in through :3000 (two-factor setup with a computed TOTP code,
  password change), edits the profile, ages `session.auth_time` in the database to trigger AC8, and checks a
  phone width.

## Design board
- https://claude.ai/artifact/V4Qwf5xMJg2fWKAGQm3QKJ ("Guardian page designs"). It holds every page in
  `docs/PAGES.md`: the sign-in pages (S1–S16, settled; S1 and S4 are the reference), the emails E1–E6, and Home,
  the account area and the admin area in **design F** (settled for now). Earlier directions (A, B, D, E) are in
  an archive section at the bottom. Dashed tags (0.3, 0.5, 1.x) mark parts of later releases, for review only.
- AD11 tries a full-width glass plate behind the page title; the owner has not decided on it yet.
- Colours: the sign-in blue is the main highlight (`#4fd1e0` on dark), Sheikah orange (`#ff9a3c` on dark) the
  secondary one. Font: Figtree (not bundled yet; the system font is the fallback).
- The board's page files were generated by a script that is not in the repo; edit the board files directly.

## Users, pages and personal data
- `docs/USERS.md`: roles and every requirement with a stable id (V1, U12, O3, A18, P2, M1). Never renumber ids;
  add new ones. `docs/PAGES.md`: every page (S, H, AC, AD, E) with its requirements, and the reverse table. Keep
  both directions in step.
- Personal data only where someone went to see it: Home and the admin overview show none; the account area opens
  on the profile, where the email is masked until shown; session IPs are masked too.

## Working conventions
- Never let staleness exceed the app's `access_token_ttl_seconds`; every refresh re-checks session, account,
  app and groups (`issueTokens`).
- No feature may depend on the number of backend replicas, or on which cluster a replica runs in.
- Secrets and tokens are stored only as hashes or encrypted values. Never log query strings on OIDC routes; logs
  hold account ids at most.
- `docs/openapi.yaml` changes with every API change; `docs/ARCHITECTURE.md`'s mermaid diagrams (they render with
  `mmdc`) change with the design.
- Check visual changes in a real browser (Playwright in the cloud workspace) before handing them over.

## Agreed chart layout (0.2 onwards)
```
charts/guardian/
├── Chart.yaml                 # version = chart semver, appVersion = image tag for both images
├── values.yaml
├── values.schema.json         # fails early on missing host, DB, or secret
├── ci/                        # chart-testing values: default, ha, external-db
├── templates/
│   ├── _helpers.tpl, NOTES.txt, serviceaccount.yaml, configmap.yaml
│   ├── ingress.yaml           # optional standard Ingress; one host, path routing (/account, /admin, /_app -> frontend; rest -> backend)
│   ├── httproute.yaml         # optional Gateway API HTTPRoute, same routing, attaches to an existing Gateway
│   ├── networkpolicy.yaml
│   ├── postgres/ statefulset, service, secret   # only when database.mode=bundled
│   ├── backend/  deployment, service (public), service-internal, hpa, pdb, servicemonitor
│   ├── frontend/ deployment, service, hpa, pdb
│   └── tests/test-connection.yaml
```
0.2 needs only a minimal subset (backend, bundled or external Postgres, routing, required Secrets, startup
migrations); the rest comes in 0.5. The chart generates no secrets (Argo CD renders without `lookup`); everything
comes from operator-provided Secrets, which the owner fills from Bitwarden.
