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
    screenshots. No network. The preinstalled Go is too old: unpack `.tools/go1.26.11.linux-amd64.tar.gz`
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

## Status (2026-11-19)
- **0.1 is done.** Everything up to and including the sign-in pages, Home, single-app groups and the Grafana
  check is committed (`632a0d4`). The owner ran the Grafana flow with Docker: admin signs in as Grafana Admin, an
  account without groups is refused, a `grafana-viewers` member signs in as Viewer, removal from the group
  refuses the next sign-in, and Grafana's sign-out goes through Guardian's.
- **Next: 0.2** (`docs/ROADMAP.md` section 5): a minimal Helm chart and `guardian backup` / `guardian restore`,
  installed via Argo CD in the staging cluster.
- Tests: 154, all passing with `-race` (`docs/TESTING.md`).

## Repository map
- `backend/` — Go module `guardian` (Go 1.26): chi, pgx, goose, golang-jwt, prometheus.
  - `cmd/guardian/main.go` — entry point (`serve`, `migrate`): loads `.env` if present, validates the
    configuration, sets up logging, runs the server.
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
  - `internal/auth/` — argon2id, AES key encryption, RSA signing keys and JWKS.
  - `internal/store/` — queries (imported as `db`); goose migrations at startup.
  - `migrations/00001_init.sql` — the whole data model, embedded. Edited in place until 1.0; it records a
    fingerprint of itself and Guardian refuses a database made by another revision, so **after any edit, existing
    development databases must be recreated (`docker compose down -v`); tell the owner.** Columns for later
    features (require-MFA flag, key stages, keyring tags, deletion log) are added with their feature, not before.
  - `internal/testutil/` (helpers for database tests), `e2e/` (HTTP tests against both routers).
- `charts/guardian/` — only an empty `Chart.yaml` and empty `helper/` and `images/` folders (0.2 starts here).
- `frontend/` — empty (0.4).
- `docker-compose.yml` — backend, Postgres 16, Mailpit, and Grafana behind the `grafana` profile.
- `.github/workflows/backend.yml` — format check, vet, tests against Postgres, image build.
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
- Parts of later releases (forgot password, security key, email at sign-up, "go to your account") stay out until
  they work. `/` is a simple Home (connected and available apps) until the management UI's Home in 0.4.
- The background image is the 640×360 one from the design board; a full-size one would look sharper.

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
