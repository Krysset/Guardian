# Guardian architecture and design decisions

How Guardian is built and why. `docs/ROADMAP.md` (section 2) lists every design rule in detail;
`docs/INTEGRATION.md` is the guide for app developers.

## Requirements that drive the design

1. Sign-up is open to everyone (rate limited).
2. Group changes, logout and disabled accounts reach apps within a known, per-app window
   (`access_token_ttl_seconds`, at least 15 seconds), and at once for apps with back-channel logout.
3. Apps must not depend on Guardian for every request, so Guardian is not overloaded and a short Guardian
   outage does not take every app down.
4. Apps integrate with any standard OIDC library.
5. One Guardian deployment (frontend, backend, Postgres) that works with any number of replicas, in one or
   several clusters, against one shared Postgres. Prometheus scrapes its metrics.

## Decisions

| Decision | Why |
|---|---|
| **Groups**, not per-app permissions | Guardian knows who is in which group; each app decides what a group means. Groups are flat, membership can expire, and an app only ever sees the groups linked to it. Keeps Guardian simple and apps in charge of their own rules. |
| Access tokens are **short-lived signed JWTs** (`at+jwt`, RFC 9068) | Apps verify them locally (3, 4). They carry `sub`, `aud`, `scope`, `sid`, `amr` and `groups`, but no profile data, and are not stored. |
| **Every refresh re-checks live data** | Session, account, the app's access rule and groups are read from Postgres at each refresh, in one place (`issueTokens`). That is what bounds staleness to the token lifetime (2). |
| **Stable refresh tokens** for apps with a secret | One per sign-in, never replaced, valid while the session lives. Parallel refreshes and retries cannot trip a reuse detector; a stolen token is useless without the client secret. Apps without a secret get none until rotation is added for mobile apps. |
| **Back-channel logout** on logout, account deletion and leaving a group | Makes those changes immediate for apps that support it (2). Delivery is best effort; the next refresh is the safety net. |
| The **access rule** is enforced by Guardian | With `groups`, accounts outside the app's linked groups never get a code or a token, at sign-in or at refresh. Apps do not have to remember to refuse them. |
| **Single-app groups** | A group made for one app can be bound to it for good, so it can never grant access to another app, not even by being moved. Binding and linking lock the same rows, so they cannot race. |
| **Sign-in pages rendered by the backend** | Go templates with embedded styles and scripts: they work without JavaScript, share the session cookie's origin, and allow a strict Content-Security-Policy (no inline styles or scripts). The management UI (0.4) is a separate frontend on the same origin. |
| An account with a **temporary password** gets nothing until it chooses its own | Login, Home and `/authorize` all send it to the new-password page first, so an admin-set password never reaches an app. |
| **No Redis, no cache** | Each refresh is a handful of indexed queries. Load scales with signed-in users times apps divided by the token lifetime, not with request rate. One component fewer to run and keep consistent. |
| **Two listeners**: public `:3001`, internal `:3002` | Metrics and probes are never reachable through the ingress, even if an ingress rule is wrong. |
| Rate limits in an UNLOGGED Postgres table | Correct across replicas without Redis; fine for login and sign-up volumes (1). |
| Sign-in failures count per **account and address**, never per account alone | By default 5 failures for one account from one address in 15 minutes refuse that pair, and 50 from one address refuse it for all accounts (both settings). Accounts are never locked, so nobody can lock out an owner by guessing from elsewhere. Honeypot fields on sign-up and forgot-password catch form-filling bots without a CAPTCHA. |
| The **management UI is a static single-page app** on the same origin | SvelteKit with `adapter-static`: nginx serves the files and one fallback page; all data comes from `/api/v1` with the session cookie, so no second server holds sessions or secrets. Its CSP allows only its own scripts (Kit's start script by hash). The font, background and logo are the backend's `/static/` files, shared with the sign-in pages. |
| Sign-in returns only to known places | `return_to` must be `/authorize?...` or a page under `/account` or `/admin` (no `//`, `..` or backslashes), so the sign-in pages cannot be used as an open redirect. |
| Client IP from `X-Forwarded-For` only with `TRUSTED_PROXY_HOPS` | Behind an ingress the TCP peer is the proxy; trusting the header blindly lets attackers dodge limits. |
| Origin check on `/api`, SameSite=Lax cookies, CSRF tokens on HTML forms | CSRF defence for the browser API and sign-in pages. |
| The machine API uses Bearer tokens with Guardian as audience | An app reads its own groups and users without a user present. A user's access token (audience: the app) is never accepted there. |
| At most 4 concurrent argon2 hashes | Each hash needs 64 MiB; unbounded logins would exhaust a memory-limited pod. |
| Migrations with goose, embedded in the binary | One image, no SQL files beside it; a Postgres lock makes replicas take turns. |
| **Keys change on a schedule every replica runs** | Each minute every replica rereads the keyring file, advances the signing keys (an advisory lock makes one do it), reloads them and re-encrypts values under old keyring keys. No leader, no restart; the database is the only shared state. |
| **The keyring's order is its roles** | The first key encrypts, every key decrypts. Rotating is: append, reorder, remove. Values name their key and carry their table, column and row as associated data, so a value cannot be moved to another row. |
| **Deletion waits, erasure is final** | A deleted account is disabled and its memberships are set aside (`held_memberships`), so it counts for nothing but can be restored whole. Erasure deletes the row (everything else cascades), strips IP addresses and personal details from its audit entries, and keeps only its id in `deletion_log`, which backups carry and restores re-apply. |
| **No session until the second factor** | After the password, a sealed (AES-GCM, key encryption key) 10-minute cookie names the account and where sign-in continues. A setup is carried in a sealed token in the form. Nothing half-done is stored, and nothing needs cleaning up. |
| **Administrators' rights need a two-factor session** | `AdminOnly` and group ownership answer `403 mfa_required` to a session whose `amr` lacks `otp`, so becoming an admin, or an admin session from before two-factor, cannot skip it. |
| **TOTP is Guardian's own code** | RFC 6238 with the fixed parameters every app supports is about 30 lines (tested against the RFC's vectors); a dependency would add more than it saves. The last used time step is stored, so a code works once. |
| **Re-authentication moves the session's `auth_time`** | Protected changes need `auth_time` within 5 minutes; `POST /me/reauth` moves it. One timestamp, the same one OIDC reports, instead of a second clock that could disagree. |
| **Email queued in memory**, sent in the background | Pages answer at once and in the same time whether or not an email goes out, so the reset page reveals nothing. A queued email is lost if the pod stops; the user asks for a new link. No outbox table to run. |
| A **confirmation link signs in only the browser that signed up** | A cookie set at sign-up must match the link. Mail scanners and forwarded links confirm the address but get no session. |
| **Backups through the CLI**, encrypted with age to an offline key | `kubectl exec` access decides who can back up or restore; the cluster never holds the private key. Logical rows (JSON) instead of `pg_dump`, so a restore can check schema revision, keys and counts, and refuses to overwrite an installation in use. |
| Graceful shutdown, `/healthz`, `/readyz`, bounded DB pool | Rolling deployments without dropped requests; Postgres connections stay bounded. |

## Load and when to worry

The steady load is refreshes: about `signed-in users × apps ÷ token lifetime` per second. 10,000 signed-in
users with one app each on the default 300 seconds is about 33 refreshes per second. Each refresh is a few
indexed reads and one RS256 signature.

Watch `guardian_http_request_duration_seconds{route="/token"}`, `guardian_token_requests_total` and the
`guardian_db_*` pool gauges. If they become a problem, in this order: longer token lifetimes for apps that do
not need short ones, PgBouncer, a bigger Postgres. Do not read from replicas for refreshes: replication lag
would let revoked access through.

## Diagrams

### Topology

```mermaid
flowchart LR
  B[Browser] -->|HTTPS| I[Ingress / Gateway]
  subgraph K[Kubernetes cluster]
    I -->|/account, /admin, /_app| F["Frontend pods<br/>(0.4, nginx planned)"]
    I -->|everything else| P
    subgraph G[Guardian backend pods]
      P["public :3001<br/>OIDC, sign-in pages, /api/v1"]
      N["internal :3002<br/>metrics, probes"]
    end
    A[Apps] -->|"/token (refresh), /userinfo,<br/>machine API"| I
    G -->|back-channel logout| A
    M[Prometheus] -->|scrape /metrics| N
    P --> D[(Postgres)]
  end
```

Apps validate access tokens themselves against Guardian's public keys (`/jwks.json`), so they only call
Guardian to sign users in, to refresh, and optionally for userinfo or the machine API.

### Sign-in (single sign-on)

```mermaid
sequenceDiagram
  participant B as Browser
  participant A as App
  participant G as Guardian
  B->>A: open protected page
  A-->>B: redirect to /authorize (PKCE)
  B->>G: GET /authorize
  alt no session cookie
    G-->>B: sign-in page
    B->>G: POST /login (password)
    G-->>B: session cookie, redirect back
  end
  opt temporary password set by an admin
    G-->>B: choose a new password first
  end
  Note over G: access rule: is the account in a group linked to the app?
  G-->>B: redirect to app with code
  B->>A: callback with code
  A->>G: POST /token (code, verifier, secret)
  G-->>A: ID token + access token (JWTs) + refresh token
  Note over B,G: 2nd app: session cookie exists, no password prompt
```

### A group change reaching an app

```mermaid
sequenceDiagram
  participant Ad as Admin
  participant G as Guardian
  participant D as Postgres
  participant A as App
  A->>A: verify access token locally on every request
  Ad->>G: DELETE /api/v1/groups/{group}/members/{account}
  G->>D: DELETE, COMMIT
  G-->>A: back-channel logout (if the app is linked to the group)
  Note over A: an app without back-channel logout keeps the old token until it expires
  A->>G: POST /token (refresh)
  G->>D: session, account, access rule, groups (live)
  G-->>A: new tokens without the group, or invalid_grant
```

### Data model (main tables)

```mermaid
erDiagram
  ACCOUNT ||--o{ GROUP_MEMBER : "is in"
  USER_GROUP ||--o{ GROUP_MEMBER : has
  USER_GROUP |o--o{ USER_GROUP : "owns (owner group)"
  APP ||--o{ APP_GROUP : "is told about"
  USER_GROUP ||--o{ APP_GROUP : "linked to"
  APP |o--o{ USER_GROUP : "binds (single-app)"
  ACCOUNT ||--o{ SESSION : "signs in"
  SESSION ||--o{ REFRESH_TOKEN : "ends with"
  APP ||--o{ REFRESH_TOKEN : holds
  SESSION ||--o{ SESSION_APP : "used by"
  APP ||--o{ APP_USER : "was used by"
```

## Kubernetes notes

The Helm chart (`charts/guardian`, `docs/INSTALL.md`) creates these; the NetworkPolicy comes in 0.5. The shape
matters more than the details:

- The ingress or Gateway points only at port 3001. Port 3002 is exposed by a separate ClusterIP Service.
- A NetworkPolicy lets only the ingress controller reach 3001 (its namespace is a chart value) and only
  Prometheus and the kubelet reach 3002.
- Every replica is the same; nothing is stored per pod or per cluster.
