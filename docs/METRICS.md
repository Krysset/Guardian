# Metrics

Guardian serves Prometheus metrics at `/metrics` on its internal port, 3002. In the cluster that is the
`guardian-internal` Service, which only Prometheus can reach (`networkPolicy.metricsFrom`). With Docker Compose it
is http://localhost:3002/metrics, open to your machine only.

## What a metric may hold

Metrics count **what happens, never who it happens to**. A label value comes from a small, fixed set that
Guardian chooses: an outcome, a method, a reason, a route pattern, or an app's name. No label ever holds a
username, email, account or session id, IP address, user agent or a value a client sent. A client id nobody
registered is counted as the app `unknown`. This keeps the metrics free of personal data (GDPR), and keeps their
size bounded. Questions about one person belong in the audit log, which has its own retention and access
control. `TestE2EMetricsCountHowNotWho` checks that no username, id or raw request value reaches a series.

Do not publish `/metrics`: on a small installation even a count such as "1 disabled account" can point to a
person when combined with what an operator already knows.

## Counters: what happens

Counters are per replica. Use `sum(rate(...))` across replicas.

| Metric | Labels | What it counts |
|---|---|---|
| `guardian_logins_total` | `method`: password, passkey, password_and_code, password_and_key, password_and_recovery_code | Completed sign-ins on the sign-in pages. |
| `guardian_login_failures_total` | `factor`: password, passkey, code, recovery_code, key. `reason`: wrong_password, unknown_account, account_disabled, email_unconfirmed, not_recognised, expired, wrong_code | Failed steps on the sign-in pages, including the two-factor step before an app that requires it. Attempts the rate limiter refused are in `guardian_rate_limited_total` instead. |
| `guardian_app_signins_total` | `app` | Sign-ins to an app: authorization codes given to it, with a sign-in or with single sign-on. |
| `guardian_app_access_denied_total` | `app` | Sign-ins to an app refused because the account is in none of its groups. |
| `guardian_tokens_issued_total` | `app`, `grant`: authorization_code, refresh_token, client_credentials | Tokens issued. Refreshes are the steady load: one per signed-in user per app per token lifetime. |
| `guardian_token_refusals_total` | `app`, `grant` (also `other`), `reason` (below) | Token requests answered without tokens. |
| `guardian_rate_limited_total` | `endpoint`: login, register, reauth, mfa, mail, forgot, honeypot | Requests refused by a rate limiter, and honeypot hits (bots). |
| `guardian_csrf_refusals_total` | `check`: form, origin | Requests refused as possibly cross-site (below). |
| `guardian_passkey_clone_warnings_total` | none | Security key uses refused because the key may have been copied (below). |
| `guardian_pow_checks_total` | `form`: signup, forgot, login, api_signup. `result`: passed, missing, invalid | Proof-of-work answers checked (below). |
| `guardian_signups_total` | `result`: awaiting_email, confirmed, active | Self-service sign-ups (below). |
| `guardian_mail_sent_total` | `result`: sent, failed, dropped | Emails: sent, given up after retries, or dropped because the queue was full. |
| `guardian_http_requests_total` | `listener`, `route` (pattern), `method`, `code` | Every HTTP request. |
| `guardian_http_request_duration_seconds` | `listener`, `route`, `method` | Request latency (histogram). |

**Token refusal reasons.**

- Expected; they are how sign-outs and access changes reach apps:
  - `session_ended`: the sign-in session ended (signed out, timed out, revoked);
  - `account_unavailable`: the account was disabled or deleted;
  - `access_lost`: the account is no longer in any of the app's groups.
- Worth a look:
  - `wrong_secret`: a known app without its secret, or with a wrong or retired one;
  - `unknown_client`: a client id that is not registered;
  - `app_disabled`: the app is disabled;
  - `unknown_refresh_token`: a refresh token that never existed or was revoked;
  - `bad_code`: an authorization code that is wrong, expired or already used;
  - `pkce_failed`: the code verifier did not match;
  - `grant_not_allowed`: a grant the app may not use;
  - `public_client`: an app without a secret asked for a token of its own;
  - `malformed`: the request body could not be read.
- Guardian's fault: `server_error`.

Refresh tokens are stable (one per sign-in, never replaced; see ARCHITECTURE.md), so using one twice is normal
and nothing counts it. A stolen refresh token is useless without the app's secret, so `wrong_secret` is the one
to watch.
- **If it rises for one app:** check the app's own deployment first. The usual cause is a secret rotation that
  did not reach every instance.
- **If it is not that:** someone has the app's client id, and perhaps tokens, but not its secret. Rotate the
  app's secret. If you think tokens were taken too, end the affected sessions: that kills their refresh tokens
  at once.

**CSRF refusals.**
- `form`: a form on a sign-in page was posted without the hidden token that proves it came from Guardian's own
  page. A trickle is normal: a tab left open for hours, or a browser that blocks cookies.
- `origin`: a browser asked the API to change something from a site that is not Guardian's
  (`ALLOWED_ORIGINS`).
- A burst of either means another site is trying to make people's browsers act on Guardian. It is blocked, but
  worth knowing.

**Passkey clone warnings.**
- Some security keys keep a counter that goes up with every use. If a key shows up with a lower counter than
  last time, two copies of it may exist.
- Guardian refuses that use and records `mfa.key_clone_warning` in the audit log, with the account and the
  key's name.
- It should stay at 0. Synced passkeys (iCloud, Google, password managers) keep no counter and never trigger it.
- **If it fires:** ask the account's owner whether they still have the key. Remove the key from the account
  either way, and have them add it again only if they are sure it is the original.

**Proof of work.**
- Sign-up and forgot-password always carry a puzzle; sign-in does once an address has failed three times.
- `missing` is a form sent without an answer: a browser without JavaScript, or a bot that does not run it.
  `invalid` is a wrong, expired or reused answer, which a browser running the page never sends.
- Many `missing` or `invalid` at once mean bots are trying; the puzzle is making each attempt cost them.

**Sign-ups.**
- `awaiting_email` is an account created and waiting for the link in the email; `confirmed` is the link
  followed.
- Bots rarely confirm, so a growing gap between the two is the sign of spam sign-ups.
- `active` is a sign-up without an email address, usable at once.
- `guardian_accounts{status="pending"}` shows the same from the other side.

## Gauges: the state of the installation

These are read from the database, at most every 30 seconds, so several scrapers do not each run the queries.
**Every replica reports the same value: use `max()`, never `sum()`.**
`guardian_state_metrics_up` is 0, and the counts are missing, when the database could not be read.

| Metric | Labels | What it shows |
|---|---|---|
| `guardian_accounts` | `status`: active, pending, disabled, deleted | Accounts. `pending` is waiting for email confirmation; `deleted` is in the grace period before erasure. |
| `guardian_accounts_second_factor` | `factor`: none, authenticator_app, security_key, both | Accounts that are not deleted, by the second factor they have: how two-factor and passkeys are adopted. |
| `guardian_admins_without_second_factor` | none | Active administrators with no second factor yet; they must set one up at their next sign-in. |
| `guardian_sessions` | none | Live sign-in sessions (one per signed-in browser), whatever apps they use. |
| `guardian_app_sessions` | `app` | Live sessions that have received tokens for the app. Every app is listed, with 0 when unused. |
| `guardian_apps` | `state`: enabled, disabled | Registered apps. |
| `guardian_groups` | `kind`: shared, single_app | Groups. |
| `guardian_signing_key_activated_timestamp_seconds` | `alg`: RS256, ES256 | When each algorithm's signing key in use started signing. |
| `guardian_signing_key_rotation_due_timestamp_seconds` | `alg` | When it is due to be replaced (`SIGNING_KEY_LIFETIME` later). Rotation is automatic. |
| `guardian_backup_last_success_timestamp_seconds` | none | When the last backup was written; 0 if there is none. |
| `guardian_keyring_values` | `key_id` | Encrypted values per keyring key. A key may leave the keyring once it has none. |

**Sessions and app sessions are different things.** A person signed in once and using three apps is one
session and three app sessions. Summing `guardian_app_sessions` over apps counts people several times. For "how
many are signed in", use `guardian_sessions`; for "how many use this app", use `guardian_app_sessions{app="..."}`.

Per replica, not from the database:
- `guardian_mail_queue_depth`: emails waiting in that replica's queue; at 256 new ones are dropped.
- `guardian_build_info{version}`: always 1.
- `guardian_db_*`: the connection pool.
- `go_*` and `process_*`: the runtime.

## Suggested alerts

```yaml
- alert: GuardianTokenSecretFailures      # an app's secret is wrong: a missed rotation, or someone without it
  expr: sum by (app) (rate(guardian_token_refusals_total{reason="wrong_secret"}[10m])) > 0.1
  for: 10m
- alert: GuardianTokenServerErrors
  expr: sum(rate(guardian_token_refusals_total{reason="server_error"}[5m])) > 0
  for: 5m
- alert: GuardianPasswordGuessing         # many wrong passwords across accounts: credential stuffing
  expr: sum(rate(guardian_login_failures_total{factor="password"}[10m])) > 1
  for: 10m
- alert: GuardianPasskeyCloneWarning
  expr: increase(guardian_passkey_clone_warnings_total[1h]) > 0
- alert: GuardianCrossSiteRequests
  expr: sum(increase(guardian_csrf_refusals_total[15m])) > 20
- alert: GuardianAdminWithoutTwoFactor
  expr: max(guardian_admins_without_second_factor) > 0
  for: 1d
- alert: GuardianSigningKeyRotationStuck
  expr: time() - max by (alg) (guardian_signing_key_rotation_due_timestamp_seconds) > 3600
- alert: GuardianMailQueueFilling
  expr: max(guardian_mail_queue_depth) > 128
  for: 5m
- alert: GuardianUnconfirmedSignups       # sign-ups that never confirm: likely bots
  expr: sum(increase(guardian_signups_total{result="awaiting_email"}[1d])) - sum(increase(guardian_signups_total{result="confirmed"}[1d])) > 50
- alert: GuardianBackupOld
  expr: time() - max(guardian_backup_last_success_timestamp_seconds) > 2 * 86400
- alert: GuardianStateMetricsDown
  expr: max(guardian_state_metrics_up) == 0
  for: 10m
```

The thresholds are starting points; tune them to your traffic.
