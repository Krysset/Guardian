# Changelog

Guardian follows [semantic versioning](https://semver.org). From 1.0.0 on, the database schema only changes
through new migrations, settings are only removed after a release that warns about them, and `/api/v1`
only gains fields and routes.

## 1.0.0 (unreleased)

The first release: an OpenID Connect sign-in service with groups, for apps you run yourself, on Kubernetes.

### Signing in
- Sign-in pages for username or email and password, with two-factor: an authenticator app, security keys,
  or recovery codes. Passkeys sign in on their own.
- Self-service sign-up, with email confirmation (optional, or required with `REQUIRE_EMAIL`), and password
  reset by email.
- Abuse protection: rate limits per account and address (accounts are never locked by strangers, IPv6
  counted per /64), a honeypot, and a proof-of-work puzzle on sign-up, forgot-password, and sign-in after
  repeated failures from an address or to an account. Sign-up never reveals whether an address is in use.
- Protected changes, and admin actions that could take over an account, ask the signed-in person to confirm
  it is them.

### OpenID Connect
- Authorization code flow with PKCE, discovery, JWKS, userinfo, revocation, RP-initiated logout and
  back-channel logout.
- Lean signed access tokens (RFC 9068) that apps check on their own; stable refresh tokens for apps with a
  secret, each refresh re-checking the session, the account and the app's groups.
- RS256 or ES256 per app, each with its own key and automatic rotation.
- `acr_values=mfa` asks for two-factor for one sign-in; tokens say which class it met (`acr`).
- A machine API for apps to read their own groups and members.

### Groups and apps
- Groups decide who may sign in to which app and what the app is told. Owner groups manage members;
  single-app groups are bound to one app for good; memberships can expire.
- Groups can be copied, hidden from their members, opened to requests to join (decided by their owners,
  with emails both ways), and joined by every new account.
- App admins: an app's owner group manages the app, links only groups it owns, and reads the app's audit
  entries.

### Management UI
- The account area (profile, security, sessions, connected apps, groups, data download and deletion) and the
  admin area (overview, accounts, groups, apps, audit log, deleted accounts).

### Operations
- Helm chart with Ingress or Gateway API routing, bundled or external Postgres, migrations at startup or as a
  Job, network policies, autoscaling and a ServiceMonitor.
- Encrypted backups (age) with a manifest, verify and restore, scheduled backups onto a volume, and a
  deletion log that keeps erased accounts erased after a restore.
- Signing-key rotation, an emergency key withdrawal, a rotatable encryption keyring, and a runbook for a
  locked-out administrator.
- Prometheus metrics that carry nothing about a person (`docs/METRICS.md`), graceful shutdown with
  draining, and logs without personal data.

### Data protection
- Account deletion with a grace period and erasure, a data download, audit retention, and minimal data
  (`docs/DATA-PROTECTION.md`).
