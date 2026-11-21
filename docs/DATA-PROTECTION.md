# Data protection

What Guardian stores about people, why, for how long, who sees it, and how people use their rights under the
GDPR. It is written for whoever runs a Guardian installation: you are the controller of the data it holds, and
this page is the material for your own privacy notice and records of processing.

Guardian keeps as little as an identity service can: no phone numbers, no birthdates, no tracking, no
third-party scripts, and nothing sent anywhere except the emails it sends and the claims it gives to apps
people sign in to.

## What is stored

| Data | Why | Where |
|---|---|---|
| Username | To sign in, and as `preferred_username` for apps | `account` |
| Password | To sign in. Only an argon2id hash is kept. | `account` |
| Display name, given and family name, picture address, language, time zone | Optional. Given to apps that ask for the `profile` scope; the time zone also formats times in emails. | `account` |
| Email address, and when it was confirmed | Optional (required with `REQUIRE_EMAIL`). Password resets and security notices; given to apps with the `email` scope. | `account` |
| Two-factor: authenticator app secret, security keys and passkeys (public keys, names, last use), recovery codes | To sign in with two-factor. The app secret is encrypted with the keyring; recovery codes are hashed; security keys are only public keys. | `account_mfa` |
| Group memberships, with who added them and when they expire | To decide which apps someone may use, and what the apps are told | `group_member` |
| Requests to join a group, with the optional message | So owners can decide | `group_request` |
| Sessions: when signed in, last active, IP address, browser (user agent), how they signed in | To keep people signed in, to show them where they are signed in, and to sign them out | `session` |
| Apps a person has used, consents given | To skip asking again, and for "Connected apps" | `app_user`, `account_consent` |
| Refresh tokens and authorization codes | Sign-in to apps. Only hashes are kept. | `refresh_token`, `authorization_code` |
| One-time links (password reset, email confirmation) | Only hashes, until used or expired | `account_token` |
| Audit log: what happened, when, by which account, about which account, app or group, and the IP address | Security and accountability | `audit_log` |
| Rate-limit counters per account and address | Abuse protection | `rate_limit` |
| Deletion log: ids of erased accounts, and when | So a restored backup erases them again | `deletion_log` |

**Cookies.** Guardian sets only cookies it needs to work: the session (`guardian_session`), a form token
against cross-site requests (`guardian_csrf`), and short-lived cookies that carry one sign-in step
(`guardian_mfa`, `guardian_passkey`, `guardian_signup`). None tracks people, so no consent banner is needed
for them. The management UI keeps nothing in the browser's storage beyond what its pages show.

**Logs and metrics.** The server's logs hold account ids at most: never names, email addresses, IP addresses
or tokens (the end-to-end tests fail if an email or IP address reaches the log). Metrics count events and
never carry anything about a person (`docs/METRICS.md`).

## Who sees what

| Who | Sees |
|---|---|
| The person | Everything about themselves, in the account area and in their data download |
| Apps they sign in to | The claims of the scopes the app may ask for: `sub`, and with `profile` the profile fields, with `email` the address, with `groups` the keys of the app's groups they are in. An app that is not first-party asks for consent first. Apps with the machine API can list the members of their own linked groups. |
| Group owners | The usernames and display names of their groups' members, and of people asking to join, with their messages |
| App admins | Their app's settings and its audit entries, which name the accounts involved, without IP addresses |
| Guardian admins | Accounts (email addresses masked until shown), groups, apps and the full audit log, with IP addresses |
| Operators | The database and backups |

The email server you configure (`SMTP_HOST`) receives the emails Guardian sends: the recipient's address
and the email's text. It is your processor.

## How long it is kept

| Data | Kept |
|---|---|
| An account and everything about it | Until it is deleted, then 30 days (`DELETION_GRACE_PERIOD`) before it is erased |
| A sign-up waiting for its email confirmation | 48 hours, then removed with its username |
| Sessions (with IP address and browser) | Until they end (at most 30 days, `SESSION_MAX_LIFETIME`; 7 days idle, `SESSION_IDLE_TIMEOUT`), then 30 more days |
| Revoked refresh tokens | 7 days |
| Expired one-time links and codes | 1 to 7 days |
| Decided requests to join a group | 30 days |
| Rate-limit counters | 1 day |
| Audit log | 6 months (`AUDIT_RETENTION`, at least 1 day) |
| Deletion log | For as long as backups from before an erasure exist; it holds ids only |
| Backups | As long as you keep them (`backup.keep`, 14 by default for scheduled backups) |

A maintenance job removes expired data every hour, on whichever replica takes its lock.

## People's rights

- **Access and portability.** "Download your data" in the account area (`GET /api/v1/me/export`) gives a
  JSON file (after confirming it's them) with the profile, two-factor methods (no secrets), groups, requests to join, consents, apps used,
  sessions and the audit entries about the account (up to 5000).
- **Rectification.** The profile and email address are edited in the account area; a new address is
  confirmed by a link before it counts. An administrator can correct them too.
- **Erasure.** "Delete account" in the account area (it asks to confirm it's them), or an administrator.
  The account is signed out everywhere and disabled at once; its group memberships are taken away. During the
  grace period an administrator can restore it. Then it is erased: the account and everything that refers to
  it is deleted, its id goes into the deletion log, and its audit entries lose their IP addresses and
  personal details (they keep what happened, and when). An administrator can erase at once.
- **Objection and restriction.** An administrator can disable an account, which stops all processing except
  keeping the data.
- **Withdrawing consent from an app.** "Connected apps" in the account area removes an app's consent and its
  refresh tokens; the app's tokens stop working within their lifetime.

## Backups and restore

A backup holds accounts, groups, apps, two-factor (still encrypted), requests to join, signing keys, the
deletion log and, unless left out, the audit log. Sessions and tokens are not in it. Backups are encrypted to
your age keys, and the cluster never holds the private key.

Data stays in a backup until the backup is deleted. When you restore one, give it the current deletion log
(`guardian restore --apply-deletions`): accounts erased after the backup was taken are erased again before
anyone can sign in. See `docs/INSTALL.md`, "Backup and restore".

## Security measures, in short

- Passwords hashed with argon2id; secrets and one-time links stored as hashes; the authenticator app secrets
  and signing keys encrypted with a keyring that can be rotated.
- Two-factor required for administrators, group owners and app admins; sessions confirm who their user is
  again before protected changes, the data download, and admin actions that could take over an account.
- Rate limits, a honeypot and proof of work against automated sign-ups and password guessing; accounts are
  never locked by strangers.
- The internal port (metrics, probes) is reachable only inside the cluster; the images run as non-root with
  read-only file systems.
- Every change is in the audit log.
