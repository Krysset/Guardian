# Testing Guardian

> **Status:** the whole suite was run for the first time on 2026-11-14 (Go 1.24, PostgreSQL 16, with `-race`):
> 102 tests, all passing, none skipped (119 after the configuration, migration and group tests; last full run with Go 1.26 and the pgx driver). The first run found one real bug, an app could not be registered through
> the API without `post_logout_redirect_uris`, which is fixed. When something fails, read the message first: it
> may be a bug in the test, not in Guardian.

## Running

Unit tests need nothing:

```
go mod download
go test ./...        # database tests skip themselves
```

Database and end-to-end tests need a PostgreSQL database **dedicated to testing**. They truncate every table, so
they refuse to run unless the database name ends in `_test` and you opt in explicitly:

```
createdb guardian_test
export GUARDIAN_TEST_DB=1 DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASSWORD=... DB_NAME=guardian_test
go test -race -count=1 ./...
```

Each test process takes a Postgres advisory lock, so packages can run in parallel without `-p 1`.
CI: `.github/workflows/backend.yml` (at the repository root) runs everything against a Postgres service container and builds the image.

## Layers

| Layer | Where | Needs DB | What it proves |
|---|---|---|---|
| Unit | `internal/config`, `internal/auth`, `internal/server`, and `util_test.go`, `handlers_test.go`, `templates_test.go` in `internal/api` | no | argon2 hashing and malformed-hash rejection, key encryption, JWT signing and forgery rejection (alg none, wrong key, unknown kid), PKCE (RFC 7636 vector), client IP and trusted-proxy handling, open-redirect guards, CSRF and Origin checks, claim release per scope, HTML escaping and security headers, request validation, metrics labelling, discovery document |
| Database | `internal/store/*_test.go` | yes | migrations through goose (recorded once, safe when replicas start together), the schema script (idempotent, never overwrites edits, safe under concurrent startup), groups (membership and expiry, app links, the access rule, owners, the last-administrator rule also under concurrency), token introspection validity rules, immediate revocation, single-use codes (also under concurrency), refresh rotation and theft detection, rate-limit counters, client secrets, cleanup job |
| End to end | `e2e/*_test.go` | yes | the real public and internal routers over HTTP: login, SSO, tokens, introspection, logout everywhere, back-channel logout delivery, consent, rate limits, CSRF, admin APIs, metrics |

## Requirements and the tests that pin them down

| Requirement | Tests |
|---|---|
| Group changes are effective immediately | `TestRemovingAMemberIsVisibleToTheNextIntrospection`, `TestE2EGroupChangesByAnAdminAreImmediate`, `TestAnAppOnlySeesTheGroupsLinkedToIt` |
| An app only sees the groups linked to it | `TestAnAppOnlySeesTheGroupsLinkedToIt`, `TestIntrospectionReturnsTheGroupsOfTheCallerNotTheTokenApp` |
| The access rule decides who may sign in to an app | `TestE2EAppAccessRuleDecidesWhoMaySignIn`, `TestAppAccessRule` |
| Only administrators manage Guardian; owners manage only their groups' members | `TestE2EGroupAndAppAPIsAreForAdministrators`, `TestE2EGroupOwnersManageOnlyTheMembersOfTheirGroups`, `TestGroupOwnersAreTheMembersOfTheOwnerGroup` |
| There is always an administrator | `TestE2ETheLastAdministratorIsProtected`, `TestTheLastAdministratorCannotBeRemoved`, `TestAdministratorsRemovingEachOtherAtTheSameTimeLeaveOne` |
| Logout ends everything everywhere | `TestE2ESingleSignOnAndLogoutEverywhere`, `TestRevokeSessionEndsEverythingUnderIt` |
| Account deletion / app disabling lock out at once | `TestE2EAdminDeletionLocksTheUserOutImmediately`, `TestE2EDisablingAnAppKillsItsTokensAndLogins`, `TestIntrospectionValidityRules` |
| Services integrate with one call | `TestE2EIntrospectionAuthenticationAndBoundaries`, `TestIntrospectionReturnsTheGroupsOfTheCallerNotTheTokenApp` |
| Introspection is internal only | `TestE2EIntrospectionAuthenticationAndBoundaries`, `TestInternalRouterBasics` |
| Open sign-up with rate limiting | `TestE2ESignUpIsOpenButRateLimited`, `TestE2ELoginThrottlingAndNoUserEnumeration`, `TestRateLimit*` |
| Secrets never stored in plaintext | cookie, token, code, secret and password assertions in the e2e and database tests |
| A database from another schema revision is refused, not half-used | `TestADatabaseFromAnotherSchemaRevisionIsRefused`, `TestInitMigrationCarriesItsFingerprint` |
| Startup script safe for several replicas | `TestSchemaScriptSurvivesConcurrentStartups`, `TestSchemaScriptIsIdempotentAndNeverOverwrites` |
| Metrics available for the Prometheus scrape | `TestE2EInternalListenerProbesAndMetrics`, `TestMetricsMiddlewareRecordsRoutePatternAndStatus` |

## Not covered (yet)

* Real browsers, TLS and the `Secure` / `__Host-` cookie path (tests run over plain HTTP).
* `TRUSTED_PROXY_HOPS` end to end (only the IP function is unit tested).
* Graceful SIGTERM shutdown, `/readyz` failing when the database is down, connection-pool limits.
* Kubernetes manifests and the NetworkPolicy.
* Load and latency: use `guardian_http_request_duration_seconds{route="/introspect"}` from a staging deployment.
* Email verification, password reset, MFA (not implemented).

## Known fragile spots

* `TestRateLimitWindowsRollOver` and `TestE2ERPInitiatedLogout` sleep about two seconds (window rollover, ID token expiry).
* `TestE2ERPInitiatedLogout` shortens an app's token lifetime to 1 second to obtain an expired ID token.
* Metrics tests assume chi reports route patterns such as `/things/{id}` through `RoutePattern()`.
