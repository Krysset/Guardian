# Testing Guardian

> **Status (2026-11-20):** 206 tests, all passing with `-race` against PostgreSQL 16 and Go 1.26, none skipped.
> When something fails, read the message first: it may be a bug in the test, not in Guardian.

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

The management UI (`frontend/`) has no automated tests yet: `npm run check` type-checks it against the API types
generated from `docs/openapi.yaml`, and each part is checked in a real browser (Playwright) before it is handed
over. Browser tests in the repository come with part 5 of 0.4.

## Layers

| Layer | Where | Needs DB | What it proves |
|---|---|---|---|
| Unit | `internal/config`, `internal/auth`, `internal/server`, `internal/httpx`, `internal/web`, `internal/oidc`, `internal/internalapi`, `internal/backup` (file format), `cmd/guardian` (backup command line), and request validation in `internal/api` | no | argon2 hashing and malformed-hash rejection, key encryption, JWT signing and forgery rejection (alg none, wrong key, unknown kid), PKCE (RFC 7636 vector), client IP and trusted-proxy handling, open-redirect guards, CSRF and Origin checks, claim release per scope, every sign-in page rendering with escaping, security headers and no inline styles or scripts, static files and their caching, request validation (unknown fields refused, one error shape), metrics labelling, discovery document, `docs/openapi.yaml` matching the router route for route, the backup file's checksum catching truncation and damage |
| Database | `internal/store/*_test.go` | yes | migrations through goose (recorded once, safe when replicas start together), the schema script (idempotent, never overwrites edits, safe under concurrent startup), groups (membership and expiry, app links, the access rule, owners, single-app groups, the last-administrator rule also under concurrency), session idle and absolute timeouts, immediate revocation, single-use codes (also under concurrency), stable refresh tokens (bound to their app and session, safe under parallel use), the machine API's visibility rules, account administration (disabling, admin-set passwords, search and paging), app edits and secret rotation, the audit log, rate-limit counters, client secrets, cleanup job; in `internal/backup`, backup and restore against a real database |
| End to end | `e2e/*_test.go` | yes | the real public and internal routers over HTTP: the sign-in pages driven like a browser without JavaScript (sign-up, sign-in by username or email, temporary passwords, switching account, Home, error pages), SSO, signed access tokens, stable refresh tokens and their re-checks, session timeouts, revocation, logout everywhere, back-channel logout delivery, consent, rate limits, CSRF, the `/api/v1` admin and self-service routes, metrics |

## Requirements and the tests that pin them down

| Requirement | Tests |
|---|---|
| Group changes reach an app at its next refresh, and at once with back-channel logout | `TestE2EGroupChangesReachTheAppAtItsNextRefresh`, `TestE2ELeavingAGroupEndsAccessAndNotifiesTheApp`, `TestLeavingAGroupNotifiesOnlyTheAppsLinkedToIt` |
| An app only sees the groups linked to it | `TestAnAppOnlySeesTheGroupsLinkedToIt`, `TestE2EEachAppSeesOnlyItsOwnGroupsAndNoProfileInAccessTokens` |
| The access rule decides who may sign in to an app | `TestE2EAppAccessRuleDecidesWhoMaySignIn`, `TestAppAccessRule` |
| Only administrators manage Guardian; owners manage only their groups' members | `TestE2EGroupAndAppAPIsAreForAdministrators`, `TestE2EGroupOwnersManageOnlyTheMembersOfTheirGroups`, `TestGroupOwnersAreTheMembersOfTheOwnerGroup` |
| An app's machine API shows only its own groups and users | `TestE2EMachineAPIShowsAnAppOnlyItsOwnGroupsAndUsers`, `TestAnAppMayKnowItsGroupMembersAndItsUsersOnly`, `TestAnAppSeesOnlyItsLinkedGroupsAndTheirActiveMembers` |
| Refresh tokens are stable and re-check everything | `TestE2ERefreshTokensAreStableAndRecheckEverything`, `TestE2ESessionTimeoutsEndRefreshes`, `TestConcurrentUseOfOneRefreshTokenAllSucceeds` |
| `/api/v1` and `docs/openapi.yaml` describe the same routes | `TestOpenAPIDescribesEveryRoute` |
| Disabling an account or setting its password ends its sessions at once | `TestE2EDisablingAnAccountLocksItOutAndEnablingLetsItBackIn`, `TestE2EAnAdminSetPasswordEndsSessionsAndMustBeChanged`, `TestDisablingAnAccountEndsItsSessionsAndSparesTheLastAdmin`, `TestPasswordChangesEndTheRightSessions` |
| A rotated app secret keeps the old one only for the grace period | `TestE2EAdminsEditAppsAndRotateSecrets`, `TestAppUpdatesAndSecretRotation` |
| There is always an administrator | `TestE2ETheLastAdministratorIsProtected`, `TestE2EAPIErrorsAndUnknownRoutes`, `TestTheLastAdministratorCannotBeRemoved`, `TestAdministratorsRemovingEachOtherAtTheSameTimeLeaveOne` |
| Logout ends everything everywhere | `TestE2ESingleSignOnAndLogoutEverywhere`, `TestRevokeSessionEndsEverythingUnderIt` |
| Account deletion / app disabling stop refreshes and userinfo at once | `TestE2EAdminDeletionLocksTheUserOutImmediately`, `TestE2EDisablingAnAppStopsItsRefreshesAndLogins`, `TestSoftDeleteLocksTheAccountOutEverywhere` |
| Access tokens are lean signed JWTs that apps verify themselves | `TestE2ELoginIssuesSignedAccessAndIDTokens`, `TestE2EEachAppSeesOnlyItsOwnGroupsAndNoProfileInAccessTokens` |
| Introspection is gone; internal endpoints are not public | `TestE2EEachAppSeesOnlyItsOwnGroupsAndNoProfileInAccessTokens`, `TestInternalRouterBasics` |
| Open sign-up with rate limiting | `TestE2ESignUpIsOpenButRateLimited`, `TestE2ELoginThrottlingAndNoUserEnumeration`, `TestE2EAbuseProtection`, `TestRateLimit*` |
| Secrets never stored in plaintext | cookie, token, code, secret and password assertions in the e2e and database tests |
| A database from another schema revision is refused, not half-used | `TestADatabaseFromAnotherSchemaRevisionIsRefused`, `TestInitMigrationCarriesItsFingerprint` |
| Startup script safe for several replicas | `TestSchemaScriptSurvivesConcurrentStartups`, `TestSchemaScriptIsIdempotentAndNeverOverwrites` |
| Sign-up signs the new account in and continues to the app; mistakes come back on the form | `TestE2ESignUpPageCreatesAnAccountAndSignsItIn`, `TestSignupPageStructure` |
| An admin-set password must be replaced before anything else | `TestE2ETemporaryPasswordMustBeReplacedBeforeSignIn` |
| The sign-in pages escape everything, keep a strict CSP and never show technical details | `TestEveryPageRendersAndEscapesUntrustedData`, `TestPagesHaveNoInlineStylesOrScripts`, `TestPagesSendSecurityHeaders`, `TestErrorPagesNeverShowDetails`, `TestE2EPagesRoutingAndStaticFiles` |
| Home lists only the apps the account may use | `TestE2EHomeListsTheAppsTheAccountMayUse` |
| The account area: Home's apps, connected apps and Remove access (consent, refresh tokens and the machine API's right gone), sessions (another account's not found, sign out one, everywhere else, or this one), the email address (pending, cancelled, removed), groups the user is in and manages, owners adding by exact username or email; each protected change needs re-authentication | `TestE2EHomeAndConnectedApps`, `TestE2EMySessions`, `TestE2EMyEmailAddress`, `TestE2EMyGroupsAndAddingMembersByLogin`, `TestDescribeUserAgent` |
| The admin area: the overview counts without naming anyone (and only for administrators), accounts page with a total and filter by status, an account's details, signing it out everywhere, activity about it with who acted, who deleted it; the step-up asks a session without two-factor for a code and returns only to the management UI | `TestE2EAdminOverviewCountsWithoutNamingAnyone`, `TestE2EAdminAccountsPagesFiltersAndActivity`, `TestE2EStepUpForTheManagementUI` |
| A single-app group can never be linked to another app | `TestSingleAppGroupsAreBoundToOneAppForGood`, `TestE2ESingleAppGroupsThroughTheAPI` |
| Email links: sign-up waits for its confirmation, links work once and only the newest, the link signs in only the browser that signed up, the first account to confirm an address gets it, resets end every session, the reset answer never reveals an account | `TestE2ESignUpWithAnEmailWaitsForItsConfirmation`, `TestE2EAConfirmationLinkOpenedElsewhereDoesNotSignIn`, `TestE2ETheFirstAccountToConfirmAnAddressGetsIt`, `TestE2EPasswordResetByEmail`, `TestE2EChangingTheEmailAddress`, `TestE2EEmailOffAndEmailRequired` |
| Emails are valid, escaped, and never sent in the clear when STARTTLS is asked for | `TestEveryEmailRendersBothPartsAndEscapes`, `TestComposeIsAValidMultipartMessage`, `TestSMTPSendsAndStartTLSIsRequired` |
| Keys: the RFC-style lifecycle (pending, active, retiring, retired) on schedule and by hand, the emergency path, every replica following a rotation, the keyring's add-promote-remove rotation with re-encryption, and a keyring that lacks a needed key refused | `TestSigningKeysMoveThroughTheirStages`, `TestKeysFollowARotation`, `TestKeyringRotationReencryptsEverything`, `TestRotatingTheKeyring`, `TestKeysCommandLine` |
| Deleting accounts: the grace period, restoring with the memberships that still can be, erasing now (audit entries scrubbed, id in the deletion log, username free again), erasing when due, the last administrator kept, "download my data" without secrets, and a newer deletion log applied on restore | `TestE2EDeletingYourOwnAccountAndRestoringIt`, `TestE2EErasingAnAccountNow`, `TestE2EDownloadMyData`, `TestE2ETheLastAdministratorCannotDeleteItself`, `TestDeletedAccountsAreErasedAfterTheGracePeriod`, `TestRestoreAppliesANewerDeletionLog` |
| Two-factor: no session before the code; codes and recovery codes work once; setup saves nothing until one recovery code is typed back; administrators, group owners and apps that require it get the setup or a step-up; attempts are limited; the admin reset ends sessions and emails the reason | `TestE2ETwoFactorThroughTheAPIAndAtSignIn`, `TestE2ETwoFactorAttemptsAreLimitedAndCanBeCancelled`, `TestE2EAdministratorsAndOwnersMustUseTwoFactor`, `TestE2EAppsThatRequireTwoFactor`, `TestE2EAdministratorsResetTwoFactor`, `TestTOTPMatchesTheRFC` |
| Protected changes need a sign-in or re-authentication within 5 minutes, per session; wrong passwords are limited | `TestE2EProtectedChangesNeedARecentSignIn`, `TestE2EReauthIsLimited` |
| A backup restores exactly into a new installation, and never over one in use | `TestBackupRestoresIntoAFreshInstallationExactly`, `TestBackupWithoutAuditLogAndDryRun`, `TestEveryTableIsBackedUpOrLeftOutOnPurpose`, `TestFormatDetectsDamage`, `TestBackupCommandLine` |
| Metrics available for the Prometheus scrape | `TestE2EInternalListenerProbesAndMetrics`, `TestMetricsMiddlewareRecordsRoutePatternAndStatus` |

## Not covered (yet)

* Real browsers, TLS and the `Secure` / `__Host-` cookie path (tests run over plain HTTP). The sign-in pages'
  JavaScript (password show buttons, vertical centring) and their look are checked by hand.
* `TRUSTED_PROXY_HOPS` end to end (only the IP function is unit tested).
* Graceful SIGTERM shutdown, `/readyz` failing when the database is down, connection-pool limits.
* Kubernetes manifests and the NetworkPolicy.
* Load and latency: use `guardian_http_request_duration_seconds{route="/token"}` and `guardian_token_requests_total` from a staging deployment.
* Delivery through a real mail server with TLS (tests use a fake SMTP server without TLS; Mailpit by hand).
* Security keys and passkeys (0.5).
* Real off-the-shelf apps: Grafana is checked by hand (`docs/LOCAL-GRAFANA.md`).

## Known fragile spots

* `TestRateLimitWindowsRollOver` and `TestE2ERPInitiatedLogout` sleep about two seconds (window rollover, ID token expiry).
* `TestE2ERPInitiatedLogout` shortens an app's token lifetime to 1 second to obtain an expired ID token.
* Metrics tests assume chi reports route patterns such as `/things/{id}` through `RoutePattern()`.
