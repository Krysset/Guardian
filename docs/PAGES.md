# Guardian's pages

Every page of the sign-in pages and the management UI, and which requirements from `docs/USERS.md` each one
serves. The next step adds what each page contains; after that come the design drafts.

Page ids: **S** sign-in pages, **AC** account area (`/account`), **AD** admin area (`/admin`), **E** emails.
"Who" is the least role that sees the page; roles that inherit from it see it too (`docs/USERS.md`).

## Sign-in pages (served by the backend)

| Page | Purpose | Requirements | Who | Release |
|---|---|---|---|---|
| S1 Sign in | Username or email and password; links to sign-up and forgotten password; "Use a security key" (0.5). The approved design. | V1, V2, V7 (keys), V8 | Visitor | 0.1 |
| S2 Sign up | Create an account, with the three notices. | V3 | Visitor | 0.1 |
| S3 Choose a new password | After an admin set a temporary password. | U3 | User | 0.1 |
| S4 Consent | What an app asks for; allow or deny. | U1 | User | 0.1 |
| S5 No access | The account may not use this app. | U2 | User | 0.1 |
| S6 Sign out? | Confirm signing out of Guardian and all apps. | U5 | User | 0.1 |
| S7 Signed out | Confirmation, and a way back. | U5 | Visitor | 0.1 |
| S8 Already signed in | Who is signed in; go to the account area, or sign out. | U6 | User | 0.1 |
| S9 Error | Broken requests from apps, expired forms and links, unknown pages, server errors. | V4 | Visitor | 0.1 |
| S10 Forgot password | Ask for a reset link. | V5 | Visitor | 0.3 |
| S11 Reset password | Set a new password from the link. | V5 | Visitor | 0.3 |
| S12 Email confirmation | The result of a confirmation link. | V6 | Visitor | 0.3 |
| S13 Second factor | Authenticator code, or a recovery code; switch to a security key (0.5). | V7 | Visitor | 0.3 |
| S14 Security key | Waiting for a security key or passkey (needs JavaScript). | V7, V8 | Visitor | 0.5 |
| S15 Set up two-factor | Required setup: choose a method, scan the QR code or enter the secret, confirm a code. | U4, O4, A24 | User | 0.3 |
| S16 Recovery codes | Show the 10 codes once and ask for one back. Also reached from AC2. | U4, U11 | User | 0.3 |

## Account area (`/account`)

| Page | Purpose | Requirements | Who | Release |
|---|---|---|---|---|
| AC0 Start | The account area's start page: the way to each part, and actions needed, with no personal details. | U19 | User | 0.4 |
| AC1 Profile | Name, picture, locale, time zone, username, email (masked until shown, with its confirmation state). | U7, U8, U9 | User | 0.4 |
| AC2 Security | Password, two-factor methods, security keys and passkeys (0.5), recovery codes. | U10, U11 | User | 0.4 |
| AC3 Sessions | Where they are signed in; sign out one or all. | U12 | User | 0.4 |
| AC4 Connected apps | Apps they use, what each can see; remove access. | U13 | User | 0.4 |
| AC5 Groups | Groups they are in (not hidden ones), and the groups they own, linking to AC6. | U18, O1 | User | 0.4 |
| AC6 Owned group | One group they own: members and expiry, add by exact username or email, remove, linked apps. | O2, O3, O5 | Group owner | 0.4 |
| AC7 Your data | Download their data; delete the account. | U14, U15 | User | 0.4 |
| AC8 Confirm it's you (dialog) | Password or second factor before a protected change, then the change is saved. Used by AC1, AC2, AC3, AC4 and AC7. | U16 | User | 0.4 |

## Admin area (`/admin`)

Every admin page carries the one-administrator warning (A23) while it applies. The admin area opens on AD13, which shows no personal data; every page with personal data must be opened deliberately (see "Showing personal data" in `docs/USERS.md`).

| Page | Purpose | Requirements | Who | Release |
|---|---|---|---|---|
| AD13 Overview | The start page: aggregated figures only, nothing that identifies a person. | A28 | Guardian admin | 0.4 |
| AD1 Accounts | Search and filter, paged list. | A1 | Guardian admin | 0.4 |
| AD2 Account | Profile and email, status, groups and their expiry, temporary password, sign out everywhere, two-factor reset (0.3), delete or erase, restore during grace (0.3). | A2, A4, A5, A6, A7, A8, A9, A10, A13 | Guardian admin | 0.4 |
| AD3 New account | Username, password, email. | A3 | Guardian admin | 0.4 |
| AD4 Groups | All groups: key, name, members, owner group, built-in, bound app (single-app), hidden (1.x), linked apps. | A11, A26, A27 | Guardian admin | 0.4 |
| AD5 Group | Name, description, owner group, the app it is bound to (single-app), hidden (1.x), copy (1.x), members and expiry, linked apps; delete. | A12, A13, A14, A26, A27, A29, O5 | Guardian admin | 0.4 |
| AD6 New group | Key (never changes), name, description, owner group, "Is this group for one app only?" (no preselected answer; yes asks for the app), hidden (1.x). | A12, A26, A27 | Guardian admin | 0.4 |
| AD7 Apps | All apps (app admins in 1.x: their own). | A15 | App admin | 0.4 |
| AD8 App | Settings, access (rule, linked groups, machine API for Guardian admins), credentials and secret rotation, setup details to copy, disable, delete (Guardian admins), the app's audit entries. | A17, A18, A19, A20, A21, A22, A25 | App admin | 0.4 |
| AD9 New app | The settings and access of a new app. | A16 | Guardian admin | 0.4 |
| AD10 Secret, shown once (dialog) | After registering an app or rotating its secret: copy it, warned it will not be shown again. | A16, A19 | App admin | 0.4 |
| AD11 Audit log | All entries, filter by event and account, paged, with each entry's details. | A22 | Guardian admin | 0.4 |
| AD12 Deleted accounts | Accounts in their grace period: restore or erase now. | A7, A8 | Guardian admin | 0.4 (after 0.3) |

## Emails

Sent only to accounts with a confirmed address (except E1, which confirms it).

| Email | Requirements | Release |
|---|---|---|
| E1 Confirm your email address | U9, V3, V6 | 0.3 |
| E2 Reset your password | V5 | 0.3 |
| E3 Your password was changed | U17 | 0.3 |
| E4 Two-factor was added or removed | U17 | 0.3 |
| E5 Your email address is being changed (to the old address) | U9, U17 | 0.3 |
| E6 An administrator reset your two-factor (with the reason) | A9, U17 | 0.3 |

## Requirements without pages

| Requirements | Where they are met |
|---|---|
| O4, A24 | Enforced at sign-in by S15; no page of their own. |
| P1–P7 | The CLI, Kubernetes and Prometheus. |
| M1, M2 | OIDC and the machine API. |

## Every requirement and its pages

| Requirement | Pages |
|---|---|
| V1 | S1 |
| V2 | S1 |
| V3 | S2, E1 |
| V4 | S9 |
| V5 | S10, S11, E2 |
| V6 | S12, E1 |
| V7 | S1, S13, S14 |
| V8 | S1, S14 |
| U1 | S4 |
| U2 | S5 |
| U3 | S3 |
| U4 | S15, S16 |
| U5 | S6, S7 |
| U6 | S8 |
| U7 | AC1 |
| U8 | AC1 |
| U9 | AC1, E1, E5 |
| U10 | AC2 |
| U11 | AC2, S16 |
| U12 | AC3 |
| U13 | AC4 |
| U14 | AC7 |
| U15 | AC7 |
| U16 | AC8 |
| U17 | E3, E4, E5, E6 |
| U18 | AC5 |
| U19 | AC0 |
| O1 | AC5 |
| O2 | AC6 |
| O3 | AC6 |
| O4 | S15 |
| O5 | AC6, AD5 |
| A1 | AD1 |
| A2 | AD2 |
| A3 | AD3 |
| A4 | AD2 |
| A5 | AD2 |
| A6 | AD2 |
| A7 | AD2, AD12 |
| A8 | AD2, AD12 |
| A9 | AD2, E6 |
| A10 | AD2 |
| A11 | AD4 |
| A12 | AD5, AD6 |
| A13 | AD2, AD5 |
| A14 | AD5 |
| A15 | AD7 |
| A16 | AD9, AD10 |
| A17 | AD8 |
| A18 | AD8 |
| A19 | AD8, AD10 |
| A20 | AD8 |
| A21 | AD8 |
| A22 | AD8, AD11 |
| A23 | every AD page |
| A24 | S15 |
| A25 | AD8 |
| A26 | AD4, AD5, AD6 (1.x, if needed) |
| A27 | AD4, AD5, AD6 |
| A28 | AD13 |
| A29 | AD5 (1.x) |
| P1–P7 | CLI |
| M1, M2 | OIDC, machine API |
