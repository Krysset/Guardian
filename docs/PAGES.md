# Guardian's pages

Every page of the sign-in pages and the management UI, and which requirements from `docs/USERS.md` each one
serves, and what each page contains. The design drafts are made from this.

Page ids: **S** sign-in pages, **H** home (`/`), **AC** account area (`/account`), **AD** admin area (`/admin`),
**E** emails.
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

## Home (`/`)

| Page | Purpose | Requirements | Who | Release |
|---|---|---|---|---|
| H0 Home | Where a signed-in user lands: their connected apps, the apps available to them, actions needed, and the way to the account and admin areas. No personal details. | U19, U20 | User | 0.1 (simple), 0.4 |

## Account area (`/account`)

The account area opens on AC1 Profile.

| Page | Purpose | Requirements | Who | Release |
|---|---|---|---|---|
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

## What each page contains

Reviewed 2026-11-15 to 2026-11-19 and drawn on the design board. **Shows** is what the page displays, **Fields** what can be entered,
**Actions** the buttons and links, **States** the variants a design must cover. Items marked with a release
appear from that release; until then the page is drawn without them.

### Shared parts

- **F1 Sign-in frame** (every S page): the Guardian logo, a heading, the page's content, and the footer (Help,
  Privacy, "Powered by Guardian"). Works without JavaScript; only S14 needs it.
- **F2 Management UI frame** (every AC and AD page):
  - A top bar with the logo (a link to H0), the signed-in username, and Sign out. A switch between the account area and the
    admin area, shown to admins only.
  - The area's navigation.
  - In the admin area, the one-administrator warning (A23) while it applies.
- **Common elements:**
  - Every password field has a show button. Wherever a password is chosen or set (sign-up, any change or
    reset, an admin setting one), it is typed twice, in two fields, and must match; the rule ("at least 10
    characters") is shown with them.
  - Masked IP addresses, like masked emails, on AC3.
  - Masked values with a show button (an eye), used for email addresses on AC1 and AD2.
  - Confirmation dialogs for destructive actions. The most serious (deleting an account, app or group) make
    the admin type the name.
  - Field-level error messages and a page-level error banner.
  - Short success messages ("Saved").
  - Empty states ("No members yet").
  - Status badges: active, disabled, deleted, built-in, bound to an app.
  - Page controls for paged lists: Next and Previous.
  - A date picker for membership expiry.
  - Copy buttons for ids, URLs and secrets.

### Sign-in pages

**S1 Sign in** (approved design)
- Fields: username or email; password.
- Actions: Sign in. "Forgot password?" (0.3). "Use a security key" (0.5). **"Create an account"** (new, leads to
  S2).
- States: wrong username or password (the same message whether or not the account exists); too many
  attempts, try again in a few minutes (by default 5 failures for one account from one address, or 50 from one
  address, in 15 minutes; the account itself is never locked); form expired, reload. The username is kept after an error.

**S2 Sign up**
- Fields: username (with its rule: 3–64 letters, digits, `.`, `_`, `-`); password, twice; email (0.3:
  optional, or required when `REQUIRE_EMAIL` is set); a honeypot field that people never see.
- Shows the three notices:
  - without an email, only an administrator can reset a forgotten password;
  - Guardian is a hobby project under active development;
  - use a password you use nowhere else.
- Actions: Create account. "Already have an account? Sign in".
- States: username taken; email already in use (0.3); password too short; passwords do not match; too many
  sign-ups from this address.
- After sign-up the user is signed in and continues to the app they came from (or their account). With an
  email (0.3), sign-up is only complete once the address is confirmed: the page says "Check your inbox" (with
  Resend and Change address, S2b), and the confirmation link (S12) signs them in and continues.
- Built in 0.3: the link signs in only in the browser that signed up (a short-lived cookie ties them), so a
  mail scanner that opens the link confirms the address but gets no session. Opened elsewhere, the page says
  the account is ready and offers Sign in. Until the link is used, signing in with the right password says to
  confirm the address first. An unconfirmed sign-up is removed after 48 hours, freeing its username.

**S3 Choose a new password**
- Shows: why ("An administrator set a temporary password for your account. Choose your own to continue.").
- Fields: new password, twice.
- Actions: Save and continue. Sign out. There is no way to skip it.
- States: too short; passwords do not match; same as the temporary password.

**S4 Consent**
- Shows:
  - the app's logo and name, with "wants to use your Guardian account";
  - "Signed in as `<username>`", with "Not you? Sign out";
  - what the app will get, one line per scope, for example "Your name and username", "Your email address",
    "Your groups that are linked to this app".
- Actions: Allow, Deny.

**S5 No access**
- Shows:
  - "You don't have access to `<app>`";
  - what to do: ask an administrator to add you to a group with access;
  - "Signed in as `<username>`".
- Actions: Sign out to switch account (signs out, then back to sign-in for the same app); go to your account
  (0.4).

**S6 Sign out?**
- Shows: "Sign out of Guardian? You will also be signed out of the apps you use through Guardian."
- Actions: Sign out, Cancel.

**S7 Signed out**
- Shows: "You're signed out." When the app gave a page to return to, there is no page: the browser goes there.
- Actions: Sign in again.

**S8 Already signed in**
- Shows: "You're signed in as `<username>`."
- Actions: Go to your account (0.4); Sign out.

**S9 Error**
- Shows: a plain title, what happened, and what to do. Never technical details.
- Variants:
  - the app's sign-in link is broken (unknown app or redirect address): contact whoever runs the app;
  - session expired: start again from the app;
  - form expired: reload the page;
  - link expired or already used (0.3): request a new one;
  - page not found;
  - something went wrong on Guardian's side: try again later.

**S10 Forgot password** (0.3)
- Fields: username or email; a honeypot field that people never see (a filled one gets the usual answer and no
  email).
- Actions: Send reset link; back to sign in.
- States: afterwards always the same message: "If the account has a confirmed email address, we have sent
  a link." Accounts without one are told, on this page, to contact an administrator.

**S11 Reset password** (0.3)
- Fields: new password, twice.
- Shows: "Two-factor still applies when you sign in."
- Actions: Save.
- States: link expired or used (S9 variant).
- Built in 0.3: after saving, every session of the account ends and S1 confirms the change.

**S12 Email confirmation** (0.3)
- States: confirmed (signs the user in if sign-up was waiting for it, and continues; otherwise continue to
  your account); link expired (request a new one from your profile); the address is now used by another
  account.
- Built in 0.3: until the account area exists (0.4), "your profile" is Home. A link of a waiting sign-up leads
  back to S2b (new link, or another address); a used link says so.

**S13 Second factor** (0.3)
- Fields: a 6-digit code from the authenticator app; or, after "Use a recovery code", a recovery code.
- Actions: Verify. Switch between code and recovery code. "Use a security key" (0.5). Sign out.
- States: wrong code; too many attempts.
- Built in 0.3: the page comes between the password and the session (a sealed, 10-minute cookie holds the
  waiting sign-in), and also when an app requires two-factor of a session that signed in without it. Five
  wrong codes in 15 minutes make the account wait. "Sign out" drops the waiting sign-in (and ends a session
  that was stepping up).

**S14 Security key** (0.5)
- Shows: "Use your security key or passkey", with what to do and a waiting state.
- Actions: Try again; use another method.
- States: cancelled; not recognised; this browser doesn't support security keys; JavaScript is off.
- Built in 0.5: it is `/mfa?key`, and `/mfa` itself for an account with keys but no authenticator app. S1 also
  has "Sign in with a passkey" and the browser's passkey suggestions in the username field.

**S15 Set up two-factor** (0.3)
- Shows: why it is required ("Administrators must use two-factor", or "`<app>` requires two-factor").
- Fields: the method (authenticator app; security key from 0.5). For the authenticator: a QR code, the secret
  as text (with copy) for typing in by hand, and a code to confirm.
- Actions: Continue (to S16). Sign out. There is no way to skip it.
- States: wrong code.
- Built in 0.3: a wrong code shows a new QR code and secret (the first may have been scanned wrongly). The
  method choice is left out until security keys exist (0.5). Voluntary setup is the API's until the account
  area (0.4). Built in 0.5: the choice is two tabs, "Authenticator app" and "Security key or passkey" (a name,
  then the browser's dialog, then S16).

**S16 Recovery codes** (0.3)
- Shows:
  - 10 codes, each usable once;
  - that this is the only time they are shown;
  - Copy, Download as a text file, Print.
- Fields: one of the codes, typed back, to prove they were saved.
- Actions: Finish.
- Built in 0.3: nothing is saved until Finish. Copy, Download and Print need JavaScript and are hidden without
  it; printing shows only the codes.

### Home

**H0 Home**
- Uses the management UI frame (F2) without an area navigation.
- Shows actions that need the user, without personal details: "Set up two-factor" (0.3), "Confirm your new
  email address" (0.3; the address is not shown).
- **Your connected apps:** the apps the user has signed in to: logo, display name, description; each opens the
  app's homepage. A link to AC4 to see what each app can see and remove access.
- **Available apps:** the apps the user may sign in to but has not used yet, the same way.
- Apps without a homepage, and apps the user may not sign in to, are not listed.
- **Manage:** Your account (AC1); Admin area (AD13, admins only).
- States: no apps at all ("No apps yet. Ask an administrator for access."); either card empty is left out.
- Visitors who are not signed in go to S1, and come back here afterwards. Signing in or up without an app
  to return to also lands here.
- 0.1 has a simple version in the sign-in page style (served by the backend): the username, connected and
  available apps, and Sign out. The full Home in the management UI design replaces it in 0.4 (built in part 2);
  the backend's version stays as the fallback until the chart sends `/` to the frontend.

### Account area

**AC1 Profile**
- Fields: picture (an https address, with a preview); display name; given name; family name; username;
  locale; time zone.
- Shows the email (0.3), masked until shown, in one of these states: none (add one); confirmed (change,
  remove); a new address waiting for confirmation (resend the link, cancel).
- Actions: Save. Changing the username or email asks to confirm it's you (AC8, 0.3).
- States: username taken; picture address not https.

**AC2 Security**
- **Password:** current password, and the new one twice; Change. Shows that other sessions are signed out.
- **Two-factor** (0.3):
  - whether it is on, and whether it is required for you and why;
  - authenticator app: set up or remove;
  - recovery codes: how many are left, make new ones (shown as on S16);
  - security keys and passkeys (0.5): name, added, last used; add, rename, remove.
- Removing the last way to recover the account asks for an extra confirmation. Removing two-factor while it
  is required is refused.

**AC3 Sessions**
- Shows one row per session: browser and system (from the user agent), IP address (partly masked, for
  example `203.0.113.•••`, until shown), signed in, last active, and "This device" on the current one.
- Actions: Sign out (per row); Sign out everywhere else.

**AC4 Connected apps**
- Shows one row per app the user has used: logo, name, what it can see (the scope lines from S4), first and
  last use.
- Actions: Remove access. This forgets the consent, ends the app's refresh tokens and tells the app with
  back-channel logout.

**AC5 Groups**
- **Groups you're in:** display name, description, when the membership expires. Display names only: users
  never need group keys.
- **Groups you manage** (group owners): display name, number of members, linked apps; open (AC6).
- States: no groups.

**AC6 Owned group**
- Shows: name, description, the apps it is linked to (names only).
- Shows the members: username, display name, added, expires.
- Fields: username or email (exact); expiry date (optional). There are no suggestions.
- Actions: Add (the only answers are "No user found" and "User added"); Remove (with confirmation); change a
  member's expiry.

**AC7 Your data**
- **Download your data:** Download (a JSON file).
- **Delete your account** (0.3):
  - what happens: you are signed out everywhere at once; the account is erased after 30 days; an
    administrator can restore it until then; apps may keep data of their own;
  - type your username to confirm, then confirm it's you (AC8).
  - States: refused for the last administrator, with the reason.

**AC8 Confirm it's you** (dialog, 0.3)
- Shows: what is about to change ("Confirm it's you to change your email address").
- Fields: password, or a second-factor code, or a security key (0.5).
- Actions: Confirm (then the change is saved); Cancel. It is not asked again for 5 minutes.

### Admin area

**AD13 Overview**
- Shows figures only:
  - accounts: active, disabled, waiting for erasure (0.3);
  - groups;
  - apps: enabled and disabled;
  - over the last 24 hours: sign-ins, failed sign-ins, rate-limited requests;
  - administrators, and from 0.3 how many have two-factor.
- Actions: links to Accounts, Groups, Apps, Audit log.

**AD1 Accounts**
- Fields: search (username, name or email); status filter.
- Shows a table: username, display name, email, status, last sign-in; Next and Previous.
- Actions: open an account (AD2); New account (AD3).

**AD2 Account**
- Shows: username, status badge, created, last sign-in, "must choose a new password" when set.
- **Profile:** the same fields as AC1, with the email masked until shown. An email set here counts as
  confirmed.
- **Access:**
  - Disable or enable: confirmation explains that disabling signs the account out everywhere; refused for
    the last administrator.
  - Sign out everywhere.
  - Set a temporary password: typed twice by the admin. From 0.5, a Generate button fills in a random one and
    copies it to the clipboard. The user must change it at the next sign-in.
  - Reset two-factor (0.3): a reason is required; the user is emailed.
- **Groups:** groups with expiry; add to a group (with expiry); remove.
- **Activity:** recent audit entries about this account, with a link to the full audit log.
- **Delete:** type the username. Erase now (0.3). A deleted account (0.3) shows when it will be erased and a
  Restore button.

**AD3 New account**
- Fields: username; password, twice (Generate from 0.5, as on AD2); email (optional, counts as confirmed).
- The new account must choose its own password at the first sign-in (S3).
- Actions: Create (opens AD2).

**AD4 Groups**
- Shows a table: display name, key, members, owner group, linked apps, badges (built-in, bound to `<app>`).
- Fields: filter by name or key.
- Actions: open a group (AD5); New group (AD6).

**AD5 Group**
- Shows: key (read-only, "never changes"), bound app (read-only), linked apps (linking is done on the app's
  page).
- Fields: display name, description, owner group.
- **Members:** the same as AC6, except that admins may also search accounts.
- Actions: Save; Bind to an app (only while it is linked to at most that one app; with a warning that it is
  permanent); Copy (1.x); Delete (type the key; shows the members and linked apps it affects).
- States: built-in groups are read-only, with a note why.

**AD6 New group**
- Fields: key (live check of the rule, warning that it never changes); display name; description; owner
  group (optional).
- Fields: "Is this group for one app only?" Yes or No, with neither preselected; Yes asks for the app.
- Actions: Create (opens AD5).

**AD7 Apps**
- Shows a table: logo, name, type (with or without a secret), access rule, linked groups, enabled.
- Actions: open an app (AD8); New app (AD9).

**AD8 App**
- **Setup:** client id, discovery URL and issuer, each with copy; the redirect URIs.
- **Settings:**
  - name (read-only), display name, description, logo, homepage;
  - redirect URIs and sign-out redirect URIs (list editors);
  - back-channel logout URI;
  - skip consent;
  - token lifetime, with guidance (60 seconds or more; how stale the app's view may get);
  - scopes.
- **Access:**
  - rule: members of linked groups only, or anyone with an account;
  - linked groups (groups bound to another app cannot be picked);
  - machine API on or off (Guardian admins, apps with a secret only).
- **Credentials:** rotate the secret, with a grace period for the old one (none, 1 hour, 1 day, 7 days),
  leading to AD10.
- **Activity:** recent audit entries about the app.
- **Danger zone:** disable or enable; delete (Guardian admins; type the name).

**AD9 New app**
- Fields:
  - name (machine name, never changes) and display name;
  - type: "with a secret" (a server-side app) or "without a secret" (a browser or mobile app), with what
    each means;
  - redirect URIs;
  - the access rule (default: linked groups only, with a note that nobody can sign in until a group is
    linked) and the linked groups;
  - the other settings of AD8, folded away.
- Actions: Register (then AD10 for apps with a secret, then AD8).

**AD10 Secret, shown once** (dialog)
- Shows: the secret with copy; "This is the only time it is shown. Store it now." After a rotation, also when
  the old secret stops working.
- Actions: Done, enabled once Copy was pressed or "I have stored it" is ticked.

**AD11 Audit log**
- Fields: event type (a list of known types); account (exact username).
- Shows a table: time, event, who (username or app), IP address, summary. A row opens to show all its
  details. Next and Previous.

**AD12 Deleted accounts** (0.3)
- Shows a table: username, deleted, erased on, deleted by.
- Actions: Restore; Erase now (type the username).

### Emails (0.3)

Every email names the Guardian deployment, says what happened and when, and what to do if it wasn't the
user. It holds no other personal data.

- **E1 Confirm your email address:** the link, and when it expires.
- **E2 Reset your password:** the link, when it expires, and that two-factor still applies.
- **E3 Your password was changed:** when.
- **E4 Two-factor was added or removed:** which method, when.
- **E5 Your email address is being changed:** sent to the old address; the new address masked.
- **E6 An administrator reset your two-factor:** when, and the reason given.

### What the API still lacks for these pages

Nothing since 0.4: every page gets its data from `/api/v1`.

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
| U19 | H0 |
| U20 | H0 |
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
