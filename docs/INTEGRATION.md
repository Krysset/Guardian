# Integrating an app with Guardian

Guardian is a standard OpenID Connect provider. Use any OIDC library, ask for the `groups` scope, and map
groups to your own permissions. Your app checks access tokens by itself; it does not call Guardian on every
request.

## 1. Register the app (once, as a Guardian administrator)

```
POST /api/v1/apps                (administrator session, JSON; see docs/openapi.yaml)
{
  "name": "billing",
  "pretty_name": "Billing",
  "description": "Invoices",
  "redirect_uris": ["https://billing.example.com/auth/callback"],
  "post_logout_redirect_uris": ["https://billing.example.com/"],
  "backchannel_logout_uri": "https://billing.example.com/auth/backchannel-logout",   // optional, recommended
  "access_token_ttl_seconds": 300,                                                    // optional, see below
  "scopes": ["openid", "profile", "email", "groups"],
  "access_rule": "groups",                                                            // or "anyone"
  "group_ids": ["<id of billing-users>", "<id of billing-approvers>"]
}
```

The answer contains `client_id` and, once, `client_secret`. Keep both in a Kubernetes Secret.

- **`access_rule`:** with `groups` (the default) only members of a linked group can sign in to the app;
  Guardian refuses everyone else before your app sees them. With `anyone` every account can sign in.
- **`require_mfa`:** `true` makes signing in to your app need two-factor. Guardian asks for the code, or walks
  the user through setting up an authenticator app, before your app gets a code. The `amr` claim then holds
  `otp`. Change it with `PATCH /api/v1/apps/{id}`.
- **`group_ids`:** the groups your app is told about. Your app never sees any other group a user is in.
  Change both later with `PUT /api/v1/apps/{id}/access` (`{"access_rule", "group_ids"}`).
- Groups are managed under `/api/v1/groups`. A group's `key` (for example `billing-approvers`) never changes;
  that is the value your app receives.
- A group made only for your app can be a **single-app group**: create it with `"bound_app_id": "<app id>"`, or
  bind it later with `POST /api/v1/groups/{id}/bind`. It is then linked to your app and can never be linked to
  any other, so it can never grant access elsewhere.
- The secret can be rotated with `POST /api/v1/apps/{id}/secret`. Pass `{"grace_seconds": 3600}` to keep the
  old secret working for an hour while you roll out the new one.

## 2. Sign users in

Use your OIDC library with:

- discovery URL `https://<guardian>/.well-known/openid-configuration`;
- the authorization code flow with PKCE;
- scopes `openid profile email groups`.

The token response holds:

| Token | What it is | Lifetime |
|---|---|---|
| `id_token` | Who the user is: `sub`, profile claims, `groups`, `sid`, `amr`. For your login code. | `access_token_ttl_seconds` |
| `access_token` | A signed JWT (`typ: at+jwt`, RFC 9068) with `sub`, `aud`, `client_id`, `scope`, `sid`, `amr` and `groups`. No profile data. Send it to your own APIs. | `access_token_ttl_seconds` |
| `refresh_token` | Gets new tokens. Only for apps with a client secret. It stays the same until the user's Guardian session ends. | the session |

Keep tokens on your server, never in the browser.

## 3. Check access tokens yourself

Validate every access token locally: signature against Guardian's JWKS (`jwks_uri`, RS256), `iss`, `aud`
(your `client_id`), `exp`, and the header `typ` must be `at+jwt`. Every JWT library does this. Then read
`groups` and decide what the user may do.

Identify users by `sub`. Never by username or email: both can change, and a freed username can be taken by
someone else.

## 4. Refresh, and what a refresh means

Refresh before the access token expires: `grant_type=refresh_token` with your client credentials.

Every refresh is checked against live data: the user's session, the account, your app, the access rule and
the user's groups. So **group changes, logout and disabled accounts reach your app at its next refresh**,
within `access_token_ttl_seconds`. Each refresh returns a new access token and a new ID token with the
current groups and profile.

How to react to a failed refresh:

- **`400 invalid_grant`:** the user is signed out, disabled or no longer allowed into your app. End your
  session for them.
- **A network error or a 5xx:** Guardian is unreachable. Keep the user signed in and retry for about one
  more token lifetime, so a Guardian restart does not sign everyone out of every app.

The refresh token does not change. Several replicas of your app, or a retry after a lost answer, can use it
at the same time.

`GET /userinfo` with an access token also checks live data and returns the current claims and groups. It is
useful when you want to know "right now", but it is a call to Guardian, so do not use it on every request.

## 5. Logout

- Users sign out at Guardian (`/logout`), or your app sends them to `end_session_endpoint` with
  `id_token_hint`.
- **Back-channel logout (recommended):** register `backchannel_logout_uri`. Guardian POSTs a signed
  `logout_token` (`typ: logout+jwt`) with the user's `sub` and `sid` when the session ends, when the account
  is deleted, and when the user leaves a group linked to your app. Verify it with your OIDC library and drop
  your session for that `sid`. This makes those changes immediate for your app instead of waiting for the
  next refresh.
- To end only your own refresh token, for example when the user signs out of your app alone, call
  `POST /revoke` (RFC 7009) with `token=<refresh token>` and your client credentials.

## Reading groups and users without a signed-in user (machine API)

Sometimes an app needs to know about users who are not signed in right now, for example to show "who can
approve invoices". For that an app with a secret can use Guardian's read-only machine API.

1. An administrator turns it on: `PUT /api/v1/apps/{id}/access` with `"machine_api": true` (together with
   the app's `access_rule` and `group_ids`).
2. The app gets a token for itself: `POST /token` with `grant_type=client_credentials` and its client
   credentials. The token's audience is Guardian, it has no user, and it lives `access_token_ttl_seconds`.
   Get a new one when it expires; there is no refresh token.
3. The app calls, with `Authorization: Bearer <token>`:

| Endpoint | Returns |
|---|---|
| `GET /api/v1/apps/self` | The app's own name, client id, access rule and scopes. |
| `GET /api/v1/apps/self/groups` | The groups linked to the app, with `key`, `display_name`, `description` and `member_count`. |
| `GET /api/v1/apps/self/groups/{key}/members` | The active members of one linked group. |
| `GET /api/v1/apps/self/users/{sub}` | One account, by `sub`. |

Lists come as `{"items": [...]}`, and errors as `{"error": "<code>", "message": "<text>"}` (`invalid_token`
for a bad or expired token, `not_found` for anything the app may not see). `docs/openapi.yaml` describes
every field.

What an app can see:

- **Groups:** only those linked to it. Any other group answers 404.
- **Accounts:** members of its linked groups, and accounts that have signed in to it. Any other account
  answers 404, exactly like an account that does not exist.
- **Claims:** what the app's allowed scopes permit (for example no email without the `email` scope), plus
  `groups` (only linked groups) if the app may use the `groups` scope.

Turning machine access off, or disabling the app, stops the app's existing tokens at once. A user's access
token is never accepted here.

## Choosing `access_token_ttl_seconds`

It is how stale your app's view of a user can get, if your app does not implement back-channel logout.

- Default: 300 seconds (5 minutes). Minimum: 15. Maximum: 86400.
- 60 seconds or more is recommended: clocks differ a little, and your JWT library adds its own leeway.
- An admin panel or anything sensitive: 60 seconds. Ordinary apps: the default.

## Apps that do not refresh

Some off-the-shelf apps read the ID token once at sign-in and then keep their own session. Group changes
reach such an app only when its own session ends or when it receives a back-channel logout. Check how the app
behaves when you connect it.

## Off-the-shelf apps

- **Email may be missing.** Email is optional in Guardian, and the `email` claim is left out when an account
  has none. Apps that insist on an email need a fallback, for example `<sub>@guardian.invalid`.
- **Usernames may clash** with an app's own built-in accounts (many apps have an `admin`). Rename the app's
  local account, or match users on `sub` where the app allows it.
- **Grafana** works with its generic OAuth provider. `docker-compose.yml` and `docs/LOCAL-GRAFANA.md` have a
  tested configuration: PKCE, roles from the `groups` claim, the email fallback above, and sign-out through
  Guardian. Grafana does not support back-channel logout.

## What Guardian does not decide

Guardian knows who a user is and which of your app's groups they are in. Rules about individual records
("may this user open invoice 42?") belong in your app.
