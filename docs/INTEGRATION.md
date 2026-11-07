# Integrating a service with Guardian

Everything a service needs is: **one OIDC login** and **one HTTP call per request**. No JWT validation,
no JWKS, no key rotation, no token caching.

## 1. Register the service (once, as a Guardian admin)

```
POST /api/service/add            (admin session, JSON)
{
  "name": "billing",
  "pretty_name": "Billing",
  "description": "Invoices",
  "redirect_uris": ["https://billing.example.com/auth/callback"],
  "post_logout_redirect_uris": ["https://billing.example.com/"],
  "backchannel_logout_uri": "https://billing.example.com/auth/backchannel-logout",   // optional
  "access_token_ttl_seconds": 28800,                                                  // optional, see below
  "scopes": ["openid", "profile", "email", "offline_access"]
}
```

The response contains `client_id` and, once, `client_secret`. Put both in a Kubernetes Secret.
Then define the permissions your service understands (they are opaque strings to Guardian):

```
POST /api/access/permissions     { "app_id": "<id>", "name": "invoices.approve", "pretty_name": "Approve invoices" }
POST /api/access/grant-role      { "account_id": "<id>", "role_id": "<id>" }
POST /api/access/grant-permission{ "account_id": "<id>", "permission_id": "<id>", "attributes": {"limit": 5000} }
```

## 2. Log users in (browser)

Use any OIDC library with the discovery URL `https://<guardian>/.well-known/openid-configuration`,
the authorization-code flow with PKCE, and scopes `openid profile email`. After the callback, keep the
returned **access token in your server-side session** (never in the browser). Your own session cookie
is only a pointer to it.

## 3. Authorize every request (service to Guardian, in-cluster)

```
POST http://guardian-internal.guardian.svc:3002/introspect
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=<the user's access token>
```

```json
{ "active": true, "sub": "<account id>", "client_id": "<app the token was issued to>",
  "scope": "openid profile", "exp": 1767225600, "iat": 1767224700, "sid": "<session id>",
  "permissions": ["invoices.read", "invoices.approve"],
  "attributes": { "invoices.approve": { "limit": 5000 } } }
```

* `active: false` means logged out, revoked, expired or disabled: end your session and send the user to login.
* `permissions` are the user's permissions **in your app**, computed from the database at that moment.
  `attributes` are the optional app-defined JSON from direct grants.
* **Do not cache the answer.** That is what makes revocation immediate. It is a cheap, indexed lookup.
* If Guardian is unreachable, **fail closed** (503), do not fall back to the last answer.

Go:

```go
func requirePermission(perm string, next http.Handler) http.Handler {
	client := &http.Client{Timeout: 2 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := url.Values{"token": {accessTokenFromSession(r)}}
		req, _ := http.NewRequestWithContext(r.Context(), "POST", introspectURL, strings.NewReader(form.Encode()))
		req.SetBasicAuth(clientID, clientSecret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 { http.Error(w, "auth unavailable", 503); return }
		defer resp.Body.Close()
		var t struct {
			Active      bool     `json:"active"`
			Sub         string   `json:"sub"`
			Permissions []string `json:"permissions"`
		}
		if json.NewDecoder(resp.Body).Decode(&t) != nil { http.Error(w, "auth unavailable", 503); return }
		if !t.Active { endSession(w, r); http.Redirect(w, r, "/login", http.StatusFound); return }
		if !slices.Contains(t.Permissions, perm) { http.Error(w, "forbidden", 403); return }
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), t.Sub)))
	})
}
```

Python:

```python
def introspect(token):
    r = requests.post(INTROSPECT_URL, data={"token": token}, auth=(CLIENT_ID, CLIENT_SECRET), timeout=2)
    r.raise_for_status()
    return r.json()          # {"active": false} or the document above
```

## 4. Service-to-service calls on behalf of a user

Pass the user's access token as `Authorization: Bearer <token>`. The receiving service introspects it
**as itself** and gets the user's permissions in *its own* app. `client_id` in the answer tells it which app
the token was issued to, so it can refuse tokens from apps it does not trust.

## 5. Logout

* Users log out at Guardian (`/logout`), or your app redirects to `end_session_endpoint` with `id_token_hint`.
* Guardian ends the SSO session; **every access token of that session becomes inactive at once**, so your next
  introspection already returns `active: false`.
* Optional but nice: implement the back-channel logout endpoint you registered. Guardian POSTs a signed
  `logout_token` (JWT) with the user's `sid`; verify it with the OIDC library and delete your sessions for that `sid`.

## Choosing `access_token_ttl_seconds`

Revocation does not depend on the TTL (introspection is live), so make it as long as your own session
(for example 8 hours) and you never need refresh tokens. If you prefer short tokens, request `offline_access`
and use the refresh token grant.
