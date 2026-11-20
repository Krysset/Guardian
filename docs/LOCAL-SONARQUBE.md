# Trying Guardian with SonarQube locally

This checks a real app that cannot speak OIDC itself: SonarQube (Community Build). Since its 25.x versions,
self-hosted SonarQube signs in only with SAML, LDAP, a few code hosts, or **HTTP headers** set by a proxy in
front of it. So [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) signs in through Guardian as an
ordinary OIDC app and hands SonarQube the user in headers. The same pattern works for any app without OIDC.

It needs Docker, and about 3 GB of memory for SonarQube. Everything here is for local development only.

```
browser ──> oauth2-proxy (localhost:3006) ──> SonarQube (no port of its own)
                 │
                 └── signs in through Guardian (localhost:3001), refreshes every minute
```

## 1. Start Guardian

As in `docs/LOCAL-GRAFANA.md`: `docker compose up -d --build`, then sign in at http://localhost:3001 as `admin`.

## 2. Register SonarQube's proxy

While signed in, open http://localhost:3001/api/v1/me in a tab, open the browser's developer console there,
paste this and press Enter:

```js
(async () => {
  const api = async (method, path, body) => {
    const r = await fetch('/api/v1' + path, {
      method, headers: { 'Content-Type': 'application/json' }, body: body && JSON.stringify(body),
    });
    const data = r.status === 204 ? null : await r.json();
    if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${JSON.stringify(data)}`);
    return data;
  };
  const created = await api('POST', '/apps', {
    name: 'sonarqube', pretty_name: 'SonarQube', description: 'Code quality (local test)',
    homepage_url: 'http://localhost:3006',
    redirect_uris: ['http://localhost:3006/oauth2/callback'],
    scopes: ['openid', 'profile', 'email', 'groups'],
    is_first_party: true,
    access_rule: 'groups',
  });
  const app = created.app;
  const admins = await api('POST', '/groups', { key: 'sonarqube-admins', display_name: 'SonarQube admins', bound_app_id: app.id });
  const users = await api('POST', '/groups', { key: 'sonarqube-users', display_name: 'SonarQube users', bound_app_id: app.id });
  // A test account. SonarQube has a built-in "admin" of its own, so Guardian's admin is not used here.
  const link = await api('POST', '/accounts', { username: 'link', password: 'hylia-shield-1', email: 'link@guardian.test' });
  await api('PUT', `/groups/${users.id}/members/${link.id}`, {});
  console.log(`groups: admins ${admins.id}, users ${users.id}; link ${link.id}`);
  const env = `SONARQUBE_CLIENT_ID=${app.client_id}\nSONARQUBE_CLIENT_SECRET=${created.client_secret}`;
  console.log(env);
  return env;
})();
```

It registers the proxy as the app "SonarQube" (only members of its linked groups may sign in), creates the
single-app groups `sonarqube-admins` and `sonarqube-users`, and the account `link` (password
`hylia-shield-1`, to be changed at the first sign-in) in `sonarqube-users`. Note the ids it prints.

Add the two `SONARQUBE_...` lines to `.env` next to `docker-compose.yml`.

## 3. Start SonarQube and prepare its groups

```
docker compose --profile sonarqube up -d sonarqube sonarqube-proxy
```

SonarQube takes a minute or two to start (`docker logs -f guardian-sonarqube` until "SonarQube is
operational").

SonarQube only fills in groups that exist in SonarQube, so create the admins' group once, with SonarQube's
own `admin` (password `admin` until changed). These calls go to SonarQube directly, from inside its network,
so no proxy headers are involved:

```
docker run --rm --network container:guardian-sonarqube curlimages/curl:8.11.1 -sf -u admin:admin -X POST "http://localhost:9000/api/users/change_password?login=admin&previousPassword=admin&password=Sonar-local-admin-1"
docker run --rm --network container:guardian-sonarqube curlimages/curl:8.11.1 -sf -u admin:Sonar-local-admin-1 -X POST "http://localhost:9000/api/user_groups/create?name=sonarqube-admins"
docker run --rm --network container:guardian-sonarqube curlimages/curl:8.11.1 -sf -u admin:Sonar-local-admin-1 -X POST "http://localhost:9000/api/permissions/add_group?groupName=sonarqube-admins&permission=admin"
```

## 4. Sign in through Guardian

In a private window, open http://localhost:3006. oauth2-proxy sends you to Guardian; sign in as `link` (and
choose a new password). You land in SonarQube as `link`, with the email `link@guardian.test`.

## 5. Check groups and how stale SonarQube gets

Use the console tab of step 2 (signed in as Guardian's `admin`) and a watch on the clock:

1. **Group added.** `PUT /api/v1/groups/<admins id>/members/<link id>`. Within about two minutes (oauth2-proxy
   refreshes every minute, SonarQube rereads the headers every minute), `link`'s next page shows
   Administration. Write down how long it took.
2. **Group removed.** `DELETE /api/v1/groups/<admins id>/members/<link id>`. Administration goes away the same
   way.
3. **Access removed.** Also remove `link` from `sonarqube-users`. At the proxy's next refresh (within a minute)
   Guardian refuses it, oauth2-proxy drops the session, and the next page sends `link` to Guardian, which shows
   "You don't have access to SonarQube".
4. **Disabled.** Put `link` back in `sonarqube-users`, sign in again, then disable the account
   (`PATCH /api/v1/accounts/<link id>` with `{"status": "disabled"}`). Same as 3.

oauth2-proxy has no back-channel logout, so these all take up to one refresh interval
(`OAUTH2_PROXY_COOKIE_REFRESH`, 1 minute here) plus SonarQube's header refresh
(`SONAR_WEB_SSO_REFRESHINTERVALINMINUTES`, 1 minute here, 5 by default) for group changes.

## Signing out

SonarQube's own "Log out" signs out of SonarQube only, and the proxy signs it straight back in. To sign out
for real, open http://localhost:3006/oauth2/sign_out?rd=http%3A%2F%2Flocalhost%3A3001%2Flogout, which ends
the proxy's session and then Guardian's.

## What this tells us for INTEGRATION.md

- The proxy's refresh interval is the staleness bound; set it at or below the app's access-token lifetime.
- The app must be reachable only through the proxy, and the proxy must replace (not pass on) any
  `X-Forwarded-*` user headers a browser sends. SonarQube trusts the headers without checking them.
- Fill in the measured times from step 5 here once the owner has run it:
  - group added → visible in SonarQube: _
  - access removed → refused: _
