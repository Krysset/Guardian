# Trying Guardian with Grafana locally

This checks the whole 0.1 flow by hand: a real app signs in through Guardian and gets the right groups.
It needs Docker. Everything here is for local development only.

## 1. Start Guardian

```
docker compose down -v      # only needed once after a schema change; it deletes the local database
docker compose up -d --build
```

Open http://localhost:3001 and sign in as `admin` with `guardian-dev-admin` (`ADMIN_INITIAL_PASSWORD` in
`docker-compose.yml`). The first sign-in asks for a new password.

## 2. Register Grafana

There is no admin area until 0.4, so the app is registered through the API from the browser. While signed in:

1. Open http://localhost:3001/api/v1/me in a tab. (The sign-in pages block scripts of their own on purpose;
   this JSON page does not.)
2. Open the browser's developer console on that tab, paste the script below and press Enter.

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
  const me = await api('GET', '/me');
  const created = await api('POST', '/apps', {
    name: 'grafana', pretty_name: 'Grafana', description: 'Dashboards (local test)',
    homepage_url: 'http://localhost:3005',
    redirect_uris: ['http://localhost:3005/login/generic_oauth'],
    post_logout_redirect_uris: ['http://localhost:3005/login'],
    scopes: ['openid', 'profile', 'email', 'groups'],
    is_first_party: true,
    access_rule: 'groups',
  });
  const app = created.app;
  const admins = await api('POST', '/groups', { key: 'grafana-admins', display_name: 'Grafana admins', bound_app_id: app.id });
  await api('POST', '/groups', { key: 'grafana-viewers', display_name: 'Grafana viewers', bound_app_id: app.id });
  await api('PUT', `/groups/${admins.id}/members/${me.id}`, {});
  if (!me.email) await api('PATCH', `/accounts/${me.id}`, { email: me.username + '@guardian.test' });
  const env = `GRAFANA_CLIENT_ID=${app.client_id}\nGRAFANA_CLIENT_SECRET=${created.client_secret}`;
  console.log(env);
  return env;
})();
```

The script:

- registers Grafana: only members of its linked groups may sign in, and it skips the consent page;
- creates the single-app groups `grafana-admins` and `grafana-viewers`, both bound to Grafana;
- adds you to `grafana-admins`;
- gives your account an email address if it has none. (Accounts without one still work: Grafana is set up to
  use `<sub>@guardian.invalid` instead.)

Grafana's own built-in user is renamed to `grafana-local-admin` in `docker-compose.yml`, so that it does not clash
with Guardian's `admin`.

It prints two lines. Put them in a file named `.env` next to `docker-compose.yml` (it is git-ignored). The
secret is shown only this once; if it is lost, rotate it with `POST /api/v1/apps/{id}/secret`.

## 3. Start Grafana and sign in

```
docker compose --profile grafana up -d grafana
```

Open http://localhost:3005 and choose "Sign in with Guardian". You should:

- land in Grafana as an **Admin** (from `grafana-admins`);
- see Grafana on Guardian's Home (http://localhost:3001) under "Your connected apps".

## 4. Check the groups

- Create a second account at http://localhost:3001/signup in a private window, then try Grafana with it:
  Guardian shows "You don't have access to Grafana".
- Add that account to `grafana-viewers` (from the console tab: `GET /api/v1/accounts?q=<name>` for its id,
  then `PUT /api/v1/groups/<viewers id>/members/<account id>`). It can now sign in, as a **Viewer**.
- Remove yourself from `grafana-admins` (`DELETE /api/v1/groups/<admins id>/members/<your id>`). Your next
  sign-in to Grafana is refused, because you are no longer in a group linked to it.

Grafana does not support back-channel logout, so signing out of Guardian does not end a Grafana session that
is already open; Grafana's "Sign out" sends you through Guardian's sign-out.
