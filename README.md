# Guardian

An OIDC login service with accounts and groups, meant to be the single source of truth for users across your
apps. Named after the Guardians in *The Legend of Zelda: Breath of the Wild*.

Guardian is a hobby project under active development. It is not ready for production use.

## Status

Release 0.1 (it runs locally) is done: OIDC with signed JWT access tokens, groups and per-app access rules,
the sign-in pages, a simple Home, the JSON API at `/api/v1`, and a read-only machine API for apps. 0.2 is in
progress: the Helm chart and encrypted backups (`guardian backup`, `guardian restore`) are built, and wait for
the cluster. 0.3 (accounts: email, two-factor, deletion, key rotation) is built. The management UI (the account and admin areas, in `frontend/`) is being built in 0.4. The plan is in
[docs/ROADMAP.md](docs/ROADMAP.md).

## Run it locally

You need Docker.

```
docker compose up --build
```

- Guardian: <http://localhost:3001>. Sign in as `admin` with `ADMIN_INITIAL_PASSWORD` from `docker-compose.yml`;
  the first sign-in asks for a new password.
- Metrics and health checks: <http://localhost:3002/metrics>, `/healthz`, `/readyz`.
- Mailpit: <http://localhost:3003> catches every email Guardian sends (confirmation and reset links).
- To try a real app, follow [docs/LOCAL-GRAFANA.md](docs/LOCAL-GRAFANA.md).

The passwords and keys in `docker-compose.yml` are throwaway development values.

## Develop the backend

You need Go and a PostgreSQL database.

```
cd backend
cp .env.example .env      # then fill in the values; every setting is described there
go run ./cmd/guardian
```

Guardian creates its tables by itself when it starts. The schema lives in `backend/migrations/`. Until 1.0 the
first migration is still edited in place, and a database that already ran it does not pick up the edits. Guardian
notices this at startup and stops with a message that says so. After a schema change, recreate your development
database (`docker compose down -v` removes the compose one).

## Tests

See [docs/TESTING.md](docs/TESTING.md). In short:

```
cd backend
go test ./...                                   # unit tests; database tests skip themselves
createdb guardian_test
GUARDIAN_TEST_DB=1 DB_HOST=localhost DB_USER=postgres DB_NAME=guardian_test go test -race -count=1 ./...
```

## Documentation

For app developers:

- [docs/INTEGRATION.md](docs/INTEGRATION.md): how to connect an app.
- [docs/INSTALL.md](docs/INSTALL.md): installing Guardian in Kubernetes with the Helm chart.
- [docs/openapi.yaml](docs/openapi.yaml): the JSON API, `/api/v1`.
- [docs/LOCAL-GRAFANA.md](docs/LOCAL-GRAFANA.md): try the whole sign-in flow locally with Grafana.

For working on Guardian:

- [docs/ROADMAP.md](docs/ROADMAP.md): the design decisions and the plan to 1.0.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how Guardian is built and why.
- [docs/USERS.md](docs/USERS.md) and [docs/PAGES.md](docs/PAGES.md): who uses Guardian, what they need, and
  the pages that serve it.
- [docs/TESTING.md](docs/TESTING.md): the tests and what they prove.
- [Agents.md](Agents.md): working notes for AI agents.
