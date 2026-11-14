# Guardian

An OIDC login service with accounts and groups, meant to be the single source of truth for users across your
apps. Named after the Guardians in *The Legend of Zelda: Breath of the Wild*.

Guardian is a hobby project under active development. It is not ready for production use.

## Status

Work is tracked in [docs/ROADMAP.md](docs/ROADMAP.md). The backend (Go and PostgreSQL) has the OIDC core. The
console frontend and the Helm chart are not built yet.

## Run it locally

You need Docker.

```
docker compose up --build
```

- Guardian: <http://localhost:3001>. Sign in as `admin` with the password set in `docker-compose.yml`.
- Metrics and health checks: <http://localhost:3002/metrics>, `/healthz`, `/readyz`.

The passwords and keys in `docker-compose.yml` are throwaway development values.

## Develop the backend

You need Go and a PostgreSQL database.

```
cd backend
cp .env.example .env      # then fill in the values
go run .
```

## Tests

See [docs/TESTING.md](docs/TESTING.md). In short:

```
cd backend
go test ./...                                   # unit tests; database tests skip themselves
createdb guardian_test
GUARDIAN_TEST_DB=1 DB_HOST=localhost DB_USER=postgres DB_NAME=guardian_test go test -race -count=1 ./...
```

## Documentation

- [docs/ROADMAP.md](docs/ROADMAP.md): the design and the plan to 1.0.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/INTEGRATION.md](docs/INTEGRATION.md): partly outdated, being rewritten.
- [Agents.md](Agents.md): notes for AI agents working on this repository.
