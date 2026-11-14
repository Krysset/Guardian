# syntax=docker/dockerfile:1

# Build stage. GO_VERSION must be at least the "go" line in go.mod.
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION} AS build
WORKDIR /src

# Dependencies first, so they are cached until go.mod or go.sum change.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
# The module's main package is at its root. CGO is off so the binary is static and runs on distroless.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/guardian .

# Run stage: no shell, no package manager, non-root user (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/guardian /guardian
# database/connection.go reads SCHEMA_PATH, default /schema.sql.
COPY schema.sql /schema.sql
USER nonroot:nonroot
# 3001 public (OIDC, pages, /api), 3002 internal (/introspect, /metrics, probes).
EXPOSE 3001 3002
ENTRYPOINT ["/guardian"]
