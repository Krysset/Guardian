# syntax=docker/dockerfile:1

# Build stage. GO_VERSION must be at least the "go" line in go.mod.
ARG GO_VERSION=1.26
# The build runs on the builder's own platform and cross-compiles, so a multi-platform image needs no emulation.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
ARG TARGETOS TARGETARCH
# The release sets VERSION; a local build says "dev".
ARG VERSION=dev
WORKDIR /src

# Dependencies first, so they are cached until go.mod or go.sum change.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
# CGO is off so the binary is static and runs on distroless. The database schema is embedded in it.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X guardian/internal/server.Version=${VERSION}" -o /out/guardian ./cmd/guardian

# Run stage: no shell, no package manager, non-root user (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/guardian /guardian
USER nonroot:nonroot
# 3001 public (OIDC, hosted pages, /api/v1), 3002 internal (/metrics, /healthz, /readyz).
EXPOSE 3001 3002
ENTRYPOINT ["/guardian"]
