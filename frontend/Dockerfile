# syntax=docker/dockerfile:1
# The management UI: the static single-page app, served by nginx as a non-root user. Routes send only
# /, /account..., /admin... and /_app/... here; everything else goes to the backend.

# Build stage. The output is the same for every platform, so it runs on the builder's own.
FROM --platform=$BUILDPLATFORM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json .npmrc ./
RUN npm ci
COPY . .
RUN npm run build

# Run stage: nginx without root (uid 101), listening on 8080. With a read-only root filesystem, mount an
# empty directory at /tmp (the chart does).
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY nginx/headers.conf /etc/nginx/headers.conf
COPY --from=build /src/build /usr/share/nginx/html
EXPOSE 8080
