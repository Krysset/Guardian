# Installing Guardian in Kubernetes

The Helm chart is in `charts/guardian`. It works with plain Helm and with Argo CD. This first version (release
0.2) installs the backend, a bundled or external Postgres, and an HTTPRoute or Ingress. It has no email
settings yet (0.3 adds email to Guardian; the chart follows when the cluster is ready), so installations from
this chart run without email. The management UI, the
NetworkPolicy, autoscaling and the ServiceMonitor come in later releases (`docs/ROADMAP.md`).

Until 1.0 all data is test data: a new release may need a fresh database (see "Upgrades" below).

## 1. Build and push the image

There is no published image yet. Build the backend image and push it to your registry:

```
docker build -t registry.example.com/guardian-backend:0.2.0 backend
docker push registry.example.com/guardian-backend:0.2.0
```

If the registry needs credentials, create a pull secret in the namespace and list it in `imagePullSecrets`.

## 2. Create the Secret

The chart creates no secrets. Create one Secret with three keys before installing (fill it from your password
manager; the names below are the chart's defaults):

| Key | What it is |
|---|---|
| `key-encryption-key` | 32 random bytes, base64 (`openssl rand -base64 32`). Encrypts Guardian's signing keys in the database. **If it is lost, every signing key is lost**: keep it with your backups. |
| `admin-initial-password` | The first password of the built-in `admin` account. It must be changed at the first sign-in. |
| `db-password` | The database password. With the bundled Postgres it is set on the first start; changing it later is a manual step (`ALTER ROLE`, then update the Secret). |

```
kubectl create namespace auth
kubectl -n auth create secret generic guardian \
  --from-literal=key-encryption-key="$(openssl rand -base64 32)" \
  --from-literal=admin-initial-password='<a long password>' \
  --from-literal=db-password='<another long password>'
```

With an external Postgres, the password can live in its own Secret: set `database.passwordSecret` and
`database.passwordKey`.

## 3. Choose the values

A staging setup with the bundled Postgres behind a Gateway API HTTPRoute:

```yaml
issuerURL: https://auth.example.com      # the OIDC issuer: never change it once apps are connected
image:
  repository: registry.example.com/guardian-backend
  tag: "0.2.0"
secrets:
  existingSecret: guardian
httpRoute:
  enabled: true
  parentRefs:
    - name: main-gateway                 # your existing Gateway; the chart never creates one
      namespace: gateway-system
      sectionName: https
trustedProxyHops: 1                      # one proxy (the gateway) appends to X-Forwarded-For
```

- `issuerURL` must be `https://` outside local development: it turns on secure cookies.
- `trustedProxyHops` must match the number of proxies in front of Guardian, or rate limits see the proxy's
  address instead of the user's.
- For a standard Ingress instead, set `ingress.enabled: true` and `ingress.className` (for example `traefik`).
- For an external Postgres, set `database.mode: external` and `database.external.host` (and `port`, `user`,
  `name`, `sslMode`).
- `values.yaml` describes every value; `values.schema.json` refuses an install that lacks the required ones.

## 4. Install

With Helm:

```
helm install guardian charts/guardian -n auth -f staging-values.yaml
```

With Argo CD, an Application that points at this repository:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: guardian
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/<you>/guardian.git
    targetRevision: dev
    path: charts/guardian
    helm:
      valuesObject:
        issuerURL: https://auth.example.com
        image: { repository: registry.example.com/guardian-backend, tag: "0.2.0" }
        secrets: { existingSecret: guardian }
        httpRoute:
          enabled: true
          parentRefs: [{ name: main-gateway, namespace: gateway-system, sectionName: https }]
  destination:
    server: https://kubernetes.default.svc
    namespace: auth
  syncPolicy:
    automated: { prune: true, selfHeal: true }
```

The backend waits for the database and applies its migrations when it starts (several replicas take turns
under a lock), so no ordering between Postgres and the backend is needed.

## 5. First sign-in

Open the issuer URL and sign in as `admin` with `admin-initial-password`. Guardian asks for a new password
straight away. Then register apps through `/api/v1` (`docs/INTEGRATION.md`); the admin area arrives in 0.4.

Check the installation:

- `https://auth.example.com/.well-known/openid-configuration` answers with the issuer URL;
- `kubectl -n auth get pods` shows the backend pods ready (2 by default) and, if bundled, `guardian-postgres-0`;
- metrics are on the `guardian-internal` Service, port 3002, `/metrics`, inside the cluster only.

## Backup and restore

Backups are taken with `kubectl exec` and land on your machine. They are encrypted with
[age](https://age-encryption.org): the cluster only ever sees the public key, and the private key stays offline
(in Bitwarden). Generate the key pair once, on your machine:

```
age-keygen -o guardian-backup-key.txt      # the private key: store it offline, then delete this file
age-keygen -y guardian-backup-key.txt      # prints the public key, age1...
```

### Taking a backup

```
kubectl -n auth exec deploy/guardian -- /guardian backup --recipient age1...      # dry run: shows the row counts
kubectl -n auth exec deploy/guardian -- /guardian backup --execute --reason "before the 0.3 upgrade" \
  --recipient age1... > guardian-$(date +%F).gbk
```

- The file holds accounts, groups, apps, consents, signing keys (still encrypted with `key-encryption-key`) and
  the audit log (`--without-audit` leaves it out). Sessions and tokens are left out: everyone signs in again
  after a restore.
- It starts with a manifest in the clear (times, counts, no personal data). Check a file at any time, without
  the private key: `guardian backup verify guardian-2026-11-19.gbk`.
- Every backup is recorded in the audit log, and `guardian_backup_last_success_timestamp_seconds` on the
  metrics port tells when the last one was taken: alert when it gets old.
- **The backup is useless without `key-encryption-key`.** Keep that key with the age private key.

`guardian backup verify` and `guardian backup decrypt` need no database and no configuration, so they run on
your machine with the image (`docker run --rm -i <image> backup verify - < file.gbk`) or with a local build
(`go build ./cmd/guardian` in `backend`).

### Restoring

A restore only goes into a **new installation**: no apps, no groups of its own, no account but the built-in
admin, and nobody signed in. It refuses anything else, so it can never overwrite a Guardian in use. It also
needs the same release (until 1.0) and the same `key-encryption-key` as the installation that took the backup.

1. Install Guardian as above, into an empty database, with the old `key-encryption-key` and the same issuer URL.
   Do not sign in.
2. Decrypt the backup on your machine, so the private key never enters the cluster:
   `guardian backup decrypt --identity-file guardian-backup-key.txt --out plain.gbk guardian-2026-11-19.gbk`.
   The decrypted file holds personal data in the clear: delete it when you are done.
3. Rehearse, then restore:
   ```
   kubectl -n auth exec -i deploy/guardian -- /guardian restore - < plain.gbk
   kubectl -n auth exec -i deploy/guardian -- /guardian restore --execute --reason "lost the database" \
     --confirm auth.example.com - < plain.gbk
   ```
   The dry run does the whole restore in a transaction and rolls it back, so a dry run that succeeds means the
   real one will. `--confirm` is the issuer's host, typed back.
4. `kubectl -n auth rollout restart deploy/guardian`, so every replica loads the restored signing keys.

### After a restore

A restore brings back the state of the backup, including what was changed for security reasons since:

- Accounts and administrators removed since the backup are back: remove them again.
- Passwords changed since are back to their old values: ask the people affected to change them again, and set
  a new one for anyone whose password leaked.
- App secrets rotated since are the old ones again: rotate them (`POST /api/v1/apps/{app}/secret`) and update
  the apps.
- Apps keep working: the signing keys are the same, so tokens still verify. Everyone signs in again.
- The audit log records the restore (`backup.restored`), and refused attempts (`backup.restore_failed`).

### Restore drill

Only a real restore proves a backup works. Now and then, restore the latest backup into a throwaway
installation, such as `docker compose` on your machine:

```
docker compose down -v && docker compose up -d --build
docker compose exec -T backend /guardian restore --execute --reason drill --confirm localhost:3001 - < plain.gbk
docker compose restart backend
```

The compose installation has another `KEY_ENCRYPTION_KEY` and issuer, so set the backed-up installation's key
in `docker-compose.yml` for the drill, and add `--allow-other-issuer`. Then sign in with a real account.

## Upgrades

- Until 1.0 the database schema is still edited in place. A release that changes it refuses to start on an
  older database, with a message that says so, and a backup only restores into the release that took it. So
  until 1.0 such an upgrade means starting from an empty database.
- Never change `key-encryption-key`: Guardian cannot decrypt its signing keys with another one and refuses to
  start. Key rotation comes in 0.3.

## Uninstalling

`helm uninstall` (or deleting the Argo CD Application) leaves the bundled Postgres' disk claim in place, so the
data survives a reinstall. Delete the claim (`data-guardian-postgres-0`) to wipe it.
