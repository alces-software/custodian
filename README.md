# Custodian

Self-hosted service that **issues and renews Let's Encrypt certificates** for allowlisted hostnames using **DNS-01** against **Google Cloud DNS**, stores material in **PostgreSQL**, and exposes a small **HTTP API** with **scoped API keys**. Designed for Dokku (or any container host) with **external cron** for renewal.

## Features

- Issue certificates for specific CNs (+ optional SANs) within a domain catalog
- **Per-domain Cloud DNS zones** (one GCP service account for all zones)
- **Scoped API keys**: each key may only access certain domains; admin key for cron
- Encrypted private keys at rest (AES-256-GCM)
- List / download PEM bundles
- Force renew one cert, or bulk renew due certs (`POST /v1/renew` — admin only)
- Let's Encrypt **staging** by default unless `LE_DIRECTORY=production`

## Auth model (lowest friction)

No OAuth for v1. Clients send `Authorization: Bearer <key>` as before.

| Role | Capabilities |
|------|----------------|
| `tenant` | Issue / list / get / bundle / renew / delete only for names covered by its `patterns` |
| `admin` | All catalog domains; required for `POST /v1/renew` (cron) |

Out-of-scope access by id returns **404** (no existence leak). Issue for an unauthorized name returns **403**.

## Quick start (local)

```bash
export DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
docker compose up --build
```

Or run the binary against Compose Postgres (legacy env still works):

```bash
docker compose up -d db
export DATABASE_URL='postgres://custodian:custodian@localhost:5432/custodian?sslmode=disable'
export API_KEYS='dev-api-key-change-me'
export ALLOWED_DOMAINS='*.example.com,example.com'
export CLOUDDNS_ZONE='example-com'
export LE_EMAIL='ops@example.com'
export LE_DIRECTORY=staging
export DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
go run ./cmd/custodian serve
```

### Recommended: scoped clients + multi-zone catalog

```bash
export DOMAIN_CATALOG='[
  {"pattern":"*.apps.example.com","zone":"apps-example-com"},
  {"pattern":"api.example.com","zone":"example-com"},
  {"pattern":"example.com","zone":"example-com"}
]'
export API_CLIENTS='[
  {"id":"admin","key":"'"$(openssl rand -hex 24)"'","role":"admin"},
  {"id":"payments","key":"'"$(openssl rand -hex 24)"'","role":"tenant","patterns":["pay.example.com"]}
]'
```

You can also load JSON from files via `DOMAIN_CATALOG_FILE` and `API_CLIENTS_FILE`.

## API

All routes except health require `Authorization: Bearer <api-key>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | DB readiness |
| `POST` | `/v1/certificates` | Issue (or return still-valid cert) |
| `GET` | `/v1/certificates` | List metadata (filtered by key scope) |
| `GET` | `/v1/certificates/{id}` | Get metadata |
| `GET` | `/v1/certificates/{id}/bundle` | Download PEMs (JSON; `?format=pem` for raw) |
| `POST` | `/v1/certificates/{id}/renew` | Force renew one |
| `POST` | `/v1/renew` | Renew all due (**admin only**) |
| `DELETE` | `/v1/certificates/{id}` | Soft-delete |

### Issue

```bash
curl -sS -X POST https://custodian.example/v1/certificates \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"app.example.com","sans":["www.app.example.com"]}'
```

Idempotent: if an active cert for the same name set is valid for longer than `RENEW_BEFORE_DAYS`, it is returned without hitting LE. Pass `"force": true` to re-issue.

All names on one certificate must map to the **same** Cloud DNS zone.

### Download bundle

```bash
curl -sS -H "Authorization: Bearer $API_KEY" \
  https://custodian.example/v1/certificates/$ID/bundle | jq -r .fullchain_pem
```

### Cron renewal

Use an **admin** key:

```bash
curl -fsS -X POST -H "Authorization: Bearer $ADMIN_API_KEY" \
  https://custodian.example/v1/renew
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | no | Listen port. Dokku sets this; default `8080` only for local runs |
| `DATABASE_URL` | yes | Postgres URL |
| `DOMAIN_CATALOG` | yes* | JSON array of `{pattern, zone}` |
| `API_CLIENTS` | yes* | JSON array of `{id, key, role, patterns?}` |
| `DOMAIN_CATALOG_FILE` / `API_CLIENTS_FILE` | no | Load JSON from path instead of env |
| `ALLOWED_DOMAINS` + `CLOUDDNS_ZONE` | legacy | Flat patterns + single zone (maps to catalog) |
| `API_KEYS` | legacy | Comma-separated keys → admin clients |
| `LE_EMAIL` | yes | ACME account contact |
| `LE_DIRECTORY` | no | `staging` (default), `production`, or full URL |
| `DATA_ENCRYPTION_KEY` | yes | Base64 of 32 bytes |
| `GCE_PROJECT` / `GCP_PROJECT` | for issue | GCP project for Cloud DNS |
| `GCP_SERVICE_ACCOUNT_JSON` | or file | SA JSON; else `GOOGLE_APPLICATION_CREDENTIALS` |
| `DNS_PROPAGATION_TIMEOUT_SEC` | no | Default `120` |
| `RENEW_BEFORE_DAYS` | no | Default `30` |
| `MAX_SANS` | no | Default `10` |
| `LOG_LEVEL` | no | `debug` / `info` / `warn` / `error` |

\* Either the new JSON vars or the legacy pair must be set.

### Domain patterns

- Exact: `api.example.com`
- Single-label wildcard: `*.apps.example.com` matches `foo.apps.example.com`, not `a.b.apps.example.com`
- Most specific matching catalog entry wins for zone selection

### GCP IAM

Grant the service account **DNS Administrator** (or custom DNS record roles) on **each** managed zone listed in the catalog (same SA for all).

## Dokku deploy

```bash
dokku apps:create custodian
dokku postgres:create custodian-db
dokku postgres:link custodian-db custodian

ADMIN_KEY=$(openssl rand -hex 24)
APP_KEY=$(openssl rand -hex 24)

dokku config:set custodian \
  LE_EMAIL="ops@example.com" \
  LE_DIRECTORY=staging \
  DATA_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  GCE_PROJECT="your-project" \
  GCP_SERVICE_ACCOUNT_JSON="$(jq -c . < sa.json)" \
  DOMAIN_CATALOG="$(jq -c . <<'EOF'
[
  {"pattern":"*.apps.example.com","zone":"apps-example-com"},
  {"pattern":"*.example.com","zone":"example-com"},
  {"pattern":"example.com","zone":"example-com"}
]
EOF
)" \
  API_CLIENTS="$(jq -c -n \
    --arg a "$ADMIN_KEY" --arg k "$APP_KEY" \
    '[{id:"admin",key:$a,role:"admin"},{id:"myapp",key:$k,role:"tenant",patterns:["myapp.example.com"]}]')"

# cron must use the admin key
# 0 4 * * * curl -fsS -X POST -H "Authorization: Bearer $ADMIN_KEY" https://custodian.example/v1/renew
```

### Ports

Do **not** bake `EXPOSE 8080` / `ENV PORT=8080` into the image (already removed). Dokku injects `PORT` and should proxy host `80`/`443` → container `$PORT`.

```bash
dokku ports:report custodian
# if needed after an old deploy:
dokku ports:set custodian http:80:5000 https:443:5000
```

Use **staging** until DNS-01 works end-to-end, then set `LE_DIRECTORY=production`.

## Security notes

- Terminate TLS at the reverse proxy; do not expose the API on the public internet without HTTPS and strong API keys.
- Tenant keys can download private keys **for their domains only** — treat them as highly privileged for that app.
- Prefer one admin key for cron and separate tenant keys per app/domain set.
- Private keys are encrypted with `DATA_ENCRYPTION_KEY`; back up both the database and this key.
- Prefer LE staging for development to avoid production rate limits.

## Development

```bash
go test ./...
go build -o bin/custodian ./cmd/custodian
```

## License

Private / unlicensed unless otherwise stated.
