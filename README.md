# Custodian

Self-hosted service that **issues and renews Let's Encrypt certificates** for allowlisted hostnames using **DNS-01** against **Google Cloud DNS**, stores material in **PostgreSQL**, and exposes a small **API-key-authenticated HTTP API**. Designed for Dokku (or any container host) with **external cron** for renewal.

## Features

- Issue certificates for specific CNs (+ optional SANs) within a configurable domain allowlist
- DNS-01 via Cloud DNS (`lego` + `gcloud` provider)
- Encrypted private keys at rest (AES-256-GCM)
- List / download PEM bundles
- Force renew one cert, or bulk renew due certs (`POST /v1/renew` for cron)
- Let's Encrypt **staging** by default unless `LE_DIRECTORY=production`

## Quick start (local)

```bash
# generate a real encryption key
export DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)

docker compose up --build
```

Or run the binary against Compose Postgres:

```bash
docker compose up -d db
export DATABASE_URL='postgres://custodian:custodian@localhost:5432/custodian?sslmode=disable'
export API_KEYS='dev-api-key-change-me'
export ALLOWED_DOMAINS='*.example.com,example.com'
export LE_EMAIL='ops@example.com'
export LE_DIRECTORY=staging
export DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
# for real issuance:
# export GCE_PROJECT=...
# export CLOUDDNS_ZONE=...   # managed zone name in Cloud DNS
# export GCP_SERVICE_ACCOUNT_JSON='...'  # or GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
go run ./cmd/custodian serve
```

## API

All routes except health require `Authorization: Bearer <api-key>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | DB readiness |
| `POST` | `/v1/certificates` | Issue (or return still-valid cert) |
| `GET` | `/v1/certificates` | List metadata |
| `GET` | `/v1/certificates/{id}` | Get metadata |
| `GET` | `/v1/certificates/{id}/bundle` | Download PEMs (JSON; `?format=pem` for raw) |
| `POST` | `/v1/certificates/{id}/renew` | Force renew one |
| `POST` | `/v1/renew` | Renew all due (cron) |
| `DELETE` | `/v1/certificates/{id}` | Soft-delete |

### Issue

```bash
curl -sS -X POST https://custodian.example/v1/certificates \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"app.example.com","sans":["www.app.example.com"]}'
```

Idempotent: if an active cert for the same name set is valid for longer than `RENEW_BEFORE_DAYS`, it is returned without hitting LE. Pass `"force": true` to re-issue.

### Download bundle

```bash
curl -sS -H "Authorization: Bearer $API_KEY" \
  https://custodian.example/v1/certificates/$ID/bundle | jq -r .fullchain_pem
```

### Cron renewal

```bash
curl -fsS -X POST -H "Authorization: Bearer $API_KEY" \
  https://custodian.example/v1/renew
```

Schedule daily (Dokku cron, system cron, or Cloud Scheduler HTTP). Certs with `not_after` within `RENEW_BEFORE_DAYS` (default 30) are renewed.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | no | Listen port. Dokku sets this; default `8080` only for local runs |
| `DATABASE_URL` | yes | Postgres URL |
| `API_KEYS` | yes | Comma-separated bearer tokens |
| `ALLOWED_DOMAINS` | yes | Patterns: `example.com,*.apps.example.com` |
| `LE_EMAIL` | yes | ACME account contact |
| `LE_DIRECTORY` | no | `staging` (default), `production`, or full directory URL |
| `DATA_ENCRYPTION_KEY` | yes | Base64 of 32 bytes |
| `GCE_PROJECT` / `GCP_PROJECT` | for issue | GCP project for Cloud DNS |
| `CLOUDDNS_ZONE` | recommended | Sets lego `GCE_ZONE_ID` to skip auto zone detection |
| `GCP_SERVICE_ACCOUNT_JSON` | or file | Service account JSON; else `GOOGLE_APPLICATION_CREDENTIALS` |
| `DNS_PROPAGATION_TIMEOUT_SEC` | no | Default `120` |
| `RENEW_BEFORE_DAYS` | no | Default `30` |
| `MAX_SANS` | no | Default `10` |
| `LOG_LEVEL` | no | `debug` / `info` / `warn` / `error` |

### Allowlist patterns

- Exact: `api.example.com`
- Single-label wildcard: `*.apps.example.com` matches `foo.apps.example.com`, not `a.b.apps.example.com`

### GCP IAM

Grant the service account **DNS Administrator** (or a custom role with `dns.changes.*` / `dns.resourceRecordSets.*`) on the managed zone only.

## Dokku deploy

```bash
dokku apps:create custodian
dokku postgres:create custodian-db
dokku postgres:link custodian-db custodian

dokku config:set custodian \
  API_KEYS="$(openssl rand -hex 24)" \
  ALLOWED_DOMAINS="*.example.com,example.com" \
  LE_EMAIL="ops@example.com" \
  LE_DIRECTORY=staging \
  DATA_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  GCE_PROJECT="your-project" \
  CLOUDDNS_ZONE="example-com" \
  GCP_SERVICE_ACCOUNT_JSON="$(cat sa.json | jq -c .)"

# deploy from git remote, or:
# dokku git:from-image custodian your-registry/custodian:tag

# daily renew (example host cron)
# 0 4 * * * curl -fsS -X POST -H "Authorization: Bearer $KEY" https://custodian.example/v1/renew
```

### Ports

Do **not** set `PORT=8080` in Dokku config or `EXPOSE 8080` in the image. Dokku injects `PORT` and should proxy:

- `http:80 → $PORT`
- `https:443 → $PORT`

If a previous deploy taught Dokku to use 8080 publicly, reset after redeploying this image:

```bash
dokku ports:report custodian
dokku ports:set custodian http:80:5000 https:443:5000
# use whatever container port Dokku assigned (see config:show PORT or ports:report)
```

Use **staging** until DNS-01 works end-to-end, then set `LE_DIRECTORY=production`.

## Security notes

- Terminate TLS at the reverse proxy; do not expose the API on the public internet without HTTPS and strong API keys.
- Private keys are encrypted with `DATA_ENCRYPTION_KEY`; back up both the database and this key.
- Bundle endpoints return private keys — treat API keys as highly privileged.
- Prefer LE staging for development to avoid production rate limits.

## Development

```bash
go test ./...
go build -o bin/custodian ./cmd/custodian
```

## License

Private / unlicensed unless otherwise stated.
