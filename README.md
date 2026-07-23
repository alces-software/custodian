# Custodian

Self-hosted service that **issues and renews Let's Encrypt certificates** for allowlisted hostnames using **DNS-01** against **Google Cloud DNS**, stores material in **PostgreSQL**, and exposes an HTTP API with **client-held access keys**.

## Auth model

| Key | Env | Purpose |
|-----|-----|---------|
| **Admin** | `ADMIN_API_KEYS` (legacy: `API_KEYS`) | Full access, bulk renew, list/revoke access keys |
| **Registrar** | `REGISTRAR_API_KEYS` | **Only** register new access keys (`POST /v1/access-keys`) |
| **Access key** | Client UUID (hashed in DB) | Issue and manage certs bound to that key |

Apps do **not** need to be listed in server env. Generate a UUID, register it once with the registrar, then use it as `Authorization: Bearer`.

```bash
export ACCESS_KEY=$(uuidgen | tr '[:upper:]' '[:lower:]')

# 1) Register (onboarding CI holds REGISTRAR_KEY only)
curl -sS -X POST "$URL/v1/access-keys" \
  -H "Authorization: Bearer $REGISTRAR_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"access_key\":\"$ACCESS_KEY\",\"description\":\"myapp prod\"}"

# 2) Issue / download (app holds ACCESS_KEY only)
curl -sS -X POST "$URL/v1/certificates" \
  -H "Authorization: Bearer $ACCESS_KEY" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"app.example.com"}'
```

Cron uses **admin**:

```bash
curl -fsS -X POST -H "Authorization: Bearer $ADMIN_KEY" "$URL/v1/renew"
```

## Features

- Domain catalog with **per-pattern Cloud DNS zones** (one GCP SA)
- Access keys with **description**, soft **revoke** (admin)
- Encrypted private keys at rest (AES-256-GCM)
- LE staging by default

## API

| Method | Path | Who |
|--------|------|-----|
| `POST` | `/v1/access-keys` | admin, registrar |
| `GET` | `/v1/access-keys` | admin |
| `GET` | `/v1/access-keys/{id}` | admin |
| `PATCH` | `/v1/access-keys/{id}` | admin (update description) |
| `DELETE` | `/v1/access-keys/{id}` | admin (soft revoke) |
| `POST` | `/v1/certificates` | access key, admin |
| `GET` | `/v1/certificates` | access key (own), admin (all) |
| `GET` | `/v1/certificates/{id}` | owner or admin |
| `GET` | `/v1/certificates/{id}/bundle` | owner or admin |
| `POST` | `/v1/certificates/{id}/renew` | owner or admin |
| `DELETE` | `/v1/certificates/{id}` | owner or admin |
| `POST` | `/v1/renew` | admin only |
| `GET` | `/healthz`, `/readyz` | public |

Admin issue on behalf of a key:

```json
{
  "common_name": "app.example.com",
  "access_key": "<registered-uuid>"
}
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | yes | Postgres |
| `ADMIN_API_KEYS` | yes* | Admin bearer secrets (`API_KEYS` legacy alias) |
| `REGISTRAR_API_KEYS` | recommended | Registrar secrets |
| `DOMAIN_CATALOG` | yes* | JSON `[{pattern, zone}, …]` |
| `ALLOWED_DOMAINS` + `CLOUDDNS_ZONE` | legacy | Flat catalog |
| `LE_EMAIL` | yes | ACME contact |
| `LE_DIRECTORY` | no | `staging` / `production` |
| `DATA_ENCRYPTION_KEY` | yes | Base64 32 bytes |
| `GCE_PROJECT` | for issue | GCP project |
| `GCP_SERVICE_ACCOUNT_JSON` | or ADC | Cloud DNS credentials |
| `PORT` | no | Default 8080 locally; Dokku injects |

`API_CLIENTS` is **removed** (ignored with a warning if set).

### Domain catalog patterns

| Pattern | Matches | Example |
|---------|---------|---------|
| `example.com` | Exact host only | `example.com` |
| `*.example.com` | **One** label under the base | `foo.example.com` — not `a.b.example.com` |
| `**.example.com` | **One or more** labels under the base | `foo.example.com`, `login.kelvin.example.com` |

Most specific match wins (exact → `*` → `**`). Apex (`example.com`) is not matched by `*`/`**`.

For nested Alces hosts under one zone:

```json
[{"pattern":"**.alces.network","zone":"alces-network"}]
```

## Local / Dokku

```bash
# local
export DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
docker compose up --build

# dokku
dokku config:set custodian \
  ADMIN_API_KEYS="$(openssl rand -hex 24)" \
  REGISTRAR_API_KEYS="$(openssl rand -hex 24)" \
  DOMAIN_CATALOG='[{"pattern":"**.example.com","zone":"example-com"}]' \
  LE_EMAIL=ops@example.com \
  LE_DIRECTORY=staging \
  DATA_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  GCE_PROJECT=… \
  GCP_SERVICE_ACCOUNT_JSON="$(jq -c . < sa.json)"
```

Scripts: `scripts/register-key.sh`, `scripts/issue.sh`, `scripts/renew.sh`.

## Development

```bash
go test ./...
go build -o bin/custodian ./cmd/custodian
```

## License

Copyright (C) 2026-present Alces Software Ltd.

Custodian is made available under the [Eclipse Public License 2.0](https://www.eclipse.org/legal/epl-2.0), or alternative license terms made available by Alces Software Ltd. Licensing inquiries: licensing@alces-flight.com.

Project: https://github.com/alces-software/custodian
