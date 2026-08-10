# custodian-cli

CLI for the Custodian certificate API (`../custodian` / `alces/custodian`).

Bearer tokens are always passed the same way (`--auth-key` / `CUSTODIAN_AUTH_KEY`). What you can do depends on which kind of key the server issued:

| Role | Capabilities |
|------|----------------|
| **Access key** | Issue/list/get/bundle/renew/delete **own** certs |
| **Registrar** | Register new access keys |
| **Admin** | Everything (keys + all certs + bulk renew) |

## Install

```bash
make build   # → bin/custodian
# or
go install alces/custodian-cli/cmd/custodian@latest
```

## Configuration

Priority: **flags > environment > config file**.

| Flag | Env | Description |
|------|-----|-------------|
| `--url` | `CUSTODIAN_URL` | Base URL |
| `--auth-key` | `CUSTODIAN_AUTH_KEY` | Bearer token |
| `--profile` | | Named profile from config |
| `--config` | | Config path (default: XDG/`~/.config/custodian/config.yaml` if present, else `<binary>/../etc/config.yaml`) |
| `--json` | | JSON output |
| `--timeout` | | HTTP timeout (default 120s; raise for slow DNS-01) |

Example config (`~/.config/custodian/config.yaml` or, for a standalone tree, `bin/../etc/config.yaml`):

```yaml
url: https://custodian.example
auth_key: your-bearer-token

profiles:
  admin:
    url: https://custodian.example
    auth_key: admin-secret
```

Standalone layout example:

```
install/
  bin/custodian
  etc/config.yaml    # used when no XDG user config exists
```

## Typical workflows

### Onboard an app (registrar or admin)

```bash
export CUSTODIAN_URL=https://custodian.example
export CUSTODIAN_AUTH_KEY=...   # registrar or admin secret

# Generates a UUID, prints it on stderr once, registers it
custodian access-key register -d "myapp prod"

# Script-friendly: only the secret on stdout
KEY=$(custodian access-key register -d "myapp prod" --brief)

# Or supply your own secret (min 16 chars)
custodian access-key register --key "$APP_SECRET" -d "myapp prod"
```

### Issue and download (app access key)

```bash
export CUSTODIAN_URL=https://custodian.example
export CUSTODIAN_AUTH_KEY=...   # registered client secret

custodian cert issue app.example.com www.app.example.com
custodian cert list
custodian cert bundle <id> --out ./certs
```

### Admin ops

```bash
export CUSTODIAN_URL=https://custodian.example
export CUSTODIAN_AUTH_KEY=...   # admin secret

custodian access-key list
custodian access-key get <id>
custodian access-key update <id> -d "new description"
custodian access-key revoke <id> -y

# Issue on behalf of a registered key
custodian cert issue app.example.com --access-key-id <key-uuid>
# or
custodian cert issue app.example.com --access-key "$CLIENT_SECRET"

custodian cert renew-due   # bulk renew (admin only)
```

## Commands

```bash
custodian health
custodian health --ready

custodian access-key register [-d desc] [--key secret] [--brief]
custodian access-key list
custodian access-key get <id>
custodian access-key update <id> -d "description"
custodian access-key revoke <id> [-y]

custodian cert list
custodian cert get <id>
custodian cert issue <cn> [san...] [--force] [--access-key|--access-key-id]
custodian cert renew <id>
custodian cert renew-due
custodian cert delete <id> -y
custodian cert bundle <id>              # metadata only (no private key)
custodian cert bundle <id> --out DIR
custodian cert bundle <id> --json
custodian cert bundle <id> --format pem
```

`access-key` is also available as `key` (alias).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | API/network failure, or `renew-due` with failures |
| 2 | Usage error / missing config |

## Development

```bash
go test ./...
make build
```
