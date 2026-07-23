#!/usr/bin/env bash
# Register a client access key. Usage:
#   ACCESS_KEY=$(uuidgen) ./scripts/register-key.sh "myapp prod"
set -euo pipefail

: "${CUSTODIAN_URL:?set CUSTODIAN_URL}"
: "${REGISTRAR_KEY:?set REGISTRAR_KEY (or ADMIN_KEY via REGISTRAR_KEY)}"

if [[ -z "${ACCESS_KEY:-}" ]]; then
  if command -v uuidgen >/dev/null 2>&1; then
    ACCESS_KEY=$(uuidgen | tr '[:upper:]' '[:lower:]')
  else
    echo "set ACCESS_KEY or install uuidgen" >&2
    exit 2
  fi
  echo "generated ACCESS_KEY=$ACCESS_KEY" >&2
fi

desc="${1:-}"
body=$(jq -n --arg k "$ACCESS_KEY" --arg d "$desc" \
  '{access_key:$k, description:$d}')

curl -fsS -X POST \
  -H "Authorization: Bearer ${REGISTRAR_KEY}" \
  -H "Content-Type: application/json" \
  -d "$body" \
  "${CUSTODIAN_URL%/}/v1/access-keys"
echo
