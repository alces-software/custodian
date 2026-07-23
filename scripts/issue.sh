#!/usr/bin/env bash
# Issue a certificate. Usage: ./scripts/issue.sh app.example.com [san2 san3...]
set -euo pipefail

: "${CUSTODIAN_URL:?set CUSTODIAN_URL}"
# Client access key (registered via POST /v1/access-keys)
: "${ACCESS_KEY:?set ACCESS_KEY}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <common_name> [san...]" >&2
  exit 2
fi

cn="$1"
shift
sans_json="[]"
if [[ $# -gt 0 ]]; then
  sans_json=$(printf '%s\n' "$@" | jq -R . | jq -s .)
fi

body=$(jq -n --arg cn "$cn" --argjson sans "$sans_json" \
  '{common_name:$cn, sans:$sans, force:false}')

curl -fsS -X POST \
  -H "Authorization: Bearer ${ACCESS_KEY}" \
  -H "Content-Type: application/json" \
  -d "$body" \
  "${CUSTODIAN_URL%/}/v1/certificates"
echo
