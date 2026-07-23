#!/usr/bin/env bash
# Cron-friendly bulk renewal. Set CUSTODIAN_URL and CUSTODIAN_API_KEY.
set -euo pipefail

: "${CUSTODIAN_URL:?set CUSTODIAN_URL, e.g. https://custodian.example}"
: "${CUSTODIAN_API_KEY:?set CUSTODIAN_API_KEY}"

curl -fsS -X POST \
  -H "Authorization: Bearer ${CUSTODIAN_API_KEY}" \
  -H "Content-Type: application/json" \
  "${CUSTODIAN_URL%/}/v1/renew"
echo
