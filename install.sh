#!/bin/bash
# =============================================================================
# Copyright (C) 2026-present Alces Software Ltd.
#
# This file is part of Custodian.
#
# Bootstrap: download CLI from a running Custodian service and register a key.
# Usage:
#   CUSTODIAN_URL=https://custodian.example REGISTRAR_KEY=... ./install.sh
# =============================================================================
set -euo pipefail

: "${CUSTODIAN_URL:?set CUSTODIAN_URL, e.g. https://custodian.example}"
: "${REGISTRAR_KEY:?set REGISTRAR_KEY (registrar or admin bearer)}"

PREFIX="${PREFIX:-/opt/service/alces/custodian}"
BIN_DIR="${PREFIX}/bin"
ETC_DIR="${PREFIX}/etc"
BASE="${CUSTODIAN_URL%/}"

mkdir -p "${BIN_DIR}" "${ETC_DIR}"
cd "${BIN_DIR}"

echo "Downloading CLI from ${BASE}/cli/custodian ..."
wget -q -O custodian "${BASE}/cli/custodian"
chmod +x custodian

cat > "${ETC_DIR}/config.yaml" <<EOF
url: ${BASE}
auth_key: NONE

profiles:
  registrar:
    url: ${BASE}
    auth_key: ${REGISTRAR_KEY}
EOF

# Optional Flight Starter integration: description from cluster name.
DESC="${flight_STARTER_cluster_name:-$(hostname -s 2>/dev/null || echo node)}"
if [[ -f /opt/flight/etc/flight-starter.rc ]]; then
  # shellcheck disable=SC1091
  source /opt/flight/etc/flight-starter.rc
  DESC="${flight_STARTER_cluster_name:-$DESC}"
fi

KEY=$(
  "${BIN_DIR}/custodian" \
    --profile registrar \
    --config "${ETC_DIR}/config.yaml" \
    access-key register \
    -d "${DESC}" \
    --brief
)

# Portable in-place replace for auth_key: NONE
if command -v sed >/dev/null 2>&1; then
  sed -i.bak -e "s/auth_key: NONE/auth_key: ${KEY}/" "${ETC_DIR}/config.yaml"
  rm -f "${ETC_DIR}/config.yaml.bak"
fi

echo "Installed CLI to ${BIN_DIR}/custodian"
echo "Config: ${ETC_DIR}/config.yaml (access key registered as description=${DESC})"
