#!/usr/bin/env bash

# =============================================================================
# Copyright (C) 2026-present Alces Software Ltd.
#
# This file is part of Custodian.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License 2.0 which is available at
# <https://www.eclipse.org/legal/epl-2.0>, or alternative license
# terms made available by Alces Software Ltd - please direct inquiries
# about licensing to licensing@alces-flight.com.
#
# Custodian is distributed in the hope that it will be useful, but
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
# IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
# OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
# PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
# details.
#
# You should have received a copy of the Eclipse Public License 2.0
# along with Custodian. If not, see:
#
#  https://opensource.org/licenses/EPL-2.0
#
# For more information on Custodian, please visit:
# https://github.com/alces-software/custodian
# ==============================================================================

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
