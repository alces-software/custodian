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
