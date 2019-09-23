#!/bin/bash
#==============================================================================
# Copyright (C) 2019-present Alces Flight Ltd.
#
# This file/package is part of Flight SSL Tools.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License 2.0 which is available at
# <https://www.eclipse.org/legal/epl-2.0>, or alternative license
# terms made available by Alces Flight Ltd - please direct inquiries
# about licensing to licensing@alces-flight.com.
#
# Flight SSL Tools is distributed in the hope that it will be useful, but
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
# IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
# OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
# PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
# details.
#
# You should have received a copy of the Eclipse Public License 2.0
# along with Flight SSL Tools. If not, see:
#
#  https://opensource.org/licenses/EPL-2.0
#
# For more information on Flight SSL Tools, please visit:
# https://github.com/alces-flight/flight-ssl-tools
#==============================================================================
rr_exists() {
  local ignore_cname rc result
  if [ "$1" == "--ignore-cname" ]; then
    ignore_cname=true
    shift
  fi
  result=$(lookup_rr "$1")
  rc=$?
  if [ "${ignore_cname}" ]; then
    # if this is a CNAME, then the first line will not be an IP address
    echo "$result" | head -n1 | egrep -q '([1-2]?[0-9]{0,2}\.){3,3}[1-2]?[0-9]{0,2}'
  else
    return $rc
  fi
}

lookup_rr() {
  local name ip
  name="$1"
  ip=$(dig +short "$name" 2>/dev/null)
  if [ "$ip" ]; then
    echo "$ip"
  else
    return 1
  fi
}

webapi_curl() {
    local url mimetype
    url="$1"
    mimetype="$2"
    shift 2

    curl "$@" -H "Accept: $mimetype" $url
}

webapi_send() {
  local verb url mimetype params auth skip_payload no_silent emit_code
  verb="$1"
  url="$2"
  shift 2
  params=()
  while [ "$1" ]; do
    case $1 in
      --auth)
        auth="$2"
        shift 2
        ;;
      --mimetype)
        mimetype="$2"
        shift 2
        ;;
      --skip-payload)
        skip_payload=true
        shift
        ;;
      --no-silent)
        no_silent=true
        shift
        ;;
      --emit-code)
        emit_code=true
        no_silent=true
        shift
        ;;
      *)
        params+=("$1")
        shift
        ;;
    esac
  done
  mimetype="${mimetype:-application/vnd.api+json}"
  params+=(-s -X ${verb})
  if [ "${auth}" ]; then
    params+=(-u "${auth}")
  fi
  if [ -z "${skip_payload}" ]; then
    params+=(-d @- -H "Content-Type: $mimetype")
  fi
  if [ -z "${no_silent}" ]; then
    params+=(-f)
  fi
  if [ "${emit_code}" ]; then
    params+=(-w "\n\ncode=%{http_code}\n")
  fi
  webapi_curl "${url}" "${mimetype}" "${params[@]}"
}

webapi_patch() {
  webapi_send PATCH "$@"
}

webapi_post() {
  webapi_send POST "$@"
}

webapi_delete() {
  webapi_send DELETE "$@" --skip-payload
}

fetch_cert() {
  local dest name names ip secret a k s meta alts d retry output rc
  dest="$1"
  name="$2"
  ip="$3"
  s="$4"
  k="$5"
  meta="$6"
  shift 6
  alts="["
  for a in "$@"; do
    alts="${alts}\"$a\","
  done
  alts="${alts%,}]"
  output=$(
    cat <<JSON | webapi_post \
                   $_URL
{
  "name": "${name}",
  "ip": "${ip}",
  "secret": "${_KEY}",
  "s": "${s}",
  "k": "${k}",
  "meta": "${meta}",
  "alts": ${alts}
}
JSON
        )
  rc="$?"
  if [ "${rc}" == "0" ]; then
    retry="$(echo "${output}" | "${_JQ}" -e -r .retry)"
    if [ $? == 0 ]; then
      sleep $retry
      # We use a high error code to distinguish this from a curl
      # exit code (at time of writing, highest exit code of curl
      # is 63).
      return 147
    else
      d="${dest}/certs-${name}"
      mkdir -p "$d"
      touch "${d}"/key.pem
      chmod 0600 "${d}"/key.pem
      echo "${output}" | "${_JQ}" -r .fullchain > "${d}"/fullchain.pem
      echo "${output}" | "${_JQ}" -r .key > "${d}"/key.pem
      echo "${output}" | "${_JQ}" -r .cert > "${d}"/cert.pem
      echo "$_KEY" > "${d}"/renewal-key.txt
    fi
  fi
  return ${rc}
}

_get_usable_name() {
  local name suffix
  suffix=$(uuid -v4 | cut -f1 -d'-')
  name="$1-${suffix}"
  while rr_exists --ignore-cname "${name}.${_DOMAIN}"; do
    suffix=$(uuid -v4 | cut -f1 -d'-')
    name="$1-${suffix}"
  done
  echo "${name}"
}

_check_usable_name() {
  local name
  name="$1"
  if rr_exists --ignore-cname "${name}.${_DOMAIN}"; then
    return 1
  else
    return 0
  fi
}

network_get_public_address() {
  local public_ipv4 tmout
  tmout=${1:-5}

  if network_is_ec2; then
    if [ "${tmout}" -gt 0 ]; then
      # Attempt to determine our public IP address using the standard EC2
      # API.
      public_ipv4=$(network_fetch_ec2_metadata public-ipv4 ${tmout})
    fi
  fi

  if [ -z "$public_ipv4" ]; then
    # Could not find it via EC2 API, use apparent public interface address.
    ip -o route get 8.8.8.8 2>/dev/null | head -n 1 | sed 's/.*src \(\S*\).*/\1/g'
  else
    echo "$public_ipv4"
  fi
}

network_get_first_iface() {
  ip -o link show 2>/dev/null \
    | grep -v 'lo:' \
    | head -n1 \
    | sed 's/^.: \(\S*\):.*/\1/g'
}

network_get_iface_mac() {
  local target_iface
  target_iface="$1"

  ip -o -4 link show dev ${target_iface} 2>/dev/null \
    | head -n 1 \
    | sed 's/.*link\/ether\s*\(\S*\)\s*.*/\1/g'
}

network_is_ec2() {
  [ -f /sys/hypervisor/uuid ] && [ "$(head -c3 /sys/hypervisor/uuid)" == "ec2" ] ||
    [ "$(dmidecode -s baseboard-manufacturer 2>/dev/null)" == "Amazon Corporate LLC" ] ||
    [ "$(dmidecode -s baseboard-manufacturer 2>/dev/null)" == "Amazon EC2" ]
}

network_fetch_ec2_metadata() {
    local item tmout
    item="$1"
    tmout="${2:-5}"
    curl -f --connect-timeout ${tmout} http://169.254.169.254/latest/meta-data/${item} 2>/dev/null
}

network_fetch_ec2_document() {
  curl -s http://169.254.169.254/latest/dynamic/instance-identity/document
}

network_ec2_hashed_account() {
  local account
  account=$(network_fetch_ec2_document | \
              "${_JQ}" -r .accountId)
  echo -n "${account}" | md5sum | cut -f1 -d' ' | base64 | cut -c1-16 | tr 'A-Z' 'a-z'
}

renew() {
  local dest name ip
  name="$1"
  if [ -z "$name" ]; then
    echo "$0: name was not supplied"
    exit 1
  fi
  src="${2:-/tmp}"
  ip="${3:-$(network_get_public_address)}"
  _KEY="$(cat ${src}/certs-${name}/renewal-key.txt)"
  if [ -z "$_KEY" ]; then
    echo "$0: key not found in: ${src}/certs-${name}/renewal-key.txt"
    return 1
  fi
  dest="${src}/certs-${name}/renew"
  process "$@"
  rc=$?
  if [ "$rc" == 0 ]; then
    old="${src}/certs-${name}/old.$(date +%Y%m%d-%H%M)"
    mkdir -p "${old}"
    mv "${src}/certs-${name}/"*.{pem,txt} "${old}"
    mv "${dest}/certs-${name}/"* "${src}/certs-${name}"
    rmdir "${dest}/certs-${name}"
    rmdir "${src}/certs-${name}/renew"
    echo "$0: cert renewed, see ${src}/certs-${name}"
  else
    echo "$0: unable to issue cert (error: $rc)"
  fi
}

process() {
  if [ "${#@}" -ge 3 ]; then
    shift 3
  else
    shift "${#@}"
  fi
  local s k
  if [ -z "$ip" ]; then
    echo "$0: unable to determine IP address"
    exit 1
  fi
  s="$(dd if=/dev/urandom bs=8 count=1 2>/dev/null | base64 | cut -c1-8)"
  k="$(echo -n "${name}:${s}:${_SEEKRET}" | md5sum | cut -f1 -d' ')"
  if network_is_ec2; then
    meta="$(network_ec2_hashed_account)"
  else
    meta="$(network_get_iface_mac $(network_get_first_iface))"
  fi
  alts=()
  alt_names=()
  for a in "$@"; do
    alts+=("${name}.${a}")
    alt_names+=("${name}.${a%:*}")
  done
  fetch_cert "${dest}" "${name}" "${ip}" "${s}" "${k}" "${meta}" "${alts[@]}"
  rc=$?
  if [ "$rc" == 147 ]; then
    # retry
    if ! fetch_cert "${dest}" "${name}" "${ip}" "${s}" "${k}" "${meta}" "${alts[@]}"; then
      echo "unable to fetch SSL cert for ${name}"
      return 1
    fi
    rc=0
  fi
  return $rc
}

issue() {
  local dest name basename ip rc
  basename="$1"
  if [ -z "$1" ]; then
    echo "$0: name was not supplied"
    exit 1
  fi
  sane_name="$(echo "${basename}" | tr "[A-Z]" "[a-z]" | sed -e 's/[^a-z0-9_]/-/g' -e 's/-[-]*/-/g' -e 's/-$//g')"
  name="$(_get_usable_name ${basename})"
  dest="${2:-/tmp}"
  ip="${3:-$(network_get_public_address)}"
  _KEY=$(uuid -v4)
  process "$@"
  rc=$?
  if [ "$rc" == 0 ]; then
    echo "$0: cert issued, see ${dest}/certs-${name}"
  else
    echo "$0: unable to issue cert (error: $rc)"
  fi
}

usage() {
  cat <<EOF
Flight SSL certificate generator v1.0.0

Usage:

= Generate a certificate =

    $0 <name prefix> [<ip address>] [<directory>]

  This will generate a certificate for:

    <name prefix>-<identifier>.${_DOMAIN}

  ...where <identifier> is an automatically generated hexadecimal
  suffix. DNS will be updated to point the name at the provided <ip
  address>, which defaults to the detected public IP address of the
  machine issuing the command.  The certificate files and a key (used
  for renewal purposes) is written to a 'certs-<name
  prefix>-<identifier>' subdirectory of the given <directory>
  (defaults to '/tmp').

  e.g.

    $0 hub 192.168.10.12 /opt/ssl

= Renew a certificate =

    $0 --renew <name> [<ip address>] [<directory>]

  This will renew a certificate for:

    <name>.${_DOMAIN}

  Note that, unlike above, the full name (including identifier) must
  be supplied.  The supplied IP must match the IP address of the
  initial request.  A renewal key is required and is read from
  '<directory>/certs-<name>/renewal-key.txt'.  The certificate files
  are written back to this directory.  Existing certificate files are
  moved to a subdirectory named 'old.<date>'.

  e.g.

    $0 --renew hub-dea7bee9 192.168.10.12 /opt/ssl

EOF
}

if [ -f /etc/xdg/flight-ssl.rc ]; then
  . /etc/xdg/flight-ssl.rc
fi
_DOMAIN="${flight_SSL_domain}"
_SEEKRET="${flight_SSL_seekret}"
_URL="${flight_SSL_url}"
if [ -z "${_SEEKRET}" -o -z "${_DOMAIN}" -o -z "${_URL}" ]; then
  echo "$0: configuration incomplete"
  exit 1
fi
_JQ=$(which jq 2>/dev/null)
if [ -z "$_JQ" ]; then
  echo "$0: could not find jq"
  exit 1
fi
if [ "$1" == "" -o "$1" == "--help" ]; then
  usage
elif [ "$1" == "--renew" ]; then
  shift
  renew "$@"
else
  issue "$@"
fi
