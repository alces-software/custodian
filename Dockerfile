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

# --- CLI binaries (served at /cli/*) ---
FROM golang:1.26-bookworm AS cli
WORKDIR /cli
COPY cli/go.mod cli/go.sum ./
RUN go mod download
COPY cli/ ./
# Explicit targets only — avoid shell $1/$$ escaping traps under Docker/Dokku
# ($$1 was expanded as PID+"1" → GOOS=11 GOARCH=12).
RUN set -eux; \
    mkdir -p /out; \
    CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/custodian-linux-amd64  ./cmd/custodian; \
    CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /out/custodian-linux-arm64  ./cmd/custodian; \
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/custodian-darwin-amd64 ./cmd/custodian; \
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /out/custodian-darwin-arm64 ./cmd/custodian; \
    cp /out/custodian-linux-amd64 /out/custodian; \
    (cd /out && sha256sum custodian custodian-linux-* custodian-darwin-* > SHA256SUMS)

# --- Server ---
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/custodian-server ./cmd/custodian

# --- Run ---
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/custodian-server /app/custodian
COPY --from=cli /out/ /app/cli/
USER nonroot:nonroot
# Do not EXPOSE a port or bake PORT here — Dokku injects PORT and maps
# host http:80 / https:443 → container $PORT.
ENV CLI_BINARIES_DIR=/app/cli
ENTRYPOINT ["/app/custodian", "serve"]
