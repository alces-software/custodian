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

.PHONY: test build run tidy sync-cli cli-binaries

# Refresh vendored CLI source from sibling checkout (../custodian-cli).
sync-cli:
	rsync -a --delete \
		--exclude '.git' --exclude 'bin' --exclude 'docs' \
		../custodian-cli/ ./cli/

# Cross-compile CLI into ./static/cli for local serve without Docker.
cli-binaries: sync-cli
	mkdir -p static/cli
	cd cli && \
	  for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
	    GOOS=$${pair%/*} GOARCH=$${pair#*/} CGO_ENABLED=0 \
	      go build -trimpath -ldflags="-s -w" \
	        -o ../static/cli/custodian-$${pair%/*}-$${pair#*/} ./cmd/custodian; \
	  done
	cp static/cli/custodian-linux-amd64 static/cli/custodian
	cd static/cli && sha256sum custodian custodian-* > SHA256SUMS

test:
	go test ./...

build:
	go build -o bin/custodian ./cmd/custodian

tidy:
	go mod tidy

run: build
	CLI_BINARIES_DIR=$${CLI_BINARIES_DIR:-./static/cli} ./bin/custodian serve
