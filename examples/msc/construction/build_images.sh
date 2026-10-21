#!/usr/bin/env bash
set -euo pipefail
TWINET_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PUBLIC_RECORD_DIR="${1:-$TWINET_ROOT/../exports/native-image-build}"
mkdir -p "$PUBLIC_RECORD_DIR"
cd "$TWINET_ROOT"
date -u +%FT%TZ > "$PUBLIC_RECORD_DIR/started_at.txt"
go version > "$PUBLIC_RECORD_DIR/go-version.txt"
CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-amd64}" go build -trimpath -o images/router/twinet-dhcpd ./cmd/twinet-dhcpd
CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-amd64}" go build -trimpath -o images/router/twinet-mcast ./cmd/twinet-mcast
docker build --progress=plain -t twinet-msc:construction-v2 images/msc
docker build --progress=plain -t twinet/router:msc-base images/router
docker build --progress=plain -t twinet/switch:msc-base images/switch
docker build --progress=plain --build-arg BASE=twinet/router:msc-base -t twinet-msc-router:construction-v2 images/msc-router
docker build --progress=plain --build-arg BASE=twinet/switch:msc-base -t twinet-msc-switch:construction-v2 images/msc-switch
sha256sum go.mod go.sum images/router/twinet-dhcpd images/router/twinet-mcast images/msc/Dockerfile images/router/Dockerfile images/switch/Dockerfile images/msc-router/Dockerfile images/msc-switch/Dockerfile > "$PUBLIC_RECORD_DIR/source-and-binary-sha256.txt"
docker image inspect --format '{{.Id}} {{json .RepoTags}} {{json .RepoDigests}}' twinet-msc:construction-v2 twinet-msc-router:construction-v2 twinet-msc-switch:construction-v2 > "$PUBLIC_RECORD_DIR/image-identities.txt"
docker run --rm twinet-msc:construction-v2 dpkg-query -W > "$PUBLIC_RECORD_DIR/msc-packages.txt"
docker run --rm --entrypoint apk twinet-msc-router:construction-v2 info -v > "$PUBLIC_RECORD_DIR/router-packages.txt"
docker run --rm --entrypoint apk twinet-msc-switch:construction-v2 info -v > "$PUBLIC_RECORD_DIR/switch-packages.txt"
date -u +%FT%TZ > "$PUBLIC_RECORD_DIR/ended_at.txt"
