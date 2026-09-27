#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
docker_cli=(docker)
if ! docker info >/dev/null 2>&1; then docker_cli=(sudo docker); fi
CGO_ENABLED=0 go build -o images/router/twinet-dhcpd ./cmd/twinet-dhcpd
CGO_ENABLED=0 go build -o images/router/twinet-mcast ./cmd/twinet-mcast
"${docker_cli[@]}" build -t twinet/router:msc-base images/router
"${docker_cli[@]}" build -t twinet/switch:msc-base images/switch
"${docker_cli[@]}" build -t hyhe/twinet-msc-router:tdn images/msc-router
"${docker_cli[@]}" build -t hyhe/twinet-msc-switch:tdn images/msc-switch
