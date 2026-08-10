#!/bin/sh
set -e
ip link set lo up 2>/dev/null || true
exec "$@"
