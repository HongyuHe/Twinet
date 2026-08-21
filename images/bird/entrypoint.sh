#!/bin/sh
# BIRD is started only after Twinet has wired interfaces and copied the
# generated configuration. PID 1 remains the supplied command so Docker can
# stop the teaching device cleanly.
set -eu

ip link set lo up 2>/dev/null || true
mkdir -p /etc/bird /etc/twinet /run

exec "$@"
