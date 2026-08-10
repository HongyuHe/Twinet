#!/bin/sh
# Twinet container entrypoint.
#
# Its only job is to make the container a well-behaved PID-1 citizen and then
# get out of the way. Configuration is pushed by the control plane after the
# container is wired, because a router cannot usefully start routing before its
# interfaces exist.
set -e

# Loopback is always up: routing protocols and iBGP sessions depend on it, and
# leaving it down produces failures that look like configuration errors.
ip link set lo up 2>/dev/null || true

# Some images ship a stale pid file if the container was committed while
# running; clear it so the daemon does not refuse to start.
rm -f /var/run/frr/*.pid 2>/dev/null || true

exec "$@"
