#!/usr/bin/env bash
# Rebuild twinetd and roll it out to every node, verifying that each node ends
# up with exactly the binary that was just built.
#
# The verification matters: a stale agent silently renders old configuration,
# which looks like a bug in the network rather than a stale deployment. This
# script exists because that happened once.
export PATH="$PATH:/usr/local/go/bin"
set -euo pipefail

cd "$(dirname "$0")/.."
NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    echo "usage: $0 <node> [node...]" >&2
    exit 2
fi

make build
WANT=$(md5sum bin/twinetd | cut -d' ' -f1)
echo "built twinetd ${WANT}"

for n in "${NODES[@]}"; do
    if [ "$n" = "$(hostname -s)" ]; then
        sudo systemctl stop twinetd || true
        sudo install -m 0755 bin/twinetd /usr/local/bin/twinetd
        sudo systemctl start twinetd
    else
        sudo ssh -o BatchMode=yes "$n" 'systemctl stop twinetd || true; rm -f /usr/local/bin/twinetd'
        sudo scp -q bin/twinetd "root@$n:/usr/local/bin/twinetd"
        sudo ssh -o BatchMode=yes "$n" 'chmod 0755 /usr/local/bin/twinetd; systemctl start twinetd'
    fi

    got=$(if [ "$n" = "$(hostname -s)" ]; then md5sum /usr/local/bin/twinetd; else sudo ssh -o BatchMode=yes "$n" 'md5sum /usr/local/bin/twinetd'; fi | cut -d' ' -f1)
    if [ "$got" != "$WANT" ]; then
        echo "$n: agent is ${got}, expected ${WANT}" >&2
        exit 1
    fi
    echo "$n: agent ${got} running"
done
