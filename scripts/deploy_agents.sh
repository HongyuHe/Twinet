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

# --pki <dir> installs the mutual-TLS material alongside the agent and switches
# it off plain HTTP. The agent API creates privileged containers and rewires
# hosts, so a shared bearer token is not an acceptable resting state; this is
# how a cluster stops using one.
PKI=""
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --pki) PKI="$2"; shift 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    echo "usage: $0 <node> [node...]" >&2
    exit 2
fi

make build
WANT=$(md5sum bin/twinetd | cut -d' ' -f1)
echo "built twinetd ${WANT}"

for n in "${NODES[@]}"; do
    if [ -n "$PKI" ]; then
        cert="${PKI}/${n}_server_cert.pem"
        key="${PKI}/${n}_server_key.pem"
        ca="${PKI}/ca_cert.pem"
        for f in "$cert" "$key" "$ca"; do
            [ -f "$f" ] || { echo "missing $f; run 'twinet node pki' first" >&2; exit 1; }
        done
    fi

    install_tls() {
        local target="$1"
        if [ -z "$PKI" ]; then return 0; fi
        if [ "$target" = "local" ]; then
            sudo install -d -m 0700 /etc/twinet/pki
            sudo install -m 0644 "$cert" /etc/twinet/pki/server_cert.pem
            sudo install -m 0600 "$key" /etc/twinet/pki/server_key.pem
            sudo install -m 0644 "$ca" /etc/twinet/pki/ca_cert.pem
        else
            sudo ssh -o BatchMode=yes "$n" 'install -d -m 0700 /etc/twinet/pki'
            sudo scp -q "$cert" "root@$n:/etc/twinet/pki/server_cert.pem"
            sudo scp -q "$key" "root@$n:/etc/twinet/pki/server_key.pem"
            sudo scp -q "$ca" "root@$n:/etc/twinet/pki/ca_cert.pem"
            sudo ssh -o BatchMode=yes "$n" 'chmod 0600 /etc/twinet/pki/server_key.pem'
        fi
    }

    # The TLS flags are appended to whatever ExecStart already says, and any
    # previous ones stripped first so re-running is idempotent. Rewriting the
    # line wholesale would be simpler and would silently drop the flags already
    # there -- -underlay-dev among them, whose absence surfaces much later as a
    # tunnel sourced from the wrong interface.
    strip_re='s# -tls-cert [^ ]*##; s# -tls-key [^ ]*##; s# -client-ca [^ ]*##'
    if [ -n "$PKI" ]; then
        add=' -tls-cert /etc/twinet/pki/server_cert.pem -tls-key /etc/twinet/pki/server_key.pem -client-ca /etc/twinet/pki/ca_cert.pem'
    else
        add=''
    fi
    unit_cmd="sed -i -e '${strip_re}' -e '\#^ExecStart=#s#\$#${add}#' /etc/systemd/system/twinetd.service"

    if [ "$n" = "$(hostname -s)" ]; then
        sudo systemctl stop twinetd || true
        sudo install -m 0755 bin/twinetd /usr/local/bin/twinetd
        install_tls local
        sudo sh -c "$unit_cmd"
        sudo systemctl daemon-reload
        sudo systemctl start twinetd
    else
        sudo ssh -o BatchMode=yes "$n" 'systemctl stop twinetd || true; rm -f /usr/local/bin/twinetd'
        sudo scp -q bin/twinetd "root@$n:/usr/local/bin/twinetd"
        install_tls remote
        sudo ssh -o BatchMode=yes "$n" "chmod 0755 /usr/local/bin/twinetd; $unit_cmd; systemctl daemon-reload; systemctl start twinetd"
    fi

    got=$(if [ "$n" = "$(hostname -s)" ]; then md5sum /usr/local/bin/twinetd; else sudo ssh -o BatchMode=yes "$n" 'md5sum /usr/local/bin/twinetd'; fi | cut -d' ' -f1)
    if [ "$got" != "$WANT" ]; then
        echo "$n: agent is ${got}, expected ${WANT}" >&2
        exit 1
    fi
    echo "$n: agent ${got} running"
done
