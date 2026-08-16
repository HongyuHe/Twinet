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
#
# --bind-underlay narrows the agent's listening address from every interface to
# the cluster fabric it already knows about. The API is mutually authenticated,
# so a stranger who reaches the port cannot do anything with it -- but a port
# that is open to the internet collects scans, and there is no reason for this
# one to answer anybody outside the fabric.
PKI=""
BIND_UNDERLAY=""
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --pki) PKI="$2"; shift 2 ;;
        --bind-underlay) BIND_UNDERLAY=1; shift ;;
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
    # An existing unit that carries the token in plain sight is repaired.
    #
    # A systemd unit is world-readable, and `Environment=TWINET_TOKEN=...` put
    # the cluster secret where every account on the node could read it --
    # including the unprivileged one an evaluated RCA agent runs as, which could
    # then discard its own read-only credential and act as the controller. The
    # token is moved into a root-only file and the unit is left pointing at it.
    # shellcheck disable=SC2016  # runs on the far node, expands there
    move_secret='u=/etc/systemd/system/twinetd.service
if grep -q "^Environment=TWINET_TOKEN=" "$u"; then
  install -d -m 0700 /etc/twinet
  umask 077
  sed -n "s#^Environment=\(TWINET_TOKEN=.*\)#\1#p" "$u" > /etc/twinet/agent.env
  chmod 0600 /etc/twinet/agent.env
  sed -i "/^Environment=TWINET_TOKEN=/d" "$u"
  grep -q "^EnvironmentFile=/etc/twinet/agent.env" "$u" || \
    sed -i "/^Type=simple/a EnvironmentFile=/etc/twinet/agent.env" "$u"
fi
chmod 0644 "$u"'

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
    # Without --pki the unit is left exactly as it is. Rewriting it to remove
    # the TLS flags would mean that rolling out a new binary silently downgrades
    # a mutually authenticated cluster to a bearer token over plain HTTP -- an
    # upgrade that takes the security away, with nothing in its output saying
    # so. Removing TLS has to be asked for.
    # An existing unit that carries the token in plain sight is repaired.
    #
    # A systemd unit is world-readable, and `Environment=TWINET_TOKEN=...` put
    # the cluster secret where every account on the node could read it --
    # including the unprivileged one an evaluated RCA agent runs as, which could
    # then discard its own read-only credential and act as the controller. The
    # token is moved into a root-only file and the unit is left pointing at it.
    # shellcheck disable=SC2016  # runs on the far node, expands there
    move_secret='u=/etc/systemd/system/twinetd.service
if grep -q "^Environment=TWINET_TOKEN=" "$u"; then
  install -d -m 0700 /etc/twinet
  umask 077
  sed -n "s#^Environment=\(TWINET_TOKEN=.*\)#\1#p" "$u" > /etc/twinet/agent.env
  chmod 0600 /etc/twinet/agent.env
  sed -i "/^Environment=TWINET_TOKEN=/d" "$u"
  grep -q "^EnvironmentFile=/etc/twinet/agent.env" "$u" || \
    sed -i "/^Type=simple/a EnvironmentFile=/etc/twinet/agent.env" "$u"
fi
chmod 0644 "$u"'

    if [ -n "$PKI" ]; then
        strip_re='s# -tls-cert [^ ]*##; s# -tls-key [^ ]*##; s# -client-ca [^ ]*##'
        add=' -tls-cert /etc/twinet/pki/server_cert.pem -tls-key /etc/twinet/pki/server_key.pem -client-ca /etc/twinet/pki/ca_cert.pem'
        unit_cmd="sed -i -e '${strip_re}' -e '\#^ExecStart=#s#\$#${add}#' /etc/systemd/system/twinetd.service"
    else
        unit_cmd="true"
    fi
    unit_cmd="$move_secret; $unit_cmd"

    # The address the agent already announces as its own is the one it should
    # answer on. Taken from -underlay-ip in the unit rather than from an
    # argument, so it cannot disagree with what the rest of the cluster dials.
    if [ -n "$BIND_UNDERLAY" ]; then
        # shellcheck disable=SC2016  # runs on the far node, expands there
        bind_cmd='u=/etc/systemd/system/twinetd.service; ip=$(sed -n "s#.*-underlay-ip \([^ ]*\).*#\1#p" $u); port=$(sed -n "s#.*-listen [^ ]*:\([0-9]*\).*#\1#p" $u); if [ -n "$ip" ] && [ -n "$port" ]; then sed -i "s#-listen [^ ]*#-listen $ip:$port#" $u; fi'
        unit_cmd="$unit_cmd; $bind_cmd"
    fi

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
