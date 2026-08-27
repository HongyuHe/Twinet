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
RUNTIME=""
RUNTIME_SOCKET=""
EXPECTED_COMMIT=""
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --pki) PKI="$2"; shift 2 ;;
        --bind-underlay) BIND_UNDERLAY=1; shift ;;
        --runtime) RUNTIME="$2"; shift 2 ;;
        --runtime-socket) RUNTIME_SOCKET="$2"; shift 2 ;;
        --expect-commit) EXPECTED_COMMIT="$2"; shift 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    echo "usage: $0 [--pki DIR] [--bind-underlay] [--runtime docker|podman|containerd] [--runtime-socket ENDPOINT] [--expect-commit SHA] <node> [node...]" >&2
    exit 2
fi

# A rollout is a release boundary, not a development build. Running this
# script by relative path from the wrong checkout still produces a perfectly
# executable agent and still passes the checksum check below -- on every node,
# consistently wrong. Refuse dirty source unconditionally, and let release
# automation bind the checkout to an explicit commit when it has one.
if ! SOURCE_COMMIT=$(git rev-parse --verify HEAD 2>/dev/null); then
    echo "agent rollout requires a Git checkout with a committed HEAD" >&2
    exit 2
fi
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "refusing agent rollout from a dirty worktree at $SOURCE_COMMIT" >&2
    echo "Commit the exact release candidate and retry; the installed binary must be reproducible." >&2
    exit 2
fi
if [ -n "$EXPECTED_COMMIT" ]; then
    if ! RESOLVED_EXPECTED=$(git rev-parse --verify "${EXPECTED_COMMIT}^{commit}" 2>/dev/null); then
        echo "--expect-commit does not resolve to a commit in this checkout: $EXPECTED_COMMIT" >&2
        exit 2
    fi
    if [ "$SOURCE_COMMIT" != "$RESOLVED_EXPECTED" ]; then
        echo "refusing agent rollout from $SOURCE_COMMIT; expected $RESOLVED_EXPECTED" >&2
        exit 2
    fi
fi
echo "rolling out committed source $SOURCE_COMMIT"

case "$RUNTIME" in
    "")
        [ -z "$RUNTIME_SOCKET" ] || {
            echo "--runtime-socket requires --runtime" >&2
            exit 2
        }
        ;;
    docker)
        : "${RUNTIME_SOCKET:=unix:///var/run/docker.sock}"
        ;;
    podman)
        : "${RUNTIME_SOCKET:=unix:///run/podman/podman.sock}"
        ;;
    containerd)
        : "${RUNTIME_SOCKET:=unix:///run/containerd/containerd.sock}"
        ;;
    *)
        echo "unsupported runtime $RUNTIME (docker, podman, containerd)" >&2
        exit 2
        ;;
esac
case "$RUNTIME_SOCKET" in
    *[[:space:]]*) echo "runtime socket must not contain whitespace" >&2; exit 2 ;;
esac

# One root network namespace has one owner. A second agent may use another API
# port and another containerd metadata namespace, but its veths, bridges and
# VXLANs still live in the same kernel namespace. A stale acceptance agent did
# exactly that and repeatedly removed the active cluster's links by matching
# deterministic VNIs. Refuse before stopping or replacing any healthy agent.
for n in "${NODES[@]}"; do
    if [ "$n" = "$(hostname -s)" ]; then
        agents=$(ps -eo pid=,args=)
    else
        agents=$(sudo ssh -o BatchMode=yes "$n" 'ps -eo pid=,args=')
    fi
    agents=$(printf '%s\n' "$agents" | awk '$2 ~ /\/twinetd[^/ ]*$/ {print}')
    bad=$(printf '%s\n' "$agents" | awk 'NF && $2 != "/usr/local/bin/twinetd" {print}')
    primary_count=$(printf '%s\n' "$agents" |
        awk '$2 == "/usr/local/bin/twinetd" {n++} END {print n+0}')
    if [ -n "$bad" ] || [ "$primary_count" -gt 1 ]; then
        echo "$n: refusing rollout because another Twinet agent shares the host network namespace:" >&2
        printf '%s\n' "$agents" >&2
        echo "Stop and disable every stale/alternate twinetd service first; runtime namespaces do not isolate host links." >&2
        exit 1
    fi
done

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
        peer_cert="${PKI}/${n}_peer_cert.pem"
        peer_key="${PKI}/${n}_peer_key.pem"
        ca="${PKI}/ca_cert.pem"
        for f in "$cert" "$key" "$peer_cert" "$peer_key" "$ca"; do
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
            sudo install -m 0644 "$peer_cert" /etc/twinet/pki/peer_cert.pem
            sudo install -m 0600 "$peer_key" /etc/twinet/pki/peer_key.pem
            sudo install -m 0644 "$ca" /etc/twinet/pki/ca_cert.pem
        else
            sudo ssh -o BatchMode=yes "$n" 'install -d -m 0700 /etc/twinet/pki'
            sudo scp -q "$cert" "root@$n:/etc/twinet/pki/server_cert.pem"
            sudo scp -q "$key" "root@$n:/etc/twinet/pki/server_key.pem"
            sudo scp -q "$peer_cert" "root@$n:/etc/twinet/pki/peer_cert.pem"
            sudo scp -q "$peer_key" "root@$n:/etc/twinet/pki/peer_key.pem"
            sudo scp -q "$ca" "root@$n:/etc/twinet/pki/ca_cert.pem"
            sudo ssh -o BatchMode=yes "$n" 'chmod 0600 /etc/twinet/pki/server_key.pem /etc/twinet/pki/peer_key.pem'
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
        strip_re='s# -tls-cert [^ ]*##; s# -tls-key [^ ]*##; s# -client-ca [^ ]*##; s# -peer-tls-cert [^ ]*##; s# -peer-tls-key [^ ]*##; s# -legacy-peer-cert-until [^ ]*##'
        add=' -tls-cert /etc/twinet/pki/server_cert.pem -tls-key /etc/twinet/pki/server_key.pem -client-ca /etc/twinet/pki/ca_cert.pem -peer-tls-cert /etc/twinet/pki/peer_cert.pem -peer-tls-key /etc/twinet/pki/peer_key.pem'
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

    if [ -n "$RUNTIME" ]; then
        runtime_strip='s# -runtime [^ ]*##; s# -runtime-socket [^ ]*##; s# -runtime-namespace [^ ]*##'
        runtime_add=" -runtime $RUNTIME -runtime-socket $RUNTIME_SOCKET"
        runtime_service="docker.service"
        if [ "$RUNTIME" = "podman" ]; then
            runtime_service="podman.socket"
        elif [ "$RUNTIME" = "containerd" ]; then
            runtime_service="containerd.service"
            runtime_add="$runtime_add -runtime-namespace twinet-$n"
        fi
        runtime_cmd="sed -i -e '$runtime_strip' -e '\#^ExecStart=#s#\$#$runtime_add#' /etc/systemd/system/twinetd.service"
        runtime_cmd="$runtime_cmd; sed -i -e 's#^After=.*#After=$runtime_service#' -e 's#^Requires=.*#Requires=$runtime_service#' /etc/systemd/system/twinetd.service"
        unit_cmd="$unit_cmd; $runtime_cmd"
    fi

    if [ "$n" = "$(hostname -s)" ]; then
        sudo systemctl stop twinetd || true
        sudo install -m 0755 bin/twinetd /usr/local/bin/twinetd
        sudo install -m 0755 bin/twinet-init /usr/local/bin/twinet-init
        install_tls local
        sudo sh -c "$unit_cmd"
        sudo systemctl daemon-reload
        sudo systemctl start twinetd
    else
        # scp opens its destination in place. That fails for twinet-init while
        # any container still bind-mounts the old inode, and can leave twinetd
        # truncated if transport fails mid-copy. Stage both files beside their
        # destinations, then replace each inode atomically.
        stage="/usr/local/bin/.twinet-rollout-$$"
        if ! sudo scp -q bin/twinetd "root@$n:${stage}-agent" ||
            ! sudo scp -q bin/twinet-init "root@$n:${stage}-init"; then
            sudo ssh -o BatchMode=yes "$n" "rm -f '${stage}-agent' '${stage}-init'"
            exit 1
        fi
        install_tls remote
        sudo ssh -o BatchMode=yes "$n" \
            "systemctl stop twinetd || true; chmod 0755 '${stage}-agent' '${stage}-init'; \
             mv -f '${stage}-agent' /usr/local/bin/twinetd; \
             mv -f '${stage}-init' /usr/local/bin/twinet-init; \
             $unit_cmd; systemctl daemon-reload; systemctl start twinetd"
    fi

    got=$(if [ "$n" = "$(hostname -s)" ]; then md5sum /usr/local/bin/twinetd; else sudo ssh -o BatchMode=yes "$n" 'md5sum /usr/local/bin/twinetd'; fi | cut -d' ' -f1)
    if [ "$got" != "$WANT" ]; then
        echo "$n: agent is ${got}, expected ${WANT}" >&2
        exit 1
    fi
    echo "$n: agent ${got} running"
done
