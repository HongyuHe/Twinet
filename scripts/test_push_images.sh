#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/.test-push-images-$$"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"

log="$work/calls"
fake="$work/docker"
cat > "$fake" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

log=${FAKE_DOCKER_LOG:?}
printf '%s\n' "$*" >> "$log"
if [ "$1" = "push" ]; then
    exit 0
fi
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
    format=""
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "--format" ]; then
            format=$2
            break
        fi
        shift
    done
    if [ "$format" = '{{.Id}}' ]; then
        echo 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    else
        echo '["registry/twinet-router@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]'
    fi
    exit 0
fi
if [ "$1" = "buildx" ] && [ "$2" = "imagetools" ]; then
    if [ "${FAKE_REMOTE_FAIL:-}" = "1" ]; then
        echo 'remote lookup failed' >&2
        exit 1
    fi
    format=""
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "--format" ]; then
            format=$2
            break
        fi
        shift
    done
    if [ -z "$format" ] && [ "${FAKE_REMOTE_ABSENT:-}" = "1" ]; then
        echo 'manifest unknown' >&2
        exit 1
    fi
    case "$format" in
        '{{.Manifest.Digest}}')
            if [ "${FAKE_REMOTE_MISMATCH:-}" = "1" ]; then
                echo 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
            else
                echo 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            fi
            ;;
        '{{.Digest}}') exit 1 ;;
        '{{json .Manifest}}') echo '{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' ;;
        *) echo 'Digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
    esac
    exit 0
fi
echo "unexpected fake Docker command: $*" >&2
exit 1
FAKE
chmod +x "$fake"

if FAKE_DOCKER_LOG="$log" FAKE_REMOTE_FAIL=1 \
    bash "$root/scripts/push_images.sh" registry channel immutable router -- "$fake"; then
    echo "push_images unexpectedly moved a channel after remote verification failure" >&2
    exit 1
fi
if grep -Fx 'push -q registry/twinet-router:channel' "$log" >/dev/null; then
    echo "channel moved after remote verification failed" >&2
    exit 1
fi

: > "$log"
if FAKE_DOCKER_LOG="$log" FAKE_REMOTE_MISMATCH=1 \
    bash "$root/scripts/push_images.sh" registry channel immutable router -- "$fake"; then
    echo "push_images accepted a remote/local digest mismatch" >&2
    exit 1
fi
if grep -Fx 'push -q registry/twinet-router:channel' "$log" >/dev/null; then
    echo "channel moved after digest equality verification failed" >&2
    exit 1
fi

: > "$log"
FAKE_DOCKER_LOG="$log" FAKE_REMOTE_ABSENT=1 \
    bash "$root/scripts/push_images.sh" registry channel immutable router -- "$fake"
grep -Fx 'push -q registry/twinet-router:immutable' "$log" >/dev/null
grep -Fx 'push -q registry/twinet-router:channel' "$log" >/dev/null

: > "$log"
FAKE_DOCKER_LOG="$log" bash "$root/scripts/push_images.sh" registry channel immutable router -- "$fake"
if grep -Fx 'push -q registry/twinet-router:immutable' "$log" >/dev/null; then
    echo "idempotent retry overwrote an existing immutable tag" >&2
    exit 1
fi
grep -Fx 'push -q registry/twinet-router:channel' "$log" >/dev/null

echo "push image ordering tests passed"
