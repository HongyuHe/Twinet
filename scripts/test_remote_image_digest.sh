#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/.test-remote-image-digest-$$"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"

fake="$work/docker"
cat > "$fake" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
format=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--format" ]; then
        format=$2
        break
    fi
    shift
done
case "$format" in
    '{{.Manifest.Digest}}')
        if [ "${FAKE_JSON_ONLY:-}" = "1" ]; then
            echo 'template: manifest field unavailable' >&2
            exit 1
        fi
        echo 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        ;;
    '{{.Digest}}')
        echo 'template: Docker 29/buildx 0.36 cannot evaluate field Digest in type imagetools.tplInput' >&2
        exit 1
        ;;
    '{{json .Manifest}}')
        echo '{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        ;;
    *)
        echo 'Name: example'
        echo 'Digest:    sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        ;;
esac
FAKE
chmod +x "$fake"

want='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
got=$(bash "$root/scripts/remote_image_digest.sh" example/router:v1 "$fake")
[ "$got" = "$want" ]

got=$(FAKE_JSON_ONLY=1 bash "$root/scripts/remote_image_digest.sh" example/router:v1 "$fake")
[ "$got" = "$want" ]

echo "remote image digest compatibility tests passed"
