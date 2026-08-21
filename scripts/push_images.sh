#!/usr/bin/env bash
# Push immutable image tags, verify remote/local manifest identity, then move
# the requested channel tag. The channel can never move after a failed remote
# verification because its push is deliberately last.
set -euo pipefail

if [ "$#" -lt 6 ]; then
    echo "usage: $0 <registry> <channel-tag> <immutable-tag> <image>... -- <docker-command> [docker-args...]" >&2
    exit 2
fi

registry=$1
channel_tag=$2
immutable_tag=$3
shift 3

images=()
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    images+=("$1")
    shift
done
if [ "$#" -eq 0 ] || [ "$1" != "--" ] || [ "${#images[@]}" -eq 0 ]; then
    echo "push_images needs at least one image followed by -- and a Docker command" >&2
    exit 2
fi
shift

if [ "$#" -eq 0 ]; then
    echo "push_images needs a Docker command after --" >&2
    exit 2
fi

local_image_digest() {
    local reference=$1
    shift
    local digest
    digest=$("$@" image inspect "$reference" --format '{{.Id}}' | tr -d '[:space:]')
    if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "local image $reference has no digest" >&2
        return 1
    fi
    printf '%s\n' "$digest"
}

remote_exists() {
    local reference=$1
    shift
    local output
    if output=$("$@" buildx imagetools inspect "$reference" 2>&1); then
        return 0
    fi
    if grep -Eqi 'not found|manifest unknown|name unknown' <<<"$output"; then
        return 1
    fi
    echo "could not determine whether immutable tag $reference exists remotely: $output" >&2
    return 2
}

for image in "${images[@]}"; do
    immutable="$registry/twinet-$image:$immutable_tag"
    channel="$registry/twinet-$image:$channel_tag"
    local_digest_value=$(local_image_digest "$immutable" "$@")
    if remote_exists "$immutable" "$@"; then
        remote=$(bash scripts/remote_image_digest.sh "$immutable" "$@")
        if [ "$remote" != "$local_digest_value" ]; then
            echo "existing immutable tag $immutable has digest $remote, not local $local_digest_value; refusing to overwrite it" >&2
            exit 1
        fi
        echo "immutable $immutable already verifies; retry will not rebuild or overwrite it"
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            exit "$status"
        fi
        echo "pushing immutable $immutable before moving $channel"
        "$@" push -q "$immutable" >/dev/null
        remote=$(bash scripts/remote_image_digest.sh "$immutable" "$@")
        if [ "$remote" != "$local_digest_value" ]; then
            echo "remote digest $remote for $immutable does not equal local digest $local_digest_value; refusing to move $channel" >&2
            exit 1
        fi
    fi

    "$@" push -q "$channel" >/dev/null
done
