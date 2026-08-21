#!/usr/bin/env bash
# Print the registry manifest/index digest for an image reference.
#
# Buildx changed its top-level inspect template input in Docker 29: `.Digest`
# no longer exists, while `.Manifest.Digest` does. Prefer that structured
# field, then use older/template-JSON and standard-output fallbacks with strict
# digest validation instead of scraping arbitrary prose.
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <image-reference> <docker-command> [docker-args...]" >&2
    exit 2
fi

reference=$1
shift

is_digest() {
    [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

last_error=""
for template in '{{.Manifest.Digest}}' '{{.Digest}}'; do
    if output=$("$@" buildx imagetools inspect "$reference" --format "$template" 2>&1); then
        output=$(printf '%s' "$output" | tr -d '[:space:]')
        if is_digest "$output"; then
            printf '%s\n' "$output"
            exit 0
        fi
        last_error="template $template returned $output"
    else
        last_error="template $template failed: $output"
    fi
done

if output=$("$@" buildx imagetools inspect "$reference" --format '{{json .Manifest}}' 2>&1); then
    if digest=$(printf '%s' "$output" | python3 -c '
import json
import re
import sys

value = json.load(sys.stdin)
digest = value.get("digest", "")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit(1)
print(digest)
' 2>/dev/null); then
        printf '%s\n' "$digest"
        exit 0
    fi
    last_error="manifest JSON had no valid digest"
else
    last_error="manifest JSON failed: $output"
fi

# Older buildx releases may not expose a JSON template value. Its standard
# output has a stable, anchored Digest line; accept only that exact shape.
if output=$("$@" buildx imagetools inspect "$reference" 2>&1); then
    digest=$(printf '%s\n' "$output" | awk '
        /^Digest:[[:space:]]*sha256:[0-9a-f]{64}[[:space:]]*$/ {
            sub(/^Digest:[[:space:]]*/, "")
            sub(/[[:space:]]*$/, "")
            print
            exit
        }')
    if is_digest "$digest"; then
        printf '%s\n' "$digest"
        exit 0
    fi
    last_error="standard output contained no anchored Digest line"
else
    last_error="standard inspect failed: $output"
fi

echo "could not extract a remote manifest digest for $reference: $last_error" >&2
exit 1
