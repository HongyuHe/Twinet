#!/usr/bin/env bash
# Verify that two builds of one tree produce byte-identical binaries.
#
# Build metadata used to carry the wall clock, so this check could never have
# passed: every build differed from the last one for no reason anybody could
# inspect, and a release's provenance could only be asserted. The stamped date
# is now derived from SOURCE_DATE_EPOCH or the commit, which leaves the source
# digest as the thing that actually identifies what was built.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

work=$(mktemp -d "$repo_root/.reproducible-build.XXXXXX")
trap 'rm -rf "$work"' EXIT

build() {
    make --no-print-directory build BIN="$1" >"$work/build.log" 2>&1 || {
        cat "$work/build.log" >&2
        printf 'test_reproducible_build: build into %s failed\n' "$1" >&2
        exit 1
    }
}

build "$work/first"
# A different wall clock, working directory and timezone between the two runs
# is exactly the difference a build must not record.
sleep 1
TZ=Australia/Eucla build "$work/second"

status=0
for binary in "$work"/first/*; do
    name=$(basename "$binary")
    other="$work/second/$name"
    [ -f "$other" ] || {
        printf 'test_reproducible_build: %s was not built the second time\n' "$name" >&2
        status=1
        continue
    }
    first_hash=$(sha256sum "$binary" | cut -d' ' -f1)
    second_hash=$(sha256sum "$other" | cut -d' ' -f1)
    if [ "$first_hash" != "$second_hash" ]; then
        printf 'test_reproducible_build: %s differs between builds (%s vs %s)\n' \
            "$name" "$first_hash" "$second_hash" >&2
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    exit "$status"
fi

# The stamped date must be the source's, not the build's. A tree whose commit
# predates today cannot honestly claim to have been built in the future.
stamped=$("$work/first/twinet" version)
printf '%s\n' "$stamped" | grep -Eq 'source date [0-9]{4}-[0-9]{2}-[0-9]{2}T' || {
    printf 'test_reproducible_build: version does not report a source date: %s\n' "$stamped" >&2
    exit 1
}

epoch_date=$(SOURCE_DATE_EPOCH=1000000000 make --no-print-directory -n build 2>/dev/null |
    grep -o 'cli\.Date=[^ ]*' | head -1 | cut -d= -f2)
[ "$epoch_date" = "2001-09-09T01:46:40Z" ] || {
    printf 'test_reproducible_build: SOURCE_DATE_EPOCH was not honoured (got %q)\n' "$epoch_date" >&2
    exit 1
}

printf 'test_reproducible_build: ok\n'
