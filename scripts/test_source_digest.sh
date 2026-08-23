#!/usr/bin/env bash
# Verify that only declared grader build inputs participate in SOURCE_DIGEST.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
fixture_root="$repo_root/scripts/testdata/source_digest"

digest() {
    python3 "$repo_root/scripts/source_digest.py" --root "$1"
}

base=$(digest "$fixture_root/base")
base_again=$(digest "$fixture_root/base")
docs_only=$(digest "$fixture_root/docs_only")
source_changed=$(digest "$fixture_root/source_changed")
module_changed=$(digest "$fixture_root/module_changed")
sum_changed=$(digest "$fixture_root/sum_changed")
# The fixture roots deliberately have no Git metadata: this extra .go file
# models a compiled source file that is present but untracked.
untracked_go=$(digest "$fixture_root/untracked_go")

printf '%s\n' "$base" | grep -Eq '^[0-9a-f]{64}$' || {
    printf 'test_source_digest: invalid SHA-256 digest %q\n' "$base" >&2
    exit 1
}
[ "$base" = "$base_again" ] || {
    printf 'test_source_digest: digest was not deterministic\n' >&2
    exit 1
}
[ "$base" = "$docs_only" ] || {
    printf 'test_source_digest: documentation changed the source digest\n' >&2
    exit 1
}
[ "$base" != "$source_changed" ] || {
    printf 'test_source_digest: Go source change did not change the source digest\n' >&2
    exit 1
}
[ "$base" != "$module_changed" ] || {
    printf 'test_source_digest: go.mod change did not change the source digest\n' >&2
    exit 1
}
[ "$base" != "$sum_changed" ] || {
    printf 'test_source_digest: go.sum change did not change the source digest\n' >&2
    exit 1
}
[ "$base" != "$untracked_go" ] || {
    printf 'test_source_digest: untracked Go source did not change the source digest\n' >&2
    exit 1
}
