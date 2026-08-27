#!/usr/bin/env bash
set -euo pipefail

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/scripts"
cp "$(dirname "$0")/deploy_agents.sh" "$ROOT/scripts/"
printf 'first\n' > "$ROOT/README"

git -C "$ROOT" init -q
git -C "$ROOT" config user.name test
git -C "$ROOT" config user.email test@example.invalid
git -C "$ROOT" add README scripts/deploy_agents.sh
git -C "$ROOT" commit -qm first
FIRST=$(git -C "$ROOT" rev-parse HEAD)

printf 'second\n' >> "$ROOT/README"
git -C "$ROOT" add README
git -C "$ROOT" commit -qm second
SECOND=$(git -C "$ROOT" rev-parse HEAD)

set +e
OUTPUT=$(cd "$ROOT" && ./scripts/deploy_agents.sh --expect-commit "$FIRST" node-0 2>&1)
STATUS=$?
set -e
test "$STATUS" -eq 2
printf '%s\n' "$OUTPUT" | grep -q "refusing agent rollout from $SECOND; expected $FIRST"

printf 'dirty\n' >> "$ROOT/README"
set +e
OUTPUT=$(cd "$ROOT" && ./scripts/deploy_agents.sh --expect-commit "$SECOND" node-0 2>&1)
STATUS=$?
set -e
test "$STATUS" -eq 2
printf '%s\n' "$OUTPUT" | grep -q "refusing agent rollout from a dirty worktree"

echo "deploy_agents source guards passed"
