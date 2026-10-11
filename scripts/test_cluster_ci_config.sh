#!/usr/bin/env bash
# Exercise dispatch and automatic-run decisions without a runner or cluster.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT

required=(
    TWINET_TOKEN
    TWINET_CHAOS_AGENT_RESTART_CMD
    TWINET_CHAOS_AGENT_STOP_CMD
    TWINET_CHAOS_NODE_REBOOT_CMD
    TWINET_CHAOS_UNDERLAY_DOWN_CMD
    TWINET_CHAOS_UNDERLAY_UP_CMD
    TWINET_CHAOS_MIGRATION_MANIFEST
)
configured=()
for name in "${required[@]}"; do
    configured+=("$name=never-log-or-execute-config")
done

run_case() {
    local expected_status=$1 expected_enabled=$2 expected_message=$3
    shift 3
    local status=0
    : > "$scratch_dir/output"
    : > "$scratch_dir/summary"
    env -i PATH="$PATH" GITHUB_OUTPUT="$scratch_dir/output" \
        GITHUB_STEP_SUMMARY="$scratch_dir/summary" "$@" \
        bash "$repo_root/scripts/check_cluster_ci_config.sh" \
        > "$scratch_dir/log" 2>&1 || status=$?
    if [ "$status" -ne "$expected_status" ] ||
        [ "$(cat "$scratch_dir/output")" != "enabled=$expected_enabled" ] ||
        ! grep -Fq -e "$expected_message" "$scratch_dir/summary" ||
        ! cmp -s "$scratch_dir/summary" "$scratch_dir/log"; then
        printf 'cluster CI preflight returned the wrong decision or explanation\n' >&2
        cat "$scratch_dir/log" >&2
        exit 1
    fi
    if grep -Fq 'never-log-or-execute-config' "$scratch_dir/log"; then
        printf 'cluster CI preflight disclosed a configuration value\n' >&2
        exit 1
    fi
}

for event in push schedule; do
    run_case 0 false 'No benchmark, chaos, or soak tests ran' GITHUB_EVENT_NAME="$event"
    run_case 0 false 'Cluster evidence is disabled' GITHUB_EVENT_NAME="$event" \
        TWINET_CLUSTER_CI_ENABLED=false "${configured[@]}"
    run_case 1 false 'missing configuration' GITHUB_EVENT_NAME="$event" \
        TWINET_CLUSTER_CI_ENABLED=true
    run_case 0 true 'Required cluster configuration is present' GITHUB_EVENT_NAME="$event" \
        TWINET_CLUSTER_CI_ENABLED=true "${configured[@]}"
done

run_case 1 false 'missing configuration' GITHUB_EVENT_NAME=workflow_dispatch
run_case 0 true 'Required cluster configuration is present' \
    GITHUB_EVENT_NAME=workflow_dispatch "${configured[@]}"
run_case 0 true 'Required cluster configuration is present' \
    GITHUB_EVENT_NAME=workflow_dispatch TWINET_CLUSTER_CI_ENABLED=false "${configured[@]}"

for name in "${required[@]}"; do
    run_case 1 false "- $name" GITHUB_EVENT_NAME=workflow_dispatch "${configured[@]}" "$name="
done

run_case 1 false 'Invalid TWINET_CLUSTER_CI_ENABLED' GITHUB_EVENT_NAME=push \
    TWINET_CLUSTER_CI_ENABLED=tru "${configured[@]}"
run_case 1 false 'Unsupported event' GITHUB_EVENT_NAME=pull_request "${configured[@]}"

printf 'cluster CI configuration tests: ok\n'
