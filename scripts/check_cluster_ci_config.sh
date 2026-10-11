#!/usr/bin/env bash
# Decide whether to queue cluster evidence without contacting the cluster.
set -euo pipefail

report() {
    printf '%s\n' "$1"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
    fi
}

output() {
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf 'enabled=%s\n' "$1" >> "$GITHUB_OUTPUT"
    fi
}

case "${TWINET_CLUSTER_CI_ENABLED:-}" in
    ''|false|true) ;;
    *)
        output false
        report 'Invalid TWINET_CLUSTER_CI_ENABLED: use true, false, or leave it unset.'
        exit 1
        ;;
esac

case "${GITHUB_EVENT_NAME:-}" in
    push|schedule)
        if [ "${TWINET_CLUSTER_CI_ENABLED:-}" != true ]; then
            output false
            report 'Cluster evidence is disabled. No benchmark, chaos, or soak tests ran. Configure a dedicated runner and cluster, then set the repository variable TWINET_CLUSTER_CI_ENABLED=true to enable automatic runs. See docs/12_operator_guide.md, section 11.'
            exit 0
        fi
        ;;
    workflow_dispatch) ;;
    *)
        output false
        report 'Unsupported event: cluster evidence accepts main pushes, schedules, and manual dispatches.'
        exit 1
        ;;
esac

required=(
    TWINET_TOKEN
    TWINET_CHAOS_AGENT_RESTART_CMD
    TWINET_CHAOS_AGENT_STOP_CMD
    TWINET_CHAOS_NODE_REBOOT_CMD
    TWINET_CHAOS_UNDERLAY_DOWN_CMD
    TWINET_CHAOS_UNDERLAY_UP_CMD
    TWINET_CHAOS_MIGRATION_MANIFEST
)
missing=()
for name in "${required[@]}"; do
    if [ -z "${!name:-}" ]; then
        missing+=("$name")
    fi
done

if [ "${#missing[@]}" -ne 0 ]; then
    output false
    report 'Cluster evidence is blocked by missing configuration. No cluster job was authorized. Configure the following secret or repository variables as described in docs/12_operator_guide.md, section 11:'
    for name in "${missing[@]}"; do
        report "- $name"
    done
    exit 1
fi

output true
report 'Required cluster configuration is present. The cluster job may now queue for a self-hosted Linux runner labeled twinet-cluster. Configuration validation supplies no benchmark, chaos, or soak evidence; those results come from the cluster job.'
