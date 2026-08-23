#!/usr/bin/env bash
# Deploy an isolated scale manifest and run the destructive chaos test surface.
set -uo pipefail

program_name=$(basename "$0")
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

usage() {
    cat <<EOF
Usage: ${program_name} --allow-destructive [options]

Runs build-tagged TestChaos* cases against a fresh, copied scale manifest and
always attempts cleanup. Runner-specific fault hooks are intentionally required
by the tests; an absent hook is a failed missing capability, never a skip.

Options:
  --allow-destructive       Required acknowledgement that chaos restarts agents and faults underlay links.
  --manifest PATH           Manifest directory or twinet.yaml (default: examples/scale).
  --binary PATH             Controller binary (default: bin/twinet).
  --output FILE             Evidence JSON (default: reports/chaos/<UTC>.json).
  --allow-other-labs        Permit unrelated managed labs to remain on the cluster.
  --help                    Show this help.

Required environment:
  TWINET_TOKEN
  TWINET_CHAOS_AGENT_RESTART_CMD
  TWINET_CHAOS_AGENT_STOP_CMD
  TWINET_CHAOS_NODE_REBOOT_CMD
  TWINET_CHAOS_UNDERLAY_DOWN_CMD
  TWINET_CHAOS_UNDERLAY_UP_CMD
  TWINET_CHAOS_MIGRATION_MANIFEST
EOF
}

die_usage() {
    printf '%s: %s\n\n' "$program_name" "$1" >&2
    usage >&2
    exit 2
}

require_value() {
    if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        die_usage "$1 requires a value"
    fi
}

binary="bin/twinet"
manifest="examples/scale"
output=""
allow_destructive=0
allow_other_labs=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --allow-destructive)
            allow_destructive=1
            shift
            ;;
        --manifest)
            require_value "$@"
            manifest=$2
            shift 2
            ;;
        --binary)
            require_value "$@"
            binary=$2
            shift 2
            ;;
        --output)
            require_value "$@"
            output=$2
            shift 2
            ;;
        --allow-other-labs)
            allow_other_labs=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die_usage "unknown argument $1"
            ;;
    esac
done

if [ "$allow_destructive" -ne 1 ]; then
    die_usage "--allow-destructive is required; chaos changes real cluster state"
fi

cd "$repo_root" || exit 1
if [ -d "$manifest" ]; then
    manifest_dir=${manifest%/}
    manifest_file="${manifest_dir}/twinet.yaml"
else
    manifest_file=$manifest
    manifest_dir=$(dirname "$manifest")
fi
if [ ! -f "$manifest_file" ]; then
    die_usage "manifest ${manifest_file} does not exist"
fi
if [ ! -x "$binary" ]; then
    die_usage "controller binary ${binary} is not executable; run make build or pass --binary"
fi
if [ -z "${TWINET_TOKEN:-}" ]; then
    die_usage "TWINET_TOKEN is required to run chaos"
fi
if [ -z "${TWINET_CHAOS_AGENT_RESTART_CMD:-}" ]; then
    die_usage "TWINET_CHAOS_AGENT_RESTART_CMD is required for agent-restart coverage"
fi
if [ -z "${TWINET_CHAOS_AGENT_STOP_CMD:-}" ]; then
    die_usage "TWINET_CHAOS_AGENT_STOP_CMD is required for partial-apply coverage"
fi
if [ -z "${TWINET_CHAOS_NODE_REBOOT_CMD:-}" ]; then
    die_usage "TWINET_CHAOS_NODE_REBOOT_CMD is required for node-reboot coverage"
fi
if [ -z "${TWINET_CHAOS_UNDERLAY_DOWN_CMD:-}" ]; then
    die_usage "TWINET_CHAOS_UNDERLAY_DOWN_CMD is required for underlay-failure coverage"
fi
if [ -z "${TWINET_CHAOS_UNDERLAY_UP_CMD:-}" ]; then
    die_usage "TWINET_CHAOS_UNDERLAY_UP_CMD is required for underlay-recovery coverage"
fi
if [ -z "${TWINET_CHAOS_MIGRATION_MANIFEST:-}" ]; then
    die_usage "TWINET_CHAOS_MIGRATION_MANIFEST is required for state-migration coverage"
fi
if [ ! -e "${TWINET_CHAOS_MIGRATION_MANIFEST}" ]; then
    die_usage "TWINET_CHAOS_MIGRATION_MANIFEST does not exist"
fi

go_binary=${GO:-go}
if ! command -v "$go_binary" >/dev/null 2>&1 && [ -x /usr/local/go/bin/go ]; then
    go_binary=/usr/local/go/bin/go
fi
if ! command -v "$go_binary" >/dev/null 2>&1 && [ ! -x "$go_binary" ]; then
    die_usage "Go is required to run build-tagged chaos tests"
fi

if [ -z "$output" ]; then
    output="reports/chaos/$(date -u +%Y%m%dT%H%M%SZ).json"
fi
output_dir=$(dirname "$output")
mkdir -p "$output_dir" || exit 1
output_dir=$(cd "$output_dir" && pwd -P) || exit 1
output="$(cd "$(dirname "$output")" && pwd -P)/$(basename "$output")"
manifest_dir=$(cd "$manifest_dir" && pwd -P) || exit 1
manifest_file="${manifest_dir}/$(basename "$manifest_file")"
binary="$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")"

umask 077
scratch_dir=$(mktemp -d "${output_dir}/.chaos_e2e.XXXXXX") || exit 1
scratch_dir=$(cd "$scratch_dir" && pwd -P) || exit 1
run_manifest_dir="${scratch_dir}/manifest"
if ! cp -a "$manifest_dir" "$run_manifest_dir"; then
    rm -rf "$scratch_dir"
    printf '%s: cannot copy manifest into isolated chaos workspace\n' "$program_name" >&2
    exit 1
fi
rm -rf "${run_manifest_dir}/.twinet"
if [ -d "${manifest_dir}/.twinet/pki" ]; then
    if ! mkdir -p "${run_manifest_dir}/.twinet" ||
        ! cp -a "${manifest_dir}/.twinet/pki" "${run_manifest_dir}/.twinet/pki"; then
        rm -rf "$scratch_dir"
        printf '%s: cannot copy controller credentials into chaos workspace\n' "$program_name" >&2
        exit 1
    fi
fi
if [ "$(basename "$manifest_file")" = "twinet.yaml" ]; then
    run_manifest="$run_manifest_dir"
else
    run_manifest="${run_manifest_dir}/$(basename "$manifest_file")"
fi

migration_source=${TWINET_CHAOS_MIGRATION_MANIFEST}
if [ -d "$migration_source" ]; then
    migration_dir="${scratch_dir}/migration"
    if ! cp -a "$migration_source" "$migration_dir"; then
        rm -rf "$scratch_dir"
        printf '%s: cannot copy migration manifest into chaos workspace\n' "$program_name" >&2
        exit 1
    fi
    rm -rf "${migration_dir}/.twinet"
    if [ -d "${migration_source}/.twinet/pki" ]; then
        if ! mkdir -p "${migration_dir}/.twinet" ||
            ! cp -a "${migration_source}/.twinet/pki" "${migration_dir}/.twinet/pki"; then
            rm -rf "$scratch_dir"
            printf '%s: cannot copy migration controller credentials\n' "$program_name" >&2
            exit 1
        fi
    fi
    migration_manifest="$migration_dir"
else
    migration_parent=$(dirname "$migration_source")
    migration_dir="${scratch_dir}/migration"
    if ! cp -a "$migration_parent" "$migration_dir"; then
        rm -rf "$scratch_dir"
        printf '%s: cannot copy migration manifest into chaos workspace\n' "$program_name" >&2
        exit 1
    fi
    rm -rf "${migration_dir}/.twinet"
    if [ -d "${migration_parent}/.twinet/pki" ]; then
        if ! mkdir -p "${migration_dir}/.twinet" ||
            ! cp -a "${migration_parent}/.twinet/pki" "${migration_dir}/.twinet/pki"; then
            rm -rf "$scratch_dir"
            printf '%s: cannot copy migration controller credentials\n' "$program_name" >&2
            exit 1
        fi
    fi
    migration_manifest="${migration_dir}/$(basename "$migration_source")"
fi

start_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
failure=""
deployment_started=0
cleanup_attempted=0
cleanup_succeeded=0
cleanup_recovered_empty=0

cleanup_recovery_attempts=6
cleanup_recovery_wait=3m
cleanup_recovery_command_wait=4m
cleanup_destroy_wait=10m

run_capture() {
    local phase=$1
    shift
    local status
    printf '%q ' "$@" >"${scratch_dir}/${phase}.command"
    date -u +%Y-%m-%dT%H:%M:%SZ >"${scratch_dir}/${phase}.started_at"
    if "$@" >"${scratch_dir}/${phase}.stdout" 2>"${scratch_dir}/${phase}.stderr"; then
        status=0
    else
        status=$?
    fi
    date -u +%Y-%m-%dT%H:%M:%SZ >"${scratch_dir}/${phase}.ended_at"
    printf '%s\n' "$status" >"${scratch_dir}/${phase}.exit_code"
    return "$status"
}

record_failure() {
    if [ -z "$failure" ]; then
        failure=$1
        printf '%s: %s\n' "$program_name" "$failure" >&2
    fi
}

lab_from_topology() {
    python3 - "${scratch_dir}/topology.stdout" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

try:
    doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception as exc:
    raise SystemExit(f"topology JSON cannot be read: {exc}")
lab = doc.get("lab") if isinstance(doc, dict) else None
if not isinstance(lab, str) or not lab:
    raise SystemExit("topology JSON has no lab name")
pathlib.Path(sys.argv[2]).write_text(lab)
PY
}

lab_is_absent() {
    python3 - "${scratch_dir}/status_before.stdout" "${scratch_dir}/lab_name" \
        "$allow_other_labs" <<'PY'
import json
import pathlib
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception as exc:
    raise SystemExit(f"node status JSON cannot be read: {exc}")
lab = pathlib.Path(sys.argv[2]).read_text().strip()
allow_other_labs = sys.argv[3] == "1"
owners = []
other_labs = set()
for row in rows:
    if not isinstance(row, dict):
        raise SystemExit("node status contains a non-object entry")
    if row.get("error"):
        raise SystemExit(f"node status has an error: {row['error']}")
    status = row.get("status")
    if not isinstance(status, dict):
        raise SystemExit("node status has no status payload")
    if lab in status.get("labs", []):
        owners.append(row.get("node", "<unknown>"))
    other_labs.update(
        item for item in status.get("labs", [])
        if isinstance(item, str) and item != lab
    )
if owners:
    raise SystemExit(f"lab {lab!r} already exists on {', '.join(owners)}")
if other_labs and not allow_other_labs:
    raise SystemExit(
        "cluster is not clean; unrelated managed labs are active: "
        + ", ".join(sorted(other_labs))
        + " (use --allow-other-labs only for an explicitly co-tenant chaos run)"
    )
PY
}

recovery_inventory_is_empty() {
    local file=$1
    python3 - "$file" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text().lstrip()
try:
    report, _ = json.JSONDecoder().raw_decode(raw)
except Exception as exc:
    raise SystemExit(f"recovery report cannot be read: {exc}")
nodes = report.get("nodes") if isinstance(report, dict) else None
if not isinstance(nodes, dict) or not nodes:
    raise SystemExit("recovery report contains no nodes")
for node, status in nodes.items():
    if not isinstance(status, dict):
        raise SystemExit(f"recovery status for {node} is not an object")
    if status.get("consistent") is not True:
        raise SystemExit(f"recovery status for {node} is not consistent")
    for key in (
        "expected_containers", "observed_containers",
        "expected_vnis", "observed_vnis",
        "expected_logical_bindings", "observed_logical_bindings",
        "expected_physical_trunks", "observed_physical_trunks",
    ):
        if key not in status or status[key] != 0:
            raise SystemExit(f"recovery status for {node} has non-empty {key}={status.get(key)!r}")
PY
}

cleanup_status_is_absent() {
    local file=$1
    python3 - "$file" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
lab = pathlib.Path(sys.argv[2]).read_text().strip()
owners = []
for row in rows:
    status = row.get("status", {}) if isinstance(row, dict) else {}
    if lab in status.get("labs", []):
        owners.append(row.get("node", "<unknown>"))
if owners:
    raise SystemExit(f"cleanup left lab {lab!r} active on {', '.join(owners)}")
PY
}

cleanup_lab() {
    local attempt phase lab_name
    local -a recover_args
    lab_name=$(<"${scratch_dir}/lab_name")
    cleanup_attempted=1
    if run_capture cleanup_destroy_1 timeout --signal=TERM --kill-after=30s \
        "$cleanup_destroy_wait" "$binary" destroy -m "$run_manifest" --lab "$lab_name" --yes; then
        cleanup_succeeded=1
        printf '%s\n' cleanup_destroy_1 >"${scratch_dir}/cleanup_result_phase"
        return 0
    fi

    for ((attempt = 1; attempt <= cleanup_recovery_attempts; attempt++)); do
        phase="cleanup_recover_join_${attempt}"
        recover_args=(
            timeout --signal=TERM --kill-after=30s "$cleanup_recovery_command_wait"
            "$binary" --json recover -m "$run_manifest" --strategy rollback
            --wait "$cleanup_recovery_wait"
        )
        if [ "$attempt" -gt 1 ]; then
            phase="cleanup_recover_takeover_${attempt}"
            recover_args+=(--takeover)
        fi
        run_capture "$phase" "${recover_args[@]}" || true
        if recovery_inventory_is_empty "${scratch_dir}/${phase}.stdout" 2>/dev/null; then
            cleanup_recovered_empty=1
        fi
        if run_capture "cleanup_destroy_$((attempt + 1))" \
            timeout --signal=TERM --kill-after=30s "$cleanup_destroy_wait" \
            "$binary" destroy -m "$run_manifest" --lab "$lab_name" --yes; then
            cleanup_succeeded=1
            printf 'cleanup_destroy_%s\n' "$((attempt + 1))" >"${scratch_dir}/cleanup_result_phase"
            return 0
        fi
        if [ "$cleanup_recovered_empty" -eq 1 ]; then
            cleanup_succeeded=1
            printf '%s\n' "$phase" >"${scratch_dir}/cleanup_result_phase"
            return 0
        fi
        # A disconnected deploy can spend tens of seconds quiescing in-flight
        # runtime calls before its lease becomes recoverable. Do not burn every
        # bounded takeover attempt during that legitimate cancellation window.
        sleep 15
    done
    return 1
}

write_report() {
    local end_at
    end_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    python3 - "$output" "$scratch_dir" "$start_at" "$end_at" "$failure" \
        "$cleanup_attempted" "$allow_other_labs" "$cleanup_succeeded" \
        "$cleanup_recovered_empty" <<'PY'
import json
import pathlib
import sys

(
    output,
    scratch,
    started_at,
    ended_at,
    failure,
    cleanup_attempted,
    allow_other_labs,
    cleanup_succeeded,
    cleanup_recovered_empty,
) = sys.argv[1:]
root = pathlib.Path(scratch)

def text(name):
    path = root / name
    return path.read_text() if path.exists() else ""

def phase(name):
    raw = text(f"{name}.exit_code").strip()
    if not raw:
        return None
    return {
        "command": text(f"{name}.command").strip(),
        "started_at": text(f"{name}.started_at").strip(),
        "ended_at": text(f"{name}.ended_at").strip(),
        "exit_code": int(raw),
        "stdout": text(f"{name}.stdout"),
        "stderr": text(f"{name}.stderr"),
    }

phases = {name: phase(name) for name in (
    "topology", "status_before", "deploy", "chaos", "status_after_cleanup"
)}
cleanup_attempts = {
    path.name.removesuffix(".exit_code"): phase(path.name.removesuffix(".exit_code"))
    for path in sorted(root.glob("cleanup_*.exit_code"))
}
cleanup_result_phase = text("cleanup_result_phase").strip()
report = {
    "schema_version": 1,
    "started_at": started_at,
    "ended_at": ended_at,
    "allow_other_labs": allow_other_labs == "1",
    "phases": phases,
    "cleanup_attempted": cleanup_attempted == "1",
    "cleanup": {
        "succeeded": cleanup_succeeded == "1",
        "recovered_empty": cleanup_recovered_empty == "1",
        "result": cleanup_attempts.get(cleanup_result_phase),
        "attempts": cleanup_attempts,
    },
    "result": {
        "passed": not failure
        and cleanup_succeeded == "1"
        and all(p and p["exit_code"] == 0 for p in phases.values()),
        "failure": failure or None,
    },
}
pathlib.Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
}

finish() {
    local status=$?
    trap - EXIT INT TERM
    if [ "$deployment_started" -eq 1 ]; then
        if ! cleanup_lab; then
            record_failure "cleanup could not remove the chaos lab"
        fi
        if ! run_capture status_after_cleanup "$binary" --json node status -m "$run_manifest"; then
            record_failure "could not collect node status after chaos cleanup"
        elif ! cleanup_status_is_absent "${scratch_dir}/status_after_cleanup.stdout"; then
            record_failure "chaos lab remained active after cleanup"
        fi
    fi
    if ! write_report; then
        record_failure "could not write chaos evidence"
    fi
    rm -rf "$scratch_dir"
    printf '%s: evidence written to %s\n' "$program_name" "$output" >&2
    if [ -n "$failure" ]; then
        exit 1
    fi
    exit "$status"
}

trap finish EXIT
trap 'exit 130' INT TERM

if ! run_capture topology "$binary" --json inspect -m "$run_manifest" --links; then
    record_failure "could not inspect the chaos topology"
    exit 1
fi
if ! lab_from_topology; then
    record_failure "chaos topology did not identify a lab"
    exit 1
fi
if ! run_capture status_before "$binary" --json node status -m "$run_manifest"; then
    record_failure "could not collect status before chaos"
    exit 1
fi
if ! lab_is_absent; then
    record_failure "chaos target is not a clean lab"
    exit 1
fi
deployment_started=1
if ! run_capture deploy "$binary" deploy -m "$run_manifest" --solve --quiet; then
    record_failure "could not deploy the chaos lab"
    exit 1
fi
if ! run_capture chaos env \
    "TWINET_LAB=${run_manifest}" \
    "TWINET_BIN=${binary}" \
    "TWINET_E2E_ARTIFACT_DIR=${scratch_dir}/e2e_artifacts" \
    "TWINET_CHAOS_REQUIRED=1" \
    "TWINET_CHAOS_ALLOW_DESTRUCTIVE=1" \
    "TWINET_CHAOS_MIGRATION_MANIFEST=${migration_manifest}" \
    "$go_binary" test -count=1 -tags e2e,chaos -run '^TestChaos' -timeout 55m ./test/e2e; then
    record_failure "one or more chaos checks failed"
    exit 1
fi
