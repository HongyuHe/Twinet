#!/usr/bin/env bash
# Run the parameterized scale soak against a fresh lab and retain JSON evidence.
set -uo pipefail

program_name=$(basename "$0")
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

usage() {
    cat <<EOF
Usage: ${program_name} --allow-destructive [options]

Deploy a fresh solved scale lab, run TestScaleSoak, destroy the lab, and emit a
machine-readable report. The release setting is 24h; --short is intended for
development feedback.

Options:
  --allow-destructive       Required acknowledgement that this deploys, faults, and destroys a lab.
  --manifest PATH           Manifest directory or twinet.yaml (default: examples/scale).
  --binary PATH             Controller binary (default: bin/twinet).
  --duration D              Soak duration (default: 24h).
  --interval D              Interval between soak cycles (default: 30m).
  --short                   Use a 15m duration and 2m interval.
  --output FILE             Evidence JSON (default: reports/scale_soak/<UTC>.json).
  --device ID               Device whose configuration is fingerprinted (default: as3/CHI).
  --as N                    Student AS saved and graded during the soak (default: 3).
  --help                    Show this help.

Required environment:
  TWINET_TOKEN              Agent credential for the target cluster.

The runner refuses a pre-existing target lab and removes its own scratch files.
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

is_positive_integer() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) [ "$1" -gt 0 ] ;;
    esac
}

argv=("$0" "$@")
binary="bin/twinet"
manifest="examples/scale"
duration="24h"
interval="30m"
output=""
device="as3/CHI"
student_as=3
allow_destructive=0
short_mode=0

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
        --duration)
            require_value "$@"
            duration=$2
            shift 2
            ;;
        --interval)
            require_value "$@"
            interval=$2
            shift 2
            ;;
        --short)
            short_mode=1
            shift
            ;;
        --output)
            require_value "$@"
            output=$2
            shift 2
            ;;
        --device)
            require_value "$@"
            device=$2
            shift 2
            ;;
        --as)
            require_value "$@"
            student_as=$2
            shift 2
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
    die_usage "--allow-destructive is required; the soak mutates and destroys a lab"
fi
if ! is_positive_integer "$student_as"; then
    die_usage "--as must be a positive integer"
fi
if [ "$short_mode" -eq 1 ]; then
    duration="15m"
    interval="2m"
fi

cd "$repo_root" || {
    printf '%s: cannot enter repository root %s\n' "$program_name" "$repo_root" >&2
    exit 1
}

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
    die_usage "TWINET_TOKEN is required to run a cluster soak"
fi

go_binary=${GO:-go}
if ! command -v "$go_binary" >/dev/null 2>&1 && [ -x /usr/local/go/bin/go ]; then
    go_binary=/usr/local/go/bin/go
fi
if ! command -v "$go_binary" >/dev/null 2>&1 && [ ! -x "$go_binary" ]; then
    die_usage "Go is required to run the build-tagged soak test"
fi

if [ -z "$output" ]; then
    output="reports/scale_soak/$(date -u +%Y%m%dT%H%M%SZ).json"
fi
output_dir=$(dirname "$output")
if ! mkdir -p "$output_dir"; then
    printf '%s: cannot create evidence directory %s\n' "$program_name" "$output_dir" >&2
    exit 1
fi
output_dir=$(cd "$output_dir" && pwd -P) || exit 1
output="$(cd "$(dirname "$output")" && pwd -P)/$(basename "$output")"
soak_artifacts="${output%.json}.artifacts"
if ! mkdir -p "$soak_artifacts"; then
    printf '%s: cannot create soak artifact directory %s\n' "$program_name" "$soak_artifacts" >&2
    exit 1
fi
soak_artifacts=$(cd "$soak_artifacts" && pwd -P) || exit 1
manifest_dir=$(cd "$manifest_dir" && pwd -P) || exit 1
manifest_file="${manifest_dir}/$(basename "$manifest_file")"
binary="$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")"

umask 077
scratch_dir=$(mktemp -d "${output_dir}/.scale_soak.XXXXXX") || {
    printf '%s: cannot create scratch directory under %s\n' "$program_name" "$output_dir" >&2
    exit 1
}
scratch_dir=$(cd "$scratch_dir" && pwd -P) || exit 1
run_manifest_dir="${scratch_dir}/manifest"
if ! cp -a "$manifest_dir" "$run_manifest_dir"; then
    rm -rf "$scratch_dir"
    printf '%s: cannot copy manifest into isolated soak workspace\n' "$program_name" >&2
    exit 1
fi
rm -rf "${run_manifest_dir}/.twinet"
if [ -d "${manifest_dir}/.twinet/pki" ]; then
    if ! mkdir -p "${run_manifest_dir}/.twinet" ||
        ! cp -a "${manifest_dir}/.twinet/pki" "${run_manifest_dir}/.twinet/pki"; then
        rm -rf "$scratch_dir"
        printf '%s: cannot copy controller credentials into soak workspace\n' "$program_name" >&2
        exit 1
    fi
fi
if [ "$(basename "$manifest_file")" = "twinet.yaml" ]; then
    run_manifest="$run_manifest_dir"
else
    run_manifest="${run_manifest_dir}/$(basename "$manifest_file")"
fi

start_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start_epoch=$(date +%s)
failure=""
deployment_started=0
cleanup_attempted=0

command_string=""
for argument in "${argv[@]}"; do
    printf -v command_string '%s%q ' "$command_string" "$argument"
done
command_string=${command_string% }

record_failure() {
    if [ -z "$failure" ]; then
        failure=$1
        printf '%s: %s\n' "$program_name" "$failure" >&2
    fi
}

run_capture() {
    local phase=$1
    shift
    local started ended status command

    command=""
    for argument in "$@"; do
        printf -v command '%s%q ' "$command" "$argument"
    done
    command=${command% }
    printf '%s\n' "$command" >"${scratch_dir}/${phase}.command"
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\n' "$started" >"${scratch_dir}/${phase}.started_at"
    if "$@" >"${scratch_dir}/${phase}.stdout" 2>"${scratch_dir}/${phase}.stderr"; then
        status=0
    else
        status=$?
    fi
    ended=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\n' "$ended" >"${scratch_dir}/${phase}.ended_at"
    printf '%s\n' "$status" >"${scratch_dir}/${phase}.exit_code"
    return "$status"
}

validate_status() {
    local file=$1
    python3 - "$file" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception as exc:
    raise SystemExit(f"node status JSON cannot be read: {exc}")
if not isinstance(rows, list) or not rows:
    raise SystemExit("node status contains no nodes")
for row in rows:
    if not isinstance(row, dict):
        raise SystemExit("node status contains a non-object entry")
    if row.get("error"):
        raise SystemExit(f"unmeasurable node status: {row}")
    status = row.get("status")
    if not isinstance(status, dict):
        raise SystemExit("node status has no status payload")
    for key in ("node", "cpus", "containers", "runtime", "runtime_version"):
        if key not in status:
            raise SystemExit(f"node status lacks required field {key!r}")
PY
}

lab_from_topology() {
    python3 - "${scratch_dir}/topology.stdout" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
lab = doc.get("lab")
if not isinstance(lab, str) or not lab:
    raise SystemExit("topology response has no lab name")
pathlib.Path(sys.argv[2]).write_text(lab)
PY
}

lab_is_absent() {
    python3 - "${scratch_dir}/status_before.stdout" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
lab = pathlib.Path(sys.argv[2]).read_text().strip()
owners = []
for row in rows:
    status = row.get("status", {})
    if lab in status.get("labs", []):
        owners.append(row.get("node", "<unknown>"))
if owners:
    raise SystemExit(f"lab {lab!r} already exists on {', '.join(owners)}")
PY
}

write_report() {
    local end_at end_epoch
    end_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    end_epoch=$(date +%s)
    python3 - "$output" "$scratch_dir" "$command_string" "$manifest_file" "$soak_artifacts" \
        "$duration" "$interval" "$device" "$student_as" "$start_at" "$end_at" \
        "$start_epoch" "$end_epoch" "$failure" "$cleanup_attempted" <<'PY'
import json
import pathlib
import sys

(
    output,
    scratch,
    command,
    manifest,
    artifacts_dir,
    duration,
    interval,
    device,
    student_as,
    started_at,
    ended_at,
    started_epoch,
    ended_epoch,
    failure,
    cleanup_attempted,
) = sys.argv[1:]
root = pathlib.Path(scratch)

def text(name):
    path = root / name
    return path.read_text() if path.exists() else ""

def phase(name):
    code = text(f"{name}.exit_code").strip()
    if not code:
        return None
    try:
        exit_code = int(code)
    except ValueError:
        exit_code = None
    return {
        "command": text(f"{name}.command").strip(),
        "started_at": text(f"{name}.started_at").strip(),
        "ended_at": text(f"{name}.ended_at").strip(),
        "exit_code": exit_code,
        "stdout": text(f"{name}.stdout"),
        "stderr": text(f"{name}.stderr"),
    }

def decoded_file(name):
    raw = text(name)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"unparseable": raw}

try:
    total_duration = int(ended_epoch) - int(started_epoch)
except ValueError:
    total_duration = None

phases = {name: phase(name) for name in (
    "topology", "status_before", "deploy", "soak", "cleanup", "status_after_cleanup"
)}
test_report = decoded_file("test_report.json")
report = {
    "schema_version": 1,
    "command": command,
    "started_at": started_at,
    "ended_at": ended_at,
    "duration_seconds": total_duration,
    "release_duration": "24h",
    "requested_duration": duration,
    "interval": interval,
    "manifest": manifest,
    "artifacts_dir": artifacts_dir,
    "fingerprint_device": device,
    "student_as": int(student_as),
    "phases": phases,
    "soak_test": test_report,
    "cleanup": {
        "attempted": cleanup_attempted == "1",
        "result": phases["cleanup"],
        "node_status_after_cleanup": phases["status_after_cleanup"],
    },
    "result": {
        "passed": not failure and all(p and p["exit_code"] == 0 for p in phases.values()),
        "failure": failure or None,
    },
}
pathlib.Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
}

finish() {
    local original_status=$?
    trap - EXIT INT TERM

    if [ "$deployment_started" -eq 1 ]; then
        cleanup_attempted=1
        if ! run_capture cleanup "$binary" destroy -m "$run_manifest" --yes; then
            record_failure "cleanup could not remove the soak lab"
        fi
        if ! run_capture status_after_cleanup "$binary" --json node status -m "$run_manifest"; then
            record_failure "could not collect node status after soak cleanup"
        elif ! validate_status "${scratch_dir}/status_after_cleanup.stdout"; then
            record_failure "node status after soak cleanup was incomplete"
        fi
    fi

    if ! write_report; then
        record_failure "could not write machine-readable soak evidence"
    fi
    rm -rf "$scratch_dir"
    printf '%s: evidence written to %s\n' "$program_name" "$output" >&2
    if [ -n "$failure" ]; then
        exit 1
    fi
    exit "$original_status"
}

trap finish EXIT
trap 'exit 130' INT TERM

if ! run_capture topology "$binary" --json inspect -m "$run_manifest" --links; then
    record_failure "could not inspect the soak topology"
    exit 1
fi
if ! lab_from_topology; then
    record_failure "topology inspection did not identify a lab"
    exit 1
fi
if ! run_capture status_before "$binary" --json node status -m "$run_manifest"; then
    record_failure "could not collect status/resources before the soak"
    exit 1
fi
if ! validate_status "${scratch_dir}/status_before.stdout"; then
    record_failure "status/resources before the soak were incomplete"
    exit 1
fi
if ! lab_is_absent; then
    record_failure "soak target is not a clean lab"
    exit 1
fi

deployment_started=1
if ! run_capture deploy "$binary" deploy -m "$run_manifest" --solve --quiet; then
    record_failure "could not deploy the solved soak lab"
    exit 1
fi

if [ "$short_mode" -eq 1 ]; then
    go_timeout="35m"
else
    go_timeout="26h"
fi
if ! run_capture soak env \
    "TWINET_LAB=${run_manifest}" \
    "TWINET_BIN=${binary}" \
    "TWINET_SOAK_REQUIRED=1" \
    "TWINET_SOAK_ALLOW_DESTRUCTIVE=1" \
    "TWINET_SOAK_DURATION=${duration}" \
    "TWINET_SOAK_INTERVAL=${interval}" \
    "TWINET_SOAK_DEVICE=${device}" \
    "TWINET_SOAK_AS=${student_as}" \
    "TWINET_SOAK_REPORT=${scratch_dir}/test_report.json" \
    "TWINET_E2E_ARTIFACT_DIR=${soak_artifacts}" \
    "TWINET_SOAK_ARTIFACTS_DIR=${soak_artifacts}" \
    "$go_binary" test -count=1 -tags e2e,soak -run '^TestScaleSoak$' \
    -timeout "$go_timeout" ./test/e2e; then
    record_failure "the build-tagged soak test failed"
    exit 1
fi
