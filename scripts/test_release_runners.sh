#!/usr/bin/env bash
# Exercise runner argument handling without requiring a controller or cluster.
set -uo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root" || exit 1

fail() {
    printf 'test_release_runners: %s\n' "$1" >&2
    exit 1
}

expect_status() {
    local expected=$1
    local description=$2
    shift 2
    local actual output

    if output=$("$@" 2>&1); then
        actual=0
    else
        actual=$?
    fi
    if [ "$actual" -ne "$expected" ]; then
        printf '%s\n' "$output" >&2
        fail "${description}: expected exit ${expected}, got ${actual}"
    fi
}

expect_output() {
    local needle=$1
    local description=$2
    shift 2
    local output

    if output=$("$@" 2>&1); then
        :
    else
        output="${output}"$'\n'"command exited non-zero"
    fi
    case "$output" in
        *"$needle"*) ;;
        *)
            printf '%s\n' "$output" >&2
            fail "${description}: output did not contain ${needle@Q}"
            ;;
    esac
}

expect_status 0 "benchmark help" bash scripts/scale_benchmark.sh --help
expect_output "Usage:" "benchmark help" bash scripts/scale_benchmark.sh --help
expect_status 2 "benchmark destructive gate" bash scripts/scale_benchmark.sh
expect_status 2 "benchmark unknown argument" bash scripts/scale_benchmark.sh --unknown
expect_status 2 "benchmark invalid grade parallel" \
    bash scripts/scale_benchmark.sh --allow-destructive --grade-parallel 0
expect_status 2 "benchmark missing manifest" \
    bash scripts/scale_benchmark.sh --allow-destructive --manifest nowhere/twinet.yaml

expect_status 0 "chaos help" bash scripts/chaos_e2e.sh --help
expect_output "Runner-specific fault hooks" "chaos help" bash scripts/chaos_e2e.sh --help
expect_status 2 "chaos destructive gate" bash scripts/chaos_e2e.sh
expect_status 2 "chaos unknown argument" bash scripts/chaos_e2e.sh --unknown

expect_status 0 "soak help" bash scripts/scale_soak.sh --help
expect_output "release setting is 24h" "soak help" bash scripts/scale_soak.sh --help
expect_status 2 "soak destructive gate" bash scripts/scale_soak.sh
expect_status 2 "soak unknown argument" bash scripts/scale_soak.sh --unknown
expect_status 2 "soak invalid AS" bash scripts/scale_soak.sh --allow-destructive --as 0
expect_status 2 "soak missing manifest" \
    bash scripts/scale_soak.sh --allow-destructive --manifest nowhere/twinet.yaml

work_dir="reports/.release_runner_test.$$"
mkdir -p "$work_dir" || fail "could not create project-local runner test directory"
cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT

fake_controller="${work_dir}/twinet"
cat >"$fake_controller" <<'EOF'
#!/usr/bin/env bash
set -eu

if [ "${1:-}" = "version" ]; then
    printf 'twinet test-controller (commit test)\n'
    exit 0
fi
args=" $* "
if [[ "$args" == *" --json inspect "* ]]; then
    cat <<'JSON'
{"lab":"scale","hash":"topology-test","stats":{"devices":2,"links":1},"devices":[{"id":"as3/CHI","node":"node-a","as":3},{"id":"as4/CHI","node":"node-b","as":4}],"links":[{"a":"as3/CHI:port_AS4","b":"as4/CHI:port_AS3","inter_as":true}]}
JSON
    exit 0
fi
if [[ "$args" == *" --json node status "* ]]; then
    cat <<'JSON'
[{"node":"node-a","status":{"node":"node-a","runtime":"docker","runtime_version":"test","cpus":4,"containers":0,"labs":[],"overlays":{}}},{"node":"node-b","status":{"node":"node-b","runtime":"docker","runtime_version":"test","cpus":4,"containers":0,"labs":[],"overlays":{}}}]
JSON
    exit 0
fi
if [[ "$args" == *" node check "* ]]; then
    printf 'underlay is sufficient\n'
    exit 0
fi
if [[ "$args" == *" deploy "* ]] || [[ "$args" == *" destroy "* ]]; then
    printf 'ok\n'
    exit 0
fi
if [[ "$args" == *" grade batch "* ]]; then
    output=""
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "--out" ]; then
            output=$2
            break
        fi
        shift
    done
    mkdir -p "$output"
    printf '{"count":1,"reports":[{"submission":"group3"}]}\n' >"${output}/summary.json"
    printf 'graded one submission\n'
    exit 0
fi
if [[ "$args" == *" grade run "* ]]; then
    printf '{"duration":"1s","reports":[{"submission":"group3"}]}\n'
    exit 0
fi
printf 'unexpected fake controller command: %s\n' "$*" >&2
exit 64
EOF
chmod 0755 "$fake_controller"

benchmark_evidence="${work_dir}/benchmark.json"
if ! TWINET_TOKEN=test-token bash scripts/scale_benchmark.sh --allow-destructive \
    --binary "$fake_controller" --manifest examples/scale --output "$benchmark_evidence"; then
    fail "benchmark evidence runner rejected a complete no-cluster controller fixture"
fi
if ! python3 - "$benchmark_evidence" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["result"]["passed"], report
assert report["source"]["revision"]
assert report["source"]["binary_version"].startswith("twinet test-controller")
assert report["manifest"]["sha256"] and report["manifest"]["topology_hash"] == "topology-test"
assert report["duration_seconds"] >= 0
assert report["topology"]["placement"]["node-a"]["devices"] == 1
assert report["topology"]["links"]["cross_node"] == 1
assert report["deploy"]["exit_code"] == 0
assert report["deploy"]["duration_seconds"] >= 0
assert report["convergence"]["exit_code"] == 0
assert report["cleanup"]["attempted"] and report["cleanup"]["result"]["exit_code"] == 0
assert not report["missing_measurements"], report
PY
then
    fail "benchmark evidence report omitted required release measurements"
fi
if find "$work_dir" -maxdepth 1 -name '.scale_benchmark.*' | grep -q .; then
    fail "benchmark runner left its scratch directory behind"
fi

submissions_dir="${work_dir}/submissions"
mkdir -p "${submissions_dir}/group3"
touch "${submissions_dir}/group3/submission.tar.gz"
grade_evidence="${work_dir}/benchmark_grade.json"
if ! TWINET_TOKEN=test-token bash scripts/scale_benchmark.sh --allow-destructive \
    --binary "$fake_controller" --manifest examples/scale --submissions "$submissions_dir" \
    --output "$grade_evidence"; then
    fail "benchmark runner rejected a complete grading fixture"
fi
if ! python3 - "$grade_evidence" <<'PY'
import json
import pathlib
import sys

grade = json.loads(pathlib.Path(sys.argv[1]).read_text())["grade"]
assert grade["submissions"] == 1
assert grade["duration_seconds"] >= 0
assert grade["throughput_submissions_per_hour"] is not None
assert grade["summary"]["count"] == 1
PY
then
    fail "benchmark grading evidence omitted throughput or summary"
fi

printf 'release runner argument tests: ok\n'
