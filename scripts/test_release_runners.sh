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
expect_status 2 "benchmark invalid expected submissions" \
    bash scripts/scale_benchmark.sh --allow-destructive --expected-submissions 0
expect_status 2 "benchmark missing deploy budget" \
    bash scripts/scale_benchmark.sh --allow-destructive --deploy-budget
expect_status 2 "benchmark invalid deploy budget" \
    bash scripts/scale_benchmark.sh --allow-destructive --deploy-budget never
expect_status 2 "benchmark zero grade budget" \
    bash scripts/scale_benchmark.sh --allow-destructive --grade-budget 0s
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
if [[ "$args" == *" --token "* ]]; then
    printf 'release runner exposed bearer token through argv\n' >&2
    exit 64
fi
if [[ "$args" == *" --json inspect "* ]]; then
    cat <<'JSON'
{"lab":"scale","hash":"topology-test","stats":{"devices":2,"links":1},"devices":[{"id":"as3/CHI","node":"node-a","as":3},{"id":"as4/CHI","node":"node-b","as":4}],"links":[{"a":"as3/CHI:port_AS4","b":"as4/CHI:port_AS3","inter_as":true}]}
JSON
    exit 0
fi
if [[ "$args" == *" --json node status "* ]]; then
    labs=${FAKE_LABS_JSON:-[]}
    printf '[{"node":"node-a","status":{"node":"node-a","runtime":"docker","runtime_version":"test","cpus":4,"containers":0,"primary_containers":0,"control_containers":0,"managed_containers":0,"labs":%s,"overlays":{}}},{"node":"node-b","status":{"node":"node-b","runtime":"docker","runtime_version":"test","cpus":4,"containers":0,"primary_containers":0,"control_containers":0,"managed_containers":0,"labs":%s,"overlays":{}}}]\n' \
        "$labs" "$labs"
    exit 0
fi
if [[ "$args" == *" node check "* ]]; then
    printf 'underlay is sufficient\n'
    exit 0
fi
if [[ "$args" == *" deploy "* ]]; then
    printf 'ok\n'
    exit 0
fi
if [[ "$args" == *" destroy "* ]]; then
    if [ "${FAKE_DESTROY_ALWAYS_409:-0}" = "1" ]; then
        printf '409 recovery active\n' >&2
        exit 1
    fi
    if [ "${FAKE_DESTROY_409_ONCE:-0}" = "1" ] &&
        [ ! -e "${FAKE_DESTROY_STATE:?}" ]; then
        : >"$FAKE_DESTROY_STATE"
        printf '409 recovery active\n' >&2
        exit 1
    fi
    printf 'ok\n'
    exit 0
fi
if [[ "$args" == *" recover "* ]]; then
    cat <<'JSON'
{"lab":"scale","nodes":{"node-a":{"phase":"committed","consistent":true,"expected_containers":0,"observed_containers":0,"expected_vnis":0,"observed_vnis":0,"expected_logical_bindings":0,"observed_logical_bindings":0,"expected_physical_trunks":0,"observed_physical_trunks":0},"node-b":{"phase":"committed","consistent":true,"expected_containers":0,"observed_containers":0,"expected_vnis":0,"observed_vnis":0,"expected_logical_bindings":0,"observed_logical_bindings":0,"expected_physical_trunks":0,"observed_physical_trunks":0}}}
JSON
    exit 0
fi
if [[ "$args" == *" grade batch "* ]]; then
    if [[ "$args" != *" --all-attempts "* ]]; then
        printf 'benchmark batch did not opt into signed attempts\n' >&2
        exit 64
    fi
    if [[ "$args" == *" --token "* ]]; then
        printf 'benchmark batch exposed bearer token through argv\n' >&2
        exit 64
    fi
    output=""
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "--out" ]; then
            output=$2
            break
        fi
        shift
    done
    mkdir -p "$output"
    printf '%s\n' '{"count":1,"reports":[{"submission":"group3","attempt":"benchmark-000","as":3,"archive_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_hash":"topology-test","rubric_hash":"rubric-test","image_lock":"image-lock-test","grader_source":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","total":10,"max_total":10,"harness_type":"compact-synthetic-warm","equivalence_audit_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","questions":[{"id":"q1","results":[{"check":"fixture.check","status":"pass"}]}]}]}' >"${output}/summary.json"
    printf 'graded one submission\n'
    exit 0
fi
if [[ "$args" == *" grade run "* ]]; then
    printf '{"duration":"1s","reports":[{"submission":"group3","total":1,"max_total":1,"questions":[{"id":"convergence","status":"pass","results":[{"check":"fixture.check","status":"pass"}]}]}]}\n'
    exit 0
fi
printf 'unexpected fake controller command: %s\n' "$*" >&2
exit 64
EOF
chmod 0755 "$fake_controller"

expect_status 1 "benchmark clean-cluster gate" env FAKE_LABS_JSON='["another-lab"]' \
    TWINET_TOKEN=test-token bash scripts/scale_benchmark.sh --allow-destructive \
    --binary "$fake_controller" --manifest examples/scale \
    --output "${work_dir}/benchmark_unclean.json"

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
assert report["budgets"]["deploy"] == "10m"
assert report["budgets"]["grade"] == "15m"
assert report["budgets"]["allow_other_labs"] is False
assert report["convergence"]["exit_code"] == 0
assert "--rubric " in report["convergence"]["command"]
assert report["reference_grade"]["exit_code"] == 0
assert report["cleanup"]["attempted"] and report["cleanup"]["succeeded"]
assert report["cleanup"]["result"]["exit_code"] == 0
assert not report["missing_measurements"], report
PY
then
    fail "benchmark evidence report omitted required release measurements"
fi
if find "$work_dir" -maxdepth 1 -name '.scale_benchmark.*' | grep -q .; then
    fail "benchmark runner left its scratch directory behind"
fi

retry_evidence="${work_dir}/benchmark_cleanup_retry.json"
retry_state="${work_dir}/destroy_once"
if ! FAKE_DESTROY_409_ONCE=1 FAKE_DESTROY_STATE="$retry_state" TWINET_TOKEN=test-token \
    bash scripts/scale_benchmark.sh --allow-destructive --binary "$fake_controller" \
    --manifest examples/scale --output "$retry_evidence"; then
    fail "benchmark cleanup did not recover and retry after a 409"
fi
if ! python3 - "$retry_evidence" <<'PY'
import json
import pathlib
import sys

cleanup = json.loads(pathlib.Path(sys.argv[1]).read_text())["cleanup"]
assert cleanup["succeeded"] and cleanup["recovered_empty"], cleanup
assert cleanup["attempts"]["cleanup_destroy_1"]["exit_code"] != 0
assert cleanup["attempts"]["cleanup_recover_join_1"]["exit_code"] == 0
assert cleanup["attempts"]["cleanup_destroy_2"]["exit_code"] == 0
for name in ("cleanup_destroy_1", "cleanup_destroy_2"):
    assert "--lab scale" in cleanup["attempts"][name]["command"], cleanup["attempts"][name]
PY
then
    fail "benchmark cleanup retry evidence was incomplete"
fi

recovered_evidence="${work_dir}/benchmark_recovered_empty.json"
if ! FAKE_DESTROY_ALWAYS_409=1 TWINET_TOKEN=test-token \
    bash scripts/scale_benchmark.sh --allow-destructive --binary "$fake_controller" \
    --manifest examples/scale --output "$recovered_evidence"; then
    fail "benchmark did not accept verified recovered-empty cleanup"
fi
if ! python3 - "$recovered_evidence" <<'PY'
import json
import pathlib
import sys

cleanup = json.loads(pathlib.Path(sys.argv[1]).read_text())["cleanup"]
assert cleanup["succeeded"] and cleanup["recovered_empty"], cleanup
assert cleanup["attempts"]["cleanup_destroy_1"]["exit_code"] != 0
assert cleanup["attempts"]["cleanup_recover_join_1"]["exit_code"] == 0
assert cleanup["attempts"]["cleanup_destroy_2"]["exit_code"] != 0
PY
then
    fail "benchmark recovered-empty evidence was incomplete"
fi

submissions_dir="${work_dir}/submissions"
mkdir -p "${submissions_dir}/group3"
touch "${submissions_dir}/group3/submission.tar.gz"
compact_attestation="${work_dir}/compact_attestation.json"
compact_key="${work_dir}/compact_attestation_pub.pem"
expected_score_plan="${work_dir}/expected_scores.json"
printf '{}\n' >"$compact_attestation"
printf 'test key\n' >"$compact_key"
printf '%s\n' '{"schema_version":1,"topology_hash":"topology-test","rubric_hash":"rubric-test","image_lock":"image-lock-test","mutation_suite_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","grader_source":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","reference_archive_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","equivalence_audit_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","archives":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"submission":"group3","attempt":"benchmark-000","as":3,"expected_total_class":"full","expected_total":10,"expected_checks":[{"question_id":"q1","check_id":"fixture.check","check_index":0,"status":"pass"}]}}}' >"$expected_score_plan"
grade_evidence="${work_dir}/benchmark_grade.json"
if ! TWINET_TOKEN=test-token bash scripts/scale_benchmark.sh --allow-destructive \
    --binary "$fake_controller" --manifest examples/scale --submissions "$submissions_dir" \
    --expected-submissions 1 --compact-attestation "$compact_attestation" \
    --compact-attestation-key "$compact_key" --expected-score-plan "$expected_score_plan" \
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
assert json.loads(pathlib.Path(sys.argv[1]).read_text())["budgets"]["expected_submissions"] == 1
PY
then
    fail "benchmark grading evidence omitted throughput or summary"
fi

tampered_plan="${work_dir}/expected_scores_tampered.json"
python3 - "$expected_score_plan" "$tampered_plan" <<'PY'
import json
import pathlib
import sys

plan = json.loads(pathlib.Path(sys.argv[1]).read_text())
entry = next(iter(plan["archives"].values()))
entry["attempt"] = "benchmark-tampered"
pathlib.Path(sys.argv[2]).write_text(json.dumps(plan))
PY
expect_status 1 "benchmark rejects tampered expected plan" env TWINET_TOKEN=test-token \
    bash scripts/scale_benchmark.sh --allow-destructive --binary "$fake_controller" \
    --manifest examples/scale --submissions "$submissions_dir" --expected-submissions 1 \
    --compact-attestation "$compact_attestation" --compact-attestation-key "$compact_key" \
    --expected-score-plan "$tampered_plan" --output "${work_dir}/benchmark_tampered.json"

printf 'release runner argument tests: ok\n'
