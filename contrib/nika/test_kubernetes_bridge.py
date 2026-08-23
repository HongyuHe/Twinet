"""Unit tests for the strict Kubernetes bridge boundary."""

from __future__ import annotations

import io
import json
import os
import subprocess
import unittest
from unittest import mock

import kubernetes_bridge as bridge


def request(operation: str = "discover") -> dict[str, object]:
    value: dict[str, object] = {
        "operation": operation,
        "endpoint": "https://127.0.0.1:6443",
        "context": "kind-twinet",
    }
    if operation != "discover":
        value.update(
            {
                "fault": "k8s_worker_apiserver_partition",
                "target": {
                    "device": "k8s/twinet-nika-fixture/worker-a",
                    "params": {
                        "namespace": "twinet-nika-fixture",
                        "cluster_id": "twinet-nika-cluster",
                        "node_name": "worker-a",
                    },
                },
            }
        )
    return value


def node(name: str, cluster_id: str, *, control: bool = False) -> dict[str, object]:
    labels = {bridge.CLUSTER_LABEL: cluster_id}
    if control:
        labels["node-role.kubernetes.io/control-plane"] = ""
    return {
        "metadata": {"name": name, "labels": labels},
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "addresses": [{"type": "InternalIP", "address": "192.0.2.10"}],
        },
    }


class FakeScopeKubectl:
    def __init__(self, *, marker: bool = True, owned: bool = True):
        self.marker = marker
        self.owned = owned

    def get_optional_json(self, args: list[str]) -> dict[str, object] | None:
        if "configmap" in args:
            if not self.marker:
                return None
            return {
                "metadata": {
                    "annotations": {bridge.ALLOW_NODE_FAULTS: "true"}
                },
                "data": {
                    "cluster_id": "twinet-nika-cluster",
                    "context": "kind-twinet",
                    "endpoint": "https://127.0.0.1:6443",
                },
            }
        return {
            "metadata": {
                "labels": {
                    bridge.CLUSTER_LABEL: (
                        "twinet-nika-cluster" if self.owned else "someone-else"
                    ),
                    bridge.MANAGED_LABEL: bridge.MANAGED_VALUE,
                }
            }
        }

    def get_json(self, _args: list[str]) -> dict[str, object]:
        return {
            "items": [
                node("control", "twinet-nika-cluster", control=True),
                node("worker-a", "twinet-nika-cluster"),
                node("worker-b", "twinet-nika-cluster"),
            ]
        }


class KubernetesBridgeProtocolTest(unittest.TestCase):
    def test_request_rejects_unknown_fields(self) -> None:
        value = request()
        value["unexpected"] = True
        with self.assertRaisesRegex(bridge.BridgeError, "unknown field"):
            bridge.decode_request(io.StringIO(json.dumps(value)))

    def test_request_rejects_credentialed_endpoint(self) -> None:
        value = request()
        value["endpoint"] = "https://user:not-a-real-credential@127.0.0.1:6443"
        with self.assertRaisesRegex(bridge.BridgeError, "without credentials"):
            bridge.decode_request(io.StringIO(json.dumps(value)))

    def test_target_field_types_are_strict(self) -> None:
        value = request("inject")
        target = value["target"]
        assert isinstance(target, dict)
        target["as"] = "1"
        with self.assertRaisesRegex(bridge.BridgeError, "must be an integer"):
            bridge.decode_request(io.StringIO(json.dumps(value)))

    def test_fixture_images_must_be_immutable(self) -> None:
        bridge.validate_image_reference(
            bridge.DEFAULT_WORKLOAD_IMAGE, "--workload-image"
        )
        bridge.validate_image_reference(
            bridge.DEFAULT_HELPER_IMAGE, "--helper-image"
        )
        for image in (
            "busybox:1.36.1",
            "busybox@sha256:not-a-digest",
            "busybox@sha256:" + ("a" * 63),
        ):
            with self.assertRaisesRegex(bridge.BridgeError, "immutable"):
                bridge.validate_image_reference(image, "--workload-image")

    def test_worker_fault_requires_an_explicit_disposable_cluster_marker(self) -> None:
        value = request("inject")
        with self.assertRaisesRegex(bridge.BridgeError, "disposable acceptance marker"):
            bridge.scope_from_request(
                FakeScopeKubectl(marker=False),  # type: ignore[arg-type]
                value,
                require_ready=True,
            )

    def test_fixture_namespace_must_belong_to_the_marked_cluster(self) -> None:
        value = request("inject")
        with self.assertRaisesRegex(bridge.BridgeError, "fixture namespace is not owned"):
            bridge.scope_from_request(
                FakeScopeKubectl(owned=False),  # type: ignore[arg-type]
                value,
                require_ready=True,
            )

    def test_valid_scope_names_a_real_worker_and_independent_worker(self) -> None:
        value = request("inject")
        scope = bridge.scope_from_request(
            FakeScopeKubectl(),  # type: ignore[arg-type]
            value,
            require_ready=True,
        )
        self.assertEqual(scope.target_node, "worker-a")
        self.assertEqual(scope.independent_node, "worker-b")
        self.assertEqual(scope.control_node, "control")

    def test_node_helper_is_host_scoped_and_owner_bounded(self) -> None:
        rules = bridge.address_rules(
            "0123456789abcdef", ["10.96.0.10"]
        )
        pod = bridge.helper_pod(
            "helper",
            "config",
            "twinet-nika-fixture",
            "worker-a",
            "0123456789abcdef",
            rules,
            bridge.DEFAULT_HELPER_IMAGE,
        )
        spec = pod["spec"]
        self.assertTrue(spec["hostNetwork"])
        security = spec["containers"][0]["securityContext"]
        self.assertEqual(security["capabilities"]["add"], ["NET_ADMIN", "NET_RAW"])
        self.assertFalse(security["allowPrivilegeEscalation"])
        command = " ".join(spec["containers"][0]["command"])
        self.assertNotIn("apk", command)
        self.assertIn("python /opt/twinet/helper.py", command)
        encoded_rules = next(
            item["value"]
            for item in spec["containers"][0]["env"]
            if item["name"] == "RULES_JSON"
        )
        self.assertIn("0123456789abcdef", encoded_rules)

    @mock.patch("subprocess.run")
    def test_kubectl_receives_no_controller_credentials(
        self, run: mock.Mock
    ) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=["kubectl"], returncode=0, stdout="ok\n", stderr=""
        )
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "KUBECONFIG": "/credentials/config",
                "AWS_SECRET_ACCESS_KEY": "do-not-pass",
                "TWINET_TOKEN": "do-not-pass",
            },
            clear=True,
        ):
            bridge.Kubectl(
                "kubectl", "kind-twinet", None, "/safe/cache"
            ).run(["version"])
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin"})
        self.assertIn("--cache-dir", run.call_args.args[0])

    @mock.patch("subprocess.run")
    def test_kubectl_diagnostics_never_cross_the_protocol(
        self, run: mock.Mock
    ) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=["kubectl"],
            returncode=1,
            stdout='{"users":[{"token":"should-never-appear"}]}',
            stderr="Authorization: Bearer should-never-appear",
        )
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.Kubectl("kubectl", "kind-twinet", None).run(["version"])
        self.assertNotIn("should-never-appear", str(caught.exception))
        self.assertNotIn("Authorization", str(caught.exception))

    def test_response_uses_only_the_go_protocol_fields(self) -> None:
        value = bridge.response(
            available=True,
            state={"namespace": "twinet-nika-fixture"},
            evidence_value=bridge.evidence(True, "active", "blocked", "blocked"),
        )
        self.assertEqual(set(value), {"available", "state", "evidence"})
        self.assertEqual(
            set(value["evidence"]),
            {"verified", "detail", "observed", "expected"},
        )


if __name__ == "__main__":
    unittest.main()
