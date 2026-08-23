#!/usr/bin/env python3
"""Strict kubectl bridge for Twinet's delegated NIKA Kubernetes faults."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TextIO
from urllib.parse import urlsplit


SUPPORTED_FAULTS = frozenset(
    {
        "k8s_clusterip_routing_broken",
        "k8s_coredns_isolated",
        "k8s_networkpolicy_deny",
        "k8s_worker_apiserver_partition",
    }
)
REQUEST_FIELDS = frozenset(
    {"operation", "fault", "target", "state", "endpoint", "context"}
)
TARGET_FIELDS = frozenset({"as", "device", "iface", "peer", "prefix", "params"})
STATE_FIELDS = frozenset(
    {
        "namespace",
        "owner",
        "fault",
        "baseline",
        "cluster_id",
        "target_node",
        "control_node",
        "independent_node",
        "service_ip",
        "server_ip",
        "control_service_ip",
        "helper_config",
        "helper_relay",
        "helpers",
        "policy_name",
        "stale_pod",
        "__delegated_initial_observed",
    }
)
DISPOSABLE_RE = re.compile(
    r"^twinet-nika-[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$"
)
CLUSTER_MARKER = "twinet-nika-disposable-cluster"
CLUSTER_LABEL = "twinet.dev/disposable-cluster"
MANAGED_LABEL = "twinet.dev/managed-by"
MANAGED_VALUE = "nika-kubernetes-acceptance"
ALLOW_NODE_FAULTS = "twinet.dev/allow-node-faults"
HELPER_PORT = 18080
FIXTURE_PODS = (
    "server",
    "control-server",
    "client-target",
    "client-control",
    "audit-target",
    "audit-independent",
    "audit-control",
)
FIXTURE_SERVICES = ("echo", "control")
DEFAULT_HELPER_IMAGE = (
    "docker.io/nicolaka/netshoot:v0.13@"
    "sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b"
)
DEFAULT_WORKLOAD_IMAGE = (
    "docker.io/library/busybox:1.36.1@"
    "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
)
IMMUTABLE_IMAGE_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")

HELPER_SOURCE = r"""
import hmac
import http.server
import json
import os
import socket
import subprocess

OWNER = os.environ["OWNER"]
RULES = json.loads(os.environ.get("RULES_JSON", "[]"))
PROBE_HOST = os.environ.get("PROBE_HOST", "")
PROBE_PORT = int(os.environ.get("PROBE_PORT", "0") or "0")

def command(action, rule):
    binary = "ip6tables" if rule.get("family") == 6 else "iptables"
    command = [binary, "-w", "5", "-t", "raw", action, rule["chain"]]
    if action == "-I":
        command.append("1")
    return [*command, *rule["args"]]

def valid(rule):
    args = rule.get("args") or []
    return (
        rule.get("chain") in {"PREROUTING", "OUTPUT", "INPUT"}
        and rule.get("family") in {4, 6}
        and all(isinstance(value, str) for value in args)
        and "-j" in args
        and args[args.index("-j") + 1] == "DROP"
        and any(OWNER in value for value in args)
    )

def exists(rule):
    return subprocess.run(command("-C", rule), capture_output=True).returncode == 0

def apply():
    for rule in RULES:
        if not valid(rule):
            raise RuntimeError("invalid rule")
        if not exists(rule):
            result = subprocess.run(command("-I", rule), capture_output=True)
            if result.returncode != 0:
                raise RuntimeError("iptables insert failed")

def remove():
    for rule in reversed(RULES):
        if not valid(rule):
            raise RuntimeError("invalid rule")
        while exists(rule):
            if subprocess.run(command("-D", rule), capture_output=True).returncode != 0:
                raise RuntimeError("iptables delete failed")

def status():
    probe = None
    if PROBE_HOST and PROBE_PORT:
        try:
            with socket.create_connection((PROBE_HOST, PROBE_PORT), timeout=2):
                probe = True
        except OSError:
            probe = False
    return {"applied": bool(RULES) and all(exists(rule) for rule in RULES),
            "probe_reachable": probe}

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def reply(self, code, payload):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def allowed(self):
        return hmac.compare_digest(self.headers.get("X-Twinet-Owner", ""), OWNER)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"ready": True})
            return
        if self.path != "/status" or not self.allowed():
            self.reply(403, {"error": "forbidden"})
            return
        self.reply(200, status())

    def do_POST(self):
        if not self.allowed():
            self.reply(403, {"error": "forbidden"})
            return
        try:
            if self.path == "/apply":
                apply()
            elif self.path == "/remove":
                remove()
            else:
                self.reply(404, {"error": "not found"})
                return
            self.reply(200, status())
        except Exception:
            self.reply(500, {"error": "node filter operation failed"})

http.server.ThreadingHTTPServer(("0.0.0.0", 18080), Handler).serve_forever()
"""

RELAY_SOURCE = (
    "import json,sys,urllib.request;"
    "method=sys.argv[3];"
    "request=urllib.request.Request(sys.argv[1],"
    "data=(b'' if method=='POST' else None),"
    "headers={'X-Twinet-Owner':sys.argv[2]},method=method);"
    "print(urllib.request.urlopen(request,timeout=12).read().decode())"
)


class BridgeError(RuntimeError):
    def __init__(self, message: str, state: dict[str, str] | None = None):
        super().__init__(message)
        self.state = state


class Kubectl:
    def __init__(
        self,
        binary: str,
        context: str,
        kubeconfig: str | None,
        cache_dir: str | None = None,
    ):
        self.binary = binary
        self.context = context
        self.kubeconfig = kubeconfig
        self.cache_dir = cache_dir

    def command(self, args: list[str]) -> list[str]:
        command = [self.binary]
        if self.kubeconfig:
            command.extend(["--kubeconfig", self.kubeconfig])
        if self.cache_dir:
            command.extend(["--cache-dir", self.cache_dir])
        command.extend(["--context", self.context])
        command.extend(args)
        return command

    def execute(
        self,
        args: list[str],
        *,
        input_value: dict[str, Any] | None = None,
        timeout: int = 45,
    ) -> subprocess.CompletedProcess[str]:
        payload = (
            json.dumps(input_value, separators=(",", ":"))
            if input_value is not None
            else None
        )
        try:
            return subprocess.run(
                self.command(args),
                input=payload,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                env={"PATH": os.environ.get("PATH", "")},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BridgeError(f"kubectl could not execute {safe_action(args)}") from exc

    def run(
        self,
        args: list[str],
        *,
        input_value: dict[str, Any] | None = None,
        timeout: int = 45,
    ) -> str:
        completed = self.execute(args, input_value=input_value, timeout=timeout)
        if completed.returncode != 0:
            raise BridgeError(
                f"kubectl {safe_action(args)} failed with exit status "
                f"{completed.returncode}"
            )
        return completed.stdout.strip()

    def succeeds(self, args: list[str], *, timeout: int = 45) -> bool:
        return self.execute(args, timeout=timeout).returncode == 0

    def get_json(self, args: list[str]) -> dict[str, Any]:
        raw = self.run(args)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BridgeError(f"kubectl {safe_action(args)} returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise BridgeError(f"kubectl {safe_action(args)} returned a non-object")
        return value

    def get_optional_json(self, args: list[str]) -> dict[str, Any] | None:
        raw = self.run([*args, "--ignore-not-found", "-o", "json"])
        if not raw:
            return None
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BridgeError(f"kubectl {safe_action(args)} returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise BridgeError(f"kubectl {safe_action(args)} returned a non-object")
        return value

    def apply(self, items: list[dict[str, Any]]) -> None:
        self.run(
            ["apply", "-f", "-"],
            input_value={"apiVersion": "v1", "kind": "List", "items": items},
            timeout=180,
        )


@dataclass(frozen=True)
class ClusterScope:
    cluster_id: str
    namespace: str
    target_node: str
    control_node: str
    independent_node: str
    nodes: dict[str, dict[str, Any]]


def safe_action(args: list[str]) -> str:
    for value in args:
        if value in {
            "get",
            "apply",
            "delete",
            "wait",
            "exec",
            "logs",
            "version",
            "config",
        }:
            return value
    return "request"


def decode_request(stream: TextIO) -> dict[str, Any]:
    raw = stream.read(1024 * 1024 + 1)
    if not raw or len(raw) > 1024 * 1024:
        raise BridgeError("invalid bridge request")
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BridgeError("invalid bridge request JSON") from exc
    if not isinstance(request, dict):
        raise BridgeError("bridge request must be a JSON object")
    unknown = set(request) - REQUEST_FIELDS
    if unknown:
        raise BridgeError(f"bridge request has unknown field {sorted(unknown)[0]!r}")

    operation = request.get("operation")
    endpoint = request.get("endpoint")
    context = request.get("context")
    if operation not in {"discover", "inject", "verify", "resolve"}:
        raise BridgeError("bridge request has an unsupported operation")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise BridgeError("bridge request requires endpoint")
    if not isinstance(context, str) or not context.strip():
        raise BridgeError("bridge request requires context")
    validate_endpoint(endpoint)

    fault = request.get("fault", "")
    if operation != "discover":
        if not isinstance(fault, str) or fault not in SUPPORTED_FAULTS:
            raise BridgeError("bridge request names an unsupported fault")
    elif fault not in ("", None):
        raise BridgeError("discover request must not name a fault")

    target = request.get("target", {})
    if not isinstance(target, dict) or set(target) - TARGET_FIELDS:
        raise BridgeError("bridge request has an invalid target")
    for field in ("device", "iface", "prefix"):
        if field in target and not isinstance(target[field], str):
            raise BridgeError(f"bridge target field {field!r} must be a string")
    for field in ("as", "peer"):
        if field in target and not isinstance(target[field], int):
            raise BridgeError(f"bridge target field {field!r} must be an integer")
    params = target.get("params", {})
    if not isinstance(params, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in params.items()
    ):
        raise BridgeError("bridge target params must be strings")

    state = request.get("state", {})
    if not isinstance(state, dict) or set(state) - STATE_FIELDS or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in state.items()
    ):
        raise BridgeError("bridge request has invalid delegated state")
    return request


def validate_endpoint(endpoint: str) -> None:
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise BridgeError("Kubernetes endpoint must be an HTTP(S) URL without credentials")


def normalize_endpoint(endpoint: str) -> str:
    return endpoint.rstrip("/")


def validate_image_reference(image: str, option: str) -> None:
    if not IMMUTABLE_IMAGE_RE.fullmatch(image):
        raise BridgeError(f"{option} must be an immutable @sha256 image reference")


def ready(node: dict[str, Any]) -> bool:
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in (node.get("status") or {}).get("conditions") or []
    )


def node_internal_ip(node: dict[str, Any]) -> str:
    for address in (node.get("status") or {}).get("addresses") or []:
        if address.get("type") == "InternalIP":
            return str(address.get("address") or "")
    return ""


def is_control_plane(node: dict[str, Any]) -> bool:
    labels = (node.get("metadata") or {}).get("labels") or {}
    return (
        "node-role.kubernetes.io/control-plane" in labels
        or "node-role.kubernetes.io/master" in labels
    )


def scope_from_request(
    kubectl: Kubectl, request: dict[str, Any], *, require_ready: bool
) -> ClusterScope:
    target = request.get("target") or {}
    params = target.get("params") or {}
    cluster_id = params.get("cluster_id", "")
    namespace = params.get("namespace", "")
    target_node = params.get("node_name", "")
    if not DISPOSABLE_RE.fullmatch(cluster_id):
        raise BridgeError("target.params.cluster_id must be a twinet-nika-* identifier")
    if not DISPOSABLE_RE.fullmatch(namespace):
        raise BridgeError("target.params.namespace must be a twinet-nika-* fixture")
    if not target_node:
        raise BridgeError("target.params.node_name must name a disposable worker")
    device = target.get("device", "")
    if device and device != f"k8s/{namespace}/{target_node}":
        raise BridgeError("target device must be k8s/<namespace>/<worker>")

    marker = kubectl.get_optional_json(
        ["-n", "kube-system", "get", "configmap", CLUSTER_MARKER]
    )
    if marker is None:
        raise BridgeError("cluster lacks the disposable acceptance marker")
    data = marker.get("data") or {}
    annotations = (marker.get("metadata") or {}).get("annotations") or {}
    if (
        data.get("cluster_id") != cluster_id
        or data.get("context") != request["context"]
        or normalize_endpoint(data.get("endpoint", ""))
        != normalize_endpoint(request["endpoint"])
        or annotations.get(ALLOW_NODE_FAULTS) != "true"
    ):
        raise BridgeError("cluster disposable marker does not authorize this endpoint")

    node_items = (
        kubectl.get_json(["get", "nodes", "-o", "json"]).get("items") or []
    )
    nodes = {
        str((node.get("metadata") or {}).get("name") or ""): node
        for node in node_items
    }
    controls = sorted(name for name, node in nodes.items() if is_control_plane(node))
    workers = sorted(name for name, node in nodes.items() if name and name not in controls)
    if len(controls) != 1 or len(workers) < 2:
        raise BridgeError(
            "disposable acceptance requires one control plane and at least two workers"
        )
    if target_node not in workers:
        raise BridgeError("target.params.node_name is not a disposable worker")
    independent = next((name for name in workers if name != target_node), "")
    for name, node in nodes.items():
        labels = (node.get("metadata") or {}).get("labels") or {}
        if labels.get(CLUSTER_LABEL) != cluster_id:
            raise BridgeError(f"node {name!r} lacks the disposable cluster ownership label")
        if require_ready and not ready(node):
            raise BridgeError(f"node {name!r} is not Ready at baseline")

    fixture = kubectl.get_optional_json(["get", "namespace", namespace])
    if fixture is None:
        raise BridgeError("disposable fixture namespace does not exist")
    labels = (fixture.get("metadata") or {}).get("labels") or {}
    if labels.get(CLUSTER_LABEL) != cluster_id or labels.get(MANAGED_LABEL) != MANAGED_VALUE:
        raise BridgeError("fixture namespace is not owned by this disposable acceptance")
    return ClusterScope(
        cluster_id,
        namespace,
        target_node,
        controls[0],
        independent,
        nodes,
    )


def pod_ready(pod: dict[str, Any]) -> bool:
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in (pod.get("status") or {}).get("conditions") or []
    )


def fixture_state(kubectl: Kubectl, scope: ClusterScope) -> dict[str, str]:
    pods: dict[str, dict[str, Any]] = {}
    for name in FIXTURE_PODS:
        pod = kubectl.get_json(
            ["-n", scope.namespace, "get", "pod", name, "-o", "json"]
        )
        if not pod_ready(pod):
            raise BridgeError(f"fixture pod {name!r} is not Ready")
        pods[name] = pod
    if (pods["server"].get("spec") or {}).get("nodeName") != scope.target_node:
        raise BridgeError("fixture server is not on the named worker")
    if (pods["client-target"].get("spec") or {}).get("nodeName") != scope.target_node:
        raise BridgeError("fixture target client is not on the named worker")
    for name in ("control-server", "client-control"):
        if (pods[name].get("spec") or {}).get("nodeName") != scope.independent_node:
            raise BridgeError(f"fixture pod {name!r} is not on the independent worker")
    for name, node in {
        "audit-target": scope.target_node,
        "audit-independent": scope.independent_node,
        "audit-control": scope.control_node,
    }.items():
        if (pods[name].get("spec") or {}).get("nodeName") != node:
            raise BridgeError(f"fixture pod {name!r} is not on {node!r}")

    services = {
        name: kubectl.get_json(
            ["-n", scope.namespace, "get", "service", name, "-o", "json"]
        )
        for name in FIXTURE_SERVICES
    }
    service_ip = str((services["echo"].get("spec") or {}).get("clusterIP") or "")
    control_ip = str(
        (services["control"].get("spec") or {}).get("clusterIP") or ""
    )
    server_ip = str((pods["server"].get("status") or {}).get("podIP") or "")
    for address in (service_ip, control_ip, server_ip):
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise BridgeError("fixture has an invalid service or pod address") from exc
    return {
        "service_ip": service_ip,
        "server_ip": server_ip,
        "control_service_ip": control_ip,
    }


def pod_probe(
    kubectl: Kubectl, namespace: str, pod: str, script: str
) -> str:
    try:
        output = kubectl.run(
            ["-n", namespace, "exec", pod, "--", "sh", "-c", script],
            timeout=15,
        )
    except BridgeError as exc:
        raise BridgeError(f"probe pod {pod!r} could not execute") from exc
    return output.splitlines()[-1].strip() if output else ""


def http_probe(
    kubectl: Kubectl,
    namespace: str,
    pod: str,
    address: str,
    port: int = 80,
) -> str:
    host = f"[{address}]" if ":" in address else address
    return pod_probe(
        kubectl,
        namespace,
        pod,
        'if [ "$(wget -q -T 3 -O - http://'
        + host
        + f":{port}/"
        + ' 2>/dev/null)" = twinet-ok ]; '
        "then echo reachable; else echo blocked; fi",
    )


def dns_probe(kubectl: Kubectl, namespace: str, pod: str) -> str:
    return pod_probe(
        kubectl,
        namespace,
        pod,
        f"if nslookup echo.{namespace}.svc.cluster.local >/dev/null 2>&1; "
        "then echo reachable; else echo blocked; fi",
    )


def wait_for(
    observe: Callable[[], str], expected: str, *, timeout: int = 60
) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    observed = ""
    while True:
        observed = observe()
        if observed == expected:
            return True, observed
        if time.monotonic() >= deadline:
            return False, observed
        time.sleep(2)


def wait_node_ready(
    kubectl: Kubectl, node_name: str, wanted: bool, *, timeout: int
) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        node = kubectl.get_json(["get", "node", node_name, "-o", "json"])
        if ready(node) == wanted:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(5)


def node_resolved_addresses(
    kubectl: Kubectl, namespace: str, audit_pod: str, host: str, port: int
) -> list[str]:
    source = (
        "import json,socket,sys;"
        "print(json.dumps(sorted({item[4][0] for item in "
        "socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)})))"
    )
    try:
        raw = kubectl.run(
            [
                "-n",
                namespace,
                "exec",
                audit_pod,
                "--",
                "python",
                "-c",
                source,
                host,
                str(port),
            ]
        )
        addresses = json.loads(raw)
    except (BridgeError, json.JSONDecodeError) as exc:
        raise BridgeError("could not resolve the worker's API-server path") from exc
    if not isinstance(addresses, list) or not addresses:
        raise BridgeError("worker resolved no API-server address")
    for address in addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise BridgeError("worker resolved an invalid API-server address") from exc
    return [str(address) for address in addresses]


def baseline_evidence(
    kubectl: Kubectl, state: dict[str, str], *, wait_worker: bool = False
) -> dict[str, Any]:
    namespace = state["namespace"]
    service_ok, service_observed = wait_for(
        lambda: http_probe(
            kubectl, namespace, "client-target", state["service_ip"]
        ),
        "reachable",
        timeout=90,
    )
    independent_ok, independent_observed = wait_for(
        lambda: http_probe(
            kubectl, namespace, "client-control", state["service_ip"]
        ),
        "reachable",
        timeout=90,
    )
    control_ok, control_observed = wait_for(
        lambda: http_probe(
            kubectl, namespace, "client-control", state["control_service_ip"]
        ),
        "reachable",
        timeout=90,
    )
    dns_ok, dns_observed = wait_for(
        lambda: dns_probe(kubectl, namespace, "client-control"),
        "reachable",
        timeout=90,
    )
    worker_ok = (
        wait_node_ready(kubectl, state["target_node"], True, timeout=240)
        if wait_worker
        else ready(
            kubectl.get_json(
                ["get", "node", state["target_node"], "-o", "json"]
            )
        )
    )
    logs_ok = kubectl.succeeds(
        [
            "-n",
            namespace,
            "logs",
            "server",
            "--tail=1",
            "--request-timeout=10s",
        ],
        timeout=15,
    )
    restored = (
        service_ok and independent_ok and control_ok and dns_ok and worker_ok and logs_ok
    )
    return evidence(
        False,
        "fault absent; disposable worker fixture baseline restored"
        if restored
        else "fault is absent but the disposable worker fixture is not restored",
        f"target_service={service_observed}, independent_service={independent_observed}, "
        f"control={control_observed}, dns={dns_observed}, "
        f"worker_ready={worker_ok}, logs={logs_ok}",
        "all fixture paths reachable, worker Ready, and logs available",
    )


def assert_baseline(kubectl: Kubectl, state: dict[str, str]) -> None:
    observed = baseline_evidence(kubectl, state)
    if "not restored" in observed["detail"]:
        raise BridgeError(observed["detail"], state)


def rule(
    owner: str, chain: str, args: list[str], *, family: int = 4
) -> dict[str, Any]:
    comment = f"twinet-nika-{owner}"
    return {
        "chain": chain,
        "family": family,
        "args": [
            *args,
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "DROP",
        ],
    }


def address_rules(owner: str, addresses: list[str], *, port: int | None = None) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for address in addresses:
        network = ipaddress.ip_network(address, strict=False)
        protocols = ("tcp", "udp") if port is not None else (None,)
        for protocol in protocols:
            args = ["-d", address]
            if protocol:
                args.extend(["-p", protocol, "--dport", str(port)])
            for chain in ("PREROUTING", "OUTPUT"):
                rules.append(rule(owner, chain, args, family=network.version))
    return rules


def helper_config(name: str, namespace: str, owner: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {MANAGED_LABEL: MANAGED_VALUE, "twinet.dev/owner": owner},
        },
        "data": {"helper.py": HELPER_SOURCE},
    }


def pod_tolerations() -> list[dict[str, str]]:
    return [{"operator": "Exists"}]


def relay_pod(
    name: str, namespace: str, node: str, owner: str, image: str
) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {MANAGED_LABEL: MANAGED_VALUE, "twinet.dev/owner": owner},
        },
        "spec": {
            "nodeName": node,
            "tolerations": pod_tolerations(),
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "relay",
                    "image": image,
                    "command": ["sh", "-c", "exec sleep 86400"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "runAsGroup": 65534,
                    },
                }
            ],
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
        },
    }


def helper_pod(
    name: str,
    config: str,
    namespace: str,
    node: str,
    owner: str,
    rules: list[dict[str, Any]],
    image: str,
    probe_host: str = "",
    probe_port: int = 0,
) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {MANAGED_LABEL: MANAGED_VALUE, "twinet.dev/owner": owner},
        },
        "spec": {
            "nodeName": node,
            "hostNetwork": True,
            "dnsPolicy": "ClusterFirstWithHostNet",
            "tolerations": pod_tolerations(),
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "helper",
                    "image": image,
                    "command": [
                        "sh",
                        "-c",
                        "exec python /opt/twinet/helper.py",
                    ],
                    "env": [
                        {"name": "OWNER", "value": owner},
                        {
                            "name": "RULES_JSON",
                            "value": json.dumps(rules, separators=(",", ":")),
                        },
                        {"name": "PROBE_HOST", "value": probe_host},
                        {"name": "PROBE_PORT", "value": str(probe_port)},
                    ],
                    "ports": [{"name": "control", "containerPort": HELPER_PORT}],
                    "readinessProbe": {
                        "httpGet": {"path": "/health", "port": HELPER_PORT},
                        "periodSeconds": 2,
                        "failureThreshold": 60,
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {
                            "drop": ["ALL"],
                            "add": ["NET_ADMIN", "NET_RAW"],
                        },
                        "runAsUser": 0,
                        "runAsGroup": 0,
                    },
                    "volumeMounts": [
                        {
                            "name": "script",
                            "mountPath": "/opt/twinet",
                            "readOnly": True,
                        }
                    ],
                }
            ],
            "volumes": [
                {
                    "name": "script",
                    "configMap": {"name": config, "defaultMode": 365},
                }
            ],
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
        },
    }


def wait_pods(kubectl: Kubectl, namespace: str, names: list[str]) -> None:
    kubectl.run(
        [
            "-n",
            namespace,
            "wait",
            "--for=condition=Ready",
            *[f"pod/{name}" for name in names],
            "--timeout=180s",
        ],
        timeout=190,
    )


def helper_request(
    kubectl: Kubectl,
    state: dict[str, str],
    helper: dict[str, str],
    action: str,
) -> dict[str, Any]:
    method = "GET" if action == "status" else "POST"
    try:
        raw = kubectl.run(
            [
                "-n",
                state["namespace"],
                "exec",
                state["helper_relay"],
                "--",
                "python",
                "-c",
                RELAY_SOURCE,
                f"http://{helper['ip']}:{HELPER_PORT}/{action}",
                state["owner"],
                method,
            ],
            timeout=20,
        )
    except BridgeError as exc:
        raise BridgeError(
            f"independent relay could not reach worker helper for {action}", state
        ) from exc
    try:
        value = json.loads(raw.splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise BridgeError("worker helper returned invalid status", state) from exc
    if not isinstance(value, dict) or value.get("error"):
        raise BridgeError("worker helper rejected the node filter operation", state)
    return value


def helpers_from_state(state: dict[str, str]) -> list[dict[str, str]]:
    if not state.get("helpers"):
        return []
    try:
        value = json.loads(state["helpers"])
    except json.JSONDecodeError as exc:
        raise BridgeError("delegated helper state is invalid", state) from exc
    if not isinstance(value, list) or any(
        not isinstance(item, dict)
        or not all(isinstance(item.get(key), str) for key in ("node", "ip", "pod"))
        for item in value
    ):
        raise BridgeError("delegated helper state is invalid", state)
    return value


def create_helpers(
    kubectl: Kubectl,
    scope: ClusterScope,
    state: dict[str, str],
    plans: list[tuple[str, list[dict[str, Any]], str, int]],
    image: str,
) -> None:
    config = f"twinet-helper-{state['owner']}"
    relay = f"twinet-relay-{state['owner']}"
    helpers: list[dict[str, str]] = []
    resources: list[dict[str, Any]] = [
        helper_config(config, scope.namespace, state["owner"]),
        relay_pod(
            relay,
            scope.namespace,
            scope.independent_node,
            state["owner"],
            image,
        ),
    ]
    for index, (node, rules, probe_host, probe_port) in enumerate(plans):
        name = f"twinet-helper-{state['owner']}-{index}"
        address = node_internal_ip(scope.nodes[node])
        if not address:
            raise BridgeError(f"node {node!r} has no InternalIP", state)
        helpers.append({"node": node, "ip": address, "pod": name})
        resources.append(
            helper_pod(
                name,
                config,
                scope.namespace,
                node,
                state["owner"],
                rules,
                image,
                probe_host,
                probe_port,
            )
        )
    state["helper_config"] = config
    state["helper_relay"] = relay
    state["helpers"] = json.dumps(helpers, separators=(",", ":"))
    kubectl.apply(resources)
    wait_pods(kubectl, scope.namespace, [relay, *[h["pod"] for h in helpers]])
    for helper in helpers:
        status = helper_request(kubectl, state, helper, "apply")
        if not status.get("applied"):
            raise BridgeError("worker helper did not install its node filters", state)


def helper_filters_active(kubectl: Kubectl, state: dict[str, str]) -> bool:
    helpers = helpers_from_state(state)
    if not helpers:
        return False
    relay = kubectl.get_optional_json(
        ["-n", state["namespace"], "get", "pod", state["helper_relay"]]
    )
    if relay is None:
        return False
    return all(
        bool(helper_request(kubectl, state, helper, "status").get("applied"))
        for helper in helpers
    )


def cleanup_helpers(kubectl: Kubectl, state: dict[str, str]) -> None:
    names = [helper["pod"] for helper in helpers_from_state(state)]
    if state.get("helper_relay"):
        names.append(state["helper_relay"])
    if names:
        kubectl.run(
            [
                "-n",
                state["namespace"],
                "delete",
                "pod",
                *names,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=120s",
            ],
            timeout=130,
        )
    if state.get("helper_config"):
        kubectl.run(
            [
                "-n",
                state["namespace"],
                "delete",
                "configmap",
                state["helper_config"],
                "--ignore-not-found",
            ]
        )


def policy_manifest(namespace: str, owner: str, name: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {MANAGED_LABEL: MANAGED_VALUE, "twinet.dev/owner": owner},
        },
        "spec": {
            "podSelector": {"matchLabels": {"app": "server"}},
            "policyTypes": ["Ingress"],
            "ingress": [],
        },
    }


def stale_pod_manifest(namespace: str, node: str, name: str, image: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {MANAGED_LABEL: MANAGED_VALUE},
        },
        "spec": {
            "nodeName": node,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "probe",
                    "image": image,
                    "command": ["sh", "-c", "exec sleep 86400"],
                }
            ],
        },
    }


def discover(kubectl: Kubectl, request: dict[str, Any]) -> dict[str, Any]:
    config = kubectl.get_json(["config", "view", "--minify", "-o", "json"])
    clusters = config.get("clusters") or []
    server = ""
    if clusters:
        server = ((clusters[0].get("cluster") or {}).get("server") or "").strip()
    if normalize_endpoint(server) != normalize_endpoint(request["endpoint"].strip()):
        return response(
            available=False,
            reason="configured context does not select the named Kubernetes endpoint",
        )
    kubectl.run(["version", "--request-timeout=10s", "-o", "json"], timeout=15)
    return response(
        available=True,
        reason="kubectl reached the named Kubernetes endpoint and context",
    )


def prepare_state(
    kubectl: Kubectl, request: dict[str, Any]
) -> tuple[ClusterScope, dict[str, str]]:
    scope = scope_from_request(kubectl, request, require_ready=True)
    fixture = fixture_state(kubectl, scope)
    state = {
        "namespace": scope.namespace,
        "owner": secrets.token_hex(8),
        "fault": request["fault"],
        "baseline": "fixture_intact",
        "cluster_id": scope.cluster_id,
        "target_node": scope.target_node,
        "control_node": scope.control_node,
        "independent_node": scope.independent_node,
        **fixture,
    }
    assert_baseline(kubectl, state)
    return scope, state


def apply_fault(
    kubectl: Kubectl,
    request: dict[str, Any],
    scope: ClusterScope,
    state: dict[str, str],
    helper_image: str,
    workload_image: str,
) -> None:
    fault = request["fault"]
    if fault == "k8s_clusterip_routing_broken":
        create_helpers(
            kubectl,
            scope,
            state,
            [
                (
                    scope.target_node,
                    address_rules(state["owner"], [state["service_ip"]]),
                    "",
                    0,
                )
            ],
            helper_image,
        )
        return
    if fault == "k8s_coredns_isolated":
        service = kubectl.get_json(
            ["-n", "kube-system", "get", "service", "kube-dns", "-o", "json"]
        )
        dns_ip = str((service.get("spec") or {}).get("clusterIP") or "")
        endpoints = kubectl.get_json(
            ["-n", "kube-system", "get", "endpoints", "kube-dns", "-o", "json"]
        )
        endpoint_ips = sorted(
            {
                str(address.get("ip") or "")
                for subset in endpoints.get("subsets") or []
                for address in subset.get("addresses") or []
                if address.get("ip")
            }
        )
        pods = (
            kubectl.get_json(
                [
                    "-n",
                    "kube-system",
                    "get",
                    "pods",
                    "-l",
                    "k8s-app=kube-dns",
                    "-o",
                    "json",
                ]
            ).get("items")
            or []
        )
        nodes = sorted(
            {
                str((pod.get("spec") or {}).get("nodeName") or "")
                for pod in pods
                if (pod.get("spec") or {}).get("nodeName")
            }
        )
        if not dns_ip or not endpoint_ips or not nodes or not all(pod_ready(pod) for pod in pods):
            raise BridgeError("CoreDNS does not have ready service endpoints", state)
        rules = address_rules(
            state["owner"], [dns_ip, *endpoint_ips], port=53
        )
        create_helpers(
            kubectl,
            scope,
            state,
            [(node, rules, "", 0) for node in nodes],
            helper_image,
        )
        return
    if fault == "k8s_networkpolicy_deny":
        policy = f"twinet-deny-{state['owner']}"
        state["policy_name"] = policy
        kubectl.apply([policy_manifest(scope.namespace, state["owner"], policy)])
        return

    api_port = int((request.get("target") or {}).get("params", {}).get("apiserver_port", "6443"))
    addresses = node_resolved_addresses(
        kubectl,
        scope.namespace,
        "audit-target",
        scope.control_node,
        api_port,
    )
    rules = [
        rule(
            state["owner"],
            "OUTPUT",
            ["-d", address, "-p", "tcp", "--dport", str(api_port)],
            family=ipaddress.ip_address(address).version,
        )
        for address in addresses
    ]
    rules.extend(
        [
            rule(
                state["owner"],
                "PREROUTING",
                ["-p", "tcp", "--dport", "10250"],
                family=family,
            )
            for family in (4, 6)
        ]
    )
    create_helpers(
        kubectl,
        scope,
        state,
        [(scope.target_node, rules, scope.control_node, api_port)],
        helper_image,
    )
    if not wait_node_ready(kubectl, scope.target_node, False, timeout=180):
        raise BridgeError("worker did not become NotReady after API partition", state)
    stale = f"twinet-stale-{state['owner']}"
    state["stale_pod"] = stale
    kubectl.apply(
        [stale_pod_manifest(scope.namespace, scope.target_node, stale, workload_image)]
    )


def verify_fault(
    kubectl: Kubectl,
    request: dict[str, Any],
    state: dict[str, str],
) -> dict[str, Any]:
    scope = validated_state(kubectl, request, state)
    fault = request["fault"]
    if fault == "k8s_networkpolicy_deny":
        policy = kubectl.get_optional_json(
            [
                "-n",
                scope.namespace,
                "get",
                "networkpolicy",
                state["policy_name"],
            ]
        )
        if policy is None:
            restored = baseline_evidence(kubectl, state)
            if "not restored" in restored["detail"]:
                raise BridgeError(restored["detail"], state)
            return restored
        blocked, blocked_observed = wait_for(
            lambda: http_probe(
                kubectl,
                scope.namespace,
                "client-control",
                state["service_ip"],
            ),
            "blocked",
        )
        control, control_observed = wait_for(
            lambda: http_probe(
                kubectl,
                scope.namespace,
                "client-control",
                state["control_service_ip"],
            ),
            "reachable",
        )
        active = blocked and control
        return evidence(
            active,
            "NetworkPolicy denies only the selected ready workload"
            if active
            else "NetworkPolicy did not preserve its independent control path",
            f"selected={blocked_observed}, control={control_observed}",
            "selected Service blocked and control Service reachable",
        )

    if not helper_filters_active(kubectl, state):
        restored = baseline_evidence(
            kubectl,
            state,
            wait_worker=fault == "k8s_worker_apiserver_partition",
        )
        if "not restored" in restored["detail"]:
            raise BridgeError(restored["detail"], state)
        return restored

    if fault == "k8s_clusterip_routing_broken":
        target, target_observed = wait_for(
            lambda: http_probe(
                kubectl,
                scope.namespace,
                "client-target",
                state["service_ip"],
            ),
            "blocked",
        )
        direct, direct_observed = wait_for(
            lambda: http_probe(
                kubectl,
                scope.namespace,
                "client-target",
                state["server_ip"],
                8080,
            ),
            "reachable",
        )
        independent, independent_observed = wait_for(
            lambda: http_probe(
                kubectl,
                scope.namespace,
                "client-control",
                state["service_ip"],
            ),
            "reachable",
        )
        node_ok = ready(kubectl.get_json(["get", "node", scope.target_node, "-o", "json"]))
        active = target and direct and independent and node_ok
        return evidence(
            active,
            "named worker has broken ClusterIP routing while pod-IP and other-worker paths remain healthy"
            if active
            else "worker-scoped ClusterIP routing did not show the NIKA contrast",
            f"target_clusterip={target_observed}, target_pod_ip={direct_observed}, "
            f"independent_clusterip={independent_observed}, worker_ready={node_ok}",
            "target ClusterIP blocked, target pod IP and independent ClusterIP reachable",
        )

    if fault == "k8s_coredns_isolated":
        dns, dns_observed = wait_for(
            lambda: dns_probe(kubectl, scope.namespace, "client-control"),
            "blocked",
        )
        direct, direct_observed = wait_for(
            lambda: http_probe(
                kubectl,
                scope.namespace,
                "client-control",
                state["service_ip"],
            ),
            "reachable",
        )
        pods = (
            kubectl.get_json(
                [
                    "-n",
                    "kube-system",
                    "get",
                    "pods",
                    "-l",
                    "k8s-app=kube-dns",
                    "-o",
                    "json",
                ]
            ).get("items")
            or []
        )
        pods_ok = bool(pods) and all(pod_ready(pod) for pod in pods)
        active = dns and direct and pods_ok
        return evidence(
            active,
            "CoreDNS is isolated on its serving node while pods remain Ready and IP traffic works"
            if active
            else "CoreDNS isolation did not preserve healthy DNS pods and IP traffic",
            f"dns={dns_observed}, direct_ip={direct_observed}, pods_ready={pods_ok}",
            "DNS blocked, direct IP reachable, and CoreDNS pods Ready",
        )

    helper = helpers_from_state(state)[0]
    status = helper_request(kubectl, state, helper, "status")
    not_ready = wait_node_ready(kubectl, scope.target_node, False, timeout=180)
    workload, workload_observed = wait_for(
        lambda: http_probe(
            kubectl,
            scope.namespace,
            "client-control",
            state["server_ip"],
            8080,
        ),
        "reachable",
        timeout=30,
    )
    logs_blocked = not kubectl.succeeds(
        [
            "-n",
            scope.namespace,
            "logs",
            "server",
            "--tail=1",
            "--request-timeout=8s",
        ],
        timeout=12,
    )
    stale = kubectl.get_json(
        ["-n", scope.namespace, "get", "pod", state["stale_pod"], "-o", "json"]
    )
    stale_phase = str((stale.get("status") or {}).get("phase") or "")
    api_blocked = status.get("probe_reachable") is False
    active = (
        bool(status.get("applied"))
        and api_blocked
        and not_ready
        and workload
        and logs_blocked
        and stale_phase != "Running"
    )
    return evidence(
        active,
        "named worker lost API connectivity and became stale while its existing workload kept serving"
        if active
        else "worker API partition did not produce the NIKA node/workload signature",
        f"api_reachable={status.get('probe_reachable')}, worker_not_ready={not_ready}, "
        f"workload={workload_observed}, logs_blocked={logs_blocked}, "
        f"new_pod_phase={stale_phase or 'unset'}",
        "API blocked, worker NotReady, logs blocked, existing pod IP reachable, new pod stale",
    )


def validated_state(
    kubectl: Kubectl, request: dict[str, Any], state: dict[str, str]
) -> ClusterScope:
    required = {
        "namespace",
        "owner",
        "fault",
        "baseline",
        "cluster_id",
        "target_node",
        "control_node",
        "independent_node",
        "service_ip",
        "server_ip",
        "control_service_ip",
    }
    if not required.issubset(state):
        raise BridgeError("delegated state is incomplete")
    if state["baseline"] != "fixture_intact" or state["fault"] != request["fault"]:
        raise BridgeError("delegated state belongs to another fault or baseline")
    if not re.fullmatch(r"[0-9a-f]{16}", state["owner"]):
        raise BridgeError("delegated state has an invalid owner")
    scope = scope_from_request(kubectl, request, require_ready=False)
    if (
        state["namespace"] != scope.namespace
        or state["cluster_id"] != scope.cluster_id
        or state["target_node"] != scope.target_node
        or state["control_node"] != scope.control_node
        or state["independent_node"] != scope.independent_node
    ):
        raise BridgeError("delegated state belongs to another disposable cluster")
    return scope


def inject(
    kubectl: Kubectl,
    request: dict[str, Any],
    helper_image: str,
    workload_image: str,
) -> dict[str, Any]:
    state: dict[str, str] | None = None
    try:
        scope, state = prepare_state(kubectl, request)
        apply_fault(
            kubectl,
            request,
            scope,
            state,
            helper_image,
            workload_image,
        )
        observed = verify_fault(kubectl, request, state)
        if not observed["verified"]:
            raise BridgeError(
                f"{observed['detail']}: {observed['observed']}", state
            )
        return response(available=True, state=state, evidence_value=observed)
    except BridgeError as exc:
        if exc.state is None:
            exc.state = state
        raise


def resolve(kubectl: Kubectl, request: dict[str, Any]) -> dict[str, Any]:
    state = request.get("state") or {}
    validated_state(kubectl, request, state)
    fault = request["fault"]
    if fault == "k8s_networkpolicy_deny":
        if state.get("policy_name"):
            kubectl.run(
                [
                    "-n",
                    state["namespace"],
                    "delete",
                    "networkpolicy",
                    state["policy_name"],
                    "--ignore-not-found",
                ]
            )
    else:
        helpers = helpers_from_state(state)
        relay = kubectl.get_optional_json(
            ["-n", state["namespace"], "get", "pod", state.get("helper_relay", "")]
        )
        if helpers and relay is None:
            raise BridgeError(
                "worker filters may be active but their independent relay is missing",
                state,
            )
        for helper in helpers:
            helper_request(kubectl, state, helper, "remove")
        for helper in helpers:
            if helper_request(kubectl, state, helper, "status").get("applied"):
                raise BridgeError("worker node filter remained after resolve", state)

    if fault == "k8s_worker_apiserver_partition":
        if not wait_node_ready(kubectl, state["target_node"], True, timeout=240):
            raise BridgeError("worker did not return to Ready after API restoration", state)
        if not kubectl.succeeds(
            [
                "-n",
                state["namespace"],
                "logs",
                "server",
                "--tail=1",
                "--request-timeout=10s",
            ],
            timeout=15,
        ):
            raise BridgeError("worker logs did not recover after API restoration", state)
        if state.get("stale_pod"):
            kubectl.run(
                [
                    "-n",
                    state["namespace"],
                    "wait",
                    "--for=condition=Ready",
                    f"pod/{state['stale_pod']}",
                    "--timeout=120s",
                ],
                timeout=130,
            )
            kubectl.run(
                [
                    "-n",
                    state["namespace"],
                    "delete",
                    "pod",
                    state["stale_pod"],
                    "--wait=true",
                    "--timeout=120s",
                ],
                timeout=130,
            )

    restored = baseline_evidence(
        kubectl,
        state,
        wait_worker=fault == "k8s_worker_apiserver_partition",
    )
    if "not restored" in restored["detail"]:
        raise BridgeError(restored["detail"], state)
    cleanup_helpers(kubectl, state)
    return response(available=True, evidence_value=restored)


def evidence(
    verified: bool, detail: str, observed: str, expected: str
) -> dict[str, Any]:
    return {
        "verified": verified,
        "detail": detail,
        "observed": observed,
        "expected": expected,
    }


def response(
    *,
    available: bool,
    reason: str = "",
    state: dict[str, str] | None = None,
    evidence_value: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    value: dict[str, Any] = {"available": available}
    if reason:
        value["reason"] = reason
    if state:
        value["state"] = state
    if evidence_value:
        value["evidence"] = evidence_value
    if error:
        value["error"] = error
    return value


def default_kubeconfig() -> str | None:
    candidate = Path.home() / ".kube" / "config"
    return str(candidate) if candidate.is_file() else None


def default_cache_dir() -> str:
    return str(Path.home() / ".cache" / "twinet-kubernetes-bridge")


def run(
    request: dict[str, Any],
    *,
    kubectl_binary: str,
    kubeconfig: str | None,
    cache_dir: str,
    helper_image: str,
    workload_image: str,
) -> dict[str, Any]:
    kubectl = Kubectl(kubectl_binary, request["context"], kubeconfig, cache_dir)
    operation = request["operation"]
    if operation == "discover":
        return discover(kubectl, request)
    if operation == "inject":
        return inject(kubectl, request, helper_image, workload_image)
    if operation == "verify":
        return response(
            available=True,
            evidence_value=verify_fault(kubectl, request, request.get("state") or {}),
        )
    return resolve(kubectl, request)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--kubeconfig", default=default_kubeconfig())
    parser.add_argument("--cache-dir", default=default_cache_dir())
    parser.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE)
    parser.add_argument("--workload-image", default=DEFAULT_WORKLOAD_IMAGE)
    args = parser.parse_args(argv)

    request: dict[str, Any] | None = None
    try:
        request = decode_request(sys.stdin)
        validate_image_reference(args.helper_image, "--helper-image")
        validate_image_reference(args.workload_image, "--workload-image")
        result = run(
            request,
            kubectl_binary=args.kubectl,
            kubeconfig=args.kubeconfig,
            cache_dir=args.cache_dir,
            helper_image=args.helper_image,
            workload_image=args.workload_image,
        )
    except BridgeError as exc:
        available = bool(request and request.get("operation") != "discover")
        result = response(
            available=available,
            state=exc.state,
            error=str(exc),
        )
    except Exception:
        result = response(available=False, error="internal Kubernetes bridge error")
    sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
