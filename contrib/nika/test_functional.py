"""Functional conformance: the operations are exercised, not merely counted.

``test_conformance.py`` asserts that the contract is implemented and that the
operations problems call are present. That is worth having and it is not
evidence: a method that exists and returns the wrong thing passes every one of
those checks, and a NIKA scenario built on it fails in a way that looks like the
network rather than the adapter.

These run against a lab that is actually deployed. They are skipped when there
is not one, so the file is safe to run anywhere; on a cluster they are the only
thing that says the adapter works.

    TWINET_LAB=/path/to/examples/cos461 TWINET_TOKEN=... pytest contrib/nika
"""

from __future__ import annotations

import os

import pytest

from twinet_runtime import TwinetRuntime, TwinetError

LAB = os.environ.get("TWINET_LAB")
pytestmark = pytest.mark.skipif(
    not LAB or not os.environ.get("TWINET_TOKEN"),
    reason="needs a deployed lab: set TWINET_LAB and TWINET_TOKEN",
)


@pytest.fixture(scope="module")
def runtime() -> TwinetRuntime:
    return TwinetRuntime(manifest=LAB)


@pytest.fixture(scope="module")
def router(runtime: TwinetRuntime) -> str:
    for node in runtime.list_nodes():
        if node.endswith("/CHI") and node.startswith("as3"):
            return node
    pytest.skip("this lab has no as3/CHI to test against")


def test_the_lab_is_visible(runtime: TwinetRuntime) -> None:
    nodes = runtime.list_nodes()
    assert nodes, "the runtime lists no nodes, so every scenario has nothing to act on"
    assert runtime.exists(), "the runtime says the lab is not deployed"
    assert runtime.lab_name


def test_exec_returns_what_the_device_printed(runtime: TwinetRuntime, router: str) -> None:
    out = runtime.exec(router, "echo twinet-conformance")
    assert "twinet-conformance" in out, out


def test_node_status_distinguishes_running_from_absent(
    runtime: TwinetRuntime, router: str
) -> None:
    assert runtime.node_status(router) == "running"
    with pytest.raises((TwinetError, Exception)):
        runtime.node_status("as3/THERE_IS_NO_SUCH_ROUTER")


def test_the_frr_operations_read_the_router(runtime: TwinetRuntime, router: str) -> None:
    asn = runtime.frr_get_bgp_asn_number(router)
    assert int(asn) == 3, f"as3's routers should report AS 3, not {asn!r}"


def test_the_host_operations_read_the_host(runtime: TwinetRuntime) -> None:
    host = "as3/CHI_host"
    ifaces = runtime.get_host_interfaces(host)
    assert ifaces, "a host with no interfaces cannot be the subject of any fault"
    ip = runtime.get_host_ip(host)
    assert ip.startswith("3."), f"an AS 3 host should be addressed in 3.0.0.0/8, not {ip!r}"
    gw = runtime.get_default_gateway(host)
    assert gw.startswith("3."), f"its gateway should be in the lab, not {gw!r}"


def test_interface_state_can_be_changed_and_put_back(
    runtime: TwinetRuntime, router: str
) -> None:
    ifaces = [i for i in runtime.get_host_interfaces(router) if i.startswith("port_")]
    if not ifaces:
        pytest.skip("no router-to-router port to take down")
    iface = sorted(ifaces)[0]
    before = runtime.get_interface_operstate(router, iface)
    assert before == "up", f"{iface} is {before} before the test, so nothing below means anything"
    try:
        runtime.set_interface_state(router, iface, "down")
        assert runtime.get_interface_operstate(router, iface) == "down", (
            "set_interface_state reported success and the interface is still up, so every "
            "link fault built on it does nothing"
        )
    finally:
        runtime.set_interface_state(router, iface, "up")
    assert runtime.get_interface_operstate(router, iface) == "up", (
        "the interface was left down"
    )


def test_the_capabilities_are_the_ones_this_backend_has(runtime: TwinetRuntime) -> None:
    assert runtime.has_capability("frr")
    assert not runtime.has_capability("k8s"), (
        "declaring k8s means NIKA will hand this backend Kubernetes faults it cannot serve"
    )
    with pytest.raises(TwinetError):
        runtime.srl_set_bgp_as(runtime.list_nodes()[0], 65000)
