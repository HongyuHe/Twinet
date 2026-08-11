"""Conformance of the Twinet adapter to NIKA's runtime contract.

The adapter used to be a class with the right method names and no relationship
to ``LabRuntime``. Everything anyone thought to check passed: it had ``exec``,
it had ``list_nodes``, a scenario driven through those two worked.

What that missed is that ``LabRuntime`` inherits ``ExecSemanticOpsMixin``, which
implements about fifty semantic operations -- interface state, addresses, tc,
nft, FRR, DHCP, processes -- by delegating through ``lab_api``. NIKA's problem
classes are written against *those*, not against ``exec``. So the adapter
satisfied its tests while no NIKA problem could run against it at all, and the
documentation said the integration was done.

These tests are the check that was missing. They need NIKA importable; they skip
if it is not, because the adapter is contrib and the main suite must not require
a Python dependency to build a Go project.
"""

from __future__ import annotations

import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

nika_base = pytest.importorskip("nika.runtime.base")
from twinet_runtime import TwinetRuntime  # noqa: E402


def test_it_is_a_lab_runtime():
    """Not "has the same methods as" -- actually one."""
    assert issubclass(TwinetRuntime, nika_base.LabRuntime), (
        "TwinetRuntime does not subclass LabRuntime, so it inherits none of the "
        "semantic operations NIKA's problem classes call. It will pass any test "
        "written against exec() and fail every real scenario."
    )


def test_nothing_abstract_is_left_unimplemented():
    missing = sorted(TwinetRuntime.__abstractmethods__)
    assert not missing, (
        f"these parts of the contract are not implemented: {missing}. "
        "Python would refuse to instantiate the class, so every scenario fails "
        "at construction."
    )


def test_the_semantic_operations_are_present():
    """A sample of the operations problems actually use.

    Listed explicitly rather than counted, so that losing one to a refactor is
    a failure naming the operation rather than a number that no longer matches.
    """
    r = TwinetRuntime(manifest="examples/cos461")
    for op in (
        "set_interface_state",
        "get_interface_operstate",
        "get_host_ip",
        "get_default_gateway",
        "get_host_interfaces",
        "tc_set_netem",
        "tc_clear_intf",
        "list_nft_ruleset",
        "add_nft_drop_rule",
        "kill_process",
        "process_running",
        "write_file",
        "node_status",
        "frr_get_bgp_asn_number",
    ):
        assert hasattr(r, op), f"NIKA problems call {op}(), which this runtime lacks"


def test_exec_matches_the_declared_signature():
    """``timeout`` is keyword-only in the contract.

    A positional third argument works until a caller passes it by keyword, or
    until the mixin does -- which it does.
    """
    sig = inspect.signature(TwinetRuntime.exec)
    assert sig.parameters["timeout"].kind is inspect.Parameter.KEYWORD_ONLY, (
        "exec() takes timeout positionally; the mixin passes it by keyword"
    )


def test_the_dialect_is_opt_in_and_the_default_tells_the_truth():
    """NIKA's problems match on a literal backend name.

    Twinet is not kathara, and by default says so -- which means problems refuse
    it. Presenting the kathara dialect is a deliberate, documented choice by the
    caller, not something the adapter does quietly to make itself look
    compatible.
    """
    assert TwinetRuntime(manifest="x").backend == "twinet"
    assert TwinetRuntime(manifest="x", dialect="kathara").backend == "kathara"


def test_adjacency_is_answered_rather_than_left_empty():
    """``get_connected_devices`` defaults to returning nothing.

    A harness scoring fault localisation then treats every answer as wrong,
    including correct ones, and reports a model as having failed at something it
    was never asked. Twinet knows its own links.
    """
    assert (
        TwinetRuntime.get_connected_devices
        is not nika_base.LabRuntime.get_connected_devices
    ), "the runtime inherits the empty default, so localisation cannot be scored"
