"""A NIKA LabRuntime backed by Twinet.

NIKA drives a lab through a small protocol: name the backend, list the devices,
run a command in one, and inspect or change a container's run state. Everything
above that -- the traffic-control helpers, the FRR helpers, the semantic
operations, and every one of the problem classes -- is written against those few
calls. Implementing them is therefore enough to run NIKA's own scenarios,
unmodified, against a Twinet lab.

It shells out to the ``twinet runtime`` commands rather than speaking to the node
agents directly. The agents are mutually authenticated and their wire format is
an internal contract that changes when the implementation needs it to; the
command surface is the part that promises not to. Going through it means this
adapter cannot be broken by a change nobody thought was public, and it works
from any machine that can run the controller, without holding a cluster
credential of its own.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable


class TwinetError(RuntimeError):
    """The controller could not be run, or refused the request.

    Deliberately distinct from a command that ran and failed. A harness needs to
    tell "the router answered, with an error" -- frequently the answer it is
    looking for -- from "the lab could not be reached", which means the
    measurement is invalid rather than negative. Collapsing the two is how an
    outage becomes a result.
    """


@dataclass
class _Container:
    """The subset of a container object NIKA reads.

    NIKA calls ``reload()`` before reading ``status``, because its other
    backends hold a handle that can go stale. Here the state is fetched on each
    reload, which keeps the same contract without pretending to cache.
    """

    name: str
    _runtime: "TwinetRuntime" = field(repr=False)
    status: str = "unknown"

    def reload(self) -> None:
        self.status = self._runtime.node_status(self.name)


class TwinetRuntime:
    """A LabRuntime over a Twinet lab."""

    def __init__(
        self,
        manifest: str,
        binary: str | None = None,
        token: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.manifest = manifest
        self.binary = binary or os.environ.get("TWINET_BIN") or shutil.which("twinet") or "twinet"
        self.token = token or os.environ.get("TWINET_TOKEN", "")
        self.timeout = timeout
        self._lab_name: str | None = None
        self._nodes: list[str] | None = None

    # ---- the protocol NIKA depends on ----------------------------------

    @property
    def backend(self) -> str:
        return "twinet"

    @property
    def lab_name(self) -> str:
        if self._lab_name is None:
            self._lab_name = self._nodes_payload()["lab"]
        return self._lab_name

    def list_nodes(self) -> list[str]:
        if self._nodes is None:
            self._nodes = [n["name"] for n in self._nodes_payload()["nodes"]]
        return list(self._nodes)

    def exec(self, host_name: str, command: str, timeout: float = 10) -> str:
        """Run a shell command in a device and return its output.

        The command goes to a shell inside the container, because NIKA writes
        commands with pipes and redirection in them. Output is stdout and stderr
        together: FRR and iproute2 disagree about which they use for what, and a
        caller looking for a message it can see by hand should not have to know
        which one produced it.
        """
        res = self._json(
            ["runtime", "exec", host_name, "--", "sh", "-c", command],
            timeout=max(timeout, 5) + 10,
        )
        if res.get("error"):
            raise TwinetError(f"{host_name}: {res['error']}")
        return (res.get("stdout") or "") + (res.get("stderr") or "")

    def exec_cmd(self, host_name: str, command: str, timeout: float = 10) -> str:
        """Alias for :meth:`exec`, for the adapter that expects this name."""
        return self.exec(host_name, command, timeout=timeout)

    def get_container(self, node: str) -> _Container:
        c = _Container(name=node, _runtime=self)
        c.reload()
        return c

    # ---- run state ------------------------------------------------------

    def node_status(self, node: str) -> str:
        """Report a container's run state: running, paused, exited, absent.

        Asked of the platform rather than of the container. A frozen machine
        cannot answer for itself, and its silence is equally consistent with an
        unreachable node -- so a fault that freezes one and then asks it whether
        it is frozen reports success during an outage, and reports itself
        resolved during one too.
        """
        return self._json(["runtime", "state", node])["state"]

    def pause(self, node: str) -> None:
        self._json(["runtime", "state", node, "pause"])

    def unpause(self, node: str) -> None:
        self._json(["runtime", "state", node, "unpause"])

    def stop(self, node: str) -> None:
        self._json(["runtime", "state", node, "stop"])

    def start(self, node: str) -> None:
        self._json(["runtime", "state", node, "start"])

    def restart(self, node: str) -> None:
        self._json(["runtime", "state", node, "restart"])

    # ---- Twinet's own faults, for comparison ----------------------------

    def inject(self, fault: str, **target: Any) -> None:
        """Inject one of Twinet's own faults.

        Offered so a scenario can use whichever implementation it trusts: the
        one written here, or NIKA's, driven through this adapter. Being able to
        run both against the same lab is the only way to establish that they
        mean the same thing, which a shared name does not establish.
        """
        self._run(["fault", "inject", fault] + _target_args(target))

    def resolve_all(self) -> None:
        self._run(["fault", "resolve", "--all"])

    # ---- plumbing -------------------------------------------------------

    def _nodes_payload(self) -> dict[str, Any]:
        return self._json(["runtime", "nodes"])

    def _base(self) -> list[str]:
        return [self.binary, "-m", self.manifest]

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.token:
            env["TWINET_TOKEN"] = self.token
        return env

    def _run(self, args: Iterable[str], timeout: float | None = None) -> str:
        cmd = self._base() + list(args)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                env=self._env(),
                check=False,
            )
        except FileNotFoundError as exc:
            raise TwinetError(f"cannot run {self.binary!r}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise TwinetError(f"{' '.join(cmd)} timed out") from exc
        if proc.returncode != 0:
            raise TwinetError(
                f"{' '.join(cmd)} exited {proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:400]}"
            )
        return proc.stdout

    def _json(self, args: Iterable[str], timeout: float | None = None) -> dict[str, Any]:
        out = self._run(args, timeout=timeout)
        # The last JSON line, not the whole output: a warning printed to stdout
        # by some future version would otherwise make every call fail to parse,
        # and that failure would look like the lab being broken.
        for line in reversed(out.strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        raise TwinetError(f"no JSON in the output of {' '.join(args)}: {out.strip()[:200]}")


def _target_args(target: dict[str, Any]) -> list[str]:
    args: list[str] = []
    for key, value in target.items():
        if value is None:
            continue
        if key in {"as_", "asn"}:
            args += ["--as", str(value)]
        elif key in {"device", "iface", "prefix", "peer"}:
            args += [f"--{key}", str(value)]
        else:
            args += ["--param", f"{key}={value}"]
    return args
