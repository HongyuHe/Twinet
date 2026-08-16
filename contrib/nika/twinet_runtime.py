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

from nika.runtime.base import LabRuntime


class TwinetCommandError(RuntimeError):
    """A command ran inside a device and failed.

    Separate from TwinetError so a caller that genuinely wants to tolerate a
    non-zero exit -- "is this process running?" is a question whose answer is
    sometimes no -- can catch this and nothing else.
    """

    def __init__(self, node: str, cmd: str, code: int, output: str):
        super().__init__(f"{node}: {cmd!r} exited {code}: {output.strip()[:300]}")
        self.node = node
        self.cmd = cmd
        self.code = code
        self.output = output


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


class TwinetRuntime(LabRuntime):
    """A LabRuntime over a Twinet lab.

    It subclasses NIKA's own base class rather than merely presenting the same
    method names. That is not a formality. ``LabRuntime`` inherits
    ``ExecSemanticOpsMixin``, which implements roughly fifty semantic
    operations -- interface state, addresses, tc, nft, FRR, DHCP, processes --
    by delegating through ``lab_api``. A duck-typed class gets none of them, so
    the adapter satisfied every check anyone thought to write while NIKA's
    problem classes, which call those operations rather than ``exec``, could not
    run against it at all.
    """

    def __init__(
        self,
        manifest: str,
        binary: str | None = None,
        token: str | None = None,
        timeout: float = 60.0,
        dialect: str | None = None,
    ) -> None:
        self.manifest = manifest
        # NIKA's problem classes dispatch on the backend name with a literal
        # match, and raise RuntimeCapabilityError on anything that is not
        # "kathara" or "containerlab". A runtime can implement the protocol
        # perfectly and still be refused by every problem, which is what
        # happened here.
        #
        # What that dispatch actually selects is a device dialect: interface
        # naming ("e1-1" on containerlab, "eth0" everywhere else) and whether
        # the router is SR Linux or FRR. Twinet is Linux network namespaces
        # running FRR with eth0-style names, which is the "kathara" arm in
        # every respect the dispatch cares about.
        #
        # So the dialect is declared, not hidden. The default reports the truth
        # -- "twinet" -- and problems will refuse it. Setting dialect="kathara",
        # or TWINET_NIKA_DIALECT, asks the adapter to present the arm whose
        # behaviour is correct for these devices. It is opt-in because a
        # runtime that silently misnames itself is how a harness comes to
        # believe it measured something it did not.
        self.dialect = dialect or os.environ.get("TWINET_NIKA_DIALECT") or ""
        self.binary = binary or os.environ.get("TWINET_BIN") or shutil.which("twinet") or "twinet"
        self.token = token or os.environ.get("TWINET_TOKEN", "")
        self.timeout = timeout
        self._lab_name: str | None = None
        self._nodes: list[str] | None = None

    # ---- the protocol NIKA depends on ----------------------------------

    # What this backend can actually serve.
    #
    # "dhcp" is deliberately absent even though Twinet has a DHCP server and
    # five DHCP faults of its own. NIKA's inherited DHCP operations drive
    # dhclient, /etc/dhcp/dhcpd.conf and systemd, none of which exist in these
    # images; the calls fail, the failures were swallowed, and NIKA's own
    # verifier reads "absent" -- which is what a missing dhcpd.conf produces --
    # as proof that the edit it never made had worked. Declaring a capability
    # is a promise about behaviour, not about vocabulary.
    #
    # The base class declares a default set that includes "k8s", and its
    # SR Linux operations are inherited as ordinary methods. Twinet emulates
    # neither: a Kubernetes fault would be accepted and do nothing, and an
    # srl_* call would send Nokia CLI syntax to FRR, which answers with an
    # error that looks like the network being broken. Declaring the truth is
    # what lets NIKA refuse a scenario this backend cannot serve instead of
    # running it and scoring the result.
    CAPABILITIES = frozenset(
        {
            "exec",
            "node_status",
            "interface",
            "ip",
            "route",
            "dns",
            "service",
            "tc",
            "nft",
            "iptables",
            "process",
            "pidfile",
            "file",
            "frr",
            "traffic",
        }
    )

    @property
    def capabilities(self) -> frozenset[str]:
        return self.CAPABILITIES

    @property
    def backend(self) -> str:
        return self.dialect or "twinet"

    @property
    def lab_name(self) -> str:
        if self._lab_name is None:
            self._lab_name = self._nodes_payload()["lab"]
        return self._lab_name

    def list_nodes(self) -> list[str]:
        if self._nodes is None:
            self._nodes = [n["name"] for n in self._nodes_payload()["nodes"]]
        return list(self._nodes)

    def exec(self, node: str, cmd: str, *, timeout: float = 10.0) -> str:
        """Run a shell command in a device and return its output.

        The command goes to a shell inside the container, because NIKA writes
        commands with pipes and redirection in them. Output is stdout and stderr
        together: FRR and iproute2 disagree about which they use for what, and a
        caller looking for a message it can see by hand should not have to know
        which one produced it.
        """
        res = self._json(
            ["runtime", "exec", node, "--", "sh", "-c", cmd],
            timeout=max(timeout, 5) + 10,
        )
        if res.get("error"):
            raise TwinetError(f"{node}: {res['error']}")
        out = (res.get("stdout") or "") + (res.get("stderr") or "")
        # A command that failed is not a command that printed nothing.
        #
        # The exit status was discarded, so "sh: dhclient: not found" came back
        # as ordinary output and every caller that looked for a symptom in the
        # text carried on as though the command had run. NIKA's semantic layer
        # treats several of those texts as evidence.
        code = res.get("exit_code")
        if isinstance(code, int) and code != 0:
            raise TwinetCommandError(node, cmd, code, out)
        return out

    def exec_cmd(self, host_name: str, command: str, timeout: float = 10) -> str:
        """Alias for :meth:`exec`, for the adapter that expects this name."""
        return self.exec(host_name, command, timeout=timeout)

    # ---- lab lifecycle --------------------------------------------------

    def deploy(self) -> None:
        """Bring the lab up, converging whatever is already running.

        Twinet's deploy is idempotent, so this satisfies "deploy if it is not
        already running" without a separate existence check that could race
        against another harness.
        """
        self._run(["deploy"], timeout=self.timeout * 10)
        self._nodes = None
        self._lab_name = None

    def destroy(self) -> None:
        """Tear the lab down."""
        self._run(["destroy", "--yes"], timeout=self.timeout * 10)
        self._nodes = None

    def exists(self) -> bool:
        """Report whether any device of the lab is running.

        A lab that is declared but has nothing running is not deployed, so this
        asks the cluster rather than reading the manifest -- the manifest is
        present whether or not anything was ever started.
        """
        try:
            nodes = self._nodes_payload().get("nodes") or []
        except TwinetError:
            return False
        if not nodes:
            return False
        # Ask about one device rather than reading a field of the listing.
        # The listing is compiled from the manifest and describes what the lab
        # should contain, so every device appears in it whether or not anything
        # was ever started; a status taken from there reported a lab as running
        # before it had been deployed even once.
        for n in nodes[:3]:
            try:
                if self.node_status(n["name"]) in ("running", "paused"):
                    return True
            except TwinetError:
                continue
        return False

    def inspect(self, *, with_status: bool = False) -> list[dict[str, Any]]:
        """Return one row per container, shaped like ``list_lab_containers``.

        Run state is only fetched when asked for. Reading it means one call per
        device, which on a class-scale lab is a couple of hundred round trips,
        and every caller that only wants names and images would pay for it.
        Callers that need status ask for it, or use :meth:`node_status`.
        """
        rows: list[dict[str, Any]] = []
        for n in self._nodes_payload().get("nodes") or []:
            name = n.get("name") or ""
            status = "unknown"
            if with_status:
                try:
                    status = self.node_status(name)
                except TwinetError:
                    status = "unknown"
            rows.append(
                {
                    "name": name,
                    "container_name": n.get("container") or name,
                    "lab_name": self.lab_name,
                    "status": status,
                    "image": n.get("image") or "",
                    "node": n.get("node") or "",
                }
            )
        return rows

    def get_connected_devices(self, node: str) -> list[str]:
        """Return the devices directly linked to ``node``.

        The base class returns nothing when a backend has no topology to
        consult, which makes localisation scoring look uniformly wrong rather
        than unavailable. Twinet knows its own links, so it answers.
        """
        out: list[str] = []
        for link in self._nodes_payload().get("links") or []:
            a, b = link.get("a"), link.get("b")
            if a == node and b and b not in out:
                out.append(b)
            elif b == node and a and a not in out:
                out.append(a)
        return out

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


def _unsupported(name: str, what: str = "an operation this backend does not implement"):
    """Refuse an operation this backend cannot serve, by name.

    The base class implements the Nokia SR Linux operations by sending SR Linux
    CLI syntax over exec. Against an FRR router that is not a no-op: the command
    fails, and the failure is indistinguishable from the network being broken --
    so a scenario built on one would be scored as though the agent's diagnosis
    were the problem. Twinet's devices run FRR, so the honest answer is to say
    so at the point of call.
    """

    def refuse(self, *_args, **_kwargs):
        raise TwinetError(
            f"{name}() is {what}, which this backend cannot serve. "
            f"It declares the capabilities it has "
            f"({', '.join(sorted(TwinetRuntime.CAPABILITIES))}); "
            "run this scenario on a backend that has the rest."
        )

    refuse.__name__ = name
    return refuse


# Bound after the class body so the list is derived from the base class rather
# than written out again and left to drift.
for _name in dir(LabRuntime):
    if _name.startswith("srl_") and _name not in TwinetRuntime.__dict__:
        setattr(TwinetRuntime, _name, _unsupported(_name, "a Nokia SR Linux operation"))
    elif _name.startswith("dhcp_") or _name in ("renew_dhcp_leases", "list_dhcp_client_nodes"):
        if _name not in TwinetRuntime.__dict__:
            setattr(
                TwinetRuntime,
                _name,
                _unsupported(
                    _name,
                    "an ISC dhclient/dhcpd operation, and Twinet's DHCP server is its own "
                    "(see `twinet fault list` for dhcp_service_down, dhcp_missing_subnet, "
                    "dhcp_spoofed_gateway, dhcp_spoofed_dns and dhcp_spoofed_subnet)",
                ),
            )
del _name
