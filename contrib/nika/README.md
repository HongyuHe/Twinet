# Running NIKA against Twinet

NIKA drives a lab through a small protocol: name the backend, list the devices,
run a command in one, and inspect or change a container's run state. Everything
above that — the traffic-control helpers, the FRR helpers, the semantic
operations and every problem class — is written against those few calls.

`twinet_runtime.py` implements them by subclassing NIKA's own `LabRuntime`:

```python
import sys; sys.path.insert(0, "contrib/nika")
from twinet_runtime import TwinetRuntime

runtime = TwinetRuntime(manifest="examples/cos461", dialect="kathara")

runtime.frr_get_bgp_asn_number("as3/MSP")       # -> 3
runtime.tc_set_netem("as3/CHI", "port_MSP", delay_ms=350)
runtime.get_interface_operstate("as3/CHI", "port_MSP")
```

Subclassing is the point, not a detail. `LabRuntime` inherits
`ExecSemanticOpsMixin`, which implements around fifty semantic operations by
delegating through `lab_api`. NIKA's problem classes call those, not `exec`. An
adapter that merely has the same method names passes every test written against
`exec()` and cannot run a single real scenario — which is what this one did
until it was checked properly. `contrib/nika/test_conformance.py` is that check.

## `dialect` — read this before claiming it runs unmodified

NIKA's problem classes choose their behaviour with a literal match on the
backend name:

```python
match self.lab_backend:
    case "kathara": ...
    case "containerlab": ...
    case backend: raise RuntimeCapabilityError(...)
```

A runtime reporting `"twinet"` is refused by every one of them, however
completely it implements the protocol. What that match actually selects is a
device dialect — interface naming (`e1-1` on containerlab, `eth0` elsewhere) and
whether the router is SR Linux or FRR. Twinet is Linux network namespaces
running FRR with `eth0`-style names: the `kathara` arm is correct for it in
every respect the dispatch cares about.

So the adapter defaults to reporting `"twinet"`, which is true and which
problems will reject, and presenting the `kathara` dialect is something the
caller asks for explicitly with `dialect="kathara"` or `TWINET_NIKA_DIALECT`. A
runtime that quietly misnames itself is how a harness comes to believe it
measured something it did not.

The alternative is a one-line `case "twinet":` in each NIKA problem, which is
the better fix if NIKA can be changed.

Verified against a live three-node cluster: 212 devices listed, commands run,
FRR queried, traffic control set and cleared, a container paused and resumed,
and NIKA's unmodified `LinkFailure` problem driven through `inject_fault` and
`verify_fault` with `{'verified': True, ...}` returned.

## Why it shells out

The adapter runs the `twinet runtime` commands rather than speaking to the node
agents directly. The agents are mutually authenticated and their wire format is
an internal contract that changes when the implementation needs it to; the
command surface is the part that promises not to. Going through it means the
adapter cannot be broken by a change nobody thought was public, and it works
from any machine that can run the controller without holding a cluster
credential of its own.

## Two implementations of the same fault

Twinet implements 34 of NIKA's 44 in-substrate fault types itself, and the
adapter also lets NIKA inject its own through Twinet. That is deliberate:
running both against the same lab is the only way to establish that a fault of a
given name means the same thing in both, which sharing a name does not
establish. Two disagreements were found exactly this way — `bgp_asn_misconfig`
changed a neighbour's remote AS where NIKA changes the router's own, and
`host_crash` took interfaces down where NIKA freezes the machine — and both were
corrected here rather than left as a footnote.

## Kubernetes delegation bridge

`kubernetes_bridge.py` is the concrete controller-host bridge for NIKA's four
Kubernetes faults. It accepts exactly one `nikaKubernetesRequest` JSON object on
stdin and writes exactly one `nikaKubernetesResponse` JSON object on stdout.
It shells out only to `kubectl`, verifies that the requested context selects
the named API endpoint, and never copies kubectl diagnostics or credential
environment variables into its response.

This bridge is intentionally **not** a production-cluster fault tool. Before it
will mutate a node, the cluster must have a `kube-system/`
`twinet-nika-disposable-cluster` marker naming the exact endpoint, context, and
cluster ID; every node and the fixture namespace must carry that same ownership
label. The real gate creates those markers only after both destructive and
disposable-cluster acknowledgements, and removes them afterwards.

Within that boundary the mechanisms match NIKA's Kubernetes implementations:

- ClusterIP routing installs owner-tagged raw-table drops on the named worker;
  pods on that worker lose the Service VIP while pod-IP traffic and an
  independent worker's Service path remain healthy.
- CoreDNS isolation installs the same port-53 drops on the nodes actually
  hosting CoreDNS; CoreDNS pods/endpoints remain healthy and direct IP traffic
  continues.
- NetworkPolicy deny applies a real deny-ingress policy to the selected
  disposable workload and checks an unaffected control Service.
- Worker/API partition blocks the named worker's API-server path. The node
  becomes `NotReady`, logs stop, a new pinned pod stays stale, and the existing
  pod keeps serving by pod IP.

Capability-scoped host-network helper pods hold only `NET_ADMIN`/`NET_RAW`.
Their raw-table rules contain a unique owner comment and are removed through an
independent-worker relay, so resolution remains possible after the target
worker loses its API path. The test audits every node for rule residue and
compares the fixture object set before and after each lifecycle. A
NetworkPolicy-capable CNI is required.

The destructive acceptance gate discovers the current context and endpoint:

```sh
TWINET_K8S_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE=1 \
TWINET_K8S_DISPOSABLE_CLUSTER=1 \
  make k8s-fault-integration
```

For a non-default kubeconfig, export `KUBECONFIG` before invoking Make. To use a
different kubectl binary, mirror, or kubeconfig path, override the bridge
command without putting credentials in it. Both images must retain an
`@sha256:<64 hex>` digest; mutable tags are rejected before fixture creation:

```sh
TWINET_NIKA_KUBERNETES_BRIDGE='python3 contrib/nika/kubernetes_bridge.py --kubectl kubectl --kubeconfig /safe/path/config --helper-image registry.example/netshoot@sha256:<digest> --workload-image registry.example/busybox@sha256:<digest>'
```

The bundled defaults are immutable multi-platform digests for
`nicolaka/netshoot:v0.13` and `busybox:1.36.1`, not mutable tags. The pinned
helper already contains Python, `iptables`, and `ip6tables`; pods perform no
package installation or repository access at startup.

The endpoint URL must not contain user information, query credentials, or a
fragment. The controller starts the bridge with only `PATH`; kubeconfig content,
tokens, cloud credentials, and certificates are never passed through the JSON
protocol or persisted in delegated state/evidence.
