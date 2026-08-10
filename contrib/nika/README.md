# Running NIKA against Twinet

NIKA drives a lab through a small protocol: name the backend, list the devices,
run a command in one, and inspect or change a container's run state. Everything
above that — the traffic-control helpers, the FRR helpers, the semantic
operations and every problem class — is written against those few calls.

`twinet_runtime.py` implements them, so NIKA's own adapter runs unmodified:

```python
import sys; sys.path.insert(0, "contrib/nika")
from twinet_runtime import TwinetRuntime
from nika.service.lab.adapters import lab_api_for_runtime

runtime = TwinetRuntime(manifest="examples/cos461")
lab = lab_api_for_runtime(runtime)          # -> LabRuntimeLabAPI, 76 operations

lab.frr_get_bgp_asn_number("as3/MSP")       # -> 3
lab.tc_set_netem("as3/CHI", "port_MSP", delay_ms=350)
lab.get_interface_operstate("as3/CHI", "port_MSP")
```

Verified against a live three-node cluster: 212 devices listed, commands run,
FRR queried, traffic control set and cleared, and a container paused and
resumed.

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
