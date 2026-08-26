package deploy

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/state"
)

// namespaceSnapshot files one canonical namespace-backed snapshot, the way a
// capture writes it and a restore reads it back.
func namespaceSnapshot(t *testing.T, store *state.Store, lab string, d *model.Device,
	kind state.Kind, facts ...string,
) {
	t.Helper()
	body := dynamicStateVersion + " " + string(kind) + "\n"
	if len(facts) > 0 {
		body += strings.Join(facts, "\n") + "\n"
	}
	if _, err := store.Put(state.Snapshot{
		Lab: lab, AS: d.ASN, Device: d.ID, Kind: kind,
		TakenAt: time.Now().UTC(), Content: []byte(body),
	}); err != nil {
		t.Fatal(err)
	}
}

// snapshotFiles names the files holding a saved snapshot of one kind.
func snapshotFiles(t *testing.T, store *state.Store, kind state.Kind, suffix string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(store.Root(), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, suffix) &&
			filepath.Base(filepath.Dir(path)) == string(kind) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("no %s file for a %s snapshot was written", suffix, kind)
	}
	return out
}

// A snapshot that cannot be read is not a device with nothing saved.
//
// Every failure used to be the same answer. State.Current returns an error for
// a body whose digest does not match what was recorded beside it, for a
// half-written pair of files, and for a disk that is refusing reads -- and all
// of them were mapped to "no saved facts", which is exactly the condition
// under which an empty namespace proves continuous. So the one circumstance
// where the stored copy of a student's work is already in question was the
// circumstance that let a device's emptiness be recorded as its baseline and
// then captured over the top of the snapshot that was in doubt.
func TestASavedSnapshotThatCannotBeReadIsNotTreatedAsNothingSaved(t *testing.T) {
	cases := []struct {
		name   string
		damage func(t *testing.T, store *state.Store)
	}{
		{
			name: "a body that does not match its digest",
			damage: func(t *testing.T, store *state.Store) {
				for _, path := range snapshotFiles(t, store, state.KindAddrs, ".body") {
					if err := os.WriteFile(path, []byte("twinet-state/v2 addrs\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "a body that is not there at all",
			damage: func(t *testing.T, store *state.Store) {
				for _, path := range snapshotFiles(t, store, state.KindAddrs, ".body") {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "metadata that cannot be parsed",
			damage: func(t *testing.T, store *state.Store) {
				for _, path := range snapshotFiles(t, store, state.KindAddrs, ".json") {
					if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, top, devices, runtime := namespaceAwareLinkedLab(t)
			store, err := testStateStore(t)
			if err != nil {
				t.Fatal(err)
			}
			engine.State = store
			doubtful := devices[1]
			namespaceSnapshot(t, store, top.Name, doubtful, state.KindAddrs,
				"addr inet port_H0 10.0.1.2/24")
			tc.damage(t, store)
			// Wired exactly as modelled, and carrying the addressing the
			// damaged snapshot claims. Everything except the snapshot itself
			// says this device is fine.
			runtime.setContents(doubtful.Container, namespaceProbeOutput(
				modelledNamespaceInterfaces(doubtful),
				map[string][]string{"port_H0": {"10.0.1.2/24"}}))

			if _, err := engine.Build(top); err != nil {
				t.Fatal(err)
			}
			if _, ok := persistedNamespaces(t, engine, top.Name)[doubtful.ID]; ok {
				t.Fatal("a device whose saved state could not be read was baselined " +
					"against a namespace nothing could be compared with")
			}
			reason := engine.UnprovenNamespaceDevices()[doubtful.ID]
			if !strings.Contains(reason, "saved network state could not be read") {
				t.Fatalf("the refusal did not say the snapshot was unreadable: %q", reason)
			}
			kept := engine.storableSnapshots(context.Background(), doubtful, []state.Snapshot{
				{Device: doubtful.ID, Kind: state.KindAddrs, Content: []byte("twinet-state/v2 addrs\n")},
			})
			if len(kept) != 0 {
				t.Fatal("a capture was allowed to overwrite the snapshot whose readability " +
					"is the thing in doubt")
			}
			if _, ok := persistedNamespaces(t, engine, top.Name)[devices[0].ID]; !ok {
				t.Fatal("one unreadable snapshot stopped every other device being baselined")
			}
		})
	}
}

// The control for the case above. A device that has genuinely never had a
// snapshot taken is not in doubt about anything: there is nothing to compare
// its namespace against because nobody has configured anything on it yet, and
// refusing to baseline it would leave the whole upgrade window open for a lab
// nobody has started work in.
func TestADeviceWithNothingSavedIsStillBaselined(t *testing.T) {
	engine, top, devices, _ := namespaceAwareLinkedLab(t)
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	engine.State = store

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	for _, d := range devices {
		if _, ok := persistedNamespaces(t, engine, top.Name)[d.ID]; !ok {
			t.Fatalf("%s has never had anything saved and was refused a baseline anyway; "+
				"a lab nobody has started work in would never be protected", d.ID)
		}
	}
	if len(engine.UnprovenNamespaceDevices()) != 0 {
		t.Fatalf("a lab with an empty state store reported unresolved devices: %v",
			engine.UnprovenNamespaceDevices())
	}
}

// A namespace holds more than addresses.
//
// A VLAN sub-interface and a VRF master are objects in their own right -- they
// are captured alongside the addressing precisely because the addressing
// depends on them -- and a tunnel and a bridge port are the whole of what the
// other two snapshots are. Comparing only the addresses meant a switch whose
// ports had lost every VLAN, and a router that came back without its 6in4
// tunnel, read as continuous: their emptiness was recorded as the namespace
// their student had worked in, and the next capture wrote it over the work.
func TestEveryStableSavedObjectMustStillBeInTheNamespace(t *testing.T) {
	cases := []struct {
		name string
		kind state.Kind
		// prepare adapts the fixture's device to the kind of device this
		// object belongs to, and returns the saved facts.
		prepare func(t *testing.T, engine *Engine, top *model.Topology,
			runtime *namespaceAwareRuntime, d *model.Device) []string
		// restore puts the object back where the store says it was.
		restore func(runtime *namespaceAwareRuntime, d *model.Device)
		names   string
	}{
		{
			name: "a VLAN sub-interface",
			kind: state.KindAddrs,
			prepare: func(_ *testing.T, _ *Engine, _ *model.Topology,
				_ *namespaceAwareRuntime, _ *model.Device,
			) []string {
				return []string{"link vlan port_H0.10 port_H0 10"}
			},
			restore: func(runtime *namespaceAwareRuntime, d *model.Device) {
				runtime.setContents(d.Container, namespaceProbeOutputWith(
					modelledNamespaceInterfaces(d), nil,
					[]string{vlanLinkLine("port_H0.10", "port_H0", "10")}, nil))
			},
			names: "port_H0.10",
		},
		{
			name: "a VRF master",
			kind: state.KindAddrs,
			prepare: func(_ *testing.T, _ *Engine, _ *model.Topology,
				_ *namespaceAwareRuntime, _ *model.Device,
			) []string {
				return []string{"link vrf vrf_blue 10"}
			},
			restore: func(runtime *namespaceAwareRuntime, d *model.Device) {
				runtime.setContents(d.Container, namespaceProbeOutputWith(
					modelledNamespaceInterfaces(d), nil, nil,
					[]string{vrfLinkLine("vrf_blue", "10")}))
			},
			names: "vrf_blue",
		},
		{
			name: "a tunnel",
			kind: state.KindTunnels,
			prepare: func(t *testing.T, engine *Engine, top *model.Topology,
				runtime *namespaceAwareRuntime, d *model.Device,
			) []string {
				// Only a router is ever asked for its tunnels, and BIRD keeps
				// this one clear of the FRR control sidecar.
				d.Kind, d.NOS = model.KindRouter, "bird"
				reseedContainerSpec(t, engine, top, runtime, d)
				return []string{"tunnel gre1 198.51.100.9 198.51.100.10"}
			},
			restore: func(runtime *namespaceAwareRuntime, d *model.Device) {
				runtime.setTunnels(d.Container,
					"gre1: gre/ip  remote 198.51.100.9  local 198.51.100.10  ttl inherit\n")
			},
			names: "gre1",
		},
		{
			name: "a switch port's VLAN",
			kind: state.KindOVS,
			prepare: func(t *testing.T, engine *Engine, top *model.Topology,
				runtime *namespaceAwareRuntime, d *model.Device,
			) []string {
				d.Kind = model.KindSwitch
				reseedContainerSpec(t, engine, top, runtime, d)
				return []string{"port port_H0 tag=10 trunks= mode="}
			},
			restore: func(runtime *namespaceAwareRuntime, d *model.Device) {
				// The spelling ovs-vsctl actually prints, which has to
				// canonicalise to the saved fact or nothing would ever match.
				runtime.setPorts(d.Container, "port port_H0 tag=10 trunks=[] mode=[]\n")
			},
			names: "port_H0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, top, devices, runtime := namespaceAwareLinkedLab(t)
			store, err := testStateStore(t)
			if err != nil {
				t.Fatal(err)
			}
			engine.State = store
			d := devices[1]
			facts := tc.prepare(t, engine, top, runtime, d)
			namespaceSnapshot(t, store, top.Name, d, tc.kind, facts...)

			// Every cable back and every address on it. Only the object this
			// case is about is missing.
			runtime.setContents(d.Container, namespaceProbeOutput(
				modelledNamespaceInterfaces(d), nil))

			if _, err := engine.Build(top); err != nil {
				t.Fatal(err)
			}
			if diff := engine.LastBuildDiff(); diff.Create[d.ID] || diff.Configure[d.ID] {
				t.Fatalf("the fixture's device was dirty for some other reason, so it "+
					"never reached the baselining this is about: %#v", diff)
			}
			if _, ok := persistedNamespaces(t, engine, top.Name)[d.ID]; ok {
				t.Fatalf("a namespace missing %s was recorded as the one the "+
					"student's work was done in", tc.name)
			}
			if reason := engine.UnprovenNamespaceDevices()[d.ID]; !strings.Contains(reason, tc.names) {
				t.Fatalf("the refusal did not name the missing object: %q", reason)
			}
			kept := engine.storableSnapshots(context.Background(), d, []state.Snapshot{
				{Device: d.ID, Kind: tc.kind, Content: []byte(dynamicStateVersion + " " + string(tc.kind) + "\n")},
			})
			if len(kept) != 0 {
				t.Fatalf("an empty %s reading was cleared to be captured over the saved one", tc.kind)
			}

			// And the other way: put the object back, in the spelling the
			// runtime actually prints, and the device is baselined.
			tc.restore(runtime, d)
			if _, err := engine.Build(top); err != nil {
				t.Fatal(err)
			}
			if _, ok := persistedNamespaces(t, engine, top.Name)[d.ID]; !ok {
				t.Fatalf("a device carrying exactly the %s the store saved was still "+
					"refused a baseline, so it stays unprotected for ever", tc.name)
			}
		})
	}
}

// The proof reads what there is evidence about, and nothing else.
//
// A router that has never had a tunnel is not asked for one, and nothing but a
// switch is asked for its bridge ports: a namespace proof that ran ovs-vsctl
// in a router's container would be proving which binaries an image ships
// rather than what is in a namespace, and would refuse every router on a lab
// whose images are perfectly correct.
func TestTheProofOnlyRunsTheReadingsThereIsSavedStateFor(t *testing.T) {
	engine, top, devices, runtime := namespaceAwareLinkedLab(t)
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	engine.State = store
	plain := devices[1]
	namespaceSnapshot(t, store, top.Name, plain, state.KindAddrs, "addr inet port_H0 10.0.1.2/24")
	runtime.setContents(plain.Container, namespaceProbeOutput(
		modelledNamespaceInterfaces(plain), map[string][]string{"port_H0": {"10.0.1.2/24"}}))
	// Neither answers. A proof that asked for them would read nothing and
	// refuse the device.
	runtime.setTunnels(plain.Container, "")
	runtime.setPorts(plain.Container, "")

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if _, ok := persistedNamespaces(t, engine, top.Name)[plain.ID]; !ok {
		t.Fatalf("a device with no saved tunnels or bridge ports was refused a baseline: %q",
			engine.UnprovenNamespaceDevices()[plain.ID])
	}
}

// Saved state that this device's kind is never read for is not quietly
// excused. The command still is not run -- a host has no ovs-vsctl and running
// it would prove nothing either way -- and the mismatch is reported as what it
// is rather than passed over on the way to recording a namespace.
func TestSavedStateAKindIsNeverReadForRefusesRatherThanBeingSkipped(t *testing.T) {
	engine, top, devices, runtime := namespaceAwareLinkedLab(t)
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	engine.State = store
	host := devices[1]
	namespaceSnapshot(t, store, top.Name, host, state.KindOVS, "port port_H0 tag=10 trunks= mode=")
	runtime.setContents(host.Container, namespaceProbeOutput(
		modelledNamespaceInterfaces(host), nil))

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if _, ok := persistedNamespaces(t, engine, top.Name)[host.ID]; ok {
		t.Fatal("a device holding saved switch-port state its kind is never read for was " +
			"baselined as though the state did not exist")
	}
	if reason := engine.UnprovenNamespaceDevices()[host.ID]; !strings.Contains(reason, "switch ports") {
		t.Fatalf("the refusal did not say why the state could not be accounted for: %q", reason)
	}
}

// A device this pass rebuilt from its image is not an unresolved device.
//
// The doubt is about which of two things a namespace is: the one the student
// worked in, or an empty one the device restarted into before any of this was
// recorded. Creating the container settles it -- the namespace is new, and the
// create path replays the store into it before anything reads it back -- which
// is why such a device is exempt from the withholding. Reporting it anyway
// would put a device the deployment had just repaired on the list of things
// somebody has to go and look at, on every first deployment of every lab.
func TestADeviceRebuiltAndRestoredThisPassIsNotReportedAsUnresolved(t *testing.T) {
	engine, _, devices, _ := namespaceAwareLinkedLab(t)
	rebuilt, left := devices[0], devices[1]
	engine.markNamespaceUnproven(rebuilt.ID, "its container is not running")
	engine.markNamespaceUnproven(left.ID, "the saved address it was last seen with is not in it")
	engine.markContainerCreated(rebuilt.ID)

	unresolved := engine.UnprovenNamespaceDevices()
	if _, ok := unresolved[rebuilt.ID]; ok {
		t.Fatalf("a device this pass rebuilt from its image and restored into was reported "+
			"as unresolved: %v", unresolved)
	}
	if _, ok := unresolved[left.ID]; !ok {
		t.Fatalf("the device nothing was done about was not reported: %v", unresolved)
	}
	// The two answers have to agree: a device that is not reported is a device
	// whose state may be stored, and the exemption is what makes a first
	// deployment able to save anything at all.
	if engine.namespaceUnproven(rebuilt.ID) {
		t.Fatal("a rebuilt device is exempt from the report but not from the withholding")
	}
	if !engine.namespaceUnproven(left.ID) {
		t.Fatal("a device that is reported as unresolved is having its state stored anyway")
	}
}
