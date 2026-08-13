package agent

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// A field the controller understands and the node does not is the worst shape
// of bug this system can have, because both halves look right.
//
// The VRF field was exactly that. The controller rendered `interface X vrf Y`
// into the router's configuration; the wire format had no VRF field, so the
// node put the interface in the main routing table; and the routing daemon was
// then configured for a table the kernel did not have. Nothing reported
// anything. Two customers using the same private address space quietly shared
// one table, which is the single failure the whole mechanism exists to prevent.
//
// The comment on Wire already says that copying across "the few fields the
// agent was known to need" is a bug generator. This is that comment enforced:
// every exported field of the model types the wire carries must be represented,
// or be named here as deliberately absent, with the reason.
func TestTheWireCarriesEveryModelField(t *testing.T) {
	cases := []struct {
		name string
		// model type the wire is derived from.
		from any
		// wire type it is carried in.
		to any
		// fields deliberately not carried, and why.
		omit map[string]string
	}{
		{
			name: "Iface",
			from: model.Iface{},
			to:   WireIface{},
			omit: map[string]string{
				"Device":     "the owning device is implied by which device's list it is in",
				"Link":       "carried as LinkID, resolved on the far side",
				"Peer":       "rebuilt from the links, which name both endpoints",
				"Prescribed": "grading-only: the node never decides whether an address was mandated",
				"Subnet":     "grading-only: the node applies an address, it does not judge one",
			},
		},
		{
			name: "Device",
			from: model.Device{},
			to:   WireDev{},
			omit: map[string]string{
				"ASN":        "carried as AS",
				"Services":   "the service devices are carried in their own list",
				"AllowVLANs": "derived on the node from the interfaces it is given",
				"FRR":        "rendered on the node from the wire, never sent: sending it would mean two renderers",
			},
		},
		{
			name: "AS",
			from: model.AS{},
			to:   WireAS{},
			omit: map[string]string{
				"Nickname": "presentation only, never used to configure anything",
				"ExtPorts": "resolved on the controller; the node sees the resulting links",
				"Labels":   "carried per device, where the container runtime needs them",
				"Node":     "a pin the placer has already honoured by the time this is sent",
				"MPLS":     "flattened into MPLSEnabled and MPLSCore",
			},
		},
	}

	for _, c := range cases {
		have := map[string]bool{}
		wt := reflect.TypeOf(c.to)
		for i := 0; i < wt.NumField(); i++ {
			have[strings.ToLower(wt.Field(i).Name)] = true
		}
		mt := reflect.TypeOf(c.from)
		var missing []string
		for i := 0; i < mt.NumField(); i++ {
			f := mt.Field(i)
			if !f.IsExported() {
				continue
			}
			if _, ok := c.omit[f.Name]; ok {
				continue
			}
			// A flattened field counts as carried when the wire has something
			// that starts with its name, e.g. MPLS -> MPLSEnabled.
			carried := have[strings.ToLower(f.Name)]
			if !carried {
				for w := range have {
					if strings.HasPrefix(w, strings.ToLower(f.Name)) {
						carried = true
						break
					}
				}
			}
			if !carried {
				missing = append(missing, f.Name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("model.%s has %v, which the wire does not carry.\n"+
				"The node would see them empty and configure something subtly different "+
				"from what the manifest says, with nothing reporting it. Add them to Wire%s, "+
				"or list them in this test's omit map with the reason they are not needed.",
				c.name, missing, c.name)
		}
	}
}

// And the values must actually survive the trip, not merely have somewhere to
// sit: a field added to the struct and forgotten in Serialise looks identical
// to one that was never added.
func TestVirtualRoutingSurvivesTheWire(t *testing.T) {
	top := &model.Topology{
		Name: "t", Hash: "h",
		Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
	}
	as := &model.AS{ASN: 1, Role: model.RoleStaff,
		MPLS: model.MPLSSpec{Enabled: true, Core: []string{"R5"}},
		VRFs: map[string]*model.VRFSpec{
			"VRF_CS": {Table: 102, RD: "1:102", Import: []string{"2:1"}, Export: []string{"2:1"}},
		},
	}
	d := &model.Device{ID: "as1/R1", Name: "R1", Kind: model.KindRouter, ASN: 1, Node: "node-0"}
	d.Ifaces = append(d.Ifaces, &model.Iface{Device: d, Name: "ext", VRF: "VRF_CS",
		Addr4: "179.1.20.1/24", Role: model.RoleInterAS})
	as.Routers = append(as.Routers, d)
	as.Devices = append(as.Devices, d)
	top.Devices[d.ID] = d
	top.ASes[1] = as

	out, err := Serialise(top).Rehydrate()
	if err != nil {
		t.Fatal(err)
	}
	rd, ok := out.Devices["as1/R1"]
	if !ok {
		t.Fatal("the device did not survive")
	}
	if got := rd.Ifaces[0].VRF; got != "VRF_CS" {
		t.Errorf("the interface arrived in VRF %q; the node would put it in the main "+
			"routing table and two customers would share one", got)
	}
	ras := out.ASes[1]
	if !ras.MPLS.Enabled || !ras.InCore("R5") {
		t.Errorf("the label-switching declaration did not survive: %+v", ras.MPLS)
	}
	v := ras.VRFs["VRF_CS"]
	if v == nil {
		t.Fatal("the routing table declaration did not survive, so the node cannot create it")
	}
	if v.Table != 102 || v.RD != "1:102" {
		t.Errorf("the table arrived as %+v", v)
	}
}
