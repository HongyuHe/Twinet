package agent

import (
	"fmt"
	"testing"

	"github.com/HongyuHe/twinet/internal/netx"
)

func TestMultiplexInventorySeparatesFourteenBindingsFromSevenTrunks(t *testing.T) {
	inventory := multiplexInventory(7, 2)
	if len(inventory.LogicalBindings) != 14 || len(inventory.PhysicalTrunks) != 7 {
		t.Fatalf("fixture = %d bindings / %d trunks", len(inventory.LogicalBindings), len(inventory.PhysicalTrunks))
	}
	if err := inventoryMatches(inventory, inventory); err != nil {
		t.Fatalf("matching multiplex inventory: %v", err)
	}
}

func TestMultiplexInventoryRejectsBindingAndTrunkDrift(t *testing.T) {
	want := multiplexInventory(2, 2)
	cases := []struct {
		name string
		edit func(*transactionInventory)
	}{
		{"missing binding", func(got *transactionInventory) {
			got.LogicalBindings = got.LogicalBindings[:len(got.LogicalBindings)-1]
			got.VNIs = bindingVNIs(got.LogicalBindings)
		}},
		{"extra VNI", func(got *transactionInventory) {
			got.LogicalBindings = append(got.LogicalBindings, netx.LogicalBinding{
				VNI: 9999, VLAN: 999, Peer: "10.0.9.9", MTU: 1450, Port: 20001, NodeA: "node-a", NodeB: "node-z",
			})
			got.VNIs = bindingVNIs(got.LogicalBindings)
		}},
		{"wrong peer", func(got *transactionInventory) { got.LogicalBindings[0].Peer = "10.99.0.1" }},
		{"wrong mtu", func(got *transactionInventory) { got.LogicalBindings[0].MTU++ }},
		{"wrong port", func(got *transactionInventory) { got.LogicalBindings[0].Port++ }},
		{"missing trunk", func(got *transactionInventory) { got.PhysicalTrunks = got.PhysicalTrunks[:1] }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cloneOverlayInventory(want)
			c.edit(&got)
			if err := inventoryMatches(want, got); err == nil {
				t.Fatalf("%s was accepted: %#v", c.name, got)
			}
		})
	}
}

func TestMultiplexInventoryAllowsLegacyPhysicalMigrationExtras(t *testing.T) {
	want := multiplexInventory(1, 2)
	got := cloneOverlayInventory(want)
	got.PhysicalTrunks = append(got.PhysicalTrunks, netx.PhysicalTrunk{
		Bridge: "twbr100", Vxlan: "twvx100", MTU: 1450, Port: netx.VXLANPort, Legacy: true,
	})
	if err := inventoryMatches(want, got); err != nil {
		t.Fatalf("legacy physical carrier during migration rejected: %v", err)
	}
}

func TestLegacyInventorySchemaRemainsRecoverable(t *testing.T) {
	want := transactionInventory{VNIs: []uint32{100, 101}}
	got := transactionInventory{VNIs: []uint32{100, 101}, Schema: overlayInventorySchema}
	if err := inventoryMatches(want, got); err != nil {
		t.Fatalf("legacy VNI inventory compatibility: %v", err)
	}
}

func multiplexInventory(trunks, bindingsPerTrunk int) transactionInventory {
	out := transactionInventory{Schema: overlayInventorySchema}
	for trunk := 0; trunk < trunks; trunk++ {
		a := fmt.Sprintf("node-%d", trunk)
		b := fmt.Sprintf("node-%d", trunk+1)
		port := 20000 + trunk
		out.PhysicalTrunks = append(out.PhysicalTrunks, netx.PhysicalTrunk{
			Bridge: fmt.Sprintf("twbp%d", trunk), Vxlan: fmt.Sprintf("twvp%d", trunk),
			MTU: 1450, Port: port, NodeA: a, NodeB: b,
		})
		for binding := 0; binding < bindingsPerTrunk; binding++ {
			vni := uint32(1000 + trunk*bindingsPerTrunk + binding)
			out.LogicalBindings = append(out.LogicalBindings, netx.LogicalBinding{
				VNI: vni, VLAN: uint16(100 + binding), Peer: fmt.Sprintf("10.0.%d.%d", trunk, binding+1),
				MTU: 1450, Port: port, NodeA: a, NodeB: b,
			})
		}
	}
	out.VNIs = bindingVNIs(out.LogicalBindings)
	return out
}

func cloneOverlayInventory(in transactionInventory) transactionInventory {
	out := in
	out.LogicalBindings = append([]netx.LogicalBinding(nil), in.LogicalBindings...)
	out.PhysicalTrunks = append([]netx.PhysicalTrunk(nil), in.PhysicalTrunks...)
	out.VNIs = append([]uint32(nil), in.VNIs...)
	return out
}
