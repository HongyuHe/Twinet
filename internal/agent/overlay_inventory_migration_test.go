package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestLegacyCommittedInventoryMigratesFourteenBindingsSevenTrunks(t *testing.T) {
	store := migrationTestStore(t)
	top, peers := inventoryTopology("lab", 7, 2)
	expected := expectedInventoryForTest(t, top, peers)
	server := inventoryMigrationServer(t, store, top, peers, expected)

	status := server.transactionInventoryStatus(context.Background(), top.Name)
	if !status.Consistent || status.ExpectedLogicalBindings != 14 ||
		status.ObservedLogicalBindings != 14 || status.ExpectedPhysicalTrunks != 7 ||
		status.ObservedPhysicalTrunks != 7 {
		t.Fatalf("migrated status = %#v", status)
	}

	if got := server.inventories[top.Name]; got.Schema != overlayInventorySchema {
		t.Fatalf("persisted schema = %d, want %d", got.Schema, overlayInventorySchema)
	}
	if _, stale := server.transactions[top.Name]; stale {
		t.Fatal("matching committed legacy transaction was not finalized/cleared")
	}

	after := coordinationTestServer(t, store)
	after.current[top.Name] = top
	after.peers[top.Name] = peers
	after.recoveryContainers = func(context.Context, string) ([]rt.Container, error) { return nil, nil }
	after.recoveryOverlayInventory = func(string) (netx.OverlayInventory, error) {
		return netx.OverlayInventory{
			Bindings: append([]netx.LogicalBinding(nil), expected.Bindings...),
			Trunks:   append([]netx.PhysicalTrunk(nil), expected.Trunks...),
		}, nil
	}
	after.loadCoordination()
	status = after.transactionInventoryStatus(context.Background(), top.Name)
	if !status.Consistent || after.inventories[top.Name].Schema != overlayInventorySchema {
		t.Fatalf("restart/idempotent status = %#v inventory=%#v", status, after.inventories[top.Name])
	}
}

func TestLegacyCommittedInventoryRetainsActiveStandardPorts(t *testing.T) {
	top, peers := inventoryTopology("lab", 2, 2)
	expected := expectedInventoryForTest(t, top, peers)
	for i := range expected.Trunks {
		expected.Trunks[i].Port = netx.VXLANPort
		for j := range expected.Bindings {
			if expected.Bindings[j].NodeA == expected.Trunks[i].NodeA &&
				expected.Bindings[j].NodeB == expected.Trunks[i].NodeB {
				expected.Bindings[j].Port = netx.VXLANPort
			}
		}
	}
	server := inventoryMigrationServer(t, nil, top, peers, expected)
	status := server.transactionInventoryStatus(context.Background(), top.Name)
	if !status.Consistent || server.inventories[top.Name].Schema != overlayInventorySchema {
		t.Fatalf("standard-port migration = %#v inventory=%#v", status, server.inventories[top.Name])
	}
}

func TestLegacyCommittedInventoryMigrationRejectsBindingAndTrunkDrift(t *testing.T) {
	top, peers := inventoryTopology("lab", 2, 2)
	expected := expectedInventoryForTest(t, top, peers)
	cases := []struct {
		name string
		edit func(*netx.OverlayInventory)
	}{
		{"missing binding", func(v *netx.OverlayInventory) {
			v.Bindings = v.Bindings[:len(v.Bindings)-1]
		}},
		{"wrong peer", func(v *netx.OverlayInventory) { v.Bindings[0].Peer = "10.99.0.1" }},
		{"wrong mtu", func(v *netx.OverlayInventory) { v.Trunks[0].MTU++ }},
		{"wrong port", func(v *netx.OverlayInventory) { v.Trunks[0].Port++ }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual := netx.OverlayInventory{
				Bindings: append([]netx.LogicalBinding(nil), expected.Bindings...),
				Trunks:   append([]netx.PhysicalTrunk(nil), expected.Trunks...),
			}
			c.edit(&actual)
			server := inventoryMigrationServer(t, nil, top, peers, actual)
			status := server.transactionInventoryStatus(context.Background(), top.Name)
			if status.Consistent || status.Error == "" {
				t.Fatalf("%s accepted: %#v", c.name, status)
			}
			if got := server.inventories[top.Name]; got.Schema >= overlayInventorySchema {
				t.Fatalf("%s upgraded invalid inventory: %#v", c.name, got)
			}
		})
	}
}

func inventoryMigrationServer(t *testing.T, store *state.Store, top *model.Topology,
	peers map[string]string, actual netx.OverlayInventory,
) *Server {
	t.Helper()
	server := coordinationTestServer(t, store)
	server.cfg.Node = "node-0"
	server.current[top.Name] = top
	server.peers[top.Name] = peers
	server.generations[top.Name] = generationState{Committed: "g"}
	server.inventories[top.Name] = transactionInventory{Generation: "g", VNIs: bindingVNIs(actual.Bindings)}
	server.transactions[top.Name] = applyTransaction{Generation: "g", Committed: true, Phase: transactionCommitted}
	server.recoveryContainers = func(context.Context, string) ([]rt.Container, error) { return nil, nil }
	server.recoveryOverlayInventory = func(string) (netx.OverlayInventory, error) {
		return netx.OverlayInventory{
			Bindings: append([]netx.LogicalBinding(nil), actual.Bindings...),
			Trunks:   append([]netx.PhysicalTrunk(nil), actual.Trunks...),
		}, nil
	}
	if store != nil {
		server.mu.Lock()
		err := server.saveCoordinationLocked()
		server.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	return server
}

func expectedInventoryForTest(t *testing.T, top *model.Topology, peers map[string]string) netx.OverlayInventory {
	t.Helper()
	eng := &deploy.Engine{Node: "node-0", PeerUnderlay: peers}
	inventory, err := eng.ExpectedOverlayInventory(top)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func inventoryTopology(lab string, trunks, bindingsPerTrunk int) (*model.Topology, map[string]string) {
	local := &model.Device{ID: lab + "/local", Name: "local", Node: "node-0"}
	top := &model.Topology{Name: lab, Devices: map[string]*model.Device{local.ID: local}}
	peers := map[string]string{"node-0": "10.0.0.1"}
	for trunk := 0; trunk < trunks; trunk++ {
		node := fmt.Sprintf("node-%d", trunk+1)
		peers[node] = fmt.Sprintf("10.0.%d.1", trunk+1)
		remote := &model.Device{ID: fmt.Sprintf("%s/remote-%d", lab, trunk), Name: "remote", Node: node}
		top.Devices[remote.ID] = remote
		for binding := 0; binding < bindingsPerTrunk; binding++ {
			a := &model.Iface{Device: local, Name: fmt.Sprintf("a%d_%d", trunk, binding)}
			b := &model.Iface{Device: remote, Name: fmt.Sprintf("b%d_%d", trunk, binding)}
			link := &model.Link{ID: fmt.Sprintf("link-%d-%d", trunk, binding), A: a, B: b, VNI: uint32(1000 + trunk*bindingsPerTrunk + binding)}
			a.Link, b.Link, a.Peer, b.Peer = link, link, b, a
			local.Ifaces = append(local.Ifaces, a)
			remote.Ifaces = append(remote.Ifaces, b)
			top.Links = append(top.Links, link)
		}
	}
	return top, peers
}

func migrationTestStore(t *testing.T) *state.Store {
	t.Helper()
	root := filepath.Join(".test-overlay-inventory-" + t.Name())
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	store, err := state.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
