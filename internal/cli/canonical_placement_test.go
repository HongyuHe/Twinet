package cli

import (
	"path/filepath"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
)

// canonicalCourseTopology loads the lab exactly as the operator guide's
// walkthrough does, so what this proves is a property of the shipped manifest
// and not of a fixture written beside it.
func canonicalCourseTopology(t *testing.T) *model.Topology {
	t.Helper()
	loaded, err := manifest.Load(filepath.Join(documentationRepoRoot(t), "examples", "cos461"))
	if err != nil {
		t.Fatal(err)
	}
	if diags := loaded.Validate(); diags.HasErrors() {
		t.Fatal(diags.Err())
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return result.Topology
}

// clusterInventory is the live allocatable view of one worker of the measured
// three-node teaching cluster, at the magnitudes the agent actually reports.
// The concentration this test guards against only appears against live
// inventory: offline, with no capacities at all, every strategy balances by
// container count and the lab looks spread when it is not.
func clusterInventory(name string) place.NodeInventory {
	containers := 1250
	cpus := 50.4
	memory := int64(225) << 30
	disk := int64(750) << 30
	pids := int64(1_000_000)
	netdevs := int64(5_000)
	return place.NodeInventory{
		Name: name,
		Allocatable: place.Capacity{
			Containers: &containers, CPUs: &cpus, MemoryBytes: &memory,
			DiskBytes: &disk, Pids: &pids, NetDevices: &netdevs,
		},
		// A cluster whose kernel imposes no file-handle ceiling. This is the
		// state the reviewed cluster was in.
		Unlimited: []string{"file descriptors"},
	}
}

// The operator guide's canonical walkthrough says this lab is deployed across
// the three nodes. It was not: every one of the 212 containers and all twelve
// ASes landed on node-0, so the documented run exercised no overlay path and
// queued every graded exec behind one agent.
func TestCanonicalCourseLabIsDeployedAcrossTheCluster(t *testing.T) {
	top := canonicalCourseTopology(t)
	inventory := []place.NodeInventory{
		clusterInventory("node-0"), clusterInventory("node-1"), clusterInventory("node-2"),
	}
	assignment, err := place.Place(top, place.Options{
		Inventory: inventory, Strict: true,
	})
	if err != nil {
		t.Fatalf("strict placement of the canonical lab: %v", err)
	}

	for _, node := range []string{"node-0", "node-1", "node-2"} {
		if assignment.Load[node] == 0 {
			t.Errorf("%s carries none of the canonical lab: %v", node, assignment.Load)
		}
	}
	// No node may hold most of the lab: two idle workers is the failure, and a
	// bare "not all on one node" would still pass with 210/1/1.
	total := 0
	for _, count := range assignment.Load {
		total += count
	}
	for node, count := range assignment.Load {
		if count*2 > total {
			t.Errorf("%s holds %d of %d containers; the lab is concentrated on one node",
				node, count, total)
		}
	}
}

// Spreading must not be bought by cutting autonomous systems in half. An AS
// split across nodes turns its internal OSPF adjacencies into tunnels and
// changes what the course exercise measures.
func TestCanonicalCourseLabKeepsEachAutonomousSystemWhole(t *testing.T) {
	top := canonicalCourseTopology(t)
	if _, err := place.Place(top, place.Options{
		Inventory: []place.NodeInventory{
			clusterInventory("node-0"), clusterInventory("node-1"), clusterInventory("node-2"),
		},
		Strict: true,
	}); err != nil {
		t.Fatal(err)
	}
	nodesOf := map[int]map[string]bool{}
	for _, device := range top.SortedDevices() {
		if device.ASN == 0 {
			continue
		}
		if nodesOf[device.ASN] == nil {
			nodesOf[device.ASN] = map[string]bool{}
		}
		nodesOf[device.ASN][device.Node] = true
	}
	for asn, nodes := range nodesOf {
		if len(nodes) != 1 {
			t.Errorf("AS %d is split across %d nodes; intra-AS links became tunnels", asn, len(nodes))
		}
	}
}
