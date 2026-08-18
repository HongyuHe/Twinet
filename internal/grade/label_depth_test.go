package grade

import "testing"

// A route whose equal-cost paths are all properly labelled is label-switched.
func TestLabelDepthAllPathsLabelled(t *testing.T) {
	installed, shallow, thinnest := labelDepth([]vpnNexthop{
		{IP: "1.152.0.1", Labels: []int{80}},
		{IP: "1.0.4.1", FIB: true, InterfaceName: "port_R2", Labels: []int{18, 80}},
		{IP: "1.0.5.1", FIB: true, InterfaceName: "port_R3", Labels: []int{23, 80}},
		{IP: "1.0.9.2", FIB: true, InterfaceName: "port_R5", Labels: []int{23, 80}},
	})
	if installed != 3 {
		t.Fatalf("installed = %d, want 3 (the recursive nexthop is not a path)", installed)
	}
	if len(shallow) != 0 {
		t.Fatalf("shallow = %v, want none", shallow)
	}
	if thinnest != 2 {
		t.Fatalf("thinnest = %d, want 2", thinnest)
	}
}

// One equal-cost path missing its transport label is not hidden by the others.
//
// This is the whole point: taking the deepest stack across the paths reported a
// route as label-switched while a third of its flows were being dropped by the
// core router, which had never handed out the VPN label they arrived carrying.
func TestLabelDepthOneShallowPathAmongMany(t *testing.T) {
	installed, shallow, _ := labelDepth([]vpnNexthop{
		{IP: "1.0.4.1", FIB: true, InterfaceName: "port_R2", Labels: []int{18, 80}},
		{IP: "1.0.5.1", FIB: true, InterfaceName: "port_R3", Labels: []int{23, 80}},
		{IP: "1.0.9.2", FIB: true, InterfaceName: "port_R5", Labels: []int{80}},
	})
	if installed != 3 {
		t.Fatalf("installed = %d, want 3", installed)
	}
	if len(shallow) != 1 || shallow[0] != "port_R5" {
		t.Fatalf("shallow = %v, want [port_R5]", shallow)
	}
}

// Two edges that are neighbours are not caught by the floor of two.
//
// LDP signals implicit-null for a prefix one hop away, so the ingress pushes
// only the VPN label onto the wire. The stack the kernel reports still holds
// the implicit-null, so the depth is two and this correct configuration -- the
// one the advanced-networks lab's directly-connected edge pair actually runs --
// keeps its mark.
func TestLabelDepthImplicitNullCounts(t *testing.T) {
	installed, shallow, thinnest := labelDepth([]vpnNexthop{
		{IP: "1.0.3.2", FIB: true, InterfaceName: "port_R3", Labels: []int{3, 80}},
	})
	if installed != 1 || len(shallow) != 0 || thinnest != 2 {
		t.Fatalf("installed=%d shallow=%v thinnest=%d, want 1/none/2 for penultimate-hop popping",
			installed, shallow, thinnest)
	}
}

// A route with no path installed is reported as such, not as an unlabelled one.
func TestLabelDepthNothingInstalled(t *testing.T) {
	installed, shallow, thinnest := labelDepth([]vpnNexthop{
		{IP: "1.152.0.1", Labels: []int{80}},
	})
	if installed != 0 {
		t.Fatalf("installed = %d, want 0", installed)
	}
	if len(shallow) != 0 {
		t.Fatalf("shallow = %v, want none: a path that is not installed carries nothing", shallow)
	}
	if thinnest != 0 {
		t.Fatalf("thinnest = %d, want 0", thinnest)
	}
}

// A path with no labels at all is shallow, and is named by its address when the
// kernel gives no interface for it.
func TestLabelDepthUnlabelledPath(t *testing.T) {
	installed, shallow, thinnest := labelDepth([]vpnNexthop{
		{IP: "1.0.9.2", FIB: true},
	})
	if installed != 1 || thinnest != 0 {
		t.Fatalf("installed=%d thinnest=%d, want 1/0", installed, thinnest)
	}
	if len(shallow) != 1 || shallow[0] != "1.0.9.2" {
		t.Fatalf("shallow = %v, want [1.0.9.2]", shallow)
	}
}
