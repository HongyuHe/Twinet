package alloc

import (
	"fmt"
	"net"
	"testing"
)

// Determinism is the property the whole no-state-store design rests on.
func TestDeterminism(t *testing.T) {
	ids := make([]string, 0, 2000)
	for i := 0; i < 2000; i++ {
		ids = append(ids, fmt.Sprintf("as%d/R1:eth0|as%d/R2:eth1", i, i+1))
	}
	a := AssignVNIs("cos461", ids)
	// Shuffle the input; the result must be identical.
	rev := make([]string, len(ids))
	for i := range ids {
		rev[i] = ids[len(ids)-1-i]
	}
	b := AssignVNIs("cos461", rev)
	if len(a) != len(b) {
		t.Fatalf("size mismatch %d vs %d", len(a), len(b))
	}
	for k, v := range a {
		if b[k] != v {
			t.Fatalf("VNI for %s differs by input order: %d vs %d", k, v, b[k])
		}
	}
}

func TestVNIUniquenessAndRange(t *testing.T) {
	ids := make([]string, 0, 5000)
	for i := 0; i < 5000; i++ {
		ids = append(ids, fmt.Sprintf("link-%d", i))
	}
	got := AssignVNIs("lab", ids)
	if len(got) != len(ids) {
		t.Fatalf("expected %d VNIs, got %d", len(ids), len(got))
	}
	seen := map[uint32]string{}
	for id, v := range got {
		if v < vniMin || v > vniMax {
			t.Fatalf("VNI %d for %s out of range", v, id)
		}
		if other, dup := seen[v]; dup {
			t.Fatalf("VNI %d assigned to both %s and %s", v, other, id)
		}
		seen[v] = id
	}
}

// Different labs on the same cluster must not collide.
func TestVNILabSeparation(t *testing.T) {
	same := 0
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("link-%d", i)
		if VNI("labA", id, 0) == VNI("labB", id, 0) {
			same++
		}
	}
	if same > 1 {
		t.Fatalf("%d/1000 VNIs collide across labs; hash is not mixing the lab name", same)
	}
}

func TestMACValidity(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		m := MAC("lab", fmt.Sprintf("as%d/ATL", i), "port_BOS")
		hw, err := net.ParseMAC(m)
		if err != nil {
			t.Fatalf("MAC %q is invalid: %v", m, err)
		}
		if hw[0]&0x01 != 0 {
			t.Fatalf("MAC %q is multicast", m)
		}
		if hw[0]&0x02 == 0 {
			t.Fatalf("MAC %q is not locally administered", m)
		}
		seen[m] = true
	}
	// Collisions are possible in principle but should be vanishingly rare.
	if len(seen) < 4990 {
		t.Fatalf("excessive MAC collisions: %d unique of 5000", len(seen))
	}
}

// Interface names must fit the kernel's IFNAMSIZ-1 = 15 byte limit, or link
// creation fails at deploy time with an opaque netlink error.
func TestGeneratedNamesFitIFNAMSIZ(t *testing.T) {
	const maxIfName = 15
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("as%d/VERYLONGROUTERNAME:port_ANOTHERLONGNAME|as%d/X:y", i, i+1)
		for _, side := range []byte{'a', 'b'} {
			n := TempIfName("some-long-lab-name", id, side)
			if len(n) > maxIfName {
				t.Fatalf("TempIfName %q is %d bytes, exceeds %d", n, len(n), maxIfName)
			}
		}
	}
	for _, vni := range []uint32{4096, 999999, 16000000} {
		if n := BridgeName(vni); len(n) > maxIfName {
			t.Fatalf("BridgeName %q too long", n)
		}
		if n := VxlanName(vni); len(n) > maxIfName {
			t.Fatalf("VxlanName %q too long", n)
		}
	}
}

func TestTempIfNameUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20000; i++ {
		n := TempIfName("lab", fmt.Sprintf("link-%d", i), 'a')
		if seen[n] {
			t.Fatalf("duplicate temp interface name %q at i=%d", n, i)
		}
		seen[n] = true
	}
}

func TestVNISaltProbeIsDeterministic(t *testing.T) {
	for salt := 0; salt < 5; salt++ {
		a := VNI("lab", "link", salt)
		b := VNI("lab", "link", salt)
		if a != b {
			t.Fatalf("salt %d not deterministic: %d vs %d", salt, a, b)
		}
		if salt > 0 && a == VNI("lab", "link", 0) {
			t.Fatalf("salt %d did not change the value", salt)
		}
	}
}
