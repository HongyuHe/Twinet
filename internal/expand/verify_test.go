package expand

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// An address that could not be allocated came out as an empty string, and every
// check downstream skipped empty strings. So a lab whose addressing plan cannot
// number its own links validated cleanly and deployed with nothing configured
// on the interfaces that join its routers.
//
// A /32 written as a point-to-point subnet is the clearest case: there is no
// room in it for two hosts, both allocations fail, and the two ends of every
// inter-AS cable come up bare.
func TestALinkSubnetTooSmallToNumberIsRefused(t *testing.T) {
	l, err := manifest.Load("../../examples/advnet")
	if err != nil {
		t.Fatal(err)
	}
	l.Lab.Addressing.InterAS = "179.{{ .Low }}.{{ .High }}.0/32"

	if _, err := Expand(l.Lab); err == nil {
		t.Fatal("a lab whose inter-AS subnets are /32 validated cleanly.\n" +
			"There is no room in a /32 for the two interfaces it has to number, so " +
			"both allocations fail, both addresses come out empty, and the routers " +
			"are deployed with nothing on the interface that joins them -- which " +
			"looks like a student's mistake rather than the lab's.")
	} else if !strings.Contains(err.Error(), "no address could be allocated") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// And an exchange fabric, whose ports are L2 and carry no address by design,
// must still validate -- or the check above makes every real lab fail.
func TestAnExchangeFabricStillValidates(t *testing.T) {
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Expand(l.Lab)
	if err != nil {
		t.Fatalf("the reference lab no longer validates: %v", err)
	}
	var fabricPorts int
	for _, d := range res.Topology.Devices {
		if d.Kind != model.KindSwitch {
			continue
		}
		for _, i := range d.Ifaces {
			if i.Addr4 == "" {
				fabricPorts++
			}
		}
	}
	if fabricPorts == 0 {
		t.Skip("this lab has no unaddressed switch ports, so it does not exercise the exemption")
	}
}
