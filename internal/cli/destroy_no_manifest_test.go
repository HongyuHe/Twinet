package cli

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// `twinet destroy --lab NAME` is what the command's own help recommends for a
// lab whose manifest is no longer available. There is no topology on that path,
// and the code went on to dereference one: the command panicked with a nil
// pointer before removing anything, so the documented way to clean up a lab
// nobody has the manifest for did not work at all.
func TestDestroyWithoutAManifestHasSomewhereToCaptureInto(t *testing.T) {
	store, err := destroyStore(nil)
	if err != nil {
		t.Fatalf("no store could be opened without a manifest: %v", err)
	}
	if store == nil {
		t.Fatal("destroying without a manifest has nowhere to save configuration, " +
			"so it would either panic or throw the work away")
	}
}

// The containers carry their own identity, which is the whole reason destroy
// can work from labels. Capturing needs devices, so they are rebuilt from them.
func TestDevicesAreRebuiltFromContainerLabels(t *testing.T) {
	cs := []rt.Container{
		{Name: "twinet-cos461-as3-atl", Labels: map[string]string{
			deploy.LabelDeviceID: "as3/ATL", deploy.LabelDevice: "ATL",
			deploy.LabelKind: "router", deploy.LabelAS: "3"}},
		{Name: "twinet-cos461-as3-atl-host", Labels: map[string]string{
			deploy.LabelDeviceID: "as3/ATL_host", deploy.LabelDevice: "ATL_host",
			deploy.LabelKind: "host", deploy.LabelAS: "3"}},
		{Name: "twinet-cos461-ixp", Labels: map[string]string{
			deploy.LabelDeviceID: "as140/RS", deploy.LabelDevice: "RS",
			deploy.LabelKind: "router", deploy.LabelAS: "140"}},
		// A container of some other lab's, or one of ours from before the
		// labels existed. It has nothing to say about itself and is skipped
		// rather than turned into a device with an empty name.
		{Name: "stranger", Labels: map[string]string{}},
	}

	top := topologyFromLabels("cos461", cs)
	if got := len(top.Devices); got != 3 {
		t.Fatalf("rebuilt %d devices from %d containers, want 3", got, len(cs))
	}
	d, ok := top.Devices["as3/ATL"]
	if !ok {
		t.Fatal("the router was not rebuilt")
	}
	if d.Kind != model.KindRouter {
		t.Errorf("kind is %q; capturing a router reads its routing configuration and "+
			"a host's is read differently, so getting this wrong loses the work", d.Kind)
	}
	if d.Container != "twinet-cos461-as3-atl" {
		t.Errorf("container name is %q, so nothing can be read from it", d.Container)
	}
	if d.ASN != 3 {
		t.Errorf("AS is %d, want 3", d.ASN)
	}
	if got := len(top.ASes[3].Devices); got != 2 {
		t.Errorf("AS 3 has %d devices, want 2", got)
	}
	if top.Name != "cos461" {
		t.Errorf("lab name is %q", top.Name)
	}
}
