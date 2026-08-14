package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// A student holds root in their own router. That is deliberate: the assignment
// is to configure it, and they need a shell to do that. It means file
// permissions inside the container protect nothing from the student.
//
// So the reference solution must never be written into one. It was, for a
// while, as /etc/twinet/reference.conf mode 0600, on every deployment and not
// only under --solve, with a comment explaining that a TA could then diff in
// place. The complete expected OSPF, iBGP, eBGP, RPKI and route-map
// configuration was therefore sitting inside the container of the person being
// asked to derive it, and `cp /etc/twinet/reference.conf /etc/frr/frr.conf`
// scored full marks.
//
// This test asserts the general property rather than the one filename: no file
// placed in a student's device may contain the configuration the grader is
// looking for.
func TestAStudentsDeviceNeverContainsTheAnswer(t *testing.T) {
	top := loadCOS461(t)
	student := deviceOf(t, top, model.RoleStudent)

	cfg, err := Router(top, student)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(cfg.Expected) == "" {
		t.Fatal("this test proves nothing if the reference is empty")
	}
	// Distinctive lines from the answer: if any of these reach the container in
	// an ungraded deployment, the exercise is solved by reading a file.
	var giveaways []string
	for _, ln := range strings.Split(cfg.Expected, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "network ") || strings.HasPrefix(ln, "neighbor ") ||
			strings.HasPrefix(ln, "route-map ") {
			giveaways = append(giveaways, ln)
		}
	}
	if len(giveaways) == 0 {
		t.Fatal("no recognisable answer lines; the test cannot detect a leak")
	}

	files, err := New(top, ModePlatform).Files(student)
	if err != nil {
		t.Fatal(err)
	}
	for path, spec := range files {
		body := string(spec.Content)
		for _, g := range giveaways {
			if strings.Contains(body, g) {
				t.Errorf("%s is written into the student's own container and contains "+
					"the answer line %q.\nThe student has root in that container, so the "+
					"mode bits do not matter: they can read it and submit it.\n"+
					"Render the reference on the controller instead "+
					"(`twinet inspect --config`).", path, g)
				break
			}
		}
	}
}

// Solve mode is the reference deployment used to check the rubric, so the
// answer is supposed to be there -- it is the running configuration. The test
// above must not be read as forbidding that.
func TestSolveModeStillInstallsTheAnswer(t *testing.T) {
	top := loadCOS461(t)
	student := deviceOf(t, top, model.RoleStudent)

	files, err := New(top, ModeSolve).Files(student)
	if err != nil {
		t.Fatal(err)
	}
	conf, ok := files["/etc/frr/frr.conf"]
	if !ok {
		t.Fatal("solve mode wrote no router configuration")
	}
	if !strings.Contains(string(conf.Content), "router bgp") {
		t.Error("solve mode did not install the reference routing configuration")
	}
}

func deviceOf(t *testing.T, top *model.Topology, role model.ASRole) *model.Device {
	t.Helper()
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as.Role != role {
			continue
		}
		for _, d := range as.Routers {
			return d
		}
	}
	t.Fatalf("no %s router in the fixture", role)
	return nil
}

// The facts file inside a container listed every prescribed address, including
// the ones a student configures themselves. For the root-cause benchmark that
// is the answer: three of the end-host faults change an address, and an agent
// could find them by comparing this file with `ip addr` instead of diagnosing
// anything -- an oracle no other backend in the comparison has.
func TestTheFactsFileDoesNotCarryStudentAddressing(t *testing.T) {
	top := &model.Topology{Name: "cos461", Lab: &model.Lab{}}
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3}
	d.Ifaces = []*model.Iface{
		{Name: "host", Owner: model.OwnerStudent, Addr4: "3.101.0.1/24", Addr6: "2001:db8:3::1/64"},
		{Name: "lo", Owner: model.OwnerPlatform, Addr4: "3.151.0.1/24"},
	}

	got := string(deviceFacts(top, d))
	if strings.Contains(got, "3.101.0.1") || strings.Contains(got, "2001:db8:3::1") {
		t.Errorf("the facts file tells the device what the student was supposed to "+
			"configure:\n%s", got)
	}
	if !strings.Contains(got, "3.151.0.1") {
		t.Error("the platform's own addressing was removed too; the container's tooling " +
			"needs it and nobody is being asked to work it out")
	}
	if !strings.Contains(got, `"name": "host"`) {
		t.Error("the interface itself is no longer described, which the student shell needs")
	}
}

// The snapshot loader copied a complete routing configuration into
// /etc/twinet/restore.conf and left it there. On a lab deployed at the
// reference that is the answer, readable by any root shell -- which is what a
// student has, and what an agent being evaluated on root-cause analysis has.
// It was found on sampled routers of three autonomous systems on a live
// cluster.
func TestEveryDeploymentScrubsConfigurationLeftInTheDevice(t *testing.T) {
	top := &model.Topology{Name: "cos461", Lab: &model.Lab{}}
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3}

	cmds, err := New(top, ModeSolve).Commands(d)
	if err != nil {
		t.Fatal(err)
	}
	var all string
	for _, c := range cmds {
		all += strings.Join(c.Args, " ") + "\n"
	}
	for _, leak := range []string{"/etc/twinet/reference.conf", "/etc/twinet/restore.conf"} {
		if !strings.Contains(all, leak) {
			t.Errorf("no deployment step removes %s, so a lab already running keeps it -- "+
				"and the labs that have been up longest are the exposed ones", leak)
		}
	}
}
