//go:build e2e

// Package e2e exercises Twinet against a real cluster.
//
// These tests exist because the failures that matter in this system are not
// reachable by unit test. Every serious bug found during development came from
// running against real containers: a token bucket whose burst was interpreted
// in scheduler ticks, a VXLAN that duplicated every flooded frame, a fault that
// reported success without taking effect because busybox's pgrep matches
// nothing, an undo that left a link faster than the topology says. None of
// those are visible from a mock.
//
// They are behind a build tag because they need a cluster. Run them with
// `make e2e`, having set TWINET_LAB to a deployed lab manifest and TWINET_TOKEN
// to the agent token.
package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain refuses to run at all without a cluster, rather than letting every
// test skip.
//
// A suite that exits PASS having run nothing is worse than one that fails: it
// is quoted as evidence, and the absence of the cluster is exactly the
// condition under which nobody looks closely. Skipping is right for one test
// that needs something optional; it is wrong for a suite whose entire purpose
// is to exercise a real deployment.
func TestMain(m *testing.M) {
	if os.Getenv("TWINET_TOKEN") == "" {
		fmt.Fprintln(os.Stderr,
			"e2e: TWINET_TOKEN is not set. These tests exist to exercise a real\n"+
				"cluster, and a green run that exercised nothing is worse than a red one.\n"+
				"Set TWINET_TOKEN, or run the unit tests instead with `go test ./...`.")
		os.Exit(1)
	}
	if dir := labDirPath(); dir == "" {
		fmt.Fprintln(os.Stderr, "e2e: no lab manifest found; set TWINET_LAB")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func labDirPath() string {
	dir := os.Getenv("TWINET_LAB")
	if dir == "" {
		dir = "../../examples/cos461"
	}
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	return dir
}

func labDir(t *testing.T) string {
	t.Helper()
	dir := labDirPath()
	if dir == "" {
		t.Fatal("no lab manifest; TestMain should have refused to start")
	}
	return dir
}

// binOnce builds the controller from the source under test, exactly once.
//
// Running whatever happens to be in bin/ is how a suite ends up passing against
// a binary nobody reviewed: the tests are green, the tree has moved on, and the
// evidence proves nothing about the code it is attached to.
var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func controller(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "twinet-e2e")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "twinet")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, "../../cmd/twinet")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("building the controller under test: %v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

func twinet(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	bin := os.Getenv("TWINET_BIN")
	if bin == "" {
		bin = controller(t)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestClusterIsHealthy(t *testing.T) {
	dir := labDir(t)
	out, err := twinet(t, "node", "status", "-m", dir)
	if err != nil {
		t.Fatalf("node status failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[1] != "ok" {
			t.Errorf("node %s is %s, not ok", f[0], f[1])
		}
	}
}

// Every registered fault must inject, be observable, and be undone. A fault
// that cannot be undone contaminates every later episode, and the contamination
// is invisible: the next episode's result is attributed to whatever it injected.
func TestEveryFaultRoundTrips(t *testing.T) {
	dir := labDir(t)

	list, err := twinet(t, "fault", "list")
	if err != nil {
		t.Fatalf("listing faults: %v\n%s", err, list)
	}

	type spec struct {
		name string
		args []string
	}
	var specs []spec
	for _, line := range strings.Split(list, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "FAULT" || strings.Contains(line, "registered") {
			continue
		}
		name := f[0]
		args := []string{"--as", "5", "--device", "CHI"}
		if strings.HasPrefix(name, "host_") {
			args = []string{"--as", "5", "--device", "CHI_host"}
		}
		// Faults that need a particular kind of device or a subject are given
		// one rather than skipped: an untested fault is one that will fail the
		// first time it matters, which is in the middle of an evaluation.
		switch name {
		case "host_ip_conflict":
			args = append(args, "--param", "victim=as5/CHI")
		case "bgp_hijacking":
			args = []string{"--as", "5", "--device", "MSP", "--peer", "3"}
		case "bgp_blackhole_route_leak":
			args = []string{"--as", "5", "--device", "MSP", "--peer", "3"}
		case "bgp_peer_asn_misconfig":
			// Only a border router has an external neighbour to misconfigure.
			args = []string{"--as", "5", "--device", "MSP"}
		case "web_dos_attack":
			args = []string{"--as", "5", "--device", "CHI_host", "--param", "victim=5.105.0.2"}
		case "flow_rule_shadowing", "flow_rule_loop":
			args = []string{"--as", "5", "--device", "DCN_S1"}
		case "dns_service_down", "dns_port_blocked", "dns_record_error", "dns_lookup_latency":
			args = []string{"--device", "svc/dns"}
		}
		specs = append(specs, spec{name, args})
	}
	if len(specs) < 15 {
		t.Fatalf("only found %d faults; the list output was not understood:\n%s", len(specs), list)
	}

	for _, s := range specs {
		t.Run(s.name, func(t *testing.T) {
			args := append([]string{"fault", "inject", "-m", dir, s.name}, s.args...)
			if out, err := twinet(t, args...); err != nil {
				t.Fatalf("inject: %v\n%s", err, out)
			}
			// Resolve re-verifies and fails closed, so a clean exit here is
			// evidence that the fault is genuinely gone rather than merely
			// that an undo command ran.
			out, err := twinet(t, "fault", "resolve", "-m", dir, "--all")
			if err != nil {
				t.Fatalf("resolve: %v\n%s", err, out)
			}
			if strings.Contains(out, "could not be resolved") {
				t.Fatalf("the lab was left contaminated:\n%s", out)
			}
		})
	}
}

// An agent being evaluated on root-cause analysis runs inside the lab. If the
// answer is reachable from in there, the measurement is worthless, and the leak
// would be silent: the score would simply be higher than it should be.
func TestGroundTruthIsNotReachableFromInsideTheLab(t *testing.T) {
	dir := labDir(t)

	if out, err := twinet(t, "fault", "inject", "-m", dir,
		"ospf_neighbor_missing", "--as", "5", "--device", "CHI"); err != nil {
		t.Fatalf("inject: %v\n%s", err, out)
	}
	defer func() {
		if out, err := twinet(t, "fault", "resolve", "-m", dir, "--all"); err != nil {
			t.Errorf("cleanup failed, the lab is contaminated: %v\n%s", err, out)
		}
	}()

	for _, probe := range []string{"ospf_neighbor_missing", "root_cause", "ground_truth", "twinet.fault"} {
		out, _ := twinet(t, "exec", "-m", dir, "as5/CHI", "--",
			"sh", "-c", "grep -rl '"+probe+"' /etc /run /var 2>/dev/null | head -3; env | grep -i '"+probe+"'")
		if strings.TrimSpace(stripCLINoise(out)) != "" {
			t.Errorf("the answer is readable from inside the lab via %q:\n%s", probe, out)
		}
	}
}

func stripCLINoise(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "twinet:") || strings.TrimSpace(l) == "" {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

// A traffic-control fault replaces the root qdisc, which is also where the
// link's own bandwidth and delay live. An undo that merely deletes it leaves
// the link faster and closer than the topology says, and nothing reports it.
func TestUndoingAShapingFaultRestoresTheDeclaredLink(t *testing.T) {
	dir := labDir(t)
	const dev, iface = "as5/CHI", "port_MSP"

	before, err := twinet(t, "exec", "-m", dir, dev, "--", "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		t.Fatalf("reading the baseline: %v\n%s", err, before)
	}

	if out, err := twinet(t, "fault", "inject", "-m", dir, "link_bandwidth_throttling",
		"--as", "5", "--device", "CHI", "--iface", iface); err != nil {
		t.Fatalf("inject: %v\n%s", err, out)
	}
	if out, err := twinet(t, "fault", "resolve", "-m", dir, "--all"); err != nil {
		t.Fatalf("resolve: %v\n%s", err, out)
	}

	after, err := twinet(t, "exec", "-m", dir, dev, "--", "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		t.Fatalf("reading the restored link: %v\n%s", err, after)
	}
	if normaliseQdisc(before) != normaliseQdisc(after) {
		t.Errorf("the link was not restored to what the topology declares.\nbefore:\n%s\nafter:\n%s",
			normaliseQdisc(before), normaliseQdisc(after))
	}
}

// normaliseQdisc drops the fields that legitimately differ between two
// identical qdiscs: netem seeds a fresh generator each time it is installed.
func normaliseQdisc(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, "qdisc") {
			continue
		}
		f := strings.Fields(l)
		var out []string
		for i := 0; i < len(f); i++ {
			if f[i] == "seed" {
				i++
				continue
			}
			out = append(out, f[i])
		}
		keep = append(keep, strings.Join(out, " "))
	}
	return strings.Join(keep, "\n")
}

// A deployment converges the platform's own state. It has no business rewriting
// the part it deliberately left to someone else. Overwriting is silent when it
// happens: FRR is not restarted, so the router keeps running correctly and the
// loss only appears later, when the container restarts onto a configuration
// nobody chose.
func TestRedeployDoesNotOverwriteStudentConfiguration(t *testing.T) {
	dir := labDir(t)
	const dev = "as5/CHI"
	const marker = "! twinet-e2e-marker"

	if out, err := twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
		"grep -q '"+marker+"' /etc/frr/frr.conf || echo '"+marker+"' >> /etc/frr/frr.conf"); err != nil {
		t.Fatalf("seeding the marker: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
			"sed -i '/twinet-e2e-marker/d' /etc/frr/frr.conf")
	})

	// An ordinary redeploy converges the platform's own state and must leave
	// the student's file alone.
	if out, err := twinet(t, "deploy", "-m", dir); err != nil {
		t.Fatalf("redeploy: %v\n%s", err, out)
	}
	out, err := twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
		"grep -c 'twinet-e2e-marker' /etc/frr/frr.conf || true")
	if err != nil {
		t.Fatalf("checking the marker: %v\n%s", err, out)
	}
	if !strings.Contains(out, "1") {
		t.Errorf("a redeploy destroyed configuration the platform does not own:\n%s", out)
	}

	// Solve mode is the exception: installing the reference solution over
	// whatever is there is its entire purpose, and preserving in that mode
	// would leave the grading oracle quietly wrong.
	if out, err := twinet(t, "deploy", "-m", dir, "--solve"); err != nil {
		t.Fatalf("solve redeploy: %v\n%s", err, out)
	}
	out, err = twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
		"grep -c 'twinet-e2e-marker' /etc/frr/frr.conf || true")
	if err != nil {
		t.Fatalf("checking the marker after solve: %v\n%s", err, out)
	}
	if !strings.Contains(out, "0") {
		t.Errorf("solve mode did not install the reference solution over what was there:\n%s", out)
	}
}

// Generating a zone and serving it are different things, and the gap between
// them is invisible from the control plane: the zone files are correct, the
// unit tests that check them pass, and inside the lab no name resolves. A
// service that is deployed, wired, addressed and running `sleep infinity` looks
// healthy from every angle except the only one that matters.
func TestNamesResolveInsideTheLab(t *testing.T) {
	dir := labDir(t)

	// Forward: the name the assignment tells students to expect.
	out, err := twinet(t, "exec", "-m", dir, "as3/MSP", "--", "dig", "+short", "msp.group3")
	if err != nil {
		t.Fatalf("resolving a lab name: %v\n%s", err, out)
	}
	if !strings.Contains(out, "3.") {
		t.Errorf("msp.group3 did not resolve to an address in AS 3:\n%s", out)
	}

	// Reverse, which is what makes a traceroute render names rather than
	// numbers -- the entire reason the zone exists.
	out, err = twinet(t, "exec", "-m", dir, "as3/MSP", "--", "dig", "+short", "-x", "3.101.0.1")
	if err != nil {
		t.Fatalf("reverse lookup: %v\n%s", err, out)
	}
	if !strings.Contains(out, "group3") {
		t.Errorf("3.101.0.1 did not reverse to a name in group3:\n%s", out)
	}

	// The resolver must be the lab's own, not whatever the container engine
	// supplied, or the names work only by accident of the outside world.
	out, err = twinet(t, "exec", "-m", dir, "as3/CHI_host", "--", "cat", "/etc/resolv.conf")
	if err != nil {
		t.Fatalf("reading resolv.conf: %v\n%s", err, out)
	}
	if !strings.Contains(out, "198.3.0.") {
		t.Errorf("a host is not pointed at the lab's resolver:\n%s", out)
	}
}

// The reference solution must score full marks.
//
// Without this the rubric is unfalsifiable: a check that can never pass is
// indistinguishable from a class that never gets it right, and every student
// who loses that mark loses it to the platform. Getting from 7.33 to 10 found
// five real defects -- a generator that made every transit link slow so the
// traffic-engineering question had no correct answer, a reference that never
// peered with the exchange it was marked on, addresses left behind by an
// earlier manifest revision, a running configuration that no longer matched
// the file, and a manifest field that silently arrived empty at the node.
func TestTheReferenceSolutionScoresFullMarks(t *testing.T) {
	dir := labDir(t)
	out := t.TempDir()

	// The report is parsed, not the console output. Searching that output for
	// "10.00" proved nothing whatsoever: every line is printed as
	// "score / 10.00", so a zero satisfied it. A test that cannot fail is
	// worse than no test, because it is quoted as evidence.
	res, err := twinet(t, "grade", "run", "-m", dir, "--as", "3",
		"-o", out, "--converge-timeout", "6m")
	if err != nil {
		t.Fatalf("grading the reference: %v\n%s", err, res)
	}

	raw, err := os.ReadFile(filepath.Join(out, "group3.json"))
	if err != nil {
		t.Fatalf("no report was written: %v", err)
	}
	var rep struct {
		Total       float64 `json:"total"`
		MaxTotal    float64 `json:"max_total"`
		Err         string  `json:"error"`
		NeedsReview bool    `json:"needs_review"`
		Questions   []struct {
			ID      string  `json:"id"`
			Awarded float64 `json:"awarded"`
			Points  float64 `json:"points"`
			Status  string  `json:"status"`
			Results []struct {
				Check  string `json:"check"`
				Status string `json:"status"`
			} `json:"results"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("the report does not parse: %v", err)
	}

	if rep.Err != "" || rep.NeedsReview {
		t.Fatalf("grading the reference did not complete cleanly: needs_review=%v err=%q",
			rep.NeedsReview, rep.Err)
	}
	if rep.MaxTotal <= 0 {
		t.Fatal("the rubric is worth nothing, so a full score means nothing")
	}
	if rep.Total < rep.MaxTotal {
		t.Errorf("the reference scored %.2f of %.2f", rep.Total, rep.MaxTotal)
	}

	// Every question must have been assessed and passed. A rubric whose own
	// reference cannot score full marks is unfalsifiable: a check that can
	// never pass looks exactly like a class that never gets it right, and
	// every student who loses that mark loses it to the platform.
	if len(rep.Questions) == 0 {
		t.Fatal("the report contains no questions")
	}
	for _, q := range rep.Questions {
		if q.Awarded < q.Points {
			t.Errorf("question %s awarded %.2f of %.2f (%s)", q.ID, q.Awarded, q.Points, q.Status)
		}
		if len(q.Results) == 0 {
			t.Errorf("question %s ran no checks at all", q.ID)
		}
		for _, r := range q.Results {
			if r.Status != "pass" {
				t.Errorf("question %s: check %s is %s", q.ID, r.Check, r.Status)
			}
		}
	}
}

// The agent API creates privileged containers and rewires hosts. A shared
// bearer token over plain HTTP is replayable by anyone who sees one request,
// identical on every node so a single leak compromises the cluster, and leaves
// the agent unauthenticated to the caller -- so anything that can occupy the
// port collects tokens.
func TestTheAgentAPIRefusesUnauthenticatedCallers(t *testing.T) {
	dir := labDir(t)
	pkiDir := filepath.Join(dir, ".twinet", "pki")
	if _, err := os.Stat(filepath.Join(pkiDir, "ca_cert.pem")); err != nil {
		t.Skip("this cluster has no PKI issued; run `twinet node pki`")
	}

	out, err := twinet(t, "node", "status", "-m", dir)
	if err != nil {
		t.Fatalf("the controller cannot reach its own cluster: %v\n%s", err, out)
	}

	// Find an agent address from the cluster's own view of itself. The columns
	// are scanned for something that parses as an address rather than indexed,
	// because the runtime column holds two words and an index silently picks
	// the wrong field -- which reads as "no cluster" and skips the test.
	addr := ""
	for _, line := range strings.Split(out, "\n")[1:] {
		for _, f := range strings.Fields(line) {
			if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
				addr = f + ":7200"
				break
			}
		}
		if addr != "" {
			break
		}
	}
	if addr == "" {
		t.Skip("could not determine an agent address")
	}

	// Plain HTTP against a TLS listener must not produce a usable answer.
	plain := &http.Client{Timeout: 5 * time.Second}
	if res, err := plain.Get("http://" + addr + "/v1/status"); err == nil {
		defer func() { _ = res.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 256))
		if res.StatusCode == http.StatusOK && strings.Contains(string(body), "underlay") {
			t.Error("the agent answered a plaintext request with cluster state")
		}
	}

	// TLS without a client certificate must be refused: possession of a bearer
	// token is not identity, which is the property a token cannot express.
	noCert := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, //nolint:gosec // deliberately testing that the server refuses us
	}}
	if res, err := noCert.Get("https://" + addr + "/v1/status"); err == nil {
		defer func() { _ = res.Body.Close() }()
		t.Errorf("a caller with no client certificate reached the API (status %d)", res.StatusCode)
	}
}

// An archive has to contain the whole answer, not the part that happens to be
// FRR configuration.
//
// It did not. Host addresses, static routes, VLAN tags and tunnels were saved
// as human-readable dumps, which cannot be replayed, and restore silently
// applied only the routing configuration. The archive looked complete and a
// student regraded from their own submission would have lost the marks for
// three of the assignment's questions, with nothing anywhere reporting that
// their work had not been loaded.
func TestASubmissionSurvivesSaveAndRestore(t *testing.T) {
	dir := labDir(t)
	archives := t.TempDir()

	if out, err := twinet(t, "save", "-m", dir, "-o", archives, "--as", "3"); err != nil {
		t.Fatalf("save: %v\n%s", err, out)
	}
	archive := filepath.Join(archives, "group3.tar.gz")
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("no archive was written: %v", err)
	}

	// Destroy the answer, in every form the archive claims to preserve.
	//
	// Removing BGP alone proves only that the FRR configuration round-trips.
	// The archive also carries addresses, routes, tunnels and VLAN assignments,
	// and each of those is written and replayed by different code. A test that
	// destroys one of the four and passes was reporting on a quarter of what it
	// appeared to cover.

	// 1. The routing configuration.
	for _, r := range []string{"MSP", "NYC", "ATL", "BOS", "CHI", "HOU", "PHY", "SFO"} {
		_, _ = twinet(t, "exec", "-m", dir, "as3/"+r, "--",
			"vtysh", "-c", "conf t", "-c", "no router bgp 3", "-c", "end")
	}
	out, _ := twinet(t, "exec", "-m", dir, "as3/MSP", "--", "vtysh", "-c", "show ip bgp summary")
	if !strings.Contains(out, "not found") {
		t.Fatalf("the answer was not actually destroyed, so a restore proves nothing:\n%s", out)
	}

	// 2. A host's addressing and its route off its own subnet.
	hostBefore, _ := twinet(t, "exec", "-m", dir, "as3/MSP_host", "--",
		"sh", "-c", "ip -o addr show; ip route show")
	// The interface name follows from the model: a host's link to its router is
	// named after that router.
	if out, err := twinet(t, "exec", "-m", dir, "as3/MSP_host", "--",
		"sh", "-c", "ip route del default; ip addr flush dev MSProuter"); err != nil {
		t.Fatalf("could not destroy the host's addressing: %v\n%s", err, out)
	}
	if out, _ := twinet(t, "exec", "-m", dir, "as3/MSP_host", "--", "ip", "route", "show"); strings.Contains(out, "default") {
		t.Fatal("the host kept its default route, so restoring it proves nothing")
	}

	// 3. A switch's VLAN assignment, which is what separates the two
	//    datacentre segments from each other.
	swBefore, _ := twinet(t, "exec", "-m", dir, "as3/DCS_S2", "--",
		"sh", "-c", "ovs-vsctl list-ports br0 | while read p; do "+
			"echo \"$p $(ovs-vsctl get port $p tag 2>/dev/null) $(ovs-vsctl get port $p trunks 2>/dev/null)\"; done")
	_, _ = twinet(t, "exec", "-m", dir, "as3/DCS_S2", "--",
		// `clear`, not `remove`: tag is a scalar column and ovs-vsctl's remove
		// takes a value for those, so it silently changed nothing and the test
		// then declared the state undestroyed.
		"sh", "-c", "for p in $(ovs-vsctl list-ports br0); do "+
			"ovs-vsctl clear port $p tag; ovs-vsctl clear port $p trunks; done")
	swWrecked, _ := twinet(t, "exec", "-m", dir, "as3/DCS_S2", "--",
		"sh", "-c", "ovs-vsctl list-ports br0 | while read p; do "+
			"echo \"$p $(ovs-vsctl get port $p tag 2>/dev/null) $(ovs-vsctl get port $p trunks 2>/dev/null)\"; done")
	if strings.TrimSpace(swBefore) == strings.TrimSpace(swWrecked) {
		t.Fatal("the switch's VLAN assignment was not actually destroyed, so restoring it proves nothing")
	}

	if out, err := twinet(t, "restore", "-m", dir, archive); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}

	reports := t.TempDir()
	if out, err := twinet(t, "grade", "run", "-m", dir, "--as", "3",
		"-o", reports, "--converge-timeout", "6m"); err != nil {
		t.Fatalf("grading the restored submission: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(reports, "group3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Total    float64 `json:"total"`
		MaxTotal float64 `json:"max_total"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Total < rep.MaxTotal {
		t.Errorf("a submission scored %.2f of %.2f after a save and restore; "+
			"part of the answer did not survive the archive", rep.Total, rep.MaxTotal)
	}

	// The score is the outcome that matters, but it can be reached without
	// every kind of state coming back -- a question may not depend on the
	// switch's VLANs. Each kind is therefore checked directly, so a silent gap
	// in the archive is reported as itself rather than as a mark nobody lost.
	hostAfter, _ := twinet(t, "exec", "-m", dir, "as3/MSP_host", "--",
		"sh", "-c", "ip -o addr show; ip route show")
	if !strings.Contains(hostAfter, "default") {
		t.Errorf("the host's default route did not survive the archive:\nbefore:\n%s\nafter:\n%s",
			hostBefore, hostAfter)
	}
	swAfter, _ := twinet(t, "exec", "-m", dir, "as3/DCS_S2", "--",
		"sh", "-c", "ovs-vsctl list-ports br0 | while read p; do "+
			"echo \"$p $(ovs-vsctl get port $p tag 2>/dev/null) $(ovs-vsctl get port $p trunks 2>/dev/null)\"; done")
	if strings.TrimSpace(swAfter) != strings.TrimSpace(swBefore) {
		t.Errorf("the switch's VLAN assignment did not survive the archive:\nbefore:\n%s\nafter:\n%s",
			swBefore, swAfter)
	}
}

// A container that restarts comes back with an empty network namespace: every
// interface gone, only lo and the kernel's sit0 left. It is running, its state
// says healthy, and it can reach nothing at all.
//
// Nothing used to notice. The wiring is idempotent and a deploy would put it
// back, but a deploy only runs when a person runs one, and the person has no
// reason to until somebody reports the symptom. In between, the device is a
// black hole in the middle of an assignment, and the first thing the student
// suspects is their own configuration.
func TestARestartedContainerRewiresItself(t *testing.T) {
	const device = "svc/matrix"
	container := containerFor(t, device)

	before := interfaceCount(t, container)
	if before < 3 {
		t.Fatalf("%s started this test with %d interfaces; it is not wired to begin with",
			device, before)
	}

	if out, err := exec.Command("sudo", "docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("restarting %s: %v: %s", container, err, out)
	}
	time.Sleep(3 * time.Second)

	if n := interfaceCount(t, container); n > 2 {
		t.Skipf("%s kept %d interfaces across a restart, so this platform does not "+
			"reproduce the failure this test exists for", device, n)
	}

	// The node repairs itself on its own schedule; no deploy is run here,
	// because the whole point is that nobody has to.
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if interfaceCount(t, container) >= before {
			t.Logf("%s rewired itself with no intervention", device)
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("%s still had %d of its %d interfaces three minutes after restarting; "+
		"a device that restarts stays disconnected until a human notices",
		device, interfaceCount(t, container), before)
}

func interfaceCount(t *testing.T, container string) int {
	t.Helper()
	out, err := exec.Command("sudo", "docker", "exec", container,
		"sh", "-c", "ip -o link show 2>/dev/null | wc -l").Output()
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0
	}
	return n
}

// containerFor resolves a lab device name to the container that runs it.
func containerFor(t *testing.T, device string) string {
	t.Helper()
	out, err := twinet(t, "runtime", "nodes", "-m", labDir(t), "--json")
	if err != nil {
		t.Fatalf("listing the lab's devices: %v", err)
	}
	var doc struct {
		Nodes []struct {
			Name      string `json:"name"`
			Container string `json:"container"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("reading the device list: %v", err)
	}
	for _, n := range doc.Nodes {
		if n.Name == device {
			return n.Container
		}
	}
	t.Fatalf("device %q is not in this lab", device)
	return ""
}
