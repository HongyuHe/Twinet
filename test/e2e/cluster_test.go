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

	agentpkg "github.com/HongyuHe/twinet/internal/agent"
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
		// Stamped with the same version the agents were built from.
		//
		// Without this the binary reports itself as "dev", and every command
		// that talks to a cluster refuses on version skew -- against agents
		// built from this very tree. The suite then failed for a reason that
		// had nothing to do with what it tests, which is the kind of failure
		// people learn to ignore.
		args := []string{"build", "-o", binPath}
		if v := describeVersion(); v != "" {
			args = append(args, "-ldflags",
				"-X github.com/HongyuHe/twinet/internal/cli.Version="+v+
					" -X github.com/HongyuHe/twinet/internal/agent.Version="+v)
		}
		args = append(args, "../../cmd/twinet")
		cmd := exec.CommandContext(ctx, "go", args...)
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
	// Long enough for the slowest thing the suite runs, which is grading a
	// system: the checks now read addresses off neighbouring devices and probe
	// every datacentre host pair, and the five-minute limit killed the
	// subprocess mid-run. A test that fails because its own deadline is shorter
	// than the work teaches nothing about the work.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
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
		// Faults that need a substrate this lab does not have are named here
		// rather than silently passing. A skip that says why is honest; a
		// suite that quietly covers 39 of 42 while the documentation claims 42
		// is not.
		if cannotBeExercisedHere[name] {
			specs = append(specs, spec{name, nil})
			continue
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
			// A victim this attacker can actually reach.
			//
			// It named a fixed address with nothing on it, and the fault --
			// correctly -- refused, because flooding a closed port produces no
			// symptom to diagnose. Each system reaches the resolver on its own
			// address, so the attacker is asked which one it uses rather than
			// being told.
			args = []string{"--as", "5", "--device", "CHI_host",
				"--param", "victim=" + resolverOf(t, dir, "as5/CHI_host"),
				"--param", "port=53"}
		case "dhcp_missing_subnet":
			// A gateway that serves more than one segment, because removing
			// the only subnet of a server that has one is the service being
			// down -- a different fault with a different symptom, and the
			// injector refuses it. The datacentre gateway serves its two VLANs
			// and its own host segment.
			args = []string{"--as", "5", "--device", "BOS"}
		case "dhcp_service_down", "dhcp_spoofed_gateway", "dhcp_spoofed_dns",
			"dhcp_spoofed_subnet":
			// Any router that serves a segment; the datacentre gateway is the
			// one whose clients an episode would actually look at.
			args = []string{"--as", "5", "--device", "BOS"}
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
			if s.args == nil {
				t.Skipf("%s: %s", s.name, whyNotExercised[s.name])
			}
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

// solveAS puts one autonomous system back to the reference solution.
//
// The suite shares a single lab, and the tests that run before these two inject
// forty-one faults and destroy configuration on purpose. A grading test that
// starts from whatever they left behind is not measuring the reference: it is
// measuring the reference minus whatever has not been put back, and the result
// moves depending on which tests ran first. That is worse than a flaky test,
// because the number it prints looks like a grade.
func solveAS(t *testing.T, dir string, as int) {
	t.Helper()
	// A grading run that was killed leaves its hold behind until the lease
	// lapses, and a deployment is refused while it is there -- correctly, since
	// a change made during grading would land in somebody's marks. So this
	// waits rather than failing: the refusal is the system working.
	deadline := time.Now().Add(5 * time.Minute)
	for {
		out, err := twinet(t, "deploy", "-m", dir, "--solve",
			"--only", fmt.Sprintf("as=%d", as))
		if err == nil {
			return
		}
		if !strings.Contains(out, "is being graded by") || time.Now().After(deadline) {
			t.Fatalf("restoring AS %d to the reference solution: %v\n%s", as, err, out)
		}
		time.Sleep(15 * time.Second)
	}
}

func TestTheReferenceSolutionScoresFullMarks(t *testing.T) {
	dir := labDir(t)
	out := t.TempDir()

	// Start from the reference, not from whatever the preceding tests left.
	solveAS(t, dir, 3)

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

	// The archive is only worth testing if what it captures is a full answer.
	solveAS(t, dir, 3)

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
	// A router, not a service container.
	//
	// This test used to restart svc/matrix and count its interfaces, and it
	// passed while the repair was leaving routers with their cables and
	// nothing else: no addresses, no VLAN sub-interfaces, no tunnel and no
	// routing daemon. The count said eleven, so nothing was ever revisited. A
	// router is the hardest case and the one that matters, and the assertions
	// below are about whether it works rather than how many devices it has.
	const device = "as5/ATL"
	container := containerFor(t, device)

	before := routerHealth(t, device)
	if before.links < 3 || !before.frr {
		t.Fatalf("%s started this test unhealthy (%+v); it proves nothing", device, before)
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
	deadline := time.Now().Add(4 * time.Minute)
	var last routerState
	for time.Now().Before(deadline) {
		last = routerHealth(t, device)
		if last.links >= before.links && last.addrs >= before.addrs &&
			last.vlans >= before.vlans && last.tunnels >= before.tunnels && last.frr {
			t.Logf("%s repaired itself with no intervention: %+v", device, last)
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("%s was still not itself four minutes after restarting: had %+v, wanted %+v. "+
		"A device that restarts stays broken until a human notices, and the first thing "+
		"the student suspects is their own configuration", device, last, before)
}

// routerState is what a router must have for the lab to be true of it.
type routerState struct {
	links, addrs, vlans, tunnels int
	frr                          bool
}

// routerHealth asks the device itself, because the platform's own opinion of
// whether it repaired something is exactly what is under test.
func routerHealth(t *testing.T, device string) routerState {
	t.Helper()
	out, _ := twinet(t, "exec", "-m", labDir(t), device, "--", "sh", "-c",
		"ip -o link show | wc -l; "+
			"ip -o -4 addr show | grep -vc ' lo '; "+
			"ip -o link show type vlan | wc -l; "+
			"ip -d tunnel show 2>/dev/null | grep -vc '^sit0'; "+
			"vtysh -c 'show version' >/dev/null 2>&1 && echo up || echo down")
	f := strings.Fields(out)
	if len(f) < 5 {
		return routerState{}
	}
	n := func(i int) int { v, _ := strconv.Atoi(f[i]); return v }
	return routerState{links: n(0), addrs: n(1), vlans: n(2), tunnels: n(3), frr: f[4] == "up"}
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

// describeVersion returns the version this working tree would build as, or ""
// if git cannot say.
func describeVersion() string {
	out, err := exec.Command("git", "describe", "--tags", "--always").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// cannotBeExercisedHere names the faults this lab cannot demonstrate, with the
// reason. They are skipped loudly rather than silently omitted: a suite that
// quietly covers 40 of 42 while the documentation claims 42 is the kind of
// evidence that is worse than none.
var cannotBeExercisedHere = map[string]bool{
	"host_vpn_membership_missing": true,
	"web_dos_attack":              true,
}

var whyNotExercised = map[string]string{
	"host_vpn_membership_missing": "needs a lab with VPN routing tables; the COS-461 lab has none. " +
		"It is exercised against examples/advnet, which has VRFs",
	"web_dos_attack": "one container cannot measurably overwhelm the lab's resolver on this " +
		"hardware, and the flood is deliberately bounded so that it cannot take down other " +
		"labs sharing the node. The fault reports the measurement and refuses rather than " +
		"claiming an effect it did not have",
}

// resolverOf asks a device which resolver it uses.
//
// Hard-coding one is how a test ends up naming an address that the device it
// runs on cannot reach, which then looks like a broken fault rather than a
// broken test.
func resolverOf(t *testing.T, dir, device string) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, device, "--",
		"sh", "-c", "grep -m1 nameserver /etc/resolv.conf | awk '{print $2}'")
	if err != nil {
		t.Fatalf("asking %s which resolver it uses: %v\n%s", device, err, out)
	}
	for _, l := range strings.Split(out, "\n") {
		if a := strings.TrimSpace(l); strings.Count(a, ".") == 3 {
			return a
		}
	}
	t.Fatalf("%s named no resolver:\n%s", device, out)
	return ""
}

// The five DHCP faults have five different symptoms, and a verifier that reads
// the server's configuration back verifies the edit rather than the fault. So
// the symptoms are proved here, by asking a real client for a lease over the
// same path a person would use.
//
// The lease is not applied -- the script is /bin/true -- because the hosts of a
// teaching lab are statically addressed and taking one would change the state a
// grading run measures.
func TestDHCPFaultsProduceTheirSymptoms(t *testing.T) {
	dir := labDir(t)
	const gw, client, iface = "as3/BOS", "as3/BOS_host", "BOSrouter"
	const realGW = "3.103.0.2"

	// The lease is decoded, not pattern-matched on udhcpc's chatter.
	//
	// "obtained from X" is the server identifier and nothing else, so a test
	// built on it could not tell a wrong gateway from a wrong server, could not
	// see the resolver or the address at all, and passed a fault that changed
	// something other than the option it names. udhcpc hands every option to
	// its script in the environment, so the script prints them and the test
	// reads the lease the client actually received.
	lease := func(t *testing.T) map[string]string {
		t.Helper()
		script := "#!/bin/sh\n" +
			"echo \"TWLEASE ip=$ip mask=$subnet router=$router dns=$dns " +
			"serverid=$serverid lease=$lease\"\n"
		cmd := "cat > /tmp/twlease.sh <<'EOS'\n" + script + "EOS\n" +
			"chmod +x /tmp/twlease.sh\n" +
			"udhcpc -i " + iface + " -n -q -f -t 6 -T 3 -s /tmp/twlease.sh 2>&1 | tail -6\n"
		var last string
		for attempt := 0; attempt < 3; attempt++ {
			out, _ := twinet(t, "exec", "-m", dir, client, "--", "sh", "-c", cmd)
			last = out
			for _, line := range strings.Split(out, "\n") {
				if !strings.Contains(line, "TWLEASE") {
					continue
				}
				got := map[string]string{"raw": out}
				for _, kv := range strings.Fields(strings.TrimSpace(line)) {
					if k, v, ok := strings.Cut(kv, "="); ok {
						got[k] = v
					}
				}
				if got["ip"] != "" {
					return got
				}
			}
			time.Sleep(5 * time.Second)
		}
		return map[string]string{"raw": last}
	}

	inPool := func(ip string) bool {
		return strings.HasPrefix(ip, "3.103.0.2") && ip != realGW
	}

	// The lab as it stands: a client is served, by the gateway, with the
	// gateway as its router and the lab's resolver.
	base := lease(t)
	switch {
	case base["ip"] == "":
		t.Fatalf("no lease before anything was injected, so nothing below would mean "+
			"anything:\n%s", base["raw"])
	case base["serverid"] != realGW:
		t.Fatalf("the lease came from %q rather than the gateway %s:\n%s",
			base["serverid"], realGW, base["raw"])
	case base["router"] != realGW:
		t.Fatalf("option 3 is %q rather than the gateway %s:\n%s",
			base["router"], realGW, base["raw"])
	case base["mask"] == "":
		t.Fatalf("option 1 is absent from the lease:\n%s", base["raw"])
	case base["dns"] == "":
		t.Fatalf("option 6 is absent from the lease:\n%s", base["raw"])
	case !inPool(base["ip"]):
		t.Fatalf("the address %q is not on the segment:\n%s", base["ip"], base["raw"])
	}
	t.Logf("healthy lease: ip=%s mask=%s router=%s dns=%s serverid=%s",
		base["ip"], base["mask"], base["router"], base["dns"], base["serverid"])

	// Every DHCP fault, and for each of them the option that must change and
	// the ones that must not. A fault that moves more than it names is two
	// faults, and an RCA episode built on it is unanswerable.
	cases := []struct {
		fault string
		says  string
		want  func(t *testing.T, got map[string]string)
	}{
		{
			fault: "dhcp_service_down",
			says:  "a client to get no lease at all",
			want: func(t *testing.T, got map[string]string) {
				if got["ip"] != "" {
					t.Errorf("a client still obtained %s while the server was down:\n%s",
						got["ip"], got["raw"])
				}
			},
		},
		{
			fault: "dhcp_missing_subnet",
			says:  "a client on the removed segment to get no lease",
			want: func(t *testing.T, got map[string]string) {
				if got["ip"] != "" {
					t.Errorf("a client still obtained %s from a server with no configuration "+
						"for its segment:\n%s", got["ip"], got["raw"])
				}
			},
		},
		{
			fault: "dhcp_spoofed_gateway",
			says:  "a client to be told to use a gateway that is not the router",
			want: func(t *testing.T, got map[string]string) {
				if got["ip"] == "" {
					t.Fatalf("a client got no lease at all, but this fault keeps serving "+
						"them:\n%s", got["raw"])
				}
				if got["router"] == realGW || got["router"] == "" {
					t.Errorf("option 3 is %q; the fault is that it should not be the "+
						"router:\n%s", got["router"], got["raw"])
				}
				// The server's identity is not the gateway it advertises.
				// Deriving option 54 from option 3 made this fault move both,
				// so the client renewed against the impostor and the symptom
				// under test was two faults rather than the one named.
				if got["serverid"] != realGW {
					t.Errorf("option 54 moved to %q with the gateway; a fault that changes "+
						"the advertised gateway must not change who the server is:\n%s",
						got["serverid"], got["raw"])
				}
				if !inPool(got["ip"]) {
					t.Errorf("the address %q also moved:\n%s", got["ip"], got["raw"])
				}
				if got["dns"] != base["dns"] {
					t.Errorf("option 6 also moved, from %q to %q:\n%s",
						base["dns"], got["dns"], got["raw"])
				}
			},
		},
		{
			fault: "dhcp_spoofed_dns",
			says:  "a client to be told to use a resolver that does not answer",
			want: func(t *testing.T, got map[string]string) {
				if got["ip"] == "" {
					t.Fatalf("a client got no lease at all, but this fault keeps serving "+
						"them:\n%s", got["raw"])
				}
				if got["dns"] == base["dns"] || got["dns"] == "" {
					t.Errorf("option 6 is %q, the same resolver as before the fault:\n%s",
						got["dns"], got["raw"])
				}
				if got["router"] != realGW {
					t.Errorf("option 3 also moved, to %q:\n%s", got["router"], got["raw"])
				}
				if got["serverid"] != realGW {
					t.Errorf("option 54 also moved, to %q:\n%s", got["serverid"], got["raw"])
				}
				if !inPool(got["ip"]) {
					t.Errorf("the address %q also moved:\n%s", got["ip"], got["raw"])
				}
			},
		},
		{
			fault: "dhcp_spoofed_subnet",
			says:  "a client to come up on a network nobody else is on",
			want: func(t *testing.T, got map[string]string) {
				if got["ip"] == "" {
					t.Fatalf("a client got no lease at all, but this fault keeps serving "+
						"them:\n%s", got["raw"])
				}
				if !strings.HasPrefix(got["ip"], "10.255.255.") {
					t.Errorf("the address is %q; the fault moves the pool to 10.255.255.0/24"+
						":\n%s", got["ip"], got["raw"])
				}
				if got["serverid"] != realGW {
					t.Errorf("option 54 also moved, to %q:\n%s", got["serverid"], got["raw"])
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.fault, func(t *testing.T) {
			if out, err := twinet(t, "fault", "inject", "-m", dir, c.fault,
				"--device", gw); err != nil {
				t.Fatalf("injecting %s: %v\n%s", c.fault, err, out)
			}
			defer func() {
				if out, err := twinet(t, "fault", "resolve", "--all", "-m", dir); err != nil {
					t.Fatalf("resolving: %v\n%s", err, out)
				}
			}()
			// The server re-reads its configuration on a timer.
			time.Sleep(14 * time.Second)
			got := lease(t)
			t.Logf("%s: ip=%s mask=%s router=%s dns=%s serverid=%s",
				c.fault, got["ip"], got["mask"], got["router"], got["dns"], got["serverid"])
			c.want(t, got)
		})
	}

	// And afterwards the lab serves leases again, with every option back where
	// it started.
	time.Sleep(14 * time.Second)
	end := lease(t)
	for _, k := range []string{"mask", "router", "dns", "serverid"} {
		if end[k] != base[k] {
			t.Errorf("after resolving every fault, %s is %q and was %q:\n%s",
				k, end[k], base[k], end["raw"])
		}
	}
	if !inPool(end["ip"]) {
		t.Errorf("after resolving every fault a client is addressed %q:\n%s",
			end["ip"], end["raw"])
	}
}

// An episode is a measurement only if something can be measured on it. The
// runner injected, waited, resolved and wrote the ground truth, and there it
// stopped: no way to hand the incident to an agent and no definition of a right
// answer, so every evaluation had to be driven from outside and compared
// against the truth in its own way.
func TestAnIncidentEvaluatesAndScoresAnAgent(t *testing.T) {
	dir := labDir(t)
	scenario := filepath.Join(dir, "incidents", "ospf_adjacency_lost.yaml")
	if _, err := os.Stat(scenario); err != nil {
		t.Skipf("no scenario to run: %v", err)
	}
	out := t.TempDir()

	// An agent that answers correctly without looking, so this measures the
	// harness rather than the agent. What it may see is the point: the brief
	// arrives on standard input and the ground truth does not arrive at all.
	agent := filepath.Join(out, "agent.sh")
	// The agent runs as an unprivileged account now, so it needs somewhere it
	// can actually write. t.TempDir() belongs to whoever ran the test.
	briefPath := filepath.Join("/tmp", "twinet-e2e-brief-"+strconv.Itoa(os.Getpid())+".json")
	if err := os.WriteFile(briefPath, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(briefPath, 0o666); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(briefPath) }()
	script := "#!/bin/sh\ncat > " + briefPath + "\n" +
		"printf '%s\\n' '{\"is_anomaly\":true,\"faulty_devices\":[\"as3/NYC\"]," +
		"\"root_cause_category\":\"misconfiguration\"," +
		"\"root_cause_name\":[\"ospf_neighbor_missing\"]}'\n"
	if err := os.WriteFile(agent, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := twinet(t, "incident", "run", "-m", dir, "--scenario", scenario,
		"--agent", "sh "+agent, "--agent-timeout", "2m", "-o", out)
	if err != nil {
		t.Fatalf("running the incident: %v\n%s", err, res)
	}

	raw, err := os.ReadFile(filepath.Join(out, "ospf_adjacency_lost.json"))
	if err != nil {
		t.Fatalf("no episode was written: %v", err)
	}
	var ep struct {
		Truth []struct {
			FaultyDevices []string `json:"faulty_devices"`
		} `json:"ground_truth"`
		Score *struct {
			Total     float64 `json:"total"`
			RootCause bool    `json:"root_cause"`
			Devices   float64 `json:"devices"`
		} `json:"score"`
		Diagnosis *struct {
			IsAnomaly bool `json:"is_anomaly"`
		} `json:"diagnosis"`
		Resolved bool `json:"resolved"`
	}
	if err := json.Unmarshal(raw, &ep); err != nil {
		t.Fatal(err)
	}
	if ep.Score == nil || ep.Diagnosis == nil {
		t.Fatal("the episode records no diagnosis and no score, so nothing was measured")
	}
	if ep.Score.Total < 0.99 {
		t.Errorf("a diagnosis naming exactly the injected device, category and root cause "+
			"scored %.2f", ep.Score.Total)
	}
	if !ep.Resolved {
		t.Error("the incident was not resolved, so the lab is left broken for whatever runs next")
	}

	// The agent must not be handed the answer.
	brief, err := os.ReadFile(briefPath)
	if err != nil {
		t.Fatalf("the agent was given no brief at all: %v", err)
	}
	for _, leak := range []string{"ospf_neighbor_missing", "as3/NYC", "ground_truth"} {
		if strings.Contains(string(brief), leak) {
			t.Errorf("the agent was told %q in its brief, which is the answer it is being "+
				"asked for:\n%s", leak, brief)
		}
	}
}

// A benchmark whose subject can read the answer measures nothing.
//
// The earlier arrangement kept the ground truth out of the agent's standard
// input and then handed it TWINET_MANIFEST, which is the directory the ledger
// lives in, and TWINET_TOKEN, which is the cluster. An agent that ran
// "cat $TWINET_MANIFEST/.twinet/injections.json" scored a perfect 1.00 without
// looking at the network at all, and the secrecy test passed because it only
// ever inspected stdin.
//
// This runs an agent that does exactly that, plus everything else it can think
// of, and requires all of it to fail.
func TestAnAgentCannotReachTheAnswer(t *testing.T) {
	dir := labDir(t)
	scenario := filepath.Join(dir, "incidents", "ospf_adjacency_lost.yaml")
	if _, err := os.Stat(scenario); err != nil {
		t.Skipf("no scenario to run: %v", err)
	}
	out := t.TempDir()

	loot := filepath.Join("/tmp", "twinet-e2e-loot-"+strconv.Itoa(os.Getpid())+".txt")
	if err := os.WriteFile(loot, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loot, 0o666); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(loot) }()

	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Every way in that has ever worked, and a few that have not.
	script := strings.Join([]string{
		"#!/bin/sh",
		"cat > /dev/null",
		"{",
		"  echo '--- whoami'; id",
		"  echo '--- manifest ledger'; cat \"$TWINET_MANIFEST/.twinet/injections.json\"",
		"  echo '--- manifest dir ledger'; cat \"$(dirname \"$TWINET_MANIFEST\")/.twinet/injections.json\"",
		"  echo '--- original lab'; cat " + abs + "/.twinet/injections.json",
		"  echo '--- original creds'; cat " + abs + "/.twinet/credentials.txt",
		"  echo '--- original roster'; cat " + abs + "/.twinet/roster.json",
		"  echo '--- listing'; ls -la " + abs + "/.twinet/",
		"  echo '--- search'; find / -name 'injections.json' -readable 2>/dev/null | head -20",
		"  echo '--- episodes'; find / -name '*.json' -path '*episode*' -readable 2>/dev/null | head -5",
		"  echo '--- docker'; docker ps --format '{{.Names}}' 2>&1 | head -3",
		"} >> " + loot + " 2>&1",
		// And the credential: it must not be able to change anything, or an
		// agent can repair the fault and report a healthy network.
		"printf '%s\\n' '{\"is_anomaly\":false}'",
	}, "\n") + "\n"
	agentPath := filepath.Join(out, "thief.sh")
	if err := os.WriteFile(agentPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}

	// The agent answers "nothing is wrong" about a lab with a fault in it, so
	// it should score badly. If it scores well, it read the answer.
	res, _ := twinet(t, "incident", "run", "-m", dir, "--scenario", scenario,
		"--agent", "sh "+agentPath, "--agent-timeout", "3m", "-o", out)
	t.Logf("incident output:\n%s", res)

	stolen, err := os.ReadFile(loot)
	if err != nil {
		t.Fatalf("the adversarial agent did not run at all: %v", err)
	}
	got := string(stolen)
	t.Logf("what the agent could reach:\n%s", got)
	for _, secret := range []string{
		"ospf_neighbor_missing", // the fault it was asked to diagnose
		"faulty_devices",        // the shape of the ground truth record
		"\"undo\"",              // how to reverse it, also in the ledger
	} {
		if strings.Contains(got, secret) {
			t.Errorf("the agent read %q out of the filesystem, so the episode measures "+
				"nothing:\n%s", secret, got)
		}
	}
	if strings.Contains(got, "uid=0(root)") {
		t.Error("the agent ran as root, so no file on this machine was out of its reach")
	}

	// And the credential it was given must be read-only and scoped to its own
	// lab. Both are checked directly against a node agent rather than inferred.
	tok := os.Getenv("TWINET_TOKEN")
	if tok == "" {
		t.Skip("no TWINET_TOKEN, so the credential cannot be checked")
	}
	diag := agentpkg.DiagnosticToken(tok, labName(t, dir))
	if err := agentpkg.ReadOnlyCommand([]string{"vtysh", "-c", "configure terminal"}); err == nil {
		t.Error("a diagnostic session may run vtysh configure, so it can repair its own incident")
	}
	if err := agentpkg.ReadOnlyCommand([]string{"ip", "link", "set", "eth0", "down"}); err == nil {
		t.Error("a diagnostic session may run ip link set, so it can break the lab it is scored on")
	}
	if err := agentpkg.ReadOnlyCommand([]string{"sh", "-c", "rm -rf /"}); err == nil {
		t.Error("a diagnostic session may run a shell")
	}
	if err := agentpkg.ReadOnlyCommand([]string{"vtysh", "-c", "show ip bgp summary"}); err != nil {
		t.Errorf("a diagnostic session may not read the BGP table, which is the whole job: %v", err)
	}
	if _, ok := strings.CutPrefix(diag, "twdiag."); !ok {
		t.Errorf("the diagnostic credential is not distinguishable from the cluster token: %q", diag)
	}
	if diag == tok {
		t.Error("the agent was handed the cluster token")
	}
}

// labName reads the deployed lab's name out of its manifest.
func labName(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "twinet.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if s, ok := strings.CutPrefix(strings.TrimSpace(line), "name:"); ok {
			return strings.TrimSpace(s)
		}
	}
	t.Fatal("the manifest has no name")
	return ""
}

// A behaviour is a declaration that has to do something.
//
// `behaviours:` -- the manifest's scripted, reversible perturbations, documented
// since the first version as the replacement for the legacy platform's
// hijack.sh -- validated, appeared in the schema, and was read by no code at
// all. The COS-461 RPKI question is built on one: a stub AS starts announcing
// somebody else's prefix and a student's filters are supposed to stop it.
// Without it the lab could only carry a permanent invalid announcement, so the
// question could never be "did your filter stop the hijack when it happened".
func TestABehaviourStartsAndStopsAHijack(t *testing.T) {
	dir := labDir(t)
	out, err := twinet(t, "behaviour", "list", "-m", dir)
	if err != nil {
		t.Fatalf("listing behaviours: %v\n%s", err, out)
	}
	if !strings.Contains(out, "stub_hijack") {
		t.Skipf("this lab declares no stub_hijack behaviour:\n%s", out)
	}

	victim := "2.0.0.0/8"
	originates := func(t *testing.T) bool {
		t.Helper()
		got, err := twinet(t, "exec", "-m", dir, "as10/MSP", "--",
			"vtysh", "-c", "show ip bgp "+victim)
		if err != nil {
			return false
		}
		// "Local" is how FRR describes a path this router originated.
		return strings.Contains(got, "Local")
	}

	if originates(t) {
		t.Fatal("AS 10 is already announcing the victim's prefix before the behaviour " +
			"was started, so nothing below would mean anything")
	}

	if out, err := twinet(t, "behaviour", "start", "stub_hijack", "-m", dir); err != nil {
		t.Fatalf("starting the behaviour: %v\n%s", err, out)
	}
	defer func() {
		if out, err := twinet(t, "behaviour", "stop", "stub_hijack", "-m", dir); err != nil {
			t.Fatalf("stopping the behaviour: %v\n%s", err, out)
		}
	}()
	time.Sleep(15 * time.Second)

	if !originates(t) {
		t.Error("the behaviour reported success and AS 10 is not announcing the prefix, " +
			"so the exercise's hijack does not happen")
	}
	// It is recorded, so an interrupted session leaves nothing live that
	// nothing on disk mentions.
	if got, err := twinet(t, "behaviour", "status", "-m", dir); err != nil {
		t.Errorf("reading the status: %v", err)
	} else if !strings.Contains(got, "running") {
		t.Errorf("a started behaviour does not report itself running:\n%s", got)
	}

	// And the reference solution rejects it: a system whose routers validate
	// origins must not select a path for the victim's prefix that came from
	// the hijacker.
	for _, dev := range []string{"as3/CHI", "as5/SFO"} {
		got, err := twinet(t, "exec", "-m", dir, dev, "--",
			"vtysh", "-c", "show ip bgp "+victim)
		if err != nil {
			t.Errorf("reading %s: %v", dev, err)
			continue
		}
		if strings.Contains(got, "10 i") || strings.Contains(got, "invalid, best") {
			t.Errorf("%s selected the hijacked path, so the reference solution does not "+
				"reject it:\n%s", dev, got)
		}
	}

	if out, err := twinet(t, "behaviour", "stop", "stub_hijack", "-m", dir); err != nil {
		t.Fatalf("stopping the behaviour: %v\n%s", err, out)
	}
	time.Sleep(10 * time.Second)
	if originates(t) {
		t.Error("the behaviour was stopped and AS 10 is still announcing the prefix, so " +
			"the lab is left hijacked for whatever runs next")
	}
	if got, err := twinet(t, "behaviour", "status", "-m", dir); err != nil {
		t.Errorf("reading the status: %v", err)
	} else if strings.Contains(got, "running") {
		t.Errorf("a stopped behaviour still reports itself running:\n%s", got)
	}
}

// One site made passive must cost marks.
//
// The multicast checks used a fixed pair of hosts -- first and last in name
// order -- and one fixed bystander. `ip pim passive` on every transit interface
// of one router leaves its PIM configuration looking perfect (the interfaces are
// listed, the rendezvous point is right) and forms no adjacency at all, so that
// site receives nothing. The pair the checks happened to use went on working and
// the exercise awarded all four marks with a sixth of it disconnected.
func TestAPassiveMulticastSiteLosesMarks(t *testing.T) {
	dir := os.Getenv("TWINET_MULTICAST_LAB")
	if dir == "" {
		t.Skip("set TWINET_MULTICAST_LAB to the multicast lab to run this")
	}
	const victim = "as1/RIGHT"
	ports := []string{"port_TOP", "port_CENTER", "port_BOTTOMR"}

	grade := func(t *testing.T) map[string]float64 {
		t.Helper()
		out := t.TempDir()
		if res, err := twinet(t, "grade", "run", "-m", dir, "--as", "1", "-o", out); err != nil {
			t.Fatalf("grading: %v\n%s", err, res)
		}
		raw, err := os.ReadFile(filepath.Join(out, "group1.json"))
		if err != nil {
			t.Fatal(err)
		}
		var rep struct {
			Questions []struct {
				ID      string  `json:"id"`
				Awarded float64 `json:"awarded"`
			} `json:"questions"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatal(err)
		}
		got := map[string]float64{}
		for _, q := range rep.Questions {
			got[q.ID] = q.Awarded
		}
		return got
	}

	setPassive := func(t *testing.T, on bool) {
		t.Helper()
		cmds := []string{"configure terminal"}
		for _, p := range ports {
			cmds = append(cmds, "interface "+p)
			if on {
				cmds = append(cmds, "ip pim passive")
			} else {
				cmds = append(cmds, "no ip pim passive")
			}
		}
		cmds = append(cmds, "end")
		args := []string{"exec", "-m", dir, victim, "--", "vtysh"}
		for _, c := range cmds {
			args = append(args, "-c", c)
		}
		if out, err := twinet(t, args...); err != nil {
			t.Fatalf("configuring %s: %v\n%s", victim, err, out)
		}
	}

	before := grade(t)
	for _, id := range []string{"q1", "q3", "q4"} {
		if before[id] < 0.999 {
			t.Fatalf("the reference does not score full marks on %s (%.2f); nothing below "+
				"could be attributed to the change", id, before[id])
		}
	}

	setPassive(t, true)
	defer func() {
		setPassive(t, false)
		// Coming back is quick: a hello is sent at once.
		time.Sleep(45 * time.Second)
		after := grade(t)
		for _, id := range []string{"q1", "q3"} {
			if after[id] < 0.999 {
				t.Errorf("%s is still %.2f after the lab was put back", id, after[id])
			}
		}
	}()
	// Long enough for the neighbours to time out.
	//
	// PIM's default hold time is 105 seconds, so a shorter wait reads a
	// neighbour that has not expired yet as evidence that the check does not
	// work.
	time.Sleep(130 * time.Second)

	broken := grade(t)
	if broken["q1"] >= before["q1"] {
		t.Errorf("q1 still scored %.2f with three transit interfaces passive; a PIM "+
			"interface with no neighbour is not running PIM", broken["q1"])
	}
	if broken["q3"] >= before["q3"] {
		t.Errorf("q3 still scored %.2f with one site unable to receive the group; the "+
			"delivery check is not covering every site", broken["q3"])
	}
}
