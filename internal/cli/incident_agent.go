package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/fault"
)

// Evaluating an agent, and scoring what it said.
//
// The runner injected faults, waited, resolved them and wrote the ground truth,
// and stopped there: there was no way to hand the incident to an agent and no
// definition of what a right answer looks like, so every evaluation had to be
// driven by something outside this repository that then compared against the
// truth in its own way. Two harnesses scoring the same episode differently is
// not a benchmark.
//
// This is the missing half. An agent is a command. It is given the brief, the
// symptoms and how to reach the lab, and it prints a diagnosis. The diagnosis
// is scored against the ground truth the episode already records.

// Diagnosis is what an agent concludes.
//
// Deliberately small, and deliberately the same shape as the ground truth: the
// two are compared field by field, and a field an agent cannot fill is a field
// it scores nothing for rather than one it can talk its way around.
type Diagnosis struct {
	// IsAnomaly is whether the agent believes anything is wrong at all. A
	// benchmark needs episodes where nothing is, or "something is broken" is
	// free.
	IsAnomaly bool `json:"is_anomaly"`
	// FaultyDevices are the devices it holds responsible, as "as3/ATL".
	FaultyDevices []string `json:"faulty_devices,omitempty"`
	// Category is the taxonomy's category, and RootCauseNames the type names.
	Category       string   `json:"root_cause_category,omitempty"`
	RootCauseNames []string `json:"root_cause_name,omitempty"`
	// Explanation is free text, recorded but not scored: scoring prose would
	// make the mark depend on a judge nobody can inspect.
	Explanation string `json:"explanation,omitempty"`
}

// Score is how well a diagnosis matched the truth.
//
// Four parts, each independently checkable, because a single number hides which
// half of the answer was right: an agent that names the right device for the
// wrong reason and one that names the right reason on the wrong device are
// different failures and a benchmark that cannot tell them apart teaches
// nothing.
type Score struct {
	Detected  bool    `json:"detected"`
	Devices   float64 `json:"devices"`
	Category  bool    `json:"category"`
	RootCause bool    `json:"root_cause"`
	Total     float64 `json:"total"`
	Detail    string  `json:"detail"`
}

// scoreDiagnosis compares what an agent said with what was injected.
func scoreDiagnosis(d Diagnosis, truth []fault.GroundTruth) Score {
	var s Score
	anomaly := false
	wantDevices := map[string]bool{}
	wantNames := map[string]bool{}
	wantCats := map[string]bool{}
	for _, t := range truth {
		if t.IsAnomaly {
			anomaly = true
		}
		for _, dev := range t.FaultyDevices {
			wantDevices[dev] = true
		}
		for _, n := range t.Names {
			wantNames[n] = true
		}
		if t.Category != "" {
			wantCats[t.Category] = true
		}
	}

	s.Detected = d.IsAnomaly == anomaly
	// Jaccard over the devices, so naming every device in the lab scores badly
	// rather than perfectly. An agent that answers "one of these two hundred"
	// has diagnosed nothing.
	if len(wantDevices) > 0 || len(d.FaultyDevices) > 0 {
		said := map[string]bool{}
		for _, dev := range d.FaultyDevices {
			said[strings.TrimSpace(dev)] = true
		}
		inter, union := 0, len(wantDevices)
		for dev := range said {
			if wantDevices[dev] {
				inter++
			} else {
				union++
			}
		}
		if union > 0 {
			s.Devices = float64(inter) / float64(union)
		}
	} else {
		s.Devices = 1
	}
	// The taxonomy has a category for compositions, and an episode that
	// injected several faults is one. Accepting any constituent category meant
	// a three-fault episode had three right answers and an agent that saw one
	// of the three scored as well as one that saw all of them -- which is the
	// opposite of what a multi-fault episode is for.
	if len(truth) > 1 {
		wantCats = map[string]bool{string(fault.CatMultiple): true}
	}
	s.Category = len(wantCats) == 0 || wantCats[d.Category]
	// Every injected root cause has to be named, and nothing else: a list of
	// all sixty type names would otherwise contain the right one.
	if len(wantNames) == 0 {
		s.RootCause = len(d.RootCauseNames) == 0
	} else {
		said := map[string]bool{}
		for _, n := range d.RootCauseNames {
			said[strings.TrimSpace(n)] = true
		}
		s.RootCause = len(said) == len(wantNames)
		for n := range wantNames {
			if !said[n] {
				s.RootCause = false
			}
		}
	}

	// Weighted towards the cause. Detecting that something is wrong is the
	// easiest part and worth the least; naming what it was is the point.
	s.Total = 0
	if s.Detected {
		s.Total += 0.2
	}
	s.Total += 0.3 * s.Devices
	if s.Category {
		s.Total += 0.2
	}
	if s.RootCause {
		s.Total += 0.3
	}

	// Getting "is anything wrong" wrong means the rest is not an answer.
	//
	// The three parts below detection are scored against what was injected, so
	// on a healthy control -- where nothing was -- naming no devices, no
	// category and no root cause is exactly right, and an agent that cried
	// wolf collected 0.80 for it. The control exists to catch the strategy of
	// always answering "yes"; it was rewarding it. The same gate closes the
	// other direction: an agent that says a broken network is fine has not
	// diagnosed it by declining to name anything.
	if !s.Detected {
		s.Total = 0
		if s.Detail == "" {
			switch {
			case anomaly:
				s.Detail = "said nothing was wrong with a network that was broken"
			default:
				s.Detail = "reported a fault in a network that was healthy"
			}
		}
	}

	var missing []string
	for dev := range wantDevices {
		found := false
		for _, said := range d.FaultyDevices {
			if strings.TrimSpace(said) == dev {
				found = true
			}
		}
		if !found {
			missing = append(missing, dev)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		s.Detail = "did not name " + strings.Join(missing, ", ")
	}
	return s
}

// runAgent hands an episode to a command and reads back its diagnosis.
//
// The agent is given the brief and the symptoms on standard input, and the
// environment it needs to look at the lab. It is *not* given the ground truth,
// the fault names, or anything else that would answer the question: a benchmark
// whose subject can read the answer measures nothing.
func runAgent(ctx context.Context, command string, ep *Episode, sb *sandbox, token string,
	timeout time.Duration) (Diagnosis, string, error) {

	var d Diagnosis
	brief := struct {
		Brief    string   `json:"brief"`
		Symptoms []string `json:"symptoms"`
		Lab      string   `json:"lab"`
		Manifest string   `json:"manifest"`
		Deadline string   `json:"deadline"`
	}{ep.Brief, ep.Symptoms, ep.Lab, sb.Manifest, timeout.String()}
	input, err := json.MarshalIndent(brief, "", "  ")
	if err != nil {
		return d, "", err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Run inside a mount namespace with the answer masked out.
	//
	// Dropping to an unprivileged account and handing it a filtered copy was
	// not enough: the original lab is world-readable, and the scenario file in
	// it names the fault, the device and the interface in plain YAML. So does
	// the end-to-end test that exercises it. An agent whose entire strategy was
	// to grep the repository for the words in its own brief scored a perfect
	// 1.00 without looking at the network.
	//
	// A namespace is the only control that holds, because there is no list of
	// files that is both short enough to allowlist and complete enough to
	// trust. Each path is covered with an empty, unreadable filesystem; the
	// mounts are private, so nothing outside this process sees them, and they
	// disappear with it.
	c, err := agentCommand(runCtx, command, sb)
	if err != nil {
		return d, "", err
	}
	c.Stdin = strings.NewReader(string(input) + "\n")
	c.Dir = sb.Dir
	// The agent is handed a credential that can look at this lab and change
	// nothing, not the cluster secret. See internal/agent/diagnostic.go.
	c.Env = append(sanitisedEnv(),
		"HOME="+sb.Dir,
		"TMPDIR="+sb.Dir,
		"TWINET_MANIFEST="+sb.Manifest,
		"TWINET_LAB="+ep.Lab,
		"TWINET_TOKEN="+agent.DiagnosticToken(token, ep.Lab),
	)
	if sb.TLSCert != "" {
		c.Env = append(c.Env,
			"TWINET_TLS_CERT="+sb.TLSCert,
			"TWINET_TLS_KEY="+sb.TLSKey,
			"TWINET_CA="+sb.TLSCA)
	}
	var out, errb strings.Builder
	c.Stdout, c.Stderr = &out, &errb
	runErr := c.Run()
	raw := strings.TrimSpace(out.String())
	if raw == "" {
		return d, errb.String(), fmt.Errorf("the agent printed no diagnosis (%v): %s",
			runErr, firstLines(errb.String(), 3))
	}
	// The last JSON object the agent printed, so an agent that narrates before
	// answering is not punished for narrating.
	if i := strings.LastIndex(raw, "{"); i > 0 {
		raw = raw[i:]
	}
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return d, errb.String(), fmt.Errorf("the agent's diagnosis could not be read (%w): %s",
			err, firstLines(raw, 3))
	}
	return d, errb.String(), nil
}

// sanitisedEnv is the environment an evaluated agent starts from: this
// process's, minus anything that would hand it the cluster or point it at the
// answer. Inheriting os.Environ() wholesale passed TWINET_TOKEN through.
func sanitisedEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "TWINET_TOKEN", "TWINET_MANIFEST", "TWINET_LAB", "TWINET_STATE_DIR",
			// The controller's own transport identity, which is not the
			// agent's: it gets one of its own, valid for hours.
			"TWINET_TLS_CERT", "TWINET_TLS_KEY", "TWINET_CA",
			"TWINET_ALLOW_VERSION_SKEW", "HOME", "TMPDIR", "XDG_STATE_HOME",
			"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "SUDO_USER", "SUDO_UID", "SUDO_GID":
			continue
		}
		out = append(out, kv)
	}
	return out
}

// agentCommand builds the process an evaluated agent runs as.
//
// Where the tools exist and this process is root, that is: a private mount
// namespace, an empty filesystem over every path that holds the answer, and
// then the agent as an unprivileged account. Where they do not, it is the
// unprivileged account alone, and the caller is told that the isolation is
// weaker than it should be rather than left to assume it is not.
// canEvaluateAgents reports whether this process can put an agent somewhere it
// cannot read the answer, so `incident run` can refuse before it injects
// anything rather than after.
func canEvaluateAgents() error {
	if os.Geteuid() != 0 {
		return errors.New("evaluating an agent needs root: the agent has to be put in a " +
			"namespace where it cannot read the scenario, the lab or the injection ledger, " +
			"and this process cannot create one. Re-run under sudo")
	}
	for _, tool := range []string{"unshare", "setpriv"} {
		if !haveTool(tool) {
			return fmt.Errorf("evaluating an agent needs %s, which is not installed: without "+
				"it the agent shares this machine's filesystem and process table, and can "+
				"read the fault it is being asked to diagnose", tool)
		}
	}
	return nil
}

func agentCommand(ctx context.Context, command string, sb *sandbox) (*exec.Cmd, error) {
	// Refused rather than weakened.
	//
	// This used to fall back to running the agent as the invoking user, with no
	// namespaces and no warning unless it happened to be root. An ordinary
	// `twinet incident run --agent ...` without sudo therefore ran the agent as
	// somebody who can read the scenario file, which names the fault and the
	// device -- so the benchmark silently measured nothing, and looked exactly
	// like one that had worked. A score that cannot be trusted is worse than no
	// score, because somebody will quote it.
	if err := canEvaluateAgents(); err != nil {
		return nil, err
	}
	var script strings.Builder
	for _, p := range sb.Hide {
		// Empty, unreadable, and not a bind of anything: a directory the agent
		// can see the name of and nothing inside.
		fmt.Fprintf(&script, "mount -t tmpfs -o size=4k,mode=0000 none %s || exit 90\n",
			shellQuote(p))
	}
	fmt.Fprintf(&script, "exec setpriv --reuid %d --regid %d --clear-groups sh -c %s\n",
		sb.UID, sb.GID, shellQuote(command))
	// A process namespace as well as a mount one.
	//
	// Masking the files was not enough: the agent shared the host's /proc, and
	// this runner's own command line contains "--scenario
	// .../ospf_adjacency_lost.yaml". An agent whose entire strategy was
	// `ps -eo args | grep 'twinet incident run'` read the scenario's name,
	// mapped it to the answer, and scored 1.00 without looking at the network.
	// The scenario names in any suite say what the fault is; that is what makes
	// them useful to a person and fatal here.
	//
	// --fork is required with --pid (the namespace applies to children), and
	// --mount-proc gives the namespace a procfs of its own, so /proc shows the
	// agent and nothing else.
	return exec.CommandContext(ctx, "unshare", "--mount", "--pid", "--fork", "--mount-proc",
		"--propagation", "private", "--", "sh", "-c", script.String()), nil
}

func haveTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
