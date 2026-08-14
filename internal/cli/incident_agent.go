package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
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
	c := agentCommand(runCtx, command, sb)
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
func agentCommand(ctx context.Context, command string, sb *sandbox) *exec.Cmd {
	if os.Geteuid() != 0 || !haveTool("unshare") || !haveTool("setpriv") {
		c := exec.CommandContext(ctx, "sh", "-c", command)
		if os.Geteuid() == 0 {
			c.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{Uid: uint32(sb.UID), Gid: uint32(sb.GID)},
			}
			slog.Warn("running the agent without a mount namespace: unshare or setpriv is " +
				"missing, so it can read the lab directory it is being scored on")
		}
		return c
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
	return exec.CommandContext(ctx, "unshare", "--mount", "--propagation", "private",
		"--", "sh", "-c", script.String())
}

func haveTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
