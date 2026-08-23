package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
)

// An incident is the reproducible unit of an evaluation: a lab, a baseline, a
// set of faults, and the ground truth. `twinet incident run` establishes the
// baseline, injects, verifies, hands an endpoint to an agent, and scores the
// diagnosis against the answer it never had access to.

// Scenario is an incident definition.
type Scenario struct {
	APIVersion string       `yaml:"apiVersion" json:"apiVersion"`
	Kind       string       `yaml:"kind" json:"kind"`
	Metadata   ScenarioMeta `yaml:"metadata" json:"metadata"`
	Faults     []FaultSpec  `yaml:"faults" json:"faults"`
	// Requirements explicitly declares typed substrates the scenario needs.
	// A scenario is rejected before injection when it omits a requirement or
	// the selected runtime cannot discover it.
	Requirements []fault.Substrate `yaml:"requirements,omitempty" json:"requirements,omitempty"`
	Brief        string            `yaml:"brief,omitempty" json:"brief,omitempty"`
	// Seed makes a time-varying fault replay exactly.
	Seed int64 `yaml:"seed,omitempty" json:"seed,omitempty"`
	// Control declares an episode that injects nothing.
	//
	// Without these, "is anything wrong?" is worth 0.2 for answering yes, and
	// an agent that always answers yes collects it on every episode in the
	// suite. A control is how the suite finds out whether an agent can tell a
	// healthy network from a broken one; a benchmark made only of broken
	// networks cannot.
	Control bool `yaml:"control,omitempty" json:"control,omitempty"`
}

// ScenarioMeta names an incident.
type ScenarioMeta struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// FaultSpec is one fault to inject.
//
// Either the scenario says where the fault goes, or it says what kind of place
// it goes and the run draws one. The second is what a published scenario should
// do: a file that names the device and the interface hands the answer to
// anybody who has read the repository, and there is no way to un-publish it.
type FaultSpec struct {
	Type   string       `yaml:"type" json:"type"`
	Target fault.Target `yaml:"target,omitempty" json:"target,omitempty"`
	Select *Selector    `yaml:"select,omitempty" json:"select,omitempty"`
}

// Episode is the durable record of one incident run.
type Episode struct {
	Scenario  string              `json:"scenario"`
	Lab       string              `json:"lab"`
	Topology  string              `json:"topology_hash"`
	Seed      int64               `json:"seed"`
	StartedAt time.Time           `json:"started_at"`
	Duration  string              `json:"duration"`
	Brief     string              `json:"brief"`
	Symptoms  []string            `json:"symptoms"`
	Truth     []fault.GroundTruth `json:"ground_truth"`
	Resolved  bool                `json:"resolved"`
	Err       string              `json:"error,omitempty"`

	// What an agent said, and what it scored. Absent when no agent was run.
	Diagnosis *Diagnosis `json:"diagnosis,omitempty"`
	Score     *Score     `json:"score,omitempty"`
	AgentErr  string     `json:"agent_error,omitempty"`
	AgentLog  string     `json:"agent_log,omitempty"`
	// SelectionSeed is what the run drew its targets with, and the only record
	// of where a scenario that does not name its own answer put the fault.
	SelectionSeed int64 `json:"selection_seed,omitempty"`
	// AgentEgress is every address and port the agent could reach while it was
	// being scored.
	//
	// A score earned with a route to the internet is a different measurement
	// from one earned without, because the scenarios are published: it belongs
	// beside the number rather than in the operator's memory.
	AgentEgress []string `json:"agent_egress,omitempty"`
	// Substrates records the native/delegated capability decision that made
	// this episode runnable. It deliberately contains no kubeconfig, token,
	// or backend command line.
	Substrates []fault.Availability `json:"substrates,omitempty"`
}

func newIncidentCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "incident",
		Short: "Run a reproducible network incident for agent evaluation",
		Long: `An incident is a lab, a baseline, a set of injected faults and the ground
truth. It is the unit an AI agent is measured on: the agent sees the reported
symptoms and the live network, and never the answer.`,
	}
	cmd.AddCommand(newIncidentRunCmd(opts), newIncidentValidateCmd(),
		newIncidentCredentialCmd(opts))
	return cmd
}

func newIncidentValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <scenario.yaml>",
		Short: "Check an incident scenario before it is run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadScenario(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is valid: %d fault(s)\n",
				s.Metadata.Name, len(s.Faults))
			return nil
		},
	}
}

func loadScenario(path string) (*Scenario, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scenario: %w", err)
	}
	var s Scenario
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Metadata.Name == "" {
		return nil, fmt.Errorf("%s: the scenario has no name", path)
	}
	if len(s.Faults) == 0 && !s.Control {
		return nil, fmt.Errorf("%s: the scenario injects no faults. If that is deliberate -- "+
			"a healthy control, so that answering \"something is wrong\" is not free -- say "+
			"so with `control: true`", path)
	}
	if len(s.Faults) > 0 && s.Control {
		return nil, fmt.Errorf("%s: a control injects nothing, but this one injects %d fault(s)",
			path, len(s.Faults))
	}
	var problems []string
	names := make([]string, 0, len(s.Faults))
	for i, f := range s.Faults {
		names = append(names, f.Type)
		if _, ok := fault.Lookup(f.Type); !ok {
			problems = append(problems,
				fmt.Sprintf("faults[%d]: %q is not a registered fault type", i, f.Type))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s:\n  %s", path, strings.Join(problems, "\n  "))
	}
	if err := fault.ValidateScenarioRequirements(names, s.Requirements); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func newIncidentRunCmd(opts *Options) *cobra.Command {
	var (
		scenarioPath     string
		outDir           string
		token            string
		hold             time.Duration
		keep             bool
		showTruth        bool
		agentCmd         string
		agentTimeout     time.Duration
		agentEgressAllow []string
		selectionSeed    int64
		allowPinned      bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Establish a baseline, inject an incident, and record it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scenarioPath == "" {
				return fmt.Errorf("pass --scenario")
			}
			// Before anything is injected.
			//
			// The agent has to run somewhere it cannot read the scenario, and
			// finding out after the faults are live means a lab left broken by
			// a run that could never have measured anything.
			if agentCmd != "" {
				if err := canEvaluateAgents(); err != nil {
					return err
				}
			}
			sc, err := loadScenario(scenarioPath)
			if err != nil {
				return err
			}
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			env, err := faultEnv(cmd, top, token)
			if err != nil {
				return err
			}
			env.Seed = sc.Seed

			// Where the faults go, if the scenario left that to the run.
			//
			// A scenario that names its device and its interface is the answer
			// written down; published, it measures whether an agent has read
			// the repository. So the draw happens here, from a seed nobody
			// could have known in advance, and the choice is recorded in the
			// episode rather than in the file.
			drawSeed := selectionSeed
			if drawSeed == 0 {
				drawSeed = time.Now().UnixNano()
			}
			candidates, err := drawTargets(top, sc.Faults, drawSeed)
			if err != nil {
				return err
			}
			var drawn []string
			if pinned := pinnedTargets(sc.Faults); len(pinned) > 0 && agentCmd != "" && !allowPinned {
				return fmt.Errorf("this scenario names its own answer:\n  %s\n"+
					"An agent scored against it may have read the file rather than the "+
					"network -- every scenario shipped with Twinet is on the internet, and "+
					"so is anything else in a repository. Give the faults a `select:` so the "+
					"run draws the target, or pass --allow-pinned-target if this scenario is "+
					"yours and has never been published", strings.Join(pinned, "\n  "))
			}

			ep := &Episode{
				Scenario: sc.Metadata.Name, Lab: top.Name, Topology: top.Hash,
				Seed: sc.Seed, StartedAt: time.Now().UTC(), Brief: sc.Brief,
			}
			for i, fs := range sc.Faults {
				f, ok := fault.Lookup(fs.Type)
				if !ok {
					continue
				}
				target := fs.Target
				if len(candidates[i]) > 0 {
					target = candidates[i][0]
				}
				ep.Substrates = append(ep.Substrates,
					fault.AvailabilityFor(cmd.Context(), f, env, target)...)
			}
			// Discover every declared substrate before the first mutation.
			// In particular, a Kubernetes incident must not inject an earlier
			// native fault and only then discover that no endpoint/context was
			// configured for its delegated half.
			for i, fs := range sc.Faults {
				f, ok := fault.Lookup(fs.Type)
				if !ok || len(candidates[i]) == 0 {
					continue
				}
				if err := fault.RequireAvailable(cmd.Context(), f, env, candidates[i][0]); err != nil {
					return fmt.Errorf("scenario substrate discovery for faults[%d] %s: %w", i, fs.Type, err)
				}
			}
			if len(pinnedTargets(sc.Faults)) < len(sc.Faults) {
				ep.SelectionSeed = drawSeed
			}
			start := time.Now()

			// Inject, remembering each success so a partial failure can still
			// be unwound: a lab left half-broken is worse than one never used.
			//
			// Each success is also written to the lab's injection record
			// before the next one is attempted. That record is what `twinet
			// fault status` reads and what `twinet fault resolve --all`
			// undoes, and until this was done the list lived only in this
			// process: an interrupted run, a lost connection, or a scenario
			// held open with --keep left faults live in the lab with nothing
			// on disk saying which, so the only way to find them was to know
			// what had been run.
			unlockInj, err := lockInjections(top)
			if err != nil {
				return err
			}
			ledger, err := loadInjections(top)
			if err != nil {
				unlockInj()
				return err
			}
			// An episode has to start from a lab with nothing wrong with it.
			//
			// Faults already live were neither refused nor recorded in the
			// episode's ground truth, so the agent was shown anomalies that the
			// scoring did not know about -- and the run could report itself
			// resolved while they were still there. Whatever an agent concludes
			// from an extra fault is then marked wrong for the right reason.
			if len(ledger) > 0 {
				unlockInj()
				names := make([]string, 0, len(ledger))
				for _, inj := range ledger {
					names = append(names, fmt.Sprintf("%s on %s", inj.Fault, inj.Target.DeviceID()))
				}
				sort.Strings(names)
				return fmt.Errorf("this lab already has %d fault(s) injected:\n  %s\n"+
					"An episode measures what an agent concludes from what it can see, and "+
					"these are not in its ground truth. Clear them with `twinet fault "+
					"resolve --all` first", len(ledger), strings.Join(names, "\n  "))
			}
			// A fault that could not be recorded is undone rather than left
			// live. Warning and carrying on recreated the exact defect this
			// record exists to close: an interruption, or a scenario held open
			// with --keep, leaves a fault in the lab that nothing on disk
			// mentions, so `twinet fault resolve --all` cannot find it and the
			// next class to use the cluster inherits it with no way to know
			// why their network is broken.
			journal := func(inj *fault.Injection) error {
				ledger = append(ledger, inj)
				if err := saveInjections(top, ledger); err != nil {
					ledger = ledger[:len(ledger)-1]
					if rerr := fault.Resolve(cmd.Context(), env, inj); rerr != nil {
						return fmt.Errorf("%s is live, could not be recorded (%v), and could "+
							"not be undone either (%v). It is still in the lab and nothing on "+
							"disk says so: resolve it by hand before using this lab again",
							inj.Fault, err, rerr)
					}
					return fmt.Errorf("%s could not be recorded (%w), so it has been undone "+
						"rather than left live with no record of it", inj.Fault, err)
				}
				return nil
			}

			var injected []*fault.Injection
			for i, fs := range sc.Faults {
				// The draw, and then its fallbacks.
				//
				// A candidate that cannot host this fault -- a link already
				// down, a symptom already present -- is refused before
				// anything is changed, so the next one is tried. Only a
				// failure that may have touched the device stops the run.
				var inj *fault.Injection
				var err error
				attempts := candidates[i]
				if len(attempts) > 5 {
					attempts = attempts[:5]
				}
				for n, t := range attempts {
					inj, err = fault.Inject(cmd.Context(), env, fs.Type, t)
					if err == nil {
						if sc.Faults[i].Select != nil {
							drawn = append(drawn, describeDraw(fs.Type, t, len(candidates[i])))
						}
						break
					}
					if inj != nil || n == len(attempts)-1 {
						break
					}
					fmt.Fprintf(cmd.ErrOrStderr(),
						"a drawn target could not host %s (%v); drawing another\n", fs.Type, err)
				}
				if err != nil {
					// A failed injection that still left something live hands
					// it back. Record it before giving up, or the lab is
					// contaminated with nothing on disk naming the cause.
					if inj != nil {
						if jerr := journal(inj); jerr != nil {
							fmt.Fprintf(cmd.ErrOrStderr(), "%v\n", jerr)
						}
						injected = append(injected, inj)
					}
					ep.Err = err.Error()
					fmt.Fprintf(cmd.ErrOrStderr(), "injection failed: %v\n", err)
					break
				}
				if jerr := journal(inj); jerr != nil {
					ep.Err = jerr.Error()
					fmt.Fprintf(cmd.ErrOrStderr(), "%v\n", jerr)
					break
				}
				injected = append(injected, inj)
				ep.Truth = append(ep.Truth, inj.Truth)
				if f, ok := fault.Lookup(fs.Type); ok {
					ep.Symptoms = append(ep.Symptoms, f.Symptom)
				}
			}

			if ep.Err == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "incident %q is live: %d fault(s) injected and verified\n",
					sc.Metadata.Name, len(injected))
				fmt.Fprintln(cmd.OutOrStdout(), "\nwhat the agent is told:")
				if sc.Brief != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", sc.Brief)
				}
				for _, s := range ep.Symptoms {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", s)
				}
				if hold > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "\nholding for %s\n", hold)
					select {
					case <-time.After(hold):
					case <-cmd.Context().Done():
					}
				}

				// The agent, if one was given, and the mark for what it said.
				//
				// This is what makes an episode a measurement rather than a
				// recording. Without it every evaluation had to be driven from
				// outside and compared against the truth in its own way, and
				// two harnesses scoring the same episode differently is not a
				// benchmark.
				if agentCmd != "" {
					// An agent that crashed, timed out or printed nothing has
					// not been evaluated, and an episode that reports no score
					// used to exit successfully -- so a harness running a
					// hundred episodes against a broken agent saw a hundred
					// clean runs and no marks. It is an error now.
					err := func() error {
						sb, serr := newSandbox(top, opts.Manifest, sc.Metadata.Name, agentEgressAllow)
						if serr != nil {
							return fmt.Errorf("preparing the agent sandbox: %w", serr)
						}
						defer sb.Remove()
						// The cluster secret, resolved the same way every
						// other command resolves it. Passing the flag through
						// raw derived the agent's credential from an empty
						// string whenever the token came from the environment,
						// so every observation it tried came back 401 and the
						// episode scored an agent that had been prevented from
						// looking at anything.
						secret, terr := tokenFor(token)
						if terr != nil {
							return fmt.Errorf("deriving the agent's credential: %w", terr)
						}
						ep.AgentEgress = sb.Net.Allowed
						d, stderr, aerr := runAgent(cmd.Context(), agentCmd, ep,
							sb, secret, agentTimeout)
						if strings.TrimSpace(stderr) != "" {
							ep.AgentLog = stderr
						}
						if aerr != nil {
							ep.AgentErr = aerr.Error()
							return fmt.Errorf("the agent did not answer: %w", aerr)
						}
						ep.Diagnosis = &d
						mark := scoreDiagnosis(d, ep.Truth)
						ep.Score = &mark
						fmt.Fprintf(cmd.OutOrStdout(),
							"\nthe agent scored %.2f of 1.00 "+
								"(detected %v, devices %.2f, category %v, root cause %v)%s\n",
							mark.Total, mark.Detected, mark.Devices, mark.Category, mark.RootCause,
							map[bool]string{true: "", false: "; " + mark.Detail}[mark.Detail == ""])
						return nil
					}()
					if err != nil {
						ep.Err = err.Error()
						fmt.Fprintf(cmd.ErrOrStderr(), "%v\n", err)
					}
				}
			}

			if !keep {
				for i := len(injected) - 1; i >= 0; i-- {
					if err := fault.Resolve(cmd.Context(), env, injected[i]); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "resolve: %v\n", err)
						ep.Err = err.Error()
						continue
					}
					// Removed from the record only once it is actually gone,
					// so anything that failed to resolve stays listed and can
					// be found later.
					// Removed by identifier, not by name and device.
					//
					// A scenario may inject the same fault type on the same
					// device twice. Matching on those removed whichever record
					// came first, so resolving one deleted the other's entry --
					// and if that one then failed to resolve, it was live with
					// nothing on disk saying so, which is the state this record
					// exists to make impossible.
					for j, l := range ledger {
						if l.ID == injected[i].ID {
							ledger = append(ledger[:j], ledger[j+1:]...)
							break
						}
					}
					if err := saveInjections(top, ledger); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "warning: updating the injection record: %v\n", err)
					}
				}
				ep.Resolved = ep.Err == ""
			}
			unlockInj()
			ep.Duration = time.Since(start).Round(time.Millisecond).String()

			if outDir == "" {
				outDir = filepath.Join("episodes", time.Now().UTC().Format("2006-01-02-150405"))
			}
			if err := os.MkdirAll(outDir, 0o750); err != nil {
				return err
			}
			raw, err := json.MarshalIndent(ep, "", "  ")
			if err != nil {
				return err
			}
			// The episode record holds the answer, so it is written with
			// restrictive permissions and never into the lab.
			path := filepath.Join(outDir, sc.Metadata.Name+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\nepisode recorded at %s\n", path)
			if showTruth {
				for _, t := range ep.Truth {
					fmt.Fprintf(cmd.OutOrStdout(), "  ground truth: %s on %s (%s)\n",
						strings.Join(t.Names, ","), strings.Join(t.FaultyDevices, ","), t.Category)
				}
				// Only here. Printing what was drawn is printing the answer,
				// and a run whose console output names the device is one
				// screenshot away from being the file it replaced.
				for _, d := range drawn {
					fmt.Fprintf(cmd.OutOrStdout(), "  drawn with seed %d: %s\n", drawSeed, d)
				}
			}
			if ep.Err != "" {
				return fmt.Errorf("the incident did not complete cleanly: %s", ep.Err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&scenarioPath, "scenario", "", "incident scenario file")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "directory for the episode record")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	cmd.Flags().DurationVar(&hold, "hold", 0, "keep the incident live for this long")
	cmd.Flags().BoolVar(&keep, "keep", false, "leave the faults injected")
	cmd.Flags().BoolVar(&showTruth, "ground-truth", false, "print the answer")
	cmd.Flags().StringVar(&agentCmd, "agent", "",
		"command to run as the agent under evaluation; it is given the brief on stdin "+
			"and must print a diagnosis as JSON")
	cmd.Flags().Int64Var(&selectionSeed, "seed", 0,
		"draw this scenario's targets with this seed instead of a fresh one, to replay an "+
			"episode exactly; the seed used is recorded in the episode either way")
	cmd.Flags().BoolVar(&allowPinned, "allow-pinned-target", false,
		"score an agent against a scenario that names its own device and interface; only "+
			"sound for a scenario that has never been published")
	cmd.Flags().StringSliceVar(&agentEgressAllow, "allow-egress", nil,
		"host:port an evaluated agent may reach beyond the node agents, repeatable; "+
			"a model endpoint is the usual reason. Recorded in the episode, because a "+
			"score means something different when the agent could reach the internet")
	cmd.Flags().DurationVar(&agentTimeout, "agent-timeout", 10*time.Minute,
		"how long the agent may take")
	return cmd
}

var _ = model.DeviceID

// newIncidentCredentialCmd mints the read-only credential an evaluated agent
// runs with, so a harness outside this repository can drive an agent itself
// without handing it the cluster.
func newIncidentCredentialCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credential",
		Short: "mint a read-only, single-lab credential for an agent under evaluation",
		Long: "An agent given TWINET_TOKEN can read every lab on the cluster, run anything " +
			"in any container, take a grading hold, and destroy the evidence. This mints a " +
			"credential that can look at one lab and change nothing: `twinet exec` and " +
			"`twinet node status` work with it, everything else is refused by the node agents.\n\n" +
			"`twinet incident run --agent` uses one automatically; this is for harnesses that " +
			"drive the agent themselves.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			token := os.Getenv("TWINET_TOKEN")
			if token == "" {
				return errors.New("the cluster token is needed to derive a credential from it: " +
					"set TWINET_TOKEN from a protected credential file")
			}
			fmt.Fprintln(cmd.OutOrStdout(), agent.DiagnosticToken(token, top.Name))
			return nil
		},
	}
	return cmd
}
