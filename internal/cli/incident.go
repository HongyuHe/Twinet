package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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
	Brief      string       `yaml:"brief,omitempty" json:"brief,omitempty"`
	// Seed makes a time-varying fault replay exactly.
	Seed int64 `yaml:"seed,omitempty" json:"seed,omitempty"`
}

// ScenarioMeta names an incident.
type ScenarioMeta struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// FaultSpec is one fault to inject.
type FaultSpec struct {
	Type   string       `yaml:"type" json:"type"`
	Target fault.Target `yaml:"target" json:"target"`
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
}

func newIncidentCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "incident",
		Short: "Run a reproducible network incident for agent evaluation",
		Long: `An incident is a lab, a baseline, a set of injected faults and the ground
truth. It is the unit an AI agent is measured on: the agent sees the reported
symptoms and the live network, and never the answer.`,
	}
	cmd.AddCommand(newIncidentRunCmd(opts), newIncidentValidateCmd())
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
	if len(s.Faults) == 0 {
		return nil, fmt.Errorf("%s: the scenario injects no faults", path)
	}
	var problems []string
	for i, f := range s.Faults {
		if _, ok := fault.Lookup(f.Type); !ok {
			problems = append(problems,
				fmt.Sprintf("faults[%d]: %q is not a registered fault type", i, f.Type))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s:\n  %s", path, strings.Join(problems, "\n  "))
	}
	return &s, nil
}

func newIncidentRunCmd(opts *Options) *cobra.Command {
	var (
		scenarioPath string
		outDir       string
		token        string
		hold         time.Duration
		keep         bool
		showTruth    bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Establish a baseline, inject an incident, and record it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scenarioPath == "" {
				return fmt.Errorf("pass --scenario")
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

			ep := &Episode{
				Scenario: sc.Metadata.Name, Lab: top.Name, Topology: top.Hash,
				Seed: sc.Seed, StartedAt: time.Now().UTC(), Brief: sc.Brief,
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
			for _, fs := range sc.Faults {
				inj, err := fault.Inject(cmd.Context(), env, fs.Type, fs.Target)
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
	return cmd
}

var _ = model.DeviceID
