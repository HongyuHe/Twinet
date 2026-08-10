package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
)

func newFaultCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fault",
		Short: "Inject, verify and resolve network faults",
		Long: `Faults serve two purposes. In a course they are the scripted misconfiguration
an exercise is built around. In an evaluation they are the incident an AI agent
is asked to diagnose, following the taxonomy of the NIKA benchmark.

Every fault is reversible and every injection is verified: an incident that
failed to inject must never be presented to an agent as a puzzle.`,
	}
	cmd.AddCommand(
		newFaultListCmd(),
		newFaultInjectCmd(opts),
		newFaultResolveCmd(opts),
		newFaultStatusCmd(opts),
	)
	return cmd
}

func newFaultListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the registered fault types",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if asJSON {
				type out struct {
					Name     string   `json:"name"`
					Category string   `json:"category"`
					Symptom  string   `json:"symptom"`
					Needs    []string `json:"needs"`
				}
				var list []out
				for _, f := range fault.All() {
					o := out{Name: f.Name, Category: string(f.Category), Symptom: f.Symptom}
					for _, c := range f.Needs {
						o.Needs = append(o.Needs, string(c))
					}
					list = append(list, o)
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(list)
			}
			byCat := fault.ByCategory()
			cats := make([]string, 0, len(byCat))
			for c := range byCat {
				cats = append(cats, string(c))
			}
			sort.Strings(cats)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "FAULT\tCATEGORY\tNEEDS\tSYMPTOM AS REPORTED")
			for _, c := range cats {
				for _, f := range byCat[fault.Category(c)] {
					needs := make([]string, 0, len(f.Needs))
					for _, n := range f.Needs {
						needs = append(needs, string(n))
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Name, c,
						strings.Join(needs, ","), f.Symptom)
				}
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\n%d fault types registered\n", len(fault.All()))
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

// injectionsPath is where an injection record lives, so resolve can undo
// exactly what inject did after the process has exited.
func injectionsPath(top *model.Topology) string {
	return filepath.Join(top.Lab.Dir, ".twinet", "injections.json")
}

func loadInjections(top *model.Topology) ([]*fault.Injection, error) {
	raw, err := os.ReadFile(injectionsPath(top))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*fault.Injection
	return out, json.Unmarshal(raw, &out)
}

func saveInjections(top *model.Topology, in []*fault.Injection) error {
	p := injectionsPath(top)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	// Ground truth lives here, in the control plane, and is never written into
	// a container: an agent that could read the answer is not being measured.
	return os.WriteFile(p, raw, 0o600)
}

func newFaultInjectCmd(opts *Options) *cobra.Command {
	var (
		target   fault.Target
		params   []string
		token    string
		showTrue bool
	)
	cmd := &cobra.Command{
		Use:   "inject <fault>",
		Short: "Inject a fault and verify it took effect",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			env, err := faultEnv(cmd, top, token)
			if err != nil {
				return err
			}
			target.Params = parseKV(params)

			inj, err := fault.Inject(cmd.Context(), env, args[0], target)
			if err != nil {
				return err
			}
			existing, _ := loadInjections(top)
			existing = append(existing, inj)
			if err := saveInjections(top, existing); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "injected %s on %s\n", inj.Fault, inj.Target.DeviceID())
			fmt.Fprintf(cmd.OutOrStdout(), "  verified: %s\n", inj.Evidence.Observed)
			if f, ok := fault.Lookup(inj.Fault); ok {
				fmt.Fprintf(cmd.OutOrStdout(), "  reported symptom: %s\n", f.Symptom)
			}
			if showTrue {
				raw, _ := json.MarshalIndent(inj.Truth, "  ", "  ")
				fmt.Fprintf(cmd.OutOrStdout(), "  ground truth: %s\n", raw)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(),
					"  ground truth withheld; pass --ground-truth to print it\n")
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&target.AS, "as", 0, "target AS")
	cmd.Flags().StringVar(&target.Device, "device", "", "target device")
	cmd.Flags().StringVar(&target.Iface, "iface", "", "target interface")
	cmd.Flags().IntVar(&target.Peer, "peer", 0, "peer AS, for faults that need one")
	cmd.Flags().StringVar(&target.Prefix, "prefix", "", "prefix, for faults that need one")
	cmd.Flags().StringArrayVar(&params, "param", nil, "fault-specific argument, key=value")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	cmd.Flags().BoolVar(&showTrue, "ground-truth", false, "print the answer")
	return cmd
}

func newFaultResolveCmd(opts *Options) *cobra.Command {
	var (
		token string
		all   bool
	)
	cmd := &cobra.Command{
		Use:   "resolve [fault]",
		Short: "Undo an injected fault and confirm it is gone",
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			env, err := faultEnv(cmd, top, token)
			if err != nil {
				return err
			}
			injections, err := loadInjections(top)
			if err != nil {
				return err
			}
			if len(injections) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "nothing is injected")
				return nil
			}

			var keep []*fault.Injection
			var resolved, failed int
			for _, inj := range injections {
				if !all && len(args) > 0 && inj.Fault != args[0] {
					keep = append(keep, inj)
					continue
				}
				if err := fault.Resolve(cmd.Context(), env, inj); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "  %v\n", err)
					keep = append(keep, inj)
					failed++
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "resolved %s on %s\n", inj.Fault, inj.Target.DeviceID())
				resolved++
			}
			if err := saveInjections(top, keep); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d fault(s) could not be resolved; the lab is not back at baseline",
					failed, resolved+failed)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "resolve every injected fault")
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

func newFaultStatusCmd(opts *Options) *cobra.Command {
	var showTrue bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what is currently injected",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			injections, err := loadInjections(top)
			if err != nil {
				return err
			}
			if len(injections) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "nothing is injected")
				return nil
			}
			if opts.JSON {
				if !showTrue {
					for _, i := range injections {
						i.Truth = fault.GroundTruth{}
					}
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(injections)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "FAULT\tTARGET\tINJECTED\tSYMPTOM")
			for _, i := range injections {
				sym := ""
				if f, ok := fault.Lookup(i.Fault); ok {
					sym = f.Symptom
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", i.Fault, i.Target.DeviceID(),
					i.InjectedAt.Format("15:04:05"), sym)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&showTrue, "ground-truth", false, "include the answer")
	return cmd
}

// faultEnv builds the execution environment a fault runs in.
func faultEnv(cmd *cobra.Command, top *model.Topology, token string) (*fault.Env, error) {
	exec, err := execFunc(cmd.Context(), top, token)
	if err != nil {
		return nil, err
	}
	life, err := lifecycleFunc(top, token)
	if err != nil {
		return nil, err
	}
	reshape, err := reshapeFunc(top, token)
	if err != nil {
		return nil, err
	}
	return &fault.Env{Topology: top, Exec: exec, Lifecycle: life, Reshape: reshape}, nil
}

func parseKV(in []string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, kv := range in {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}
