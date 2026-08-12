package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
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
		newFaultVerifyCmd(opts),
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
	// Written to a temporary file and renamed into place.
	//
	// This is the only record of what has been injected and how to undo it. A
	// partial write leaves live faults on the lab that nothing can name, and
	// the next episode runs on a network that is already broken in a way its
	// own ground truth does not mention. Rename is atomic on the same
	// filesystem, so a reader sees either the old file or the new one.
	//
	// Ground truth lives here, in the control plane, and is never written into
	// a container: an agent that could read the answer is not being measured.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".injections-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// lockInjections serialises access to the record.
//
// Two injections at once would each read the file, add their own entry, and
// write back, so one of them would be forgotten -- left running on the lab with
// nothing able to name or undo it.
func lockInjections(top *model.Topology) (func(), error) {
	p := injectionsPath(top) + ".lock"
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("waiting for the injection record: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
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

			unlock, err := lockInjections(top)
			if err != nil {
				return err
			}
			defer unlock()

			// The record is read before anything is injected, and a read error
			// is fatal.
			//
			// It used to be read afterwards with the error discarded, so an
			// unreadable record became an empty one: every fault already on the
			// lab was forgotten, left running, and could never be resolved
			// because nothing knew it was there. The next episode then ran on a
			// network broken in a way its own ground truth did not mention.
			existing, err := loadInjections(top)
			if err != nil {
				return fmt.Errorf("the record of what is already injected could not be read (%w); "+
					"injecting now would leave whatever it holds running with nothing able to "+
					"name or undo it", err)
			}

			inj, err := fault.Inject(cmd.Context(), env, args[0], target)
			if err != nil {
				return err
			}
			if err := saveInjections(top, append(existing, inj)); err != nil {
				// The fault is live and unrecorded. Undo it rather than leave
				// contamination nothing can find.
				if rerr := fault.Resolve(cmd.Context(), env, inj); rerr != nil {
					return fmt.Errorf("%s was injected but could not be recorded (%w), and undoing "+
						"it also failed (%v); the lab is contaminated and must be redeployed",
						args[0], err, rerr)
				}
				return fmt.Errorf("%s could not be recorded (%w), so it was undone rather than "+
					"left running with nothing able to name it", args[0], err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "injected %s on %s\n", inj.Fault, inj.Target.DeviceID())
			// Say what was checked and what was seen. Printing only Observed
			// showed an empty line whenever the symptom was an absence -- an
			// adjacency gone, no session established -- which is most of them,
			// so the one line meant to report the verdict was blank exactly
			// when the fault had worked.
			fmt.Fprintf(cmd.OutOrStdout(), "  verified: %s\n", describeEvidence(inj.Evidence))
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

			// Held across the read, the resolving and the write.
			//
			// Injection takes this lock and resolution did not, so an
			// injection running concurrently was read, resolved from under
			// the other command, or overwritten by the record it wrote from
			// the copy it had read before this one started. Either way a fault
			// ends up live in the lab with nothing on disk saying so, which
			// makes it unresolvable except by hand.
			unlock, err := lockInjections(top)
			if err != nil {
				return err
			}
			defer unlock()

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

// newFaultVerifyCmd re-checks that what was injected is still in effect.
//
// Injection verifies once and rolls back if the fault did not take. But a lab
// runs for hours afterwards, and faults do not always stay: an interface comes
// back, a daemon is restarted, a container is replaced and takes the fault with
// it, a student repairs it by accident while looking for something else. An
// evaluation that assumes the fault is still there scores the agent's answer
// against a network that no longer has the problem -- and the episode looks
// entirely valid, so nothing questions the result.
func newFaultVerifyCmd(opts *Options) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "verify [fault]",
		Short: "Check that an injected fault is still in effect",
		Long: `Re-runs the same predicate injection used, against the lab as it is now.

An injected fault does not necessarily stay injected: a container may be
replaced, a daemon restarted, or the symptom repaired by accident. Anything
scored against ground truth should verify first.`,
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
			var want []*fault.Injection
			for _, inj := range injections {
				if len(args) == 0 || inj.Fault == args[0] {
					want = append(want, inj)
				}
			}
			if len(want) == 0 {
				if len(args) > 0 {
					return fmt.Errorf("%s is not injected", args[0])
				}
				fmt.Fprintln(cmd.OutOrStdout(), "nothing is injected")
				return nil
			}

			type row struct {
				Fault    string         `json:"fault"`
				Target   string         `json:"target"`
				Verified bool           `json:"verified"`
				Evidence fault.Evidence `json:"evidence"`
				Error    string         `json:"error,omitempty"`
			}
			var rows []row
			gone := 0
			for _, inj := range want {
				r := row{Fault: inj.Fault, Target: inj.Target.DeviceID()}
				ev, err := fault.Verify(cmd.Context(), env, inj)
				switch {
				case err != nil:
					// A verification that could not run is not a fault that is
					// present. Reporting it as present is the failure mode this
					// command exists to catch.
					r.Error = err.Error()
					gone++
				case !ev.Verified:
					r.Evidence = ev
					gone++
				default:
					r.Verified, r.Evidence = true, ev
				}
				rows = append(rows, r)
			}
			if opts.JSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(rows); err != nil {
					return err
				}
			} else {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "FAULT\tTARGET\tSTILL IN EFFECT\tOBSERVED")
				for _, r := range rows {
					state := "yes"
					detail := r.Evidence.Observed
					if !r.Verified {
						state = "NO"
						if r.Error != "" {
							detail = r.Error
						}
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Fault, r.Target, state, firstLineOf(detail))
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
			if gone > 0 {
				return fmt.Errorf("%d of %d injected fault(s) are no longer in effect; "+
					"anything scored against this lab's ground truth would be scored against "+
					"a problem that is not there", gone, len(rows))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

// firstLineOf keeps a table one row per fault.
func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
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
	nodeState, err := nodeStateFunc(top, token)
	if err != nil {
		return nil, err
	}
	return &fault.Env{
		Topology: top, Exec: exec, Lifecycle: life,
		Reshape: reshape, NodeState: nodeState,
	}, nil
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

// describeEvidence renders a verification result as a sentence.
func describeEvidence(ev fault.Evidence) string {
	verdict := "no"
	if ev.Verified {
		verdict = "yes"
	}
	parts := []string{verdict}
	if ev.Expected != "" {
		parts = append(parts, "expected "+ev.Expected)
	}
	if ev.Observed != "" {
		parts = append(parts, "observed "+ev.Observed)
	}
	if ev.Detail != "" {
		parts = append(parts, ev.Detail)
	}
	return strings.Join(parts, "; ")
}
