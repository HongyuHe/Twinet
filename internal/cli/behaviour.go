package cli

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
)

// Behaviours: the scripted, reversible perturbations an exercise is built
// around, as opposed to the faults an incident is built around.
//
// A manifest has been able to declare these since the first version -- a BGP
// hijack against a chosen victim, a link taken down -- and nothing read the
// declaration. `behaviours:` validated, appeared in the schema, was documented
// as the replacement for the legacy platform's hijack.sh, and did nothing at
// all. The COS-461 RPKI question is built on one: a stub AS starts announcing
// somebody else's prefix, and the students' filters are supposed to reject it.
// Without this the exercise had a permanent invalid announcement instead of an
// event, so the question "did you notice, and did your filter stop it?" could
// not be asked.
//
// They are deliberately not faults, though they are implemented with the fault
// registry. A fault is a defect to be diagnosed and its existence is the
// answer; a behaviour is part of the exercise, is announced to the class, and
// is expected to be started and stopped by an instructor at will.

func newBehaviourCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "behaviour",
		Short: "Start and stop the scripted perturbations an exercise is built around",
		Long: "A behaviour is a named, reversible change the manifest declares: the BGP " +
			"hijack the RPKI question is about, a link taken down for a routing exercise. " +
			"Unlike a fault it is part of the exercise rather than something to diagnose, " +
			"so it is announced to the class and started and stopped deliberately.",
	}
	cmd.AddCommand(newBehaviourListCmd(opts), newBehaviourStartCmd(opts),
		newBehaviourStopCmd(opts), newBehaviourStatusCmd(opts))
	return cmd
}

func newBehaviourListCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list the behaviours this lab declares",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			names := behaviourNames(top)
			if len(names) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "this lab declares no behaviours")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tKIND\tSTART\tTARGETS")
			for _, n := range names {
				b := top.Lab.Behaviours[n]
				targets, err := behaviourTargets(top, n, b)
				what := fmt.Sprintf("%d", len(targets))
				if err != nil {
					what = "unresolvable: " + err.Error()
				}
				on := b.Start
				if on == "" {
					on = "manual"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", n, b.Kind, on, what)
			}
			return w.Flush()
		},
	}
}

func newBehaviourStartCmd(opts *Options) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "start <name>",
		Short: "start a declared behaviour",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBehaviour(cmd, opts, token, args[0], true)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

func newBehaviourStopCmd(opts *Options) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "stop <name>",
		Short: "stop a running behaviour and put the lab back",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBehaviour(cmd, opts, token, args[0], false)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

func newBehaviourStatusCmd(opts *Options) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "say which behaviours are running",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			live, err := loadInjections(top)
			if err != nil {
				return err
			}
			running := map[string]int{}
			for _, inj := range live {
				if n := inj.Target.Params["twinet.behaviour"]; n != "" {
					running[n]++
				}
			}
			names := behaviourNames(top)
			if len(names) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "this lab declares no behaviours")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATE\tACTIVE")
			for _, n := range names {
				state := "stopped"
				if running[n] > 0 {
					state = "running"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\n", n, state, running[n])
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

func behaviourNames(top *model.Topology) []string {
	out := make([]string, 0, len(top.Lab.Behaviours))
	for n := range top.Lab.Behaviours {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// behaviourTargets resolves a declaration into the concrete targets it applies
// to: one per victim, on the router of the AS that performs it.
func behaviourTargets(top *model.Topology, name string, b *model.Behaviour) ([]fault.Target, error) {
	if b == nil {
		return nil, fmt.Errorf("behaviour %q is not declared", name)
	}
	if _, ok := model.BehaviourFault(b.Kind); !ok {
		return nil, fmt.Errorf("kind %q is not implemented; known kinds are %s",
			b.Kind, strings.Join(model.BehaviourKinds(), ", "))
	}
	// Who performs it. Declared as `params.by` -- an AS number -- because a
	// hijack needs somebody to do the hijacking, and leaving it implicit is how
	// the previous RPKI arrangement ended up with a permanent announcement that
	// nobody owned.
	by, err := behaviourActor(top, b)
	if err != nil {
		return nil, err
	}
	device := b.Params["device"]
	if device == "" {
		as, ok := top.ASes[by]
		if !ok || len(as.Routers) == 0 {
			return nil, fmt.Errorf("AS %d has no router to perform this behaviour", by)
		}
		device = as.Routers[0].Name
	}

	victims, err := behaviourVictims(top, b, by)
	if err != nil {
		return nil, err
	}
	var out []fault.Target
	for _, v := range victims {
		t := fault.Target{
			AS: by, Device: device, Peer: v,
			Prefix: b.Prefix,
			Params: map[string]string{"twinet.behaviour": name},
		}
		for k, val := range b.Params {
			if k == "by" || k == "device" {
				continue
			}
			t.Params[k] = val
		}
		if b.Kind == "link-down" && len(b.Via) > 0 {
			t.Iface = b.Via[0]
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("this behaviour selects nothing to act on")
	}
	return out, nil
}

func behaviourActor(top *model.Topology, b *model.Behaviour) (int, error) {
	if s := b.Params["by"]; s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("params.by must be an AS number, not %q", s)
		}
		if _, ok := top.ASes[n]; !ok {
			return 0, fmt.Errorf("params.by names AS %d, which this lab does not have", n)
		}
		return n, nil
	}
	return 0, errors.New("params.by must say which AS performs this behaviour")
}

func behaviourVictims(top *model.Topology, b *model.Behaviour, by int) ([]int, error) {
	if b.Victims == nil {
		// A behaviour with a prefix and no victim acts on the prefix alone.
		if b.Prefix != "" {
			return []int{0}, nil
		}
		return nil, errors.New("this behaviour names neither victims nor a prefix")
	}
	seen := map[int]bool{}
	var out []int
	add := func(n int) {
		if n == by || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range b.Victims.List {
		if _, ok := top.ASes[n]; !ok {
			return nil, fmt.Errorf("victims list names AS %d, which this lab does not have", n)
		}
		add(n)
	}
	if b.Victims.Role != "" {
		for _, asn := range top.SortedASNs() {
			if top.ASes[asn].Role == b.Victims.Role {
				add(asn)
			}
		}
	}
	if b.Victims.Rel == "same-region" {
		mine := ""
		if as, ok := top.ASes[by]; ok {
			mine = as.Region
		}
		for _, asn := range top.SortedASNs() {
			if as := top.ASes[asn]; as.Region == mine {
				add(asn)
			}
		}
	}
	sort.Ints(out)
	if len(out) == 0 {
		return nil, errors.New("the victim selector matched no autonomous system")
	}
	return out, nil
}

// runBehaviour starts or stops one, recording it in the same ledger faults use
// so an interrupted run leaves nothing live that nothing on disk mentions.
func runBehaviour(cmd *cobra.Command, opts *Options, token, name string, start bool) error {
	top, err := loadAndPlace(opts)
	if err != nil {
		return err
	}
	b := top.Lab.Behaviours[name]
	if b == nil {
		known := behaviourNames(top)
		if len(known) == 0 {
			return fmt.Errorf("this lab declares no behaviours")
		}
		return fmt.Errorf("no behaviour called %q; this lab declares %s",
			name, strings.Join(known, ", "))
	}
	kind, _ := model.BehaviourFault(b.Kind)
	targets, err := behaviourTargets(top, name, b)
	if err != nil {
		return fmt.Errorf("behaviour %q: %w", name, err)
	}
	env, err := faultEnv(cmd, top, token)
	if err != nil {
		return err
	}
	unlock, err := lockInjections(top)
	if err != nil {
		return err
	}
	defer unlock()
	ledger, err := loadInjections(top)
	if err != nil {
		return err
	}

	if !start {
		var kept []*fault.Injection
		stopped := 0
		var problems []string
		for _, inj := range ledger {
			if inj.Target.Params["twinet.behaviour"] != name {
				kept = append(kept, inj)
				continue
			}
			if err := fault.Resolve(cmd.Context(), env, inj); err != nil {
				problems = append(problems, err.Error())
				kept = append(kept, inj)
				continue
			}
			stopped++
		}
		if err := saveInjections(top, kept); err != nil {
			return err
		}
		if len(problems) > 0 {
			return fmt.Errorf("%d of %d part(s) of %q could not be stopped: %s",
				len(problems), stopped+len(problems), name, strings.Join(problems, "; "))
		}
		fmt.Fprintf(cmd.OutOrStdout(), "behaviour %q stopped (%d part(s))\n", name, stopped)
		return nil
	}

	for _, inj := range ledger {
		if inj.Target.Params["twinet.behaviour"] == name {
			return fmt.Errorf("behaviour %q is already running; stop it first", name)
		}
	}
	var started []*fault.Injection
	for _, t := range targets {
		inj, err := fault.Inject(cmd.Context(), env, kind, t)
		if inj != nil {
			started = append(started, inj)
			ledger = append(ledger, inj)
			if serr := saveInjections(top, ledger); serr != nil {
				return fmt.Errorf("%s is live and could not be recorded (%w); stop it by hand",
					name, serr)
			}
		}
		if err != nil {
			return fmt.Errorf("starting %q: %w (the parts that did start are recorded and "+
				"can be stopped with `twinet behaviour stop %s`)", name, err, name)
		}
	}
	for _, inj := range started {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s on %s\n", inj.Fault, inj.Target.DeviceID())
	}
	fmt.Fprintf(cmd.OutOrStdout(), "behaviour %q started (%d part(s))\n", name, len(started))
	return nil
}
