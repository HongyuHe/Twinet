package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/model"
)

// The machine-readable surface a external evaluation harness drives Twinet
// through.
//
// It exists as its own command family rather than as flags on the human
// commands because the two have opposite obligations. A human command may
// improve its output whenever that helps a person; this one may not, because
// something else parses it. Keeping them apart means a change made for a
// person's benefit cannot silently break an evaluation that has already
// produced results.
func newNikaCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runtime",
		Short: "Machine-readable operations for an external evaluation harness",
		Long: `Exposes the lab as the small set of operations an evaluation harness needs:
list the devices, run a command in one, read or change its run state.

This is deliberately separate from the human-facing commands. They may improve
their output whenever it helps a person; this may not, because something else
parses it, and a change made for a reader's benefit would silently invalidate
results that had already been produced.`,
	}
	cmd.AddCommand(
		newRuntimeNodesCmd(opts),
		newRuntimeExecCmd(opts),
		newRuntimeStateCmd(opts),
	)
	return cmd
}

func newRuntimeNodesCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "nodes",
		Short: "List every device, as JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			type node struct {
				Name      string `json:"name"`
				Kind      string `json:"kind"`
				AS        int    `json:"as"`
				Node      string `json:"node"`
				Container string `json:"container"`
				Image     string `json:"image,omitempty"`
			}
			// Links are part of this payload because a harness that scores
			// fault localisation has to know which devices are adjacent. Left
			// out, NIKA's get_connected_devices returns nothing for every
			// device, and a localisation that named a correct neighbour scores
			// the same as one that named a router in another continent.
			type link struct {
				A     string `json:"a"`
				B     string `json:"b"`
				AIf   string `json:"a_iface"`
				BIf   string `json:"b_iface"`
				InfAS bool   `json:"inter_as,omitempty"`
			}
			out := struct {
				Lab   string `json:"lab"`
				Hash  string `json:"topology_hash"`
				Nodes []node `json:"nodes"`
				Links []link `json:"links"`
			}{Lab: top.Name, Hash: top.Hash}

			for _, d := range top.SortedDevices() {
				out.Nodes = append(out.Nodes, node{
					Name: d.ID, Kind: string(d.Kind), AS: d.ASN,
					Node: d.Node, Container: d.Container, Image: d.Image,
				})
			}
			for _, l := range top.Links {
				if l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
					continue
				}
				out.Links = append(out.Links, link{
					A: l.A.Device.ID, B: l.B.Device.ID,
					AIf: l.A.Name, BIf: l.B.Name, InfAS: l.InterAS,
				})
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
		},
	}
}

func newRuntimeExecCmd(opts *Options) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "exec <device> -- <command>...",
		Short: "Run a command in a device and emit the result as JSON",
		Args:  cobra.MinimumNArgs(2),
		Long: `Emits stdout, stderr and the exit status as a JSON object.

The exit status is reported rather than turned into a process failure. A harness
needs to tell "the command ran and returned non-zero", which is frequently the
answer it is looking for, from "the command could not be run at all", which
means its measurement is invalid. Collapsing both into a failed process loses
exactly the distinction that decides whether a result may be used.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			device, err := deviceNamesFor(top, args[0])
			if err != nil {
				return err
			}
			rest := args[1:]
			exec, err := execFunc(cmd.Context(), top, token)
			if err != nil {
				return err
			}
			res, err := exec(cmd.Context(), device, rest)
			out := struct {
				Device   string `json:"device"`
				Stdout   string `json:"stdout"`
				Stderr   string `json:"stderr"`
				ExitCode int    `json:"exit_code"`
				Error    string `json:"error,omitempty"`
			}{Device: device, Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode}
			if err != nil {
				out.Error = err.Error()
				out.ExitCode = -1
			}
			if encErr := json.NewEncoder(cmd.OutOrStdout()).Encode(out); encErr != nil {
				return encErr
			}
			// The process still succeeds: the JSON carries the outcome, and a
			// harness that also had to interpret an exit status would have two
			// sources of truth that can disagree.
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

func newRuntimeStateCmd(opts *Options) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "state <device> [action]",
		Short: "Read or change a device's run state",
		Args:  cobra.RangeArgs(1, 2),
		Long: `With no action, reports the container's run state. With one of pause,
unpause, stop, start or restart, applies it and reports the state afterwards.

Reading the state from the platform matters for anything that freezes a machine:
a frozen container cannot answer for itself, and its silence is equally
consistent with an unreachable node.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			device, err := deviceNamesFor(top, args[0])
			if err != nil {
				return err
			}
			stateOf, err := nodeStateFunc(top, token)
			if err != nil {
				return err
			}
			if len(args) == 2 {
				life, err := lifecycleFunc(top, token)
				if err != nil {
					return err
				}
				if err := life(cmd.Context(), device, args[1]); err != nil {
					return err
				}
			}
			st, err := stateOf(cmd.Context(), device)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Device string `json:"device"`
				State  string `json:"state"`
			}{device, st})
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs")
	return cmd
}

// deviceNamesFor is used by the runtime surface to resolve a bare device name
// the way a harness is likely to write it.
//
// A harness written against another platform names a device "MSP" or "as3/MSP"
// depending on what that platform called it. Accepting both, and refusing an
// ambiguous bare name rather than guessing, is the difference between an
// adapter that works and one that silently drives the wrong router.
func deviceNamesFor(top *model.Topology, name string) (string, error) {
	if _, ok := top.Device(name); ok {
		return name, nil
	}
	var matches []string
	for _, d := range top.SortedDevices() {
		if strings.EqualFold(d.Name, name) {
			matches = append(matches, d.ID)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no device %q", name)
	default:
		return "", fmt.Errorf("%q is ambiguous: %s", name, strings.Join(matches, ", "))
	}
}
