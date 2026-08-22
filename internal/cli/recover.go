package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/client"
)

// newRecoverCmd resumes a durable rollback rather than telling an operator to
// destroy a lab whose prior generation may still be the only safe copy.
func newRecoverCmd(opts *Options) *cobra.Command {
	var (
		token    string
		strategy string
		wait     time.Duration
		takeover bool
	)
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Resume and verify a failed cluster transaction",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if !clustered(top) {
				return fmt.Errorf("transaction recovery requires a clustered lab")
			}
			tok, err := tokenFor(token)
			if err != nil {
				return err
			}
			var lastProgress string
			report, err := client.NewCluster(top.Lab, tok).RecoverWithOptions(cmd.Context(), top.Name, strategy,
				client.RecoveryOptions{
					Wait: wait, Takeover: takeover,
					Progress: func(progress client.RecoveryReport) {
						if opts.JSON {
							return
						}
						line := recoveryProgressLine(progress)
						if line == "" || line == lastProgress {
							return
						}
						lastProgress = line
						fmt.Fprintln(cmd.ErrOrStderr(), line)
					},
				})
			if opts.JSON {
				if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil {
					return encodeErr
				}
			} else {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "NODE\tPHASE\tMODE\tGENERATION\tCONTAINERS\tVNIS\tSTATUS")
				nodes := make([]string, 0, len(report.Nodes))
				for node := range report.Nodes {
					nodes = append(nodes, node)
				}
				sort.Strings(nodes)
				for _, node := range nodes {
					status := report.Nodes[node]
					state := "verified"
					if !status.Consistent {
						state = status.Error
					}
					fmt.Fprintf(w, "%s\t%s\t%s/%d\t%s\t%d/%d\t%d/%d\t%s\n",
						node, status.Phase, status.Mode, status.Ungraded, status.Generation,
						status.ObservedContainers, status.ExpectedContainers,
						status.ObservedVNIs, status.ExpectedVNIs, state)
				}
				if flushErr := w.Flush(); flushErr != nil {
					return flushErr
				}
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"lab %q is recovered at generation %q with verified node inventories\n",
				top.Name, report.Generation)
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token (or set TWINET_TOKEN)")
	cmd.Flags().StringVar(&strategy, "strategy", "rollback",
		"recovery strategy: rollback (safe default) or forward (explicit desired transaction resume)")
	cmd.Flags().DurationVar(&wait, "wait", 2*time.Minute,
		"maximum time to join and poll an in-progress same-strategy recovery (0 reports immediately)")
	cmd.Flags().BoolVar(&takeover, "takeover", false,
		"take over only a recovery whose persisted phase deadline has expired")
	return cmd
}

func recoveryProgressLine(report client.RecoveryReport) string {
	nodes := make([]string, 0, len(report.Nodes))
	for node := range report.Nodes {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	var out string
	for _, node := range nodes {
		status := report.Nodes[node]
		if status.Phase != "recovering" {
			continue
		}
		entry := fmt.Sprintf("%s owner=%q strategy=%s phase=%s target=%q progress=%s deadline=%s",
			node, status.Owner, status.Strategy, status.Phase, status.CurrentTarget,
			status.LastProgressAt.Format(time.RFC3339), status.Deadline.Format(time.RFC3339))
		if out != "" {
			out += "; "
		}
		out += entry
	}
	return out
}
