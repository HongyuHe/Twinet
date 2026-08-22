package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/client"
)

// newRecoverCmd resumes a durable rollback rather than telling an operator to
// destroy a lab whose prior generation may still be the only safe copy.
func newRecoverCmd(opts *Options) *cobra.Command {
	var token string
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
			report, err := client.NewCluster(top.Lab, tok).Recover(cmd.Context(), top.Name)
			if opts.JSON {
				if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil {
					return encodeErr
				}
			} else {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "NODE\tPHASE\tGENERATION\tCONTAINERS\tVNIS\tSTATUS")
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
					fmt.Fprintf(w, "%s\t%s\t%s\t%d/%d\t%d/%d\t%s\n",
						node, status.Phase, status.Generation,
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
	return cmd
}
