// Package cli implements the twinet command-line interface.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is stamped at build time by the release pipeline.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Options are the flags shared by every subcommand.
type Options struct {
	Manifest string
	Verbose  bool
	JSON     bool
}

// Root builds the top-level command tree.
func Root() *cobra.Command {
	opts := &Options{}

	root := &cobra.Command{
		Use:   "twinet",
		Short: "A container-based network twin for teaching how the Internet works",
		Long: `Twinet builds and operates a mini-Internet: every student group runs a
real autonomous system with FRR, BGP, OSPF, RPKI and Open vSwitch, spread
across a cluster and graded automatically.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVarP(&opts.Manifest, "manifest", "m", ".",
		"path to the lab manifest or its directory")
	root.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose logging")
	root.PersistentFlags().BoolVar(&opts.JSON, "json", false, "emit machine-readable JSON")

	root.AddCommand(
		newValidateCmd(opts),
		newInspectCmd(opts),
		newDeployCmd(opts),
		newDestroyCmd(opts),
		newExecCmd(opts),
		newGraphCmd(opts),
		newNodeCmd(opts),
		newGradeCmd(opts),
		newFaultCmd(opts),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the twinet version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "twinet %s (commit %s, built %s)\n", Version, Commit, Date)
		},
	}
}
