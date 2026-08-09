package cli

import "github.com/spf13/cobra"

// Placeholders replaced as milestones land; keeping them here keeps the
// command tree stable so shell completions and docs do not churn.
func newDeployCmd(opts *Options) *cobra.Command {
	return &cobra.Command{Use: "deploy", Short: "Deploy the lab", RunE: notYet}
}
func newDestroyCmd(opts *Options) *cobra.Command {
	return &cobra.Command{Use: "destroy", Short: "Destroy the lab", RunE: notYet}
}
func newExecCmd(opts *Options) *cobra.Command {
	return &cobra.Command{Use: "exec", Short: "Run a command in a device", RunE: notYet}
}
func notYet(cmd *cobra.Command, _ []string) error { return errNotImplemented }
