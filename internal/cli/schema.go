package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/schema"
)

func newSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Emit the manifest's JSON Schema, generated from the Go types",
		Long: `Writes the JSON Schema for a lab manifest to stdout.

It is derived from the Go types the manifest is decoded into, so it cannot
describe a field the loader does not accept, or miss one it does. Point an
editor at it to get completion and inline errors while writing a lab:

    twinet schema > twinet.schema.json

then, in VS Code's settings:

    "yaml.schemas": {"./twinet.schema.json": "twinet.yaml"}`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := schema.JSON(model.Lab{})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
}
