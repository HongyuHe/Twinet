package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/HongyuHe/twinet/internal/msc"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/spf13/cobra"
)

func newMSCCmd(opts *Options) *cobra.Command {
	var specPath, stateDir string
	root := &cobra.Command{Use: "msc", Short: "Operate a single-worker MSC IPsec/IPsec appliance lab"}
	root.PersistentFlags().StringVar(&specPath, "spec", "examples/msc/msc.json", "explicit MSC appliance topology JSON")
	root.PersistentFlags().StringVar(&stateDir, "state-dir", "/var/lib/twinet/msc", "private persistent MSC state and PKI directory")
	output := func(cmd *cobra.Command, v any) error {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	root.AddCommand(&cobra.Command{Use: "init", Short: "Write the two-site example to --spec", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s := msc.Example()
		if err := s.Validate(); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(specPath), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(specPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}})
	root.AddCommand(&cobra.Command{Use: "plan", Short: "Validate and print the explicit appliance topology", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		s, err := msc.Load(specPath)
		if err != nil {
			return err
		}
		return output(cmd, s)
	}})
	run := func(fn func(*cobra.Command, *msc.Engine, []string) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			s, err := msc.Load(specPath)
			if err != nil {
				return err
			}
			if opts.Runtime != "" && opts.Runtime != "docker" {
				return fmt.Errorf("MSC profile currently supports the tested Docker backend only")
			}
			r := rt.NewDocker()
			defer r.Close()
			if err = rt.ConfigureEndpoint(r, opts.RuntimeSocket); err != nil {
				return err
			}
			e := &msc.Engine{Spec: s, Dir: stateDir, Runtime: r, Log: cmd.ErrOrStderr()}
			unlock, err := e.Lock()
			if err != nil {
				return err
			}
			defer unlock()
			return fn(cmd, e, args)
		}
	}
	for _, verb := range []string{"up", "recover", "down"} {
		v := verb
		root.AddCommand(&cobra.Command{Use: v, Short: map[string]string{"up": "Deploy or reconcile the declared MSC appliances", "recover": "Restore configuration, renew certificates and reestablish tunnels after a fault", "down": "Remove owned containers and links; retain private PKI state"}[v], Args: cobra.NoArgs, RunE: run(func(cmd *cobra.Command, e *msc.Engine, _ []string) error {
			if v == "down" {
				return e.Down(cmd.Context())
			}
			return e.Up(cmd.Context(), v == "recover")
		})})
	}
	root.AddCommand(&cobra.Command{Use: "status", Short: "Read live interfaces, routes, filters, certificates and redacted IPsec state as JSON", Args: cobra.NoArgs, RunE: run(func(cmd *cobra.Command, e *msc.Engine, _ []string) error {
		s, err := e.Status(cmd.Context())
		if err != nil {
			return err
		}
		return output(cmd, s)
	})})
	for _, verb := range []string{"check", "test-failures"} {
		v := verb
		root.AddCommand(&cobra.Command{Use: v, Short: map[string]string{"check": "Verify reachability, isolation, management, filters and encrypted captures", "test-failures": "Exercise SA loss, wrong peer, revocation and container restart with recovery"}[v], Args: cobra.NoArgs, RunE: run(func(cmd *cobra.Command, e *msc.Engine, _ []string) error {
			var report msc.Report
			var err error
			if v == "check" {
				report, err = e.Check(cmd.Context())
			} else {
				report, err = e.TestFailures(cmd.Context())
			}
			if err != nil {
				return err
			}
			if err = output(cmd, report); err != nil {
				return err
			}
			if !report.Passed {
				return fmt.Errorf("MSC checks failed; inspect the JSON report")
			}
			return nil
		})})
	}
	root.AddCommand(&cobra.Command{Use: "exec DEVICE -- COMMAND [ARG...]", Short: "Execute a command in an owned MSC appliance", Args: cobra.MinimumNArgs(2), RunE: run(func(cmd *cobra.Command, e *msc.Engine, args []string) error {
		r, err := e.Exec(cmd.Context(), args[0], args[1:])
		if err != nil {
			return err
		}
		fmt.Fprint(cmd.OutOrStdout(), r.Stdout)
		fmt.Fprint(cmd.ErrOrStderr(), r.Stderr)
		return r.Err()
	})})
	root.AddCommand(&cobra.Command{Use: "restart DEVICE", Short: "Restart one container and repair links/configuration/tunnels", Args: cobra.ExactArgs(1), RunE: run(func(cmd *cobra.Command, e *msc.Engine, args []string) error { return e.Restart(cmd.Context(), args[0]) })})
	root.AddCommand(&cobra.Command{Use: "fault KIND DEVICE [INTERFACE]", Short: "Inject ipsec-down, wrong-peer, revoke, link-down or firewall-open; recover explicitly", Args: cobra.RangeArgs(2, 3), RunE: run(func(cmd *cobra.Command, e *msc.Engine, args []string) error {
		iface := ""
		if len(args) == 3 {
			iface = args[2]
		}
		return e.Fault(cmd.Context(), args[0], args[1], iface)
	})})
	return root
}
