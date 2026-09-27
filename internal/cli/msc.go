package cli

import (
	"encoding/json"
	"fmt"
	"io"
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
	layout := msc.DefaultLayout()
	var layoutPath string
	initCmd := &cobra.Command{Use: "init", Short: "Write the two-site example to --spec", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if layoutPath != "" {
			f, err := os.Open(layoutPath)
			if err != nil {
				return err
			}
			defer f.Close()
			configured := msc.DefaultLayout()
			decoder := json.NewDecoder(f)
			decoder.DisallowUnknownFields()
			if err = decoder.Decode(&configured); err != nil {
				return err
			}
			var extra any
			if err = decoder.Decode(&extra); err != io.EOF {
				return fmt.Errorf("unexpected trailing layout JSON")
			}
			if cmd.Flags().Changed("name") {
				configured.Name = layout.Name
			}
			if cmd.Flags().Changed("levels") {
				configured.Levels = layout.Levels
			}
			if cmd.Flags().Changed("outer-firewalls") {
				configured.OuterFirewalls = layout.OuterFirewalls
			}
			if cmd.Flags().Changed("gray-firewalls") {
				configured.GrayFirewalls = layout.GrayFirewalls
			}
			if cmd.Flags().Changed("shared-gray") {
				configured.SharedGray = layout.SharedGray
			}
			layout = configured
		}
		s, genErr := msc.Generate(layout)
		if genErr != nil {
			return genErr
		}
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
	}}
	initCmd.Flags().StringVar(&layout.Name, "name", "msc", "lab name used for ownership labels")
	initCmd.Flags().IntVar(&layout.Levels, "levels", 2, "security levels, 1..8")
	initCmd.Flags().IntVar(&layout.OuterFirewalls, "outer-firewalls", 2, "Outer Firewalls per site, 1..levels; encryptors are distributed across them")
	initCmd.Flags().IntVar(&layout.GrayFirewalls, "gray-firewalls", 1, "Gray Firewalls per site, 1..levels")
	initCmd.Flags().BoolVar(&layout.SharedGray, "shared-gray", false, "shared outer-side OVS Gray fabric with inner encryptors behind Gray Firewalls")
	initCmd.Flags().StringVar(&layoutPath, "config", "", "small layout JSON; explicit flags override its values")
	root.AddCommand(initCmd)
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
			if cmd.Name() == "console" {
				e.Dir, err = filepath.Abs(e.Dir)
				if err != nil {
					return err
				}
				return fn(cmd, e, args)
			}
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
	var nativeOnly bool
	for _, verb := range []string{"check", "test-failures"} {
		v := verb
		checkCmd := &cobra.Command{Use: v, Short: map[string]string{"check": "Verify reachability, isolation, management, filters and encrypted captures", "test-failures": "Exercise SA loss, wrong peer, revocation and container restart with recovery"}[v], Args: cobra.NoArgs, RunE: run(func(cmd *cobra.Command, e *msc.Engine, _ []string) error {
			var report msc.Report
			var err error
			if v == "check" {
				report, err = e.Check(cmd.Context())
			} else if nativeOnly {
				report, err = e.TestNativeFailures(cmd.Context())
			} else {
				report, err = e.TestFailures(cmd.Context())
			}
			if err != nil {
				report.Passed = false
				report.Checks = append(report.Checks, msc.Check{Name: "infrastructure", Passed: false, Detail: err.Error()})
			}
			runErr := err
			if err = output(cmd, report); err != nil {
				return err
			}
			if runErr != nil {
				return runErr
			}
			if !report.Passed {
				return fmt.Errorf("MSC checks failed; inspect the JSON report")
			}
			return nil
		})}
		if v == "test-failures" {
			checkCmd.Flags().BoolVar(&nativeOnly, "native-only", false, "exercise only native CLI mistakes and router/switch restarts")
		}
		root.AddCommand(checkCmd)
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
	var exportDir string
	exportCmd := &cobra.Command{Use: "export", Short: "Export intended configs and sampled live state as a versioned, hashable evidence bundle", Args: cobra.NoArgs, RunE: run(func(cmd *cobra.Command, e *msc.Engine, _ []string) error {
		if exportDir == "" {
			return fmt.Errorf("--output DIR is required")
		}
		if err := e.Export(cmd.Context(), exportDir); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), exportDir)
		return nil
	})}
	exportCmd.Flags().StringVar(&exportDir, "output", "", "new destination directory; never overwrites an existing export")
	root.AddCommand(exportCmd)

	var noTTY bool
	console := &cobra.Command{Use: "console DEVICE [-- COMMAND ARG...]", Short: "Interactive native vtysh on routers, bash with ovs-vsctl/ovs-ofctl on switches", Args: cobra.MinimumNArgs(1), RunE: run(func(cmd *cobra.Command, e *msc.Engine, args []string) error {
		return e.Console(cmd.Context(), args[0], args[1:], cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), !noTTY)
	})}
	console.Flags().BoolVar(&noTTY, "no-tty", false, "stream without allocating a terminal")
	root.AddCommand(console)

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
