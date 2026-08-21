package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/access"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
)

func newGatewayCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Run the SSH gateway students reach their devices through",
		Long: `The gateway is the front door.

The platform this replaces put an sshd inside every container: a login daemon in
each of a thousand routers, a thousand copies of a password file to keep in
step, and authorisation resting on the assumption that a student only knows
their own port number.

Twinet authenticates once, at the edge, and then execs into the container.
Authorisation is a property of the connection: a student's device names are
looked up within their own AS, so another group's router cannot be named at all
and there is no rule left to get wrong.`,
	}
	cmd.AddCommand(
		newGatewayRunCmd(opts),
		newGatewayEndpointsCmd(opts),
		newGatewayRosterCmd(opts),
	)
	return cmd
}

// newGatewayEndpointsCmd publishes the portable multi-endpoint baseline. A
// real VIP may be layered over this list by the environment, but no gateway
// client needs to depend on a front node or a VIP to fail over.
func newGatewayEndpointsCmd(opts *Options) *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "endpoints",
		Short: "List deterministic gateway endpoints and their health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			health, err := endpointHealth(cmd.Context(), top, token)
			if err != nil {
				return err
			}
			writeEndpointList(cmd.OutOrStdout(), top.Lab.GatewayEndpoints(), health)
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token for cluster labs (or set TWINET_TOKEN)")
	return cmd
}

func newGatewayRunCmd(opts *Options) *cobra.Command {
	var (
		listen     string
		rosterPath string
		hostKey    string
		legacyBase int
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Serve SSH until interrupted",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if listen == "" {
				listen = top.Lab.Access.Listen
			}
			if listen == "" {
				listen = ":2022"
			}
			if legacyBase == 0 && top.Lab.Access.LegacyPorts != nil && top.Lab.Access.LegacyPorts.Enabled {
				legacyBase = top.Lab.Access.LegacyPorts.Base
				if legacyBase == 0 {
					legacyBase = 2000
				}
			}
			if rosterPath == "" {
				rosterPath = filepath.Join(top.Lab.Dir, ".twinet", "roster.json")
			}
			if hostKey == "" {
				hostKey = filepath.Join(top.Lab.Dir, ".twinet", "gateway_host_key")
			}

			roster, err := access.LoadRoster(rosterPath)
			if err != nil {
				return fmt.Errorf("%w\n\nRun `twinet gateway roster init` first, "+
					"which creates one credential per student AS", err)
			}
			key, err := access.LoadHostKey(hostKey)
			if err != nil {
				return err
			}

			var ex access.Execer
			if clustered(top) {
				tok, err := tokenFor("")
				if err != nil {
					return err
				}
				cl := client.NewCluster(top.Lab, tok)
				ex = &access.ClusterExec{Topology: top, Attach: func(ctx context.Context,
					node, container string, cmd []string, tty bool, rows, cols int,
					stdin io.Reader, stdout io.Writer) (int, error) {
					n, ok := cl.Node(node)
					if !ok {
						return 1, fmt.Errorf("unknown node %q", node)
					}
					return n.Attach(ctx, container, cmd, tty, rows, cols, stdin, stdout)
				}}
			} else {
				ex = &access.LocalExec{Topology: top}
			}

			srv, err := access.New(access.Config{
				Topology: top, Roster: roster, Exec: ex, HostKey: key,
				Listen: listen, LegacyBase: legacyBase,
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Fprintf(cmd.OutOrStdout(),
				"gateway for %s on %s, %d group(s) enrolled\n", top.Name, listen, len(roster.Groups))
			if legacyBase > 0 {
				fmt.Fprintf(cmd.OutOrStdout(),
					"legacy per-AS ports from %d; the port implies the AS but does not authorise it\n", legacyBase)
			}
			return srv.Serve(ctx)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to listen on")
	cmd.Flags().StringVar(&rosterPath, "roster", "", "path to the roster")
	cmd.Flags().StringVar(&hostKey, "host-key", "", "path to the gateway's host key")
	cmd.Flags().IntVar(&legacyBase, "legacy-base", 0, "also listen on base+ASN per student AS")
	return cmd
}

func newGatewayRosterCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roster",
		Short: "Manage student credentials",
	}
	cmd.AddCommand(newRosterInitCmd(opts), newRosterListCmd(opts), newRosterKeyCmd(opts))
	return cmd
}

func newRosterInitCmd(opts *Options) *cobra.Command {
	var (
		rosterPath string
		out        string
		force      bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create one credential per student AS",
		Long: `Generates a password for every student AS and writes two files.

The roster stores only a salted verifier, never the password, so a roster that
leaks does not hand an attacker working credentials for a class. The passwords
themselves are written once, to a separate file, for distribution.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if rosterPath == "" {
				rosterPath = filepath.Join(top.Lab.Dir, ".twinet", "roster.json")
			}
			if _, err := os.Stat(rosterPath); err == nil && !force {
				return fmt.Errorf("%s already exists; pass --force to replace it, "+
					"which invalidates every credential already handed out", rosterPath)
			}

			roster := &access.Roster{Groups: map[string]*access.Group{}}
			type cred struct {
				group, pass string
				asn         int
			}
			var creds []cred
			for _, asn := range top.SortedASNs() {
				as := top.ASes[asn]
				if as.Role != model.RoleStudent {
					continue
				}
				name := as.OwnerGroup
				if name == "" {
					name = fmt.Sprintf("group%d", asn)
				}
				pass, err := access.GeneratePassword()
				if err != nil {
					return err
				}
				g := &access.Group{AS: asn}
				if err := g.SetPassword(pass); err != nil {
					return err
				}
				roster.Groups[name] = g
				creds = append(creds, cred{name, pass, asn})
			}
			if len(creds) == 0 {
				return fmt.Errorf("this lab has no student ASes")
			}
			if err := roster.Save(rosterPath); err != nil {
				return err
			}

			if out == "" {
				out = filepath.Join(top.Lab.Dir, ".twinet", "credentials.txt")
			}
			var b []byte
			b = append(b, fmt.Sprintf("# Twinet credentials for %s\n# Distribute one line per group, then delete this file.\n\n", top.Name)...)
			for _, c := range creds {
				b = append(b, fmt.Sprintf("AS %-4d  ssh -p 2022 %s@<gateway>   password: %s\n", c.asn, c.group, c.pass)...)
			}
			if err := os.WriteFile(out, b, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"enrolled %d group(s)\n  roster:      %s\n  credentials: %s (delete after distributing)\n",
				len(creds), rosterPath, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&rosterPath, "roster", "", "where to write the roster")
	cmd.Flags().StringVar(&out, "credentials", "", "where to write the passwords")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing roster")
	return cmd
}

func newRosterListCmd(opts *Options) *cobra.Command {
	var rosterPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show who is enrolled",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if rosterPath == "" {
				rosterPath = filepath.Join(top.Lab.Dir, ".twinet", "roster.json")
			}
			roster, err := access.LoadRoster(rosterPath)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(roster.Groups))
			for n := range roster.Groups {
				names = append(names, n)
			}
			sort.Strings(names)

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "GROUP\tAS\tPASSWORD\tKEYS")
			for _, n := range names {
				g := roster.Groups[n]
				pw := "no"
				if g.PasswordHash != "" {
					pw = "yes"
				}
				fmt.Fprintf(w, "%s\t%d\t%s\t%d\n", n, g.AS, pw, len(g.AuthorizedKeys))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&rosterPath, "roster", "", "path to the roster")
	return cmd
}

func newRosterKeyCmd(opts *Options) *cobra.Command {
	var rosterPath string
	cmd := &cobra.Command{
		Use:   "add-key <group> <public-key-file>",
		Short: "Authorise an SSH public key for a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if rosterPath == "" {
				rosterPath = filepath.Join(top.Lab.Dir, ".twinet", "roster.json")
			}
			roster, err := access.LoadRoster(rosterPath)
			if err != nil {
				return err
			}
			g, ok := roster.Groups[args[0]]
			if !ok {
				return fmt.Errorf("no group %q in the roster", args[0])
			}
			raw, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			g.AuthorizedKeys = append(g.AuthorizedKeys, string(raw))
			if err := roster.Save(rosterPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s now has %d authorised key(s)\n",
				args[0], len(g.AuthorizedKeys))
			return nil
		},
	}
	cmd.Flags().StringVar(&rosterPath, "roster", "", "path to the roster")
	return cmd
}
