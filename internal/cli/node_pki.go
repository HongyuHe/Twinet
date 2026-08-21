package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/authz"
	"github.com/HongyuHe/twinet/internal/pki"
)

func newNodePKICmd(opts *Options) *cobra.Command {
	var (
		dir   string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "pki",
		Short: "Issue the certificates the cluster authenticates with",
		Long: `Issues a cluster CA, one server certificate per node, and a controller
certificate.

The agent API creates privileged containers and rewires hosts, so a shared
bearer token over plain HTTP is not defensible: it is replayable by anyone who
sees one request, it is identical on every node so a single leak compromises the
cluster, and it leaves the agent unauthenticated to the caller, so anything that
can occupy the port collects tokens.

Each node gets its own key. One shared server certificate would be simpler and
would recreate exactly the property that makes the token unacceptable.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if dir == "" {
				dir = filepath.Join(top.Lab.Dir, ".twinet", "pki")
			}
			if _, err := os.Stat(filepath.Join(dir, "ca_cert.pem")); err == nil && !force {
				return fmt.Errorf("%s already holds a CA; pass --force to replace it, "+
					"which invalidates every certificate already deployed", dir)
			}

			nodes := map[string][]string{}
			for _, n := range top.Lab.Placement.Nodes {
				sans := []string{n.Name}
				if n.UnderlayIP != "" {
					sans = append(sans, n.UnderlayIP)
				}
				if host := hostOf(n.Addr); host != "" && host != n.Name {
					sans = append(sans, host)
				}
				// Loopback is included so an agent can be checked from the
				// machine it runs on without disabling verification, which is
				// how "just this once" becomes the permanent configuration.
				sans = append(sans, "127.0.0.1", "localhost")
				nodes[n.Name] = sans
			}
			if len(nodes) == 0 {
				return fmt.Errorf("this lab declares no nodes")
			}

			b, err := pki.Generate(dir, nodes)
			if err != nil {
				return err
			}

			names := make([]string, 0, len(b.Nodes))
			for n := range b.Nodes {
				names = append(names, n)
			}
			sort.Strings(names)

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "issued a cluster CA, %d node server certificate(s), and %d replication-only peer certificate(s) in %s\n\n",
				len(names), len(b.Peers), dir)
			fmt.Fprintf(out, "  CA          %s\n", b.CA.CertPath)
			fmt.Fprintf(out, "  controller  %s\n", b.Client.CertPath)
			for _, n := range names {
				fmt.Fprintf(out, "  %-11s server=%s\n", n, b.Nodes[n].CertPath)
				fmt.Fprintf(out, "  %-11s peer=%s\n", "", b.Peers[n].CertPath)
			}
			fmt.Fprintf(out, "\nThe CA private key is at %s. It is the only thing an attacker\n"+
				"needs to mint their own controller certificate, so it does not belong on a\n"+
				"node, in a repository, or in a backup that others can read.\n", b.CA.KeyPath)
			fmt.Fprintf(out, "\nRoll out with: scripts/deploy_agents.sh --pki %s <node>...\n", dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "where to write the material")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing CA")
	cmd.AddCommand(newNodeCredentialCmd(opts), newNodePeerCredentialCmd(opts))
	return cmd
}

func newNodeCredentialCmd(opts *Options) *cobra.Command {
	var (
		pkiDir  string
		outDir  string
		labs    []string
		actions []string
		valid   time.Duration
		rotate  bool
	)
	cmd := &cobra.Command{
		Use:   "credential <name>",
		Short: "Issue or rotate a lab- and action-scoped operator/TA certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			name := args[0]
			if pkiDir == "" {
				pkiDir = filepath.Join(top.Lab.Dir, ".twinet", "pki")
			}
			if outDir == "" {
				outDir = filepath.Join(top.Lab.Dir, ".twinet", "credentials", name)
			}
			if len(labs) == 0 {
				labs = []string{top.Name}
			}
			if len(actions) == 0 {
				return fmt.Errorf("no actions were granted; pass --action for each permitted operation")
			}
			var (
				m        pki.Material
				rotation pki.Rotation
			)
			certPath := filepath.Join(outDir, name+"_cert.pem")
			if _, err := os.Stat(certPath); err == nil && !rotate {
				return fmt.Errorf("%s already exists; use --rotate to replace this scoped credential", certPath)
			}
			if rotate {
				m, rotation, err = pki.RotateScoped(pkiDir, outDir, name, labs, actions, valid)
			} else {
				m, err = pki.IssueScoped(pkiDir, outDir, name, authz.RoleOperator,
					labs, actions, valid)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"issued operator %q for labs %v and actions %v\n\n"+
					"  certificate  %s\n  key          %s\n  CA           %s\n",
				name, labs, actions, m.CertPath, m.KeyPath, m.CAPath)
			if rotate {
				fmt.Fprintf(cmd.OutOrStdout(), "  rotated serial %s -> %s (expires %s)\n",
					rotation.PreviousSerial, rotation.CurrentSerial, rotation.NotAfter.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pkiDir, "pki", "", "cluster PKI directory")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory")
	cmd.Flags().StringSliceVar(&labs, "lab", nil, "lab this identity may access (repeatable)")
	cmd.Flags().StringSliceVar(&actions, "action", nil, "permitted action (repeatable)")
	cmd.Flags().DurationVar(&valid, "valid", 24*time.Hour, "certificate lifetime")
	cmd.Flags().BoolVar(&rotate, "rotate", false, "replace an existing scoped credential and record its serial rotation")
	return cmd
}

func newNodePeerCredentialCmd(opts *Options) *cobra.Command {
	var (
		pkiDir string
		outDir string
		valid  time.Duration
		rotate bool
	)
	cmd := &cobra.Command{
		Use:   "peer <node>",
		Short: "Issue or rotate a node's peer-state-only replication certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			node := args[0]
			if _, ok := top.Lab.NodeByName(node); !ok {
				return fmt.Errorf("node %q is not declared in placement.nodes", node)
			}
			if pkiDir == "" {
				pkiDir = filepath.Join(top.Lab.Dir, ".twinet", "pki")
			}
			if outDir == "" {
				outDir = pkiDir
			}
			certPath := filepath.Join(outDir, node+"_peer_cert.pem")
			if _, err := os.Stat(certPath); err == nil && !rotate {
				return fmt.Errorf("%s already exists; use --rotate after rolling out a replacement peer credential", certPath)
			}
			if rotate {
				// Peer rotation has the same deliberate replacement semantics as
				// operator credentials. Preserve the old serial in the command
				// output without ever printing a key or bearer secret.
				if _, err := os.Stat(certPath); err != nil {
					return fmt.Errorf("cannot rotate peer %q: %w", node, err)
				}
			}
			m, err := pki.IssueNodePeer(pkiDir, outDir, node, valid)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"issued peer-state-only identity for %q\n\n  certificate  %s\n  key          %s\n  CA           %s\n",
				node, m.CertPath, m.KeyPath, m.CAPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&pkiDir, "pki", "", "cluster PKI directory")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory")
	cmd.Flags().DurationVar(&valid, "valid", 24*time.Hour, "certificate lifetime")
	cmd.Flags().BoolVar(&rotate, "rotate", false, "replace an existing node peer certificate")
	return cmd
}

// hostOf strips the port from a host:port address.
func hostOf(addr string) string {
	if addr == "" {
		return ""
	}
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
