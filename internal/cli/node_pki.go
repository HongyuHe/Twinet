package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

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
			fmt.Fprintf(out, "issued a cluster CA and %d node certificate(s) in %s\n\n", len(names), dir)
			fmt.Fprintf(out, "  CA          %s\n", b.CA.CertPath)
			fmt.Fprintf(out, "  controller  %s\n", b.Client.CertPath)
			for _, n := range names {
				fmt.Fprintf(out, "  %-11s %s\n", n, b.Nodes[n].CertPath)
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
