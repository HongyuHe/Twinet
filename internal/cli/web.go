package cli

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/web"
)

// newWebCmd serves the class-facing view of a lab.
//
// The manifest has declared a `builtin.web` service since the first version of
// this project and nothing served it: no container, no listener, and a schema
// that validated the declaration. This is that service. It runs on the control
// plane rather than in the lab, because one of the three things it exists to
// answer -- "is the platform working, or is it me?" -- cannot be answered from
// inside.
func newWebCmd(opts *Options) *cobra.Command {
	var (
		listen  string
		token   string
		refresh time.Duration
	)
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve the connectivity matrix and looking glass for a lab",
		Long: `Serve the read-only, class-facing view of a running lab.

Three pages: an overview of the lab and the machines hosting it, the
connectivity matrix between every pair of autonomous systems, and a looking
glass that runs a fixed list of read-only commands on any router.

Nothing here can change a device, so it can be shown to a whole class. The
matrix is hundreds of pings across the cluster, so it is taken on a timer and
served from memory rather than recomputed per request.

The listen address defaults to whatever the manifest's web service declares.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if listen == "" {
				listen = webListenFrom(top.Services)
			}
			if listen == "" {
				listen = ":9000"
			}

			exec, err := execFunc(cmd.Context(), top, token)
			if err != nil {
				return err
			}
			srv, err := web.New(top, func(ctx context.Context, id string, argv []string) (string, int, error) {
				res, err := exec(ctx, id, argv)
				if err != nil {
					return "", 0, err
				}
				out := res.Stdout
				if out == "" {
					out = res.Stderr
				}
				return out, res.ExitCode, nil
			})
			if err != nil {
				return err
			}
			srv.Refresh = refresh

			if clustered(top) {
				tok, err := tokenFor(token)
				if err != nil {
					return err
				}
				cl := client.NewCluster(top.Lab, tok)
				srv.Nodes = func(ctx context.Context) []web.NodeStatus {
					var out []web.NodeStatus
					for _, r := range cl.Status(ctx) {
						s := web.NodeStatus{Name: r.Node}
						if r.Err != nil {
							s.State, s.Err = "unreachable", r.Err.Error()
						} else {
							s.State, s.Version = "ok", r.Value.Version
							s.Containers = r.Value.Containers
						}
						out = append(out, s)
					}
					return out
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "serving %s on %s\n", top.Name, listen)
			hs := &http.Server{
				Addr:              listen,
				Handler:           srv.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			go func() {
				<-cmd.Context().Done()
				sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = hs.Shutdown(sd)
			}()
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to serve on (default: what the manifest declares)")
	cmd.Flags().StringVar(&token, "token", "", "agent token")
	cmd.Flags().DurationVar(&refresh, "refresh", 2*time.Minute,
		"how often to recompute the connectivity matrix")
	return cmd
}

// webListenFrom finds the address the manifest's web service asks for.
func webListenFrom(services map[string]*model.Service) string {
	for _, name := range sortedServiceNames(services) {
		s := services[name]
		if s.Kind == "builtin.web" && s.Listen != "" {
			return s.Listen
		}
	}
	return ""
}

func sortedServiceNames(services map[string]*model.Service) []string {
	out := make([]string, 0, len(services))
	for n := range services {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
