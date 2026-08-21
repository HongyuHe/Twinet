package cli

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
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

			exec, err := webExecFunc(cmd.Context(), top, token)
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
				// Runtime and repair events make a cached matrix stale. The
				// watcher only invalidates; takeMatrix still coalesces a burst
				// into one bounded two-exec-per-source refresh when somebody
				// asks for it.
				go invalidateMatrixOnEvents(cmd.Context(), cl, top.Name, srv.InvalidateMatrix)
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

// webExecFunc is the read-only web collector's execution path. It must not
// set Grading: otherwise matrix refreshes become grading-infrastructure
// outcomes and hide the actual pressure/errors of a class mark.
func webExecFunc(_ context.Context, top *model.Topology, token string) (
	func(context.Context, string, []string) (rt.ExecResult, error), error,
) {
	if !clustered(top) {
		runtime := rt.NewDocker()
		return func(ctx context.Context, deviceID string, command []string) (rt.ExecResult, error) {
			device, ok := top.Device(deviceID)
			if !ok {
				return rt.ExecResult{}, fmt.Errorf("no device %q", deviceID)
			}
			return runtime.Exec(ctx, device.Container, rt.ExecCmd{Cmd: command})
		}, nil
	}
	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	cluster := client.NewCluster(top.Lab, tok)
	return func(ctx context.Context, deviceID string, command []string) (rt.ExecResult, error) {
		device, ok := top.Device(deviceID)
		if !ok {
			return rt.ExecResult{}, fmt.Errorf("no device %q", deviceID)
		}
		node, ok := cluster.Node(device.Node)
		if !ok {
			return rt.ExecResult{}, fmt.Errorf("device %s is on unknown node %q", deviceID, device.Node)
		}
		result, err := node.Exec(ctx, agent.ExecRequest{
			Container: device.Container, Cmd: command, Hold: currentHoldToken(),
		})
		return rt.ExecResult{ExitCode: result.ExitCode, Stdout: result.Stdout, Stderr: result.Stderr}, err
	}, nil
}

func invalidateMatrixOnEvents(ctx context.Context, cluster *client.Cluster, lab string, invalidate func()) {
	for _, node := range cluster.Nodes {
		node := node
		go func() {
			var after uint64
			for ctx.Err() == nil {
				events, errs := node.WatchEvents(ctx, lab, after)
				for events != nil || errs != nil {
					select {
					case <-ctx.Done():
						return
					case event, ok := <-events:
						if !ok {
							events = nil
							continue
						}
						if event.Sequence > after {
							after = event.Sequence
						}
						switch event.Scope {
						case "runtime", "reconcile", "matrix":
							invalidate()
						}
					case _, ok := <-errs:
						if !ok {
							errs = nil
						}
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(250 * time.Millisecond):
				}
			}
		}()
	}
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
