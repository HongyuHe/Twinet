package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
)

// newEventsCmd exposes the bounded, scoped agent event rings as one
// deterministically merged cluster view.
func newEventsCmd(opts *Options) *cobra.Command {
	var (
		token  string
		lab    string
		follow bool
		after  uint64
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Show structured cluster events for a lab",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if lab == "" {
				lab = top.Name
			}
			if !clustered(top) {
				return fmt.Errorf("event streaming requires a node agent; this lab uses the local runtime")
			}
			tok, err := tokenFor(token)
			if err != nil {
				return err
			}
			cluster := client.NewCluster(top.Lab, tok)
			results := cluster.Events(cmd.Context(), lab, after, limit)
			events := client.MergeEvents(results)
			if err := printEvents(cmd, opts.JSON, events); err != nil {
				return err
			}
			if !follow {
				return eventNodeErrors(results)
			}
			return followEvents(cmd.Context(), cmd, opts.JSON, cluster, lab, results)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token (or set TWINET_TOKEN)")
	cmd.Flags().StringVar(&lab, "lab", "", "lab to show (default: the manifest lab)")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "continue following event streams")
	cmd.Flags().Uint64Var(&after, "after", 0, "node-local event cursor to resume after")
	cmd.Flags().IntVar(&limit, "limit", 200, "maximum events to read from each node")
	return cmd
}

func printEvents(cmd *cobra.Command, asJSON bool, events []agent.Event) error {
	if asJSON {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(events)
	}
	for _, event := range events {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			event.Timestamp.UTC().Format(time.RFC3339Nano), event.Node, dash(event.Lab),
			dash(event.Generation), event.Scope, event.Action, event.Result+eventDetail(event.Detail))
	}
	return nil
}

func eventDetail(detail string) string {
	if detail == "" {
		return ""
	}
	return "\t" + strings.ReplaceAll(detail, "\n", " ")
}

func eventNodeErrors(results []client.NodeResult[agent.EventsResponse]) error {
	var problems []string
	for _, result := range results {
		if result.Err != nil {
			problems = append(problems, result.Node+": "+result.Err.Error())
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("could not read events from %d node(s): %s", len(problems), strings.Join(problems, "; "))
}

type streamedEvent struct {
	event agent.Event
	err   error
	node  string
}

// followEvents reconnects every node stream after a transport close. A short
// coalescing window makes simultaneous node events print in the same
// timestamp/node/lab/sequence order as finite output while avoiding an
// unbounded global reorder buffer.
func followEvents(ctx context.Context, cmd *cobra.Command, asJSON bool, cluster *client.Cluster,
	lab string, initial []client.NodeResult[agent.EventsResponse],
) error {
	cursors := map[string]uint64{}
	for _, result := range initial {
		if result.Err == nil {
			cursors[result.Node] = result.Value.Next
		}
	}
	stream := make(chan streamedEvent, len(cluster.Nodes)*2)
	for _, node := range cluster.Nodes {
		node := node
		go followNodeEvents(ctx, node, lab, cursors[node.Name], stream)
	}
	pending := make([]agent.Event, 0, len(cluster.Nodes))
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	var tick <-chan time.Time
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		agent.SortEvents(pending)
		if asJSON {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			for _, event := range pending {
				if err := encoder.Encode(event); err != nil {
					return err
				}
			}
			pending = pending[:0]
			return nil
		}
		if err := printEvents(cmd, asJSON, pending); err != nil {
			return err
		}
		pending = pending[:0]
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return flush()
		case <-tick:
			tick = nil
			if err := flush(); err != nil {
				return err
			}
		case item := <-stream:
			if item.err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "events: %s\n", item.err)
				continue
			}
			cursors[item.node] = item.event.Sequence
			pending = append(pending, item.event)
			if tick == nil {
				timer.Reset(100 * time.Millisecond)
				tick = timer.C
			}
		}
	}
}

func followNodeEvents(ctx context.Context, node *client.Node, lab string, after uint64,
	out chan<- streamedEvent,
) {
	cursor := after
	for ctx.Err() == nil {
		events, errs := node.WatchEvents(ctx, lab, cursor)
		for events != nil || errs != nil {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					events = nil
					continue
				}
				if event.Sequence <= cursor {
					continue
				}
				cursor = event.Sequence
				select {
				case out <- streamedEvent{event: event, node: node.Name}:
				case <-ctx.Done():
					return
				}
			case err, ok := <-errs:
				if !ok {
					errs = nil
					continue
				}
				if err != nil {
					select {
					case out <- streamedEvent{node: node.Name, err: err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}
