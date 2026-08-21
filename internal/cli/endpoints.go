package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/model"
)

// endpointHealth is deliberately conservative: an endpoint is selectable only
// when its node agent and durable state store both answer. A missing status is
// unknown, not healthy, so endpoint publishing never routes clients toward an
// unobserved node.
func endpointHealth(ctx context.Context, top *model.Topology, token string) (map[string]bool, error) {
	health := map[string]bool{}
	if top == nil || top.Lab == nil {
		return health, fmt.Errorf("endpoint health needs a topology")
	}
	for _, node := range top.Lab.Placement.Nodes {
		health[node.Name] = false
	}
	if !clustered(top) {
		health[localNode(top)] = true
		return health, nil
	}
	tok, err := tokenFor(token)
	if err != nil {
		return health, err
	}
	for _, result := range client.NewCluster(top.Lab, tok).Status(ctx) {
		health[result.Node] = result.Err == nil &&
			(result.Value.StateStoreHealthy == nil || *result.Value.StateStoreHealthy)
	}
	return health, nil
}

func writeEndpointList(w io.Writer, endpoints []model.Endpoint, health map[string]bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tNODE\tADDRESS\tMODE\tSTATE\tVIP")
	for _, endpoint := range endpoints {
		state := "unhealthy"
		if health[endpoint.Node] {
			state = "healthy"
		}
		mode := string(endpoint.Mode)
		if endpoint.Primary {
			mode += " (primary)"
		}
		vip := endpoint.VIP
		if vip != "" && os.Getenv("TWINET_ENABLE_VIP") != "1" {
			vip = "disabled (set TWINET_ENABLE_VIP=1): " + vip
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			endpoint.Service, endpoint.Node, endpoint.Address, mode, state, vip)
	}
	if selected, err := model.SelectHealthyEndpoint(endpoints, health); err == nil {
		fmt.Fprintf(tw, "selected\t%s\t%s\t\thealthy\t\n", selected.Node, selected.Address)
	} else {
		fmt.Fprintln(tw, "selected\t-\t-\t\tno healthy endpoint\t")
	}
	_ = tw.Flush()
}
