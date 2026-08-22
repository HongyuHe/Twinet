package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// batchExecFunc coalesces passive snapshot shells per node. Each result still
// maps to its exact device, and the agent applies its node-wide ExecProbe
// limiter to the contained runtime operations.
func batchExecFunc(top *model.Topology, token string,
	single func(context.Context, string, []string) (runtime.ExecResult, error),
) (func(context.Context, []grade.BatchExecRequest) ([]grade.BatchExecResult, error), error) {
	if !clustered(top) {
		return func(ctx context.Context, requests []grade.BatchExecRequest) ([]grade.BatchExecResult, error) {
			results := make([]grade.BatchExecResult, len(requests))
			for index, request := range requests {
				result, err := single(ctx, request.DeviceID, request.Command)
				results[index] = grade.BatchExecResult{Result: result, Err: err}
			}
			return results, nil
		}, nil
	}
	tok, err := tokenFor(token)
	if err != nil {
		return nil, err
	}
	cluster := client.NewCluster(top.Lab, tok)
	return func(ctx context.Context, requests []grade.BatchExecRequest) ([]grade.BatchExecResult, error) {
		results := make([]grade.BatchExecResult, len(requests))
		type grouped struct {
			node     *client.Node
			indexes  []int
			requests []agent.ExecRequest
		}
		groups := map[string]*grouped{}
		for index, request := range requests {
			device, ok := top.Device(request.DeviceID)
			if !ok {
				results[index].Err = fmt.Errorf("no device %q", request.DeviceID)
				continue
			}
			node, ok := cluster.Node(device.Node)
			if !ok {
				results[index].Err = fmt.Errorf("device %s is on unknown node %q", device.ID, device.Node)
				continue
			}
			group := groups[node.Name]
			if group == nil {
				group = &grouped{node: node}
				groups[node.Name] = group
			}
			group.indexes = append(group.indexes, index)
			group.requests = append(group.requests, agent.ExecRequest{
				Container: device.Container, Cmd: request.Command,
				Hold: currentHoldToken(), Grading: true,
			})
		}
		var (
			mu sync.Mutex
			wg sync.WaitGroup
		)
		for _, group := range groups {
			group := group
			wg.Add(1)
			go func() {
				defer wg.Done()
				response, err := group.node.ExecBatch(ctx, agent.ExecBatchRequest{Requests: group.requests})
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					for _, index := range group.indexes {
						results[index].Err = err
					}
					return
				}
				if len(response.Results) != len(group.indexes) {
					err := fmt.Errorf("node %s returned %d batch results for %d requests",
						group.node.Name, len(response.Results), len(group.indexes))
					for _, index := range group.indexes {
						results[index].Err = err
					}
					return
				}
				for offset, item := range response.Results {
					index := group.indexes[offset]
					if item.Error != "" {
						results[index].Err = fmt.Errorf("node %s: %s", group.node.Name, item.Error)
						continue
					}
					results[index].Result = runtime.ExecResult{
						ExitCode: item.Response.ExitCode,
						Stdout:   item.Response.Stdout,
						Stderr:   item.Response.Stderr,
					}
				}
			}()
		}
		wg.Wait()
		return results, nil
	}, nil
}
