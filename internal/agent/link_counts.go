package agent

import (
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
)

func wireCrossEndpoints(results []plan.Result, top *model.Topology, planned bool) int {
	if top == nil {
		return 0
	}
	links := map[string]*model.Link{}
	for _, link := range top.Links {
		if link != nil {
			links[link.ID] = link
		}
	}
	n := 0
	for _, result := range results {
		if result.Step == nil || result.Step.Stage != plan.StageWire {
			continue
		}
		if !planned && (result.Skipped || result.Err != nil) {
			continue
		}
		id := strings.TrimPrefix(result.Step.ID, "wire:")
		if link := links[id]; link != nil && link.CrossNode() {
			n++
		}
	}
	return n
}

func plannedCrossEndpoints(p *plan.Plan, top *model.Topology) int {
	if p == nil {
		return 0
	}
	results := make([]plan.Result, 0, p.Len())
	for _, step := range p.Steps() {
		results = append(results, plan.Result{Step: step})
	}
	return wireCrossEndpoints(results, top, true)
}
