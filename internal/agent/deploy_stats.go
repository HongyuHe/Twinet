package agent

import (
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/plan"
)

func attachDeploymentStats(resp *ApplyResponse, stats deploy.DeploymentStats, report *plan.Report) {
	resp.Dirty = stats.Dirty
	resp.Mutations = stats.Mutations
	resp.PhaseMS = map[string]int64{
		"observe": stats.ObserveMS,
		"diff":    stats.DiffMS,
		"image":   0,
		"verify":  0,
		"apply":   0,
		"capture": 0,
		"record":  0,
	}
	if report == nil {
		return
	}
	resp.PhaseMS["apply"] = report.Duration.Milliseconds()
	for _, result := range report.Results {
		if result.Step == nil {
			continue
		}
		switch {
		case strings.HasPrefix(result.Step.ID, "image:"):
			resp.PhaseMS["image"] += result.Duration.Milliseconds()
		case strings.HasPrefix(result.Step.ID, "verify-image:"):
			resp.PhaseMS["verify"] += result.Duration.Milliseconds()
		}
	}
}

func addCaptureTiming(resp *ApplyResponse, elapsed time.Duration) {
	addPhaseTiming(resp, "capture", elapsed)
}

func addPhaseTiming(resp *ApplyResponse, phase string, elapsed time.Duration) {
	if resp.PhaseMS == nil {
		resp.PhaseMS = map[string]int64{}
	}
	resp.PhaseMS[phase] += elapsed.Milliseconds()
}

func (s *Server) recordDeploymentStats(stats deploy.DeploymentStats, report *plan.Report) {
	metrics := s.metricRegistry()
	metrics.observePhase("observe", time.Duration(stats.ObserveMS)*time.Millisecond, "success")
	metrics.observePhase("diff", time.Duration(stats.DiffMS)*time.Millisecond, "success")
	if report != nil {
		metrics.observePhase("apply", report.Duration, "success")
	}
}
