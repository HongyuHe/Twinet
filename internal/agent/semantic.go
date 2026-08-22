package agent

import (
	"strconv"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
)

func rendererModeKey(mode render.Mode, ungraded int) string {
	if mode == "" {
		mode = render.ModePlatform
	}
	return string(mode) + "/ungraded=" + strconv.Itoa(ungraded)
}

// renderModeForDevice mirrors render.Renderer's per-device harness policy.
// A grading harness is solved except for the one AS under evaluation; treating
// its lab-wide mode as the mode of every device loses that AS's student state
// or replaces it with the reference answer during recovery.
func renderModeForDevice(mode render.Mode, ungraded int, device *model.Device) render.Mode {
	if ungraded != 0 && device != nil && device.ASN == ungraded {
		return render.ModePlatform
	}
	return mode
}

func capturesStudentState(top *model.Topology, mode render.Mode, ungraded int, device *model.Device) bool {
	return deployStudentOwned(top, device) && renderModeForDevice(mode, ungraded, device) != render.ModeSolve
}

// deployStudentOwned deliberately mirrors deploy.StudentOwned without making
// this small mode helper import the whole deployment package.
func deployStudentOwned(top *model.Topology, device *model.Device) bool {
	if top == nil || device == nil {
		return false
	}
	as := top.ASes[device.ASN]
	return as != nil && as.Role == model.RoleStudent
}
