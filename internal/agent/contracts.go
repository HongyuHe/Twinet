package agent

import (
	"github.com/HongyuHe/twinet/internal/contract"
	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/state"
)

// ProtocolVersion changes only when the controller-to-agent API changes. It is
// separate from Version, which is the exact source build recorded in audit
// evidence.
const ProtocolVersion = "1.0.0"

// ProtocolContract declares the compatible protocol interval around
// ProtocolVersion.
var ProtocolContract = contract.Range{
	Current: ProtocolVersion, MinCompatible: ProtocolVersion, MaxCompatible: ProtocolVersion,
}

// Compatibility returns the independent contracts the agent currently serves.
func Compatibility() contract.Set {
	return contract.Set{
		Protocol: ProtocolContract,
		Renderer: render.Contract,
		State:    state.Contract,
	}
}
