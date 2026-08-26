package agent

import (
	"github.com/HongyuHe/twinet/internal/contract"
	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/state"
)

// ProtocolVersion changes only when the controller-to-agent API changes. It is
// separate from Version, which is the exact source build recorded in audit
// evidence.
//
// 1.1.0 adds the ephemeral lab lifetime: the apply request and the persisted
// topology carry a disposable marker, and /v1/ephemeral renews it. The
// additions are backwards compatible on the wire -- an older agent ignores the
// fields and answers 404 for the endpoint, which degrades to the previous
// behaviour of holding a lab indefinitely rather than to a failure. The
// compatible interval below is nonetheless exact, as it already was: a mixed
// cluster is refused, and the version now records honestly that the wire
// changed.
const ProtocolVersion = "1.1.0"

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
