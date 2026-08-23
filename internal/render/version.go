package render

import "github.com/HongyuHe/twinet/internal/contract"

// RendererVersion is incremented only when rendered configuration or renderer
// inputs cease to be compatible with another running agent. It intentionally
// does not follow the Twinet binary version.
const RendererVersion = "1.1.0"

// Contract is the renderer compatibility interval advertised by agents.
var Contract = contract.Range{
	Current: RendererVersion, MinCompatible: RendererVersion, MaxCompatible: RendererVersion,
}
