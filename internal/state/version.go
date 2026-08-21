package state

import "github.com/HongyuHe/twinet/internal/contract"

// SchemaVersion identifies the durable snapshot and control-record schema. It
// is distinct from both the binary and renderer versions.
const SchemaVersion = "1.0.0"

// Contract describes the schema interval accepted by this state store.
var Contract = contract.Range{
	Current: SchemaVersion, MinCompatible: SchemaVersion, MaxCompatible: SchemaVersion,
}
