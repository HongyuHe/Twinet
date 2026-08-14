package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// A global flag that is accepted and ignored is worse than one that is
// rejected: whatever was parsing the output gets a table and no error. These
// three took --json and printed a table anyway.
func TestJSONIsHonouredWhereItIsAccepted(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
	}{
		{"validate", []string{"validate", "-m", "../../examples/cos461", "--json"}},
		{"grade checks", []string{"grade", "checks", "--json"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := Root()
			var out strings.Builder
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(c.args)
			if err := root.Execute(); err != nil {
				t.Fatalf("%v\n%s", err, out.String())
			}
			var any any
			if err := json.Unmarshal([]byte(out.String()), &any); err != nil {
				t.Errorf("--json produced something that is not JSON (%v):\n%s",
					err, out.String())
			}
		})
	}
}
