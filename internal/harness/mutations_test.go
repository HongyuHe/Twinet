package harness

import (
	"strings"
	"testing"
)

func TestMutationSuiteRejectsRemovedRequireHitField(t *testing.T) {
	_, err := ParseMutationSuite([]byte(`apiVersion: twinet.dev/v1
kind: CompactMutationSuite
cases:
  - name: wrong
    required: {question_id: q1, check_id: fixture.check, check_index: 0}
    expected_check_status: fail
    transforms:
      - {file: ATL.conf, find: good, replace: bad, require_hit: true}
`))
	if err == nil || !strings.Contains(err.Error(), "require_hit") {
		t.Fatalf("removed require_hit field was silently accepted: %v", err)
	}
}
