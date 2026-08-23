package grade

import (
	"testing"
)

func TestObservationBatchParserPreservesMixedPassFail(t *testing.T) {
	marker := "__TWINET_OBS_test"
	body := marker + "_0_RC=0\nok\n" + marker + "_0_END\n" +
		marker + "_1_RC=7\nfailed\n" + marker + "_1_END\n"
	results, err := parseObservationBatch(body, 2, marker)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].ExitCode != 0 || results[0].Stdout != "ok" ||
		results[1].ExitCode != 7 || results[1].Stderr != "failed" {
		t.Fatalf("batch parser results = %#v", results)
	}
}
