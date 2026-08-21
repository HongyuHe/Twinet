package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFaultListJSONReportsSubstrateAvailability(t *testing.T) {
	cmd := newFaultListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name         string `json:"name"`
		Availability []struct {
			Substrate string `json:"substrate"`
			Mode      string `json:"mode"`
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
		} `json:"availability"`
	}
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	foundP4, foundK8s := false, false
	for _, row := range rows {
		switch row.Name {
		case "p4_table_entry_missing":
			foundP4 = len(row.Availability) == 1 &&
				row.Availability[0].Substrate == "p4-bmv2" &&
				row.Availability[0].Mode == "native" &&
				row.Availability[0].Reason != ""
		case "k8s_coredns_isolated":
			foundK8s = len(row.Availability) == 1 &&
				row.Availability[0].Substrate == "kubernetes" &&
				row.Availability[0].Mode == "delegated" &&
				!row.Availability[0].Available &&
				row.Availability[0].Reason != ""
		}
	}
	if !foundP4 || !foundK8s {
		t.Fatalf("fault list omitted typed availability: p4=%t k8s=%t", foundP4, foundK8s)
	}
}
