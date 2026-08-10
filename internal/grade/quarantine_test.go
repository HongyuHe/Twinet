package grade

import (
	"strings"
	"testing"
)

// The single worst failure this system can have is a platform fault becoming a
// student's zero. A report that could not be graded has a total of zero, and in
// a spreadsheet that is indistinguishable from a student who did nothing.
func TestQuarantinedReportsCarryNoTotal(t *testing.T) {
	s := Summarise("rubric", []*Report{
		{Submission: "alice", AS: 3, Total: 7.5, MaxTotal: 10,
			Questions: []QuestionResult{{ID: "q1", Awarded: 7.5}}},
		{Submission: "bob", AS: 4, Total: 0, MaxTotal: 10, NeedsReview: true,
			Err: "deploying the harness: node node-1 unreachable"},
		{Submission: "carol", AS: 5, Total: 0, MaxTotal: 10,
			Questions: []QuestionResult{{ID: "q1", Awarded: 0}}},
	}, 0)

	if got := len(s.Quarantined()); got != 1 {
		t.Fatalf("quarantined %d reports, want 1", got)
	}

	csv := s.CSV()
	var bobRow, carolRow string
	for _, line := range strings.Split(csv, "\n") {
		switch {
		case strings.HasPrefix(line, "bob,"):
			bobRow = line
		case strings.HasPrefix(line, "carol,"):
			carolRow = line
		}
	}
	if bobRow == "" || carolRow == "" {
		t.Fatalf("both submissions must appear in the gradebook:\n%s", csv)
	}
	if !strings.Contains(bobRow, "needs-review") {
		t.Errorf("a report that could not be graded is not marked:\n%s", bobRow)
	}
	if strings.Contains(bobRow, "0.00,10.00") {
		t.Errorf("a report that could not be graded exported a zero total:\n%s", bobRow)
	}
	// A genuine zero must still be exported as a zero. Quarantine must not
	// become a way for a student who did nothing to escape their mark.
	if !strings.Contains(carolRow, "graded,0.00") {
		t.Errorf("a genuine zero was not exported as a mark:\n%s", carolRow)
	}
}

func TestQuarantineNoteCannotShiftColumns(t *testing.T) {
	// An error message containing a comma or a quote would otherwise move every
	// later column of a gradebook, silently reassigning marks on import.
	s := Summarise("rubric", []*Report{
		{Submission: "dave", AS: 6, MaxTotal: 10, NeedsReview: true,
			Err: `node-1: "apply" failed, retrying, then gave up`},
	}, 0)
	row := ""
	for _, line := range strings.Split(s.CSV(), "\n") {
		if strings.HasPrefix(line, "dave,") {
			row = line
		}
	}
	header := strings.Split(strings.Split(s.CSV(), "\n")[0], ",")
	if got := len(splitCSV(row)); got != len(header) {
		t.Fatalf("row has %d fields, header has %d:\n%s", got, len(header), row)
	}
}

// splitCSV is a minimal RFC-4180 field splitter, good enough to prove that a
// quoted note occupies exactly one field.
func splitCSV(row string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(row); i++ {
		c := row[i]
		switch {
		case c == '"' && inQuote && i+1 < len(row) && row[i+1] == '"':
			cur.WriteByte('"')
			i++
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(out, cur.String())
}
