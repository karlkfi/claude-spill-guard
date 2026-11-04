// us-ssn against what it claims and what it does not. The sentence the project
// can say about SSNs is exactly these rows, so each direction is pinned: the
// value is written with hyphens and the label comes before it, within the window.

package scan

import (
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

func TestUSSSNShapes(t *testing.T) {
	set := loadShipped(t)
	ssn := testvec.Load(t).Get(t, "us-ssn")
	far := strings.Repeat("x", 65)

	cases := []struct {
		name string
		text string
		want int
	}{
		{"after a label and a colon", "ssn: " + ssn, 1},
		{"upper case, assigned", "SSN=" + ssn, 1},
		{"a JSON field", `{"ssn": "` + ssn + `"}`, 1},
		{"a snake_case key", "patient_ssn: " + ssn, 1},
		{"the long label, two words ahead", "Social Security Number: " + ssn, 1},
		{"YAML, on the line below its key", "ssn:\n  " + ssn, 1},
		{"the long label in snake_case", "social_security_number = " + ssn, 1},
		{"the long label in camelCase", `{"socialSecurityNumber": "` + ssn + `"}`, 1},
		{"no label", "reference " + ssn, 0},
		{"the label after the value", ssn + " is the ssn", 0},
		{"the label further back than the window", "ssn " + far + " " + ssn, 0},
		{"the label inside a longer word", "assn: " + ssn, 0},
		{"no hyphens", "ssn: " + strings.ReplaceAll(ssn, "-", ""), 0},
		{"an area in the 900s", "ssn: 9" + ssn[1:], 0},
		{"glued to a digit", "ssn: 1" + ssn, 0},
		{"masked", "ssn: ***-**-" + ssn[len(ssn)-4:], 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Buffer("t", []byte(tc.text+"\n"), set)
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}
			if got.Skipped != Scanned {
				t.Fatalf("not read: %s", got.Skipped)
			}
			if len(got.Findings) != tc.want {
				t.Fatalf("%d finding(s), want %d:\n%s", len(got.Findings), tc.want, report(got.Findings))
			}
			if tc.want == 1 && got.Findings[0].RuleID != "us-ssn" {
				t.Errorf("reported by %q", got.Findings[0].RuleID)
			}
		})
	}
}
