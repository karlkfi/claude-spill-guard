// aws-access-key-id against one value per arm of its alternation, because
// before this file one of the five was exercised end to end. Every other
// occurrence of ASIA, A3T, ABIA and ACCA in the tree is one of three things
// that cannot see an arm go missing: a keyword handed to the prefilter, a
// literal inside some other test's own fixture regex, or ASIAIOSFODNN7EXAMPLE,
// which aws-placeholder is required to drop. So the corpus's one ASIA reading
// was a rule staying quiet, and nothing measured one firing -- deleting four of
// the five arms left `go test ./...` green.
//
// The values come from testdata/corpus/vectors/ rather than from literals here,
// for the reason internal/testvec's own doc comment gives: GitHub's detector
// for the ASIA prefix opened an alert on internal/validate/aws_test.go, and the
// answer was a place to keep such strings rather than an exemption for
// whichever source file gets found.

package scan

import (
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

func awsAccessKeyID(t *testing.T) []rules.Rule {
	t.Helper()
	for _, rule := range loadShipped(t) {
		if rule.ID == "aws-access-key-id" {
			return []rules.Rule{rule}
		}
	}
	t.Fatal("the shipped ruleset carries no aws-access-key-id rule")
	return nil
}

func TestEveryAWSPrefixArmIsReachable(t *testing.T) {
	set := awsAccessKeyID(t)
	vec := testvec.Load(t)

	// One vector per arm of the alternation. A row missing here is an arm
	// whose deletion nothing in the tree can report.
	arms := []struct{ prefix, vector string }{
		{"A3T", "aws-a3t-key-id"},
		{"AKIA", "aws-access-key-id"},
		{"ASIA", "aws-session-key-id"},
		{"ABIA", "aws-bearer-token-id"},
		{"ACCA", "aws-context-credential-id"},
	}

	for _, arm := range arms {
		t.Run(arm.prefix, func(t *testing.T) {
			value := vec.Get(t, arm.vector)
			buf := []byte("AWS_ACCESS_KEY_ID=" + value + "\n")
			got, err := Buffer("t", buf, set)
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}
			// A buffer nothing read reports no findings, which would fail
			// the count below with a message blaming the arm.
			if got.Skipped != Scanned {
				t.Fatalf("not read: %s", got.Skipped)
			}
			if len(got.Findings) != 1 {
				t.Fatalf("%s reports %d finding(s), want 1 -- this arm is "+
					"indistinguishable from absent, which is what the whole "+
					"table is for", arm.prefix, len(got.Findings))
			}
			if got.Findings[0].RuleID != "aws-access-key-id" {
				t.Errorf("reported by %q", got.Findings[0].RuleID)
			}
		})
	}
}

// The arms are reachable and the checks behind them still bite. Without this
// the table above would pass over a rule that had lost its entropy floor or
// its placeholder check, since both of those only ever say no.
func TestTheAWSArmsStillDropWhatTheyShould(t *testing.T) {
	set := awsAccessKeyID(t)
	vec := testvec.Load(t)

	cases := []struct{ name, vector string }{
		{"AWS's published IAM example, dropped on its suffix", "aws-iam-example"},
		{"the same example on the STS prefix, so the check is not AKIA-only", "aws-sts-example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := []byte("AWS_ACCESS_KEY_ID=" + vec.Get(t, tc.vector) + "\n")
			got, err := Buffer("t", buf, set)
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}
			if got.Skipped != Scanned {
				t.Fatalf("not read: %s", got.Skipped)
			}
			if len(got.Findings) != 0 {
				t.Errorf("reported %d finding(s), want 0", len(got.Findings))
			}
		})
	}

	// A padded placeholder, which is what the entropy floor is for rather than
	// the suffix check. Inline because no scanner mistakes it for a key.
	buf := []byte("AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXXXXXXXX\n")
	got, err := Buffer("t", buf, set)
	if err != nil {
		t.Fatalf("scanning: %v", err)
	}
	if got.Skipped != Scanned {
		t.Fatalf("not read: %s", got.Skipped)
	}
	if len(got.Findings) != 0 {
		t.Errorf("a padded ASIA placeholder reports %d finding(s), want 0",
			len(got.Findings))
	}
}
