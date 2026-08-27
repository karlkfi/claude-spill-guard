package validate

import (
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

// The survivors carry the claim. A suffix check tested only on the strings it
// drops passes for a function that returns false on everything, and the failure
// hiding behind that -- every AWS key silently dropped -- reports the same clean
// result as a repository with no keys in it.
//
// A candidate that could pass for an issued credential is named rather than
// written, and the file it is named in sits under testdata/corpus/. The four
// that no scanner could mistake for a credential stay here, because there the
// exact bytes are what the case is about.
func TestNotPlaceholderAWSKeyID(t *testing.T) {
	vec := testvec.Load(t)

	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{"the key ID on AWS's IAM pages", vec.Get(t, "aws-iam-example"), false},
		{"the session key ID on the STS pages", vec.Get(t, "aws-sts-example"), false},
		{"a different body with the same suffix", vec.Get(t, "aws-iam-example-second-body"), false},

		{"a long-term key ID", vec.Get(t, "aws-access-key-id"), true},
		{"a temporary session key of the same shape", vec.Get(t, "aws-session-key-id"), true},
		// The two directions a suffix check gets wrong. Neither of these is a
		// value AWS publishes, and dropping either would be a real key lost.
		{"EXAMPLE at the head instead of the tail", vec.Get(t, "aws-example-at-head"), true},
		{"EXAMPLE in the middle", vec.Get(t, "aws-example-in-middle"), true},
		{"one character past the suffix", "AKIAIOSFODNN7EXAMPLES", true},
		{"a lowercase suffix, which the rule's regex cannot produce", "AKIAIOSFODNN7example", true},
		{"the padded placeholder the entropy floor drops", "AKIAXXXXXXXXXXXXXXXX", true},
		{"the empty string", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NotPlaceholderAWSKeyID(tc.candidate); got != tc.want {
				t.Errorf("NotPlaceholderAWSKeyID(%q) = %v, want %v",
					tc.candidate, got, tc.want)
			}
		})
	}
}
