package validate

import "testing"

// The survivors carry the claim. A suffix check tested only on the strings it
// drops passes for a function that returns false on everything, and the failure
// hiding behind that -- every AWS key silently dropped -- reports the same clean
// result as a repository with no keys in it.
func TestNotPlaceholderAWSKeyID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{"the key ID on AWS's IAM pages", "AKIAIOSFODNN7EXAMPLE", false},
		{"the session key ID on the STS pages", "ASIAIOSFODNN7EXAMPLE", false},
		{"a second documented body with the same suffix", "AKIAI44QH8DHBEXAMPLE", false},

		{"the planted fixture's key", "AKIA5J7QT2WVXMLB4RND", true},
		{"a temporary session key of the same shape", "ASIA3ZQ7WX2VLM6TBYNJ", true},
		// The two directions a suffix check gets wrong. Neither of these is a
		// value AWS publishes, and dropping either would be a real key lost.
		{"EXAMPLE at the head instead of the tail", "AKIAEXAMPLE7NNDOFSOI", true},
		{"EXAMPLE in the middle", "AKIAOFEXAMPLEND7SOIN", true},
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
