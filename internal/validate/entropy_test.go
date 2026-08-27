package validate

import (
	"math"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

func TestShannon(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    string
		want float64
	}{
		{"the empty string", "", 0},
		{"one byte", "a", 0},
		{"one byte repeated", "aaaaaaaaaaaaaaaaaaaa", 0},
		{"two bytes, evenly split", "ab", 1},
		{"four bytes, evenly split", "abcd", 2},
		{"every hex digit once", "0123456789abcdef", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Shannon(tc.s); math.Abs(got-tc.want) > 1e-12 {
				t.Errorf("Shannon(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

// A run of one byte must be exactly zero and not negative zero: a floor is a
// >= comparison, so a signed zero reads correctly, but the value is printed in
// a friction report and -0 there is a defect report waiting to be filed.
func TestShannonReturnsPositiveZeroForAConstantRun(t *testing.T) {
	if got := Shannon("aaaa"); math.Signbit(got) {
		t.Errorf("Shannon(%q) = %v, want positive zero", "aaaa", got)
	}
}

func TestEntropyAtLeast(t *testing.T) {
	vec := testvec.Load(t)

	for _, tc := range []struct {
		name string
		s    string
		min  float64
		want bool
	}{
		{"AWS's documented access key ID against the shipped floor",
			vec.Get(t, "aws-iam-example"), 3.0, true},
		{"AWS's documented secret access key against the shipped floor",
			vec.Get(t, "aws-secret-access-key"), 3.0, true},
		{"a floor of zero admits anything that is not empty", "aaaa", 0, true},

		{"a padded placeholder token", "ghp_0000000000000000000000000000000000", 3.0, false},
		{"a repeated byte", "aaaaaaaaaaaaaaaaaaaa", 3.0, false},
		{"the empty string against any positive floor", "", 0.1, false},
		// A ceiling of log2(len) rather than of the alphabet: eight bytes
		// cannot carry more than three bits each however random they are, so a
		// floor above the captured group's length silently disables the rule.
		{"eight distinct bytes against a floor of 3.5", "abcdefgh", 3.5, false},
		{"eight distinct bytes against a floor of 3.0", "abcdefgh", 3.0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EntropyAtLeast(tc.s, tc.min); got != tc.want {
				t.Errorf("EntropyAtLeast(%q, %v) = %v, want %v", tc.s, tc.min, got, tc.want)
			}
		})
	}
}
