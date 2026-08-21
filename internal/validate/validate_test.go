package validate

import "testing"

// The negative table is the one that carries the precision claim. A checksum
// with only positive cases passes for a function that returns true.
func TestLuhn(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{"the ISO 7812 worked example", "79927398713", true},
		{"a published Visa test number", "4111111111111111", true},
		{"a published Mastercard test number", "5555555555554444", true},
		{"a published Amex test number, 15 digits", "378282246310005", true},
		{"spaces, as a card is written", "4111 1111 1111 1111", true},
		{"hyphens, as a card is written", "4111-1111-1111-1111", true},

		{"the worked example with the check digit changed", "79927398710", false},
		{"a Visa test number off by one", "4111111111111112", false},
		{"repeated digits that reach no multiple of ten", "1111111111111111", false},
		{"an empty candidate", "", false},
		{"a lone check digit with nothing to check", "0", false},
		{"separators and no digits", " - ", false},
		{"a hex string a card regex must never reach", "4111111111111abc", false},
		{"a dotted version string", "6.16.13.30300400", false},
		{"the amdgpu DKMS string, flagged 268 times as a phone number",
			"1:6.16.13.30300400-2341068", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Luhn(tc.candidate); got != tc.want {
				t.Errorf("Luhn(%q) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}

// Luhn is a transcription check, so a placeholder run of zeros passes it. This
// is pinned rather than fixed: the answer is a denylist on the card rule, and
// a reader who assumes otherwise ships a rule that flags every payments README.
func TestLuhnPassesAPlaceholderRunOfZeros(t *testing.T) {
	if !Luhn("0000000000000000") {
		t.Error("Luhn(16 zeros) = false; the check itself accepts it, so a card rule needs a denylist")
	}
}

func TestMod11(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		// 11010519491231002X is the identity number GB 11643 documents; the
		// birthdate 1949-12-31 is what marks it as an example rather than a
		// person's. Its check character is derived here, not asserted:
		// ISO 7064 MOD 11-2 over the first seventeen digits yields 10, which
		// is written X.
		{"the GB 11643 documentation number", "11010519491231002X", true},
		{"lowercase x for the value ten", "11010519491231002x", true},
		{"the ISO 7064 MOD 11-2 short example", "07940", true},
		{"the shortest candidate with a body", "01", true},

		{"the documentation number with a digit check character", "110105194912310021", false},
		{"the short example with X where a zero belongs", "0794X", false},
		{"a transposition in the body", "11010519491231020X", false},
		{"an empty candidate", "", false},
		{"a check character with no body", "1", false},
		{"the shortest candidate, with the wrong check character", "00", false},
		{"a letter in the body", "1101051949123100AX", false},
		{"X inside the body rather than at the end", "1101051949123100X2", false},
		{"a Kubernetes NodePort", "30443", false},
		{"the buffer constant that became a postal code", "65536", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Mod11(tc.candidate); got != tc.want {
				t.Errorf("Mod11(%q) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}

// A check digit is one of eleven values, so a validator that always said yes
// would pass the positive table above and roughly a tenth of any negative one.
// Sweep every check character against a fixed body and require exactly one.
func TestMod11AcceptsExactlyOneCheckCharacter(t *testing.T) {
	const body = "1101051949123100"
	accepted := ""
	for _, c := range "0123456789X" {
		if Mod11(body + string(c)) {
			accepted += string(c)
		}
	}
	if accepted != "2" {
		t.Errorf("check characters accepted for %q = %q, want %q", body, accepted, "2")
	}
}
