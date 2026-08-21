// Package validate holds the checks that decide whether a regex match is a
// finding. This is where precision comes from: on 257 real files the inherited
// ruleset produced 5,679 matches across 9 rules with zero credential hits, and
// every one of those rules was numeric-only. A numeric pattern cannot be made
// precise by regex alone -- see docs/design/language-choice.md section 3.
//
// Every check here answers "does this candidate survive?", so true means the
// match is reported and false means it is dropped. Malformed input is dropped
// rather than reported: a candidate that is not a card number, not an address,
// or not a checksum is not evidence of anything, and reporting it is the noise
// these checks exist to remove. That is not a fail-open -- the fail-closed rule
// governs internal errors, and none of these functions can have one. A rule
// that names a check it should not have named is a rule the loader rejects at
// startup, not something a validator can see from here.
//
// Nothing in here retains a candidate. The strings are read and discarded; the
// caller carries a truncated hash, never the value.
package validate

// Luhn reports whether a payment card candidate passes the Luhn checksum.
//
// Spaces and hyphens are ignored, because a card rule captures the separators a
// card is written with. Any other non-digit means the candidate is not a card
// number, so it is dropped.
//
// Luhn is a transcription check and nothing more. 0000000000000000 passes it,
// as does every published test card number, so a card rule needs a placeholder
// denylist beside this one.
func Luhn(candidate string) bool {
	sum, digits := 0, 0
	// Right to left, because the doubling alternates from the check digit.
	for i := len(candidate) - 1; i >= 0; i-- {
		c := candidate[i]
		switch {
		case c == ' ' || c == '-':
			continue
		case c < '0' || c > '9':
			return false
		}
		d := int(c - '0')
		if digits%2 == 1 {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		digits++
	}
	// One digit is a check digit with nothing to check.
	return digits >= 2 && sum%10 == 0
}

// Mod11 reports whether a national ID candidate passes ISO 7064 MOD 11-2, the
// standard weighted mod-11 check: the last character is the check character,
// 'X' stands for the value 10, and the body is folded left to right.
//
// This is one mod-11 and not the only one. The Dutch elfproef weights 9..2 and
// negates the check digit, and the Norwegian fodselsnummer uses two fixed
// weight vectors; both reject numbers this accepts and vice versa. A rule
// needing one of those names a separate check rather than reusing this.
func Mod11(candidate string) bool {
	if len(candidate) < 2 {
		return false
	}
	body, check := candidate[:len(candidate)-1], candidate[len(candidate)-1]

	p := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < '0' || c > '9' {
			return false
		}
		p = ((p + int(c-'0')) * 2) % 11
	}

	switch want := (12 - p) % 11; {
	case want == 10:
		return check == 'X' || check == 'x'
	default:
		return check == byte('0'+want)
	}
}
