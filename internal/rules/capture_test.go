package rules

import (
	"math"
	"regexp"
	"strings"
	"testing"
)

func TestEntropyCeiling(t *testing.T) {
	for _, tc := range []struct {
		bytes int
		want  float64
	}{
		// A candidate with one byte in it carries no information, and neither
		// does one with none.
		{0, 0},
		{1, 0},
		{2, 1},
		{8, 3},
		{64, 6},
		// The ceiling is the count of distinct bytes, which stops at 256
		// however long the candidate is.
		{256, 8},
		{4096, 8},
	} {
		if got := entropyCeiling(tc.bytes); got != tc.want {
			t.Errorf("entropyCeiling(%d) = %v, want %v", tc.bytes, got, tc.want)
		}
	}
}

// The rest of the package compares a floor against this with >, so an exact
// power of two has to come back exact: log2(8) that returned 2.9999999999 would
// refuse a 3.0 floor on an eight-byte group, which is a live rule.
func TestEntropyCeilingIsExactOnPowersOfTwo(t *testing.T) {
	for n, want := 1, 0.0; n <= 256; n, want = n*2, want+1 {
		if got := entropyCeiling(n); got != want || math.Trunc(got) != got {
			t.Errorf("entropyCeiling(%d) = %v, want exactly %v", n, got, want)
		}
	}
}

func TestMaxCaptureBytes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		group   int
		want    int
	}{
		{"the whole match when no group is named", `\bAKIA\b`, 0, 4},
		{"a fixed-width group", `([A-Za-z0-9]{8})`, 1, 8},
		{"the AWS access key id", `\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\b`, 1, 20},
		{"the SSN, whose separators are optional", `\b(\d{3}-?\d{2}-?\d{4})\b`, 1, 11},
		{"a group with a range, measured at its top", `([A-Za-z0-9]{8,64})`, 1, 64},
		{"the second group rather than the first", `(\d{4})-(\d{2})`, 2, 2},
		{"an alternation, measured at its widest arm", `(a|bbbb|cc)`, 1, 4},
		{"a repeated group", `((?:ab){1,3})`, 1, 6},
		{"an optional group", `(a?b?)`, 1, 2},
		{"a group that matches only the empty string", `()`, 1, 0},
		{"a group holding nothing but a zero-width assertion", `(\b)`, 1, 0},
		{"a dot, which is a rune and so up to four bytes", `(.)`, 1, 4},
		{"a unicode class", `(\p{L}{4})`, 1, 16},

		// A class is inclusive rune pairs and the widest encoding is at the top
		// of a range, so reading the bottom under-estimates -- the one direction
		// that refuses a live rule at startup. Every other class case here is
		// one byte at both ends, or astral at both, so the two readings agree
		// and none of them can catch that. A negation is where they part: `[^a]`
		// parses to [\x00-\x60] and [\x62-\x{10FFFF}], one byte at the bottom
		// and four at the top.
		{"a negated class, whose widest rune is at the top of a later range",
			`([^a]{2})`, 1, 8},
		{"a negated class as a scanning rule would write it", `([^\s]{32})`, 1, 128},

		// Bytes, not runes. A folded literal matches every case of itself and
		// they are not all the same width: (?i)k matches the Kelvin sign, which
		// is three bytes. A class needs no such walk -- syntax.Parse folds it
		// into the ranges, so (?i)[k] is already [KkK].
		{"a literal", `(k)`, 1, 1},
		{"a case-folded literal", `(?i)(k)`, 1, 3},
		{"a case-folded class", `(?i)([k])`, 1, 3},

		// Anything unbounded is the clamp, because past 256 bytes a length says
		// nothing: no byte string carries more than 8 bits per byte.
		{"an unbounded repeat", `([A-Za-z0-9]+)`, 1, byteValues},
		{"a star", `(x*)`, 1, byteValues},
		{"a bounded repeat at RE2's cap", `(x{1,1000})`, 1, byteValues},
		{"a repeat that reaches the clamp exactly", `(x{256})`, 1, byteValues},
		{"a repeat one byte under the clamp", `(x{255})`, 1, 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := maxCaptureBytes(tc.pattern, tc.group)
			if err != nil {
				t.Fatalf("maxCaptureBytes(%q, %d) = %v", tc.pattern, tc.group, err)
			}
			if got != tc.want {
				t.Errorf("maxCaptureBytes(%q, %d) = %d, want %d",
					tc.pattern, tc.group, got, tc.want)
			}
		})
	}
}

// A group this cannot find has to be an error rather than a zero, which reads
// as a group that captures nothing and refuses the rule. The loader has already
// range-checked the group against the compiled regex, so reaching either of
// these is an internal inconsistency -- and this package fails closed on one.
func TestMaxCaptureBytesFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		group   int
	}{
		{"a group the regex does not have", `(a)`, 2},
		{"a pattern that does not parse", `(unclosed`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := maxCaptureBytes(tc.pattern, tc.group); err == nil {
				t.Errorf("maxCaptureBytes(%q, %d) = nil error, want one",
					tc.pattern, tc.group)
			}
		})
	}
}

// Over-estimating leaves a dead rule loaded, which is the item this came from
// half-done. Under-estimating refuses a rule that works, which takes the
// scanner down at startup. So the walk may only ever be generous -- and the
// comparison is against a string the compiled regex really captures, rather
// than against a second reading of the pattern by hand.
func TestMaxCaptureBytesNeverUnderEstimatesARealCapture(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		in      string
	}{
		{`([A-Za-z0-9]{8})`, "abcdefgh"},
		{`([A-Za-z0-9]{8,64})`, strings.Repeat("abcdefgh", 8)},
		{`\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\b`, "AKIA0123456789ABCDEF"},
		{`\b(\d{3}-?\d{2}-?\d{4})\b`, "123-45-6789"},
		{`(?i)(k)`, "\u212a"},
		{`((?:ab){1,3})`, "ababab"},
		{`(\p{L}{4})`, "\u00e9\u00e9\u00e9\u00e9"},
		// Two astral runes are eight bytes, which is what a class arm reading
		// the bottom of its ranges would report as two.
		{`([^a]{2})`, "\U0001D400\U0001D401"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			m := re.FindStringSubmatch(tc.in)
			if m == nil {
				t.Fatalf("%q does not match %q, so this case proves nothing", tc.pattern, tc.in)
			}
			got, err := maxCaptureBytes(tc.pattern, 1)
			if err != nil {
				t.Fatalf("maxCaptureBytes(%q, 1) = %v", tc.pattern, err)
			}
			if got < len(m[1]) {
				t.Errorf("maxCaptureBytes(%q, 1) = %d, but it captured %q, which is %d bytes",
					tc.pattern, got, m[1], len(m[1]))
			}
		})
	}
}
