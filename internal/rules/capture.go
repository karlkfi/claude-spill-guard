package rules

import (
	"fmt"
	"math"
	"regexp/syntax"
	"unicode"
	"unicode/utf8"
)

// byteValues is 256 because validate.Shannon counts byte frequencies: a string
// of any length draws from 256 values, so no candidate exceeds 8 bits per byte
// however long it is. Clamping every length to this is what keeps an unbounded
// repeat, a nested one and an overflowing product in the same arm as an
// ordinary one -- past 256 bytes a length has stopped saying anything.
const byteValues = 256

// entropyCeiling is the highest validate.Shannon result a candidate of n bytes
// can carry. The ceiling is log2 of the number of distinct bytes, which is at
// most n, so a one-byte candidate carries 0 bits and an eight-byte one carries
// 3 however random it is.
func entropyCeiling(n int) float64 {
	if n < 1 {
		n = 1
	}
	if n > byteValues {
		n = byteValues
	}
	return math.Log2(float64(n))
}

// maxCaptureBytes is the length of the longest string group can capture out of
// pattern, in bytes, clamped at byteValues.
//
// The longest and not the shortest. The question this answers is whether an
// entropy floor sits above everything the group can reach, and a group matching
// 8 to 64 bytes reaches log2(64) = 6 bits at its longest against 3 at its
// shortest -- so measuring the shortest would reject a floor of 4 that a
// 16-byte capture clears.
//
// It over-estimates and never under-estimates, which is the direction that
// matters when the caller stops the binary over the answer: a length that came
// back too small refuses a rule that works. `(?:ab){1,3}` is counted at 6 bytes
// though it draws on two, so its real ceiling is 1 bit where this reports
// 2.585, and a floor between them loads instead of being refused. Missing a
// dead rule leaves this check half-done; refusing a live one takes the scanner
// down.
//
// Bytes rather than runes, because Shannon counts bytes. A case-folded literal
// is the case that makes those differ: `(?i)k` matches the three-byte Kelvin
// sign, so folding is walked rather than assumed to be length-preserving. A
// character class needs no such walk -- syntax.Parse expands the fold into the
// class, and the widest rune in a range covers it.
func maxCaptureBytes(pattern string, group int) (int, error) {
	// Perl is the flag set regexp.Compile parses with, so this succeeds for
	// every pattern that got past it. Failing here is an internal
	// inconsistency, which fails closed like any other.
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, fmt.Errorf("regex compiled but does not parse: %q", err)
	}
	sub := re
	if group > 0 {
		if sub = capture(re, group); sub == nil {
			return 0, fmt.Errorf("group %d is not in the parsed regex", group)
		}
	}
	return maxBytes(sub), nil
}

// capture finds the subexpression holding capture group n.
func capture(re *syntax.Regexp, n int) *syntax.Regexp {
	if re.Op == syntax.OpCapture && re.Cap == n {
		return re
	}
	for _, s := range re.Sub {
		if got := capture(s, n); got != nil {
			return got
		}
	}
	return nil
}

// maxBytes walks one subexpression. An operator this does not name returns the
// clamp, so a future RE2 operator over-estimates rather than silently reporting
// a rule dead.
func maxBytes(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		n := 0
		for _, r := range re.Rune {
			if n = clamp(n + runeBytes(r, fold)); n == byteValues {
				break
			}
		}
		return n
	case syntax.OpCharClass:
		// Rune holds inclusive pairs, so the high end of each range is the
		// widest encoding it offers.
		n := 0
		for i := 1; i < len(re.Rune); i += 2 {
			if b := runeBytes(re.Rune[i], false); b > n {
				n = b
			}
		}
		return n
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture:
		return maxBytes(re.Sub[0])
	case syntax.OpQuest:
		return maxBytes(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		return byteValues
	case syntax.OpRepeat:
		if re.Max < 0 {
			return byteValues
		}
		return clamp(re.Max * maxBytes(re.Sub[0]))
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			if n = clamp(n + maxBytes(s)); n == byteValues {
				break
			}
		}
		return n
	case syntax.OpAlternate:
		n := 0
		for _, s := range re.Sub {
			if b := maxBytes(s); b > n {
				n = b
			}
		}
		return n
	}
	return byteValues
}

// runeBytes is how many bytes r takes, or the widest of everything it matches
// when the enclosing literal folds case.
func runeBytes(r rune, fold bool) int {
	n := utf8.RuneLen(r)
	if n < 0 {
		// Surrogates and out-of-range runes encode as U+FFFD.
		n = utf8.UTFMax
	}
	if !fold {
		return n
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if b := utf8.RuneLen(f); b > n {
			n = b
		}
	}
	return n
}

func clamp(n int) int {
	if n > byteValues {
		return byteValues
	}
	return n
}
