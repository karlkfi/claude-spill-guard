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

// symbolBudget caps how many runes one character class is walked a rune at a
// time. A class wider than this widens to every byte instead, which keeps
// `[^a]` -- a range of a million runes -- off the load path, and errs in the
// direction that leaves a dead rule loaded rather than refusing a live one.
//
// The load path is what this is sized against: the nine entropy rules in the
// shipped set cost 37.7us for the lot, and the worst pattern measured is
// `\p{L}`, whose six hundred ranges take 28.1us on their own.
const symbolBudget = 4096

// entropyCeiling is the highest validate.Shannon result a candidate of n bytes
// can carry. The ceiling is log2 of the number of distinct bytes, which is at
// most n, so a one-byte candidate carries 0 bits and an eight-byte one carries
// 3 however random it is.
//
// Length is only one of the two bounds on that count. The other is the alphabet
// the group draws on, which captureSymbols reports, and the caller passes
// whichever is smaller.
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
// back too small refuses a rule that works. Missing a dead rule leaves this
// check half-done; refusing a live one takes the scanner down. `(?:ab){1,3}` is
// counted at 6 bytes though it draws on two, so this reports 2.585 bits where
// the group reaches 1 -- captureSymbols is the second bound that closes it, and
// the caller takes whichever of the two is smaller.
//
// Bytes rather than runes, because Shannon counts bytes. A case-folded literal
// is the case that makes those differ: `(?i)k` matches the three-byte Kelvin
// sign, so folding is walked rather than assumed to be length-preserving. A
// character class needs no such walk -- syntax.Parse expands the fold into the
// class, and the widest rune in a range covers it.
func maxCaptureBytes(pattern string, group int) (int, error) {
	sub, err := captureExpr(pattern, group)
	if err != nil {
		return 0, err
	}
	return maxBytes(sub, byteValues), nil
}

// captureSymbols is how many distinct byte values group can draw on out of
// pattern, clamped at byteValues.
//
// The second bound on the entropy ceiling, and the one a length cannot see.
// validate.Shannon counts distinct bytes, and a capture holds at most as many
// as its alphabet offers however long it runs -- so `[a-f0-9]{32}` reaches
// log2(16) = 4 bits where its length alone allows log2(32) = 5, and a floor
// between the two is a rule that can never fire.
//
// It over-estimates in the same direction and for the same reason as maxBytes:
// an arm the walk cannot settle widens to every byte, because a count that came
// back too small refuses a rule that works. The union is what is left over --
// it knows which symbols the group can emit, not which of them co-occur in one
// match, so `(a{6}|b{6})` unions to two symbols and caps at 1 bit where every
// string it matches is one repeated symbol at Shannon 0.
func captureSymbols(pattern string, group int) (int, error) {
	sub, err := captureExpr(pattern, group)
	if err != nil {
		return 0, err
	}
	s := byteSet{left: symbolBudget}
	s.walk(sub)
	return s.n, nil
}

// captureExpr parses pattern and returns the subexpression holding group, or
// the whole regex when group is 0.
func captureExpr(pattern string, group int) (*syntax.Regexp, error) {
	// Perl is the flag set regexp.Compile parses with, so this succeeds for
	// every pattern that got past it. Failing here is an internal
	// inconsistency, which fails closed like any other.
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("regex compiled but does not parse: %q", err)
	}
	if group == 0 {
		return re, nil
	}
	sub := capture(re, group)
	if sub == nil {
		return nil, fmt.Errorf("group %d is not in the parsed regex", group)
	}
	return sub, nil
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
//
// limit is where the answer stops saying anything, and the two callers stop at
// different places. The entropy check clamps at byteValues, past which a length
// cannot raise the ceiling; the anchored path clamps at anchorReach, and reads
// the clamp as "unbounded, or bounded past anywhere worth anchoring" -- so the
// value it passes has to be one no bounded pattern it would accept can reach.
func maxBytes(re *syntax.Regexp, limit int) int {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		n := 0
		for _, r := range re.Rune {
			if n = clamp(n+runeBytes(r, fold), limit); n == limit {
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
		return maxBytes(re.Sub[0], limit)
	case syntax.OpQuest:
		return maxBytes(re.Sub[0], limit)
	case syntax.OpStar, syntax.OpPlus:
		return limit
	case syntax.OpRepeat:
		if re.Max < 0 {
			return limit
		}
		return clamp(re.Max*maxBytes(re.Sub[0], limit), limit)
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			if n = clamp(n+maxBytes(s, limit), limit); n == limit {
				break
			}
		}
		return n
	case syntax.OpAlternate:
		n := 0
		for _, s := range re.Sub {
			if b := maxBytes(s, limit); b > n {
				n = b
			}
		}
		return n
	}
	return limit
}

// byteSet is the set of byte values a subexpression can emit, with left as what
// remains of symbolBudget.
type byteSet struct {
	in   [byteValues]bool
	n    int
	left int
}

// walk unions in every byte value re can emit. An operator this does not name
// widens to all of them, so a future RE2 operator over-estimates the alphabet
// rather than silently reporting a rule dead.
func (s *byteSet) walk(re *syntax.Regexp) {
	if s.n == byteValues {
		return
	}
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		// Zero-width, so nothing to emit.
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		for _, r := range re.Rune {
			s.addRune(r, fold)
		}
	case syntax.OpCharClass:
		// Rune holds inclusive pairs.
		for i := 1; i < len(re.Rune); i += 2 {
			s.addRange(re.Rune[i-1], re.Rune[i])
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		s.all()
	case syntax.OpCapture, syntax.OpQuest, syntax.OpStar, syntax.OpPlus,
		syntax.OpRepeat, syntax.OpConcat, syntax.OpAlternate:
		// Repetition and choice change how much of an alphabet a match draws
		// on, never which symbols are in it, so all seven union their subtrees
		// and none of them needs an arm of its own. This is where the walk and
		// maxBytes part company: an unbounded repeat is 256 bytes long and
		// still `(x*)`, whose alphabet is one symbol.
		for _, sub := range re.Sub {
			s.walk(sub)
		}
	default:
		s.all()
	}
}

func (s *byteSet) add(b byte) {
	if !s.in[b] {
		s.in[b] = true
		s.n++
	}
}

// addRune adds the bytes r encodes to, and those of every case it folds to when
// the enclosing literal folds. Only a literal needs that walk -- syntax.Parse
// expands a class's folds into its ranges -- which is the split runeBytes makes
// for the same reason.
func (s *byteSet) addRune(r rune, fold bool) {
	s.encode(r)
	if !fold {
		return
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		s.encode(f)
	}
}

func (s *byteSet) encode(r rune) {
	// An invalid rune encodes as U+FFFD, which is what runeBytes counts too.
	var buf [utf8.UTFMax]byte
	for _, b := range buf[:utf8.EncodeRune(buf[:], r)] {
		s.add(b)
	}
}

// addRange takes one inclusive rune pair out of a character class. \p{L} is
// some six hundred of these, so a saturated set stops rather than walking the
// rest of them to learn nothing.
func (s *byteSet) addRange(lo, hi rune) {
	if s.n == byteValues {
		return
	}
	if int(hi)-int(lo) >= s.left {
		s.all()
		return
	}
	s.left -= int(hi) - int(lo) + 1
	for r := lo; r <= hi; r++ {
		s.encode(r)
	}
}

// all widens to every byte and spends the budget, so a class whose later ranges
// could add nothing is not walked at all.
func (s *byteSet) all() {
	for i := 0; i < byteValues; i++ {
		s.add(byte(i))
	}
	s.left = 0
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

func clamp(n, limit int) int {
	if n > limit {
		return limit
	}
	return n
}
