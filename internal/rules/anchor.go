package rules

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// anchorReach is the longest match an anchored rule may produce, and the value
// maxBytes saturates at when it is asked about one.
//
// It is a ceiling rather than a budget: a pattern that reaches it has either an
// unbounded repeat or a bound nobody would write, and both come back as the
// same number, which is what the caller refuses on. The longest bounded pattern
// in the shipped set is openai-api-key at 171 bytes, so nothing here is near
// it, and a rule that did reach it would be refused the anchored path rather
// than mismatched.
const anchorReach = 4096

// anchor returns pattern compiled with \A in front and the longest match it can
// produce, or nil where scan may not run the rule once per prefilter hit
// instead of scanning the whole buffer for it.
//
// The two paths have to agree exactly, and every condition below is a way they
// would not. None of them is about speed; scan decides that separately, from
// the reach this returns.
//
//   - Every keyword opens on a word byte, and the pattern opens on \b. Together
//     these make the prefilter's boundary and the pattern's the same predicate:
//     a hit is reported only where the byte in front is not a word byte, which
//     is exactly when \b holds at the head of a word-byte literal. A keyword
//     opening on punctuation carries no boundary for the prefilter to check
//     (prefilter.go says why), while \b in front of it demands a word byte
//     behind -- so the prefilter would report positions the pattern refuses and,
//     worse, the anchored pattern would refuse positions the whole-buffer pass
//     matches. scan checks the keyword half, beside the boundary it is about.
//
//   - Nothing in the pattern asks where the text begins. An attempt runs against
//     text[hit:], where \A and ^ mean the head of the slice rather than the head
//     of the buffer, so a pattern carrying either matches at every hit what the
//     whole-buffer pass matches at one. Nothing that asks where the text *ends*
//     needs refusing, because the slice ends where the buffer does.
//
//   - Every string the pattern can match begins with one of the keywords. This
//     is the property that makes the hits a complete list of the places a match
//     can start; without it the anchored path silently reports fewer findings
//     than the pass it replaces, which is this project's failure shape rather
//     than a slow scan.
//
//   - The longest match is bounded. One attempt costs whatever the engine reads
//     before its threads die, and an unbounded repeat over a class that covers
//     the text reads to the end of the buffer -- once per hit. jwt is the
//     shipped rule this refuses.
func anchor(pattern string, keywords []string) (*regexp.Regexp, int) {
	if len(keywords) == 0 {
		return nil, 0
	}
	parsed, err := captureExpr(pattern, 0)
	if err != nil {
		return nil, 0
	}
	if !opensOnWordBoundary(parsed) || asksWhereTextBegins(parsed) {
		return nil, 0
	}
	if !opensWith(parsed, "", keywords) {
		return nil, 0
	}
	reach := maxBytes(parsed, anchorReach)
	if reach >= anchorReach {
		return nil, 0
	}
	// \A rather than a rewrite of the pattern: the same program with a start
	// anchor in front, so an attempt at a hit finds what the whole-buffer pass
	// finds there and nothing else. The group is non-capturing, so every
	// group number a rule refers to is the one it had.
	re, err := regexp.Compile(`\A(?:` + pattern + `)`)
	if err != nil {
		return nil, 0
	}
	return re, reach
}

// opensOnWordBoundary reports whether the first thing the pattern does is
// demand \b.
func opensOnWordBoundary(re *syntax.Regexp) bool {
	return re.Op == syntax.OpConcat && len(re.Sub) > 0 &&
		re.Sub[0].Op == syntax.OpWordBoundary
}

// asksWhereTextBegins reports whether re carries \A or ^ anywhere in it.
func asksWhereTextBegins(re *syntax.Regexp) bool {
	if re.Op == syntax.OpBeginText || re.Op == syntax.OpBeginLine {
		return true
	}
	for _, sub := range re.Sub {
		if asksWhereTextBegins(sub) {
			return true
		}
	}
	return false
}

// headBudget caps the walk below: how many distinct prefixes it will carry at
// once, and how far it will grow one before giving up on it.
//
// A character class is expanded a rune at a time, so the prefix set is a
// product and a wide class multiplies it -- `[A-Za-z0-9]` is 62 branches and
// `[^\n]` is a million. The cap is what keeps that off the load path, and
// spending it costs a rule the anchored path rather than a finding. The widest
// class any shipped rule opens on is slack-token's `[abeprs]`, at six.
const (
	headBudget   = 64
	headMaxBytes = 64
)

// opensWith reports whether every string re can match begins with one of
// keywords, given the literal text acc already accumulated in front of it.
//
// It answers no wherever it cannot answer yes, which costs a rule the anchored
// path and never costs a finding.
//
// The comparison is exact. The prefilter folds case and this does not, so a
// rule whose keywords are written in a different case from its own pattern
// gives up the anchored path -- which is the safe direction, and the only one
// that does not put a second spelling of the fold in a second package.
func opensWith(re *syntax.Regexp, acc string, keywords []string) bool {
	live, ok := grow(re, []string{acc}, keywords)
	return ok && len(live) == 0
}

// grow extends every prefix in live by whatever re puts next, dropping each one
// as soon as a keyword covers it. An empty result means every string re can
// match is covered; ok is false where a branch reached something this cannot
// enumerate with an uncovered prefix still in hand.
//
// A set rather than one accumulated string, because the head of a pattern is
// routinely a choice: `gh[oprsu]_` is five prefixes and `(?:sk|rk)_live_` is
// two, and in both the text that covers them comes from the concatenation
// *after* the choice. Asking a branch alone whether it is covered cannot see
// that, and the shipped ruleset has four rules of the shape.
//
// What it gives up on is repetition at the head -- `(?:RSA )?PRIVATE` and
// anything under a star -- a class wider than headBudget, a folded literal, and
// any operator not named below. Each of those falls to the last return, which
// is the answer that costs a rule the anchored path.
func grow(re *syntax.Regexp, live []string, keywords []string) ([]string, bool) {
	if len(live) == 0 {
		return live, true
	}
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			// A folded literal matches runes the prefilter cannot find. `(?i)k`
			// matches the Kelvin sign at U+212A, three bytes that are not `k`
			// or `K`, and the prefilter folds ASCII only -- so a match could
			// begin somewhere it reported no hit. The whole-buffer pass has the
			// same blind spot in its gate, which is why this is a refusal here
			// rather than a fix; no shipped rule folds.
			return live, false
		}
		return extend(live, []string{string(re.Rune)}, keywords)
	case syntax.OpCharClass:
		next, ok := classRunes(re)
		if !ok {
			return live, false
		}
		return extend(live, next, keywords)
	case syntax.OpCapture:
		return grow(re.Sub[0], live, keywords)
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			var ok bool
			if live, ok = grow(sub, live, keywords); !ok {
				return live, false
			}
			if len(live) == 0 {
				return live, true
			}
		}
		return live, false
	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return live, false
		}
		var out []string
		for _, sub := range re.Sub {
			got, ok := grow(sub, live, keywords)
			if !ok {
				return live, false
			}
			out = append(out, got...)
		}
		return dedupe(out)
	}
	if zeroWidth(re.Op) {
		return live, true
	}
	return live, false
}

// extend crosses live with next, keeping only what no keyword covers.
func extend(live, next []string, keywords []string) ([]string, bool) {
	var out []string
	for _, head := range live {
		for _, add := range next {
			grown := head + add
			if covered(grown, keywords) {
				continue
			}
			if len(grown) > headMaxBytes || len(out) >= headBudget {
				return live, false
			}
			out = append(out, grown)
		}
	}
	return dedupe(out)
}

// classRunes is every rune a character class matches, as strings, or false
// where there are more of them than the budget allows.
func classRunes(re *syntax.Regexp) ([]string, bool) {
	var out []string
	// Rune holds inclusive pairs.
	for i := 1; i < len(re.Rune); i += 2 {
		for r := re.Rune[i-1]; r <= re.Rune[i]; r++ {
			if len(out) >= headBudget {
				return nil, false
			}
			out = append(out, string(r))
		}
	}
	return out, len(out) > 0
}

// dedupe keeps the prefix set from growing on repetition alone. Two branches of
// an alternation reaching the same text is ordinary once a class has been
// expanded, and the budget above is spent per distinct prefix.
func dedupe(in []string) ([]string, bool) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) > headBudget {
		return in, false
	}
	return out, true
}

// zeroWidth reports whether an operator matches without consuming text. \A and
// ^ are left out deliberately: anchor refuses a pattern carrying either, and
// naming them here would read as having handled them.
func zeroWidth(op syntax.Op) bool {
	switch op {
	case syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary,
		syntax.OpEndLine, syntax.OpEndText:
		return true
	}
	return false
}

// covered reports whether head begins with one of keywords. An empty keyword
// names no literal and would cover everything, which is the reading that turns
// a gate into a pass -- scan.gates() refuses such a list for the same reason.
func covered(head string, keywords []string) bool {
	for _, k := range keywords {
		if k != "" && strings.HasPrefix(head, k) {
			return true
		}
	}
	return false
}
