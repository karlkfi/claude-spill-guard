package scan

import (
	"bytes"
	"slices"
)

// hasKeyword reports whether any of keywords appears in buf with a word
// boundary in front of it. It is the gate in front of the regex pass: a buffer
// carrying none of a rule's literals never reaches that rule's pattern.
//
// The 255-307 MiB/s against 1.0 MiB/s in docs/design/language-choice.md
// section 2 -- roughly 280x -- is not a figure about this code. It was taken on
// a `strings.Contains` prefilter, which is the implementation that same
// subsection goes on to say has to be replaced. What this one costs is
// measured in the comment on containsKeyword, and it is not 1/280th.
//
// Three decisions, none of them free.
//
// A word boundary, not a substring search. Naive matching finds `sk-`
// inside `disk-containerd-...`, and on the 259-file corpus one broad keyword
// (`AC`) took the file hit rate from 1.2% to 18.9% by matching ordinary prose.
// The prefilter is exquisitely sensitive to keyword quality and one bad entry
// destroys it.
//
// The boundary goes in front of the keyword only. A keyword is the literal
// head of a pattern, not a whole word in it: the AWS rule keys on `AKIA` and
// the value continues `[A-Z0-9]{16}` straight after it. Requiring a boundary
// at the far end as well would reject every real key. That is where this
// parts company with internal/validate's containsLabel, which needs both
// because a label is a whole word beside a value rather than the head of one.
//
// Matching folds case even where the regex will not. The prefilter decides
// what the regex never sees, so a mismatch in its favour costs a pass over a
// buffer and a mismatch against it silently drops a finding. Folding case is
// the direction where the gate can only be too generous.
//
// It can still be too strict, and a rule author has to know where: a rule
// whose regex does not anchor its literal on \b -- `sk-[A-Za-z0-9]{32}` with
// no boundary in front -- matches text this gate refuses to hand it. Such a
// rule ships with `keywords` empty and pays for the full pass.
func hasKeyword(buf []byte, keywords []string) bool {
	for _, keyword := range keywords {
		if keyword != "" && containsKeyword(buf, keyword) {
			return true
		}
	}
	return false
}

// containsKeyword is a case-insensitive search for keyword in buf with a word
// boundary in front of the match. It stops at the first hit, which is the whole
// difference between it and keywordPositions.
func containsKeyword(buf []byte, keyword string) bool {
	hit := false
	keywordAt(buf, keyword, func(int) bool {
		hit = true
		return false
	})
	return hit
}

// keywordAt calls found at every position where keyword sits in buf with a word
// boundary in front of it, and stops where found returns false. Positions come
// out grouped by case-head rather than in order, which is why the caller that
// wants them all sorts.
//
// The two questions this file answers -- is the keyword here at all, and where
// -- are the same walk with different stopping rules, and the walk is the part
// that is easy to get subtly wrong in both directions. One implementation, so a
// fix to the boundary or the fold reaches both.
//
// It finds candidate positions with bytes.Index over a single byte, which
// dispatches to the runtime's assembly IndexByte, rather than walking the
// buffer a byte at a time in Go. The stage only earns its place by being much
// cheaper than the regex pass it skips, and the walk was not: measured
// 2026-08-24 over 67 of this repo's own text files, 0.32 MiB, min-of-7 in one
// process, the walk cost 0.398x an equivalent regex pass against this at
// 0.139x.
//
// How much that wins depends on the keywords as much as on the corpus, which
// is the part to carry away. The walk is O(buffer) and content-independent;
// this is O(occurrences of the anchor byte). So a keyword opening on a rare
// letter flatters it -- across thirteen keywords of one length on one corpus,
// 46.6x for a Z-led keyword against 3.1x for an E-led one, with the walk flat
// at 1.49-1.56 ms throughout. Realistic credential prefixes land at 6-12x. Q53
// takes the benchmark properly, over the shipped keyword list, because a
// synthetic one picks its own answer.
//
// The two arms were held to identical results before either was timed, over
// every file in that corpus and over a 360,000-case differential on random
// buffers drawn from a deliberately small alphabet, where near-misses and
// boundary characters are common. A deliberately wrong variant was run through
// the same harness and caught, so the clean result means something.
//
// Two passes over the buffer, because the match may be mixed-case and so its
// first byte can be either -- searching the whole needle in one case would miss
// `Akia`. A keyword whose first byte has no case gets one pass.
func keywordAt(buf []byte, keyword string, found func(int) bool) {
	if keyword == "" {
		return
	}
	lower := []byte(keyword)
	upper := make([]byte, len(lower))
	for i, c := range lower {
		lower[i] = lowerASCII(c)
		upper[i] = upperASCII(lower[i])
	}
	// A keyword opening on punctuation carries its own boundary, so there is
	// nothing in front of it to require.
	bounded := isWordByte(lower[0])
	heads := [][]byte{lower[:1]}
	if upper[0] != lower[0] {
		heads = append(heads, upper[:1])
	}
	for _, head := range heads {
		for at := 0; at+len(lower) <= len(buf); {
			j := bytes.Index(buf[at:], head)
			if j < 0 {
				break
			}
			i := at + j
			at = i + 1
			if i+len(lower) > len(buf) {
				break
			}
			if bounded && i > 0 && isWordByte(buf[i-1]) {
				continue
			}
			if matchesLower(buf[i:i+len(lower)], lower) && !found(i) {
				return
			}
		}
	}
}

// keywordPositions is every place in buf a rule's match can start, in order and
// without repeats: the hits hasKeyword answers yes on, kept rather than thrown
// away. ok is false where there are more than limit of them, which is the one
// arm that is a cost decision rather than an answer -- scan.go's budget() sizes
// limit so that arm is the one where the whole-buffer pass is cheaper anyway.
//
// It is only a complete list of match starts for a rule internal/rules gave an
// Anchor to, and only where boundedKeywords holds. Both are the caller's to
// check, and anchor.go says what each one is for.
func keywordPositions(buf []byte, keywords []string, limit int) ([]int, bool) {
	var at []int
	over := false
	for _, keyword := range keywords {
		keywordAt(buf, keyword, func(i int) bool {
			if len(at) >= limit {
				over = true
				return false
			}
			at = append(at, i)
			return true
		})
		if over {
			return nil, false
		}
	}
	slices.Sort(at)
	return slices.Compact(at), true
}

// boundedKeywords reports whether every keyword carries the boundary the
// prefilter checks, which is what makes a hit and the pattern's own leading \b
// the same predicate. A keyword opening on punctuation does not: nothing in
// front of it is required here, while \b in front of it demands a word byte
// behind, so the two disagree in both directions.
//
// It lives beside isWordByte rather than in the loader for that reason -- the
// condition is about this file's boundary, and anchor.go carries the rest.
func boundedKeywords(keywords []string) bool {
	for _, keyword := range keywords {
		if keyword == "" || !isWordByte(keyword[0]) {
			return false
		}
	}
	return len(keywords) > 0
}

func matchesLower(hay, lowered []byte) bool {
	for i, c := range lowered {
		if lowerASCII(hay[i]) != c {
			return false
		}
	}
	return true
}

// isWordByte is what RE2 counts as a word character -- ASCII letters, digits
// and underscore -- because this boundary has to agree with the \b in a rule's
// own regex. internal/validate's isWordByte leaves underscore out for a reason
// its comment gives; read that before reconciling the two.
func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func upperASCII(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}
