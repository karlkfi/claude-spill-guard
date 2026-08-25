package scan

// hasKeyword reports whether any of keywords appears in buf with a word
// boundary in front of it. It is the gate in front of the regex pass, and it
// is worth roughly 280x: 255-307 MiB/s against 1.0 MiB/s, measured in
// docs/design/language-choice.md section 2.
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

func containsKeyword(buf []byte, keyword string) bool {
	needle := []byte(keyword)
	for i, c := range needle {
		needle[i] = lowerASCII(c)
	}
	// A keyword opening on punctuation carries its own boundary, so there is
	// nothing in front of it to require.
	bounded := isWordByte(needle[0])
	for i := 0; i+len(needle) <= len(buf); i++ {
		if bounded && i > 0 && isWordByte(buf[i-1]) {
			continue
		}
		if matchesLower(buf[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
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
