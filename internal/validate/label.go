package validate

// DefaultLabelWindow is how many bytes before a candidate NearLabel searches
// when a rule does not set its own.
//
// Measured 2026-08-21 over 914 text files, 8.93 MiB, of real source, config and
// documentation: the seven Claude Code guard plugins checked out under
// ~/.claude/plugins/cache, 45% Markdown and 50% Python by volume, with shell,
// JSON, YAML and SVG making up the rest. Binaries were skipped on a NUL in the
// first 8 KiB, as the scanner will. Words were tokenised exactly as isWordByte
// splits them, so the figures describe this code rather than a near relative of
// it. 37,822 numeric runs not glued to a word; for each, the distance in bytes
// from the end of a preceding word to the start of the run:
//
//	                                            p50  p95  p99
//	label adjacent      ssn: 1                    2    9   18
//	one word between    ssn no: 1                 9   23   34
//	two words between   patient_ssn_no: 1        17   34   50
//
// 64 bytes covers a label two words ahead of its value at the 99th percentile
// with room to spare. That is the reach a multi-word label needs:
// patient_phone_number: puts one word between phone and the value, and
// "Social Security Number:" puts two between social and it. Nothing is bought by stopping earlier: on this
// corpus, which holds no real PII, the share of numeric runs with one of
// nineteen PII label words anywhere in the window runs 0.04% at 8 bytes, 0.27%
// at 40, 0.31% at 64, 0.59% at 128 and 0.85% at 256. There is no knee to sit
// in -- reachable words grow linearly at roughly one per 8 bytes -- so the
// number is a recall target, and 64 is where recall saturates while the cost
// is still flat.
//
// What that corpus is not: no Kubernetes manifests, no Ansible, no logs, no
// .env files, no non-English text. Those are exactly the material the inherited
// ruleset drowned in, and not one of the design's worked examples -- 65536, the
// NodePort 30443, the amdgpu string 1:6.16.13.30300400-2341068 -- comes from a
// corpus shaped like this one. Re-take this against testdata/corpus once that
// exists. It is a number measured on real files, not one measured on the right
// files.
const DefaultLabelWindow = 64

// NearLabel reports whether one of labels appears in the window bytes of buf
// immediately before at, which is the byte offset of the candidate.
//
// This is the gate that makes a bare numeric run reportable. Without it,
// \b\d{5}(?:-\d{4})?\b is a postal code rule that flags 65536 and every
// Kubernetes NodePort: 169 matches on the 257-file corpus of
// docs/design/language-choice.md section 3, none of them a postal code.
//
// Matching is ASCII case-insensitive and needs a word boundary at each end of
// the label, for the reason the prefilter does: a plain substring search finds
// `sk-` inside `disk-containerd`, and there one broad keyword took the file hit
// rate from 1.2% to 18.9%. A label whose own edge character is not a word
// character carries its boundary with it, so `ssn=` needs no space in front of
// the value and `ssn` does not match inside `assn`.
//
// The window may span newlines. 5.0% of the nearest-word gaps in the corpus
// measured for DefaultLabelWindow crossed at least one, which is block-style
// YAML putting the value on the line below its key, and refusing to cross would
// cost that recall for nothing.
//
// A rule that reaches here with no labels, or a window of zero, reports
// nothing at all. That is a rule the loader should have refused rather than
// something to paper over here.
func NearLabel(buf []byte, at int, labels []string, window int) bool {
	if window <= 0 || at <= 0 || at > len(buf) {
		return false
	}
	start := at - window
	if start < 0 {
		start = 0
	}
	for _, label := range labels {
		if label != "" && containsLabel(buf[start:at], label) {
			return true
		}
	}
	return false
}

// containsLabel is a case-insensitive search for label in hay, bounded by ASCII
// word characters at both ends of the match.
func containsLabel(hay []byte, label string) bool {
	for i := 0; i+len(label) <= len(hay); i++ {
		if !equalFoldASCII(hay[i:i+len(label)], label) {
			continue
		}
		if isWordByte(label[0]) && i > 0 && isWordByte(hay[i-1]) {
			continue
		}
		if end := i + len(label); isWordByte(label[len(label)-1]) &&
			end < len(hay) && isWordByte(hay[end]) {
			continue
		}
		return true
	}
	return false
}

func equalFoldASCII(a []byte, b string) bool {
	for i := range b {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// isWordByte is ASCII letters and digits, and deliberately not underscore --
// which is where this parts company with the prefilter's boundary, so do not
// reconcile the two without reading this.
//
// The prefilter matches credential literals against arbitrary text, where the
// measured failure is `sk-` inside `disk-containerd`. This matches identifier
// words against keys, where the surrounding syntax is snake_case: `phone` is
// the label in PHONE_NUMBER= and in patient_phone, and counting underscore as
// a word byte drops both. Neither direction of the prefilter's own case is
// affected, because a preceding letter still blocks a match -- `ssn` does not
// match inside `assn` either way.
//
// A byte over 0x7f is not a word byte, so an ASCII label at the edge of a
// UTF-8 sequence matches. That is deliberate: the labels a numeric PII rule
// carries are ASCII and the text around them frequently is not.
func isWordByte(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
