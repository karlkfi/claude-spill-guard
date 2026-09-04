// Package scan runs the pipeline over one buffer: skip binaries, gate the
// credential rules on a literal prefilter, match one rule at a time, and hand
// every candidate to the checks in internal/validate.
//
// The order is the point. Each stage exists to keep the next one off work it
// does not need to do, and the obvious way to write two of them inverts a
// measurement -- see IsBinary, hasKeyword, and the comment on the match loop
// in Buffer. docs/design/README.md, "Pipeline", is the specification.
//
// Declining to read a buffer is a thing this package says rather than a thing
// it does quietly. A Result carries the reason beside the findings, because a
// scanner reporting an unread file the way it reports a file it read and found
// nothing in reports a safety it is not providing.
//
// Nothing here retains a candidate. A Finding carries a truncated digest, so
// the value is gone by the time a caller sees anything.
package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	"github.com/karlkfi/claude-spill-guard/internal/validate"
)

// A Finding is one match that survived every check its rule named.
//
// Rule ID, path, and byte offset are what the design allows to be reported --
// no fragment, not even a redacted one. Everything a hook writes to stderr
// reaches the API, so an eight-character redacted window is eight characters
// of the secret delivered to the place this tool exists to keep it away from.
//
// Path is stored as it arrived. Escaping C0, DEL and the bidi overrides is the
// job of whatever writes it, because that is where the terminal is.
type Finding struct {
	RuleID string
	Path   string
	// Offset is where the captured group starts in the file, in bytes. Where
	// the buffer was decoded the match is found at an offset in the decoded
	// bytes and mapped back here, so this always names the same place a hex
	// dump of the file would.
	Offset int
	// Digest is the dedup key, and it is why no field here holds the value.
	// The predecessor's Finding carried the secret beside a redacted copy; it
	// was used only as a dedup key and never printed, and the field's
	// existence was the hazard.
	Digest string
}

// A Skip is why a buffer's text was not read, and the empty value means it
// was.
//
// Its text rather than its bytes, because one value here is a buffer this
// package did match -- over the raw bytes, which is not the same as having read
// what is written in them.
//
// Every value is a phrase meant to reach whoever is being told the file was not
// covered, because that is the only form of this fact that is worth anything: a
// file nothing opened produces no findings, exactly like a file that was read
// and held none.
type Skip string

const (
	// Scanned is a buffer the pipeline read.
	Scanned Skip = ""
	// SkippedBinary is a NUL byte in the sniff window, read after any decoding.
	// UTF-16 written with no byte-order mark lands here, which is the gap the
	// decode stage leaves standing: nothing in the buffer declares the encoding,
	// and guessing at one is the heuristic the NUL check was chosen instead of.
	SkippedBinary Skip = "binary: a NUL byte in the first 8 KiB"
	// SkippedUTF32 is a UTF-32 byte-order mark. Decoding it is the same shape as
	// UTF-16 and no measurement says the file class is worth carrying, so this
	// build names the encoding rather than guessing at the bytes.
	SkippedUTF32 Skip = "UTF-32: declared by a byte-order mark, and not decoded"
	// SkippedUTF16Binary is a UTF-16 byte-order mark whose *decoded* sniff
	// window holds a NUL. It is still the NUL check that decided -- what this
	// separates from SkippedBinary is that the buffer declared an encoding
	// first, which SkippedBinary's own class never does.
	//
	// The distinction is internal/hook's rather than this package's, and it is
	// carried here because this is the only stage that can still see it: by the
	// time a Result is returned, the mark is gone and both cases are a NUL in
	// eight kilobytes. Two things turn on it, one of them a bug this closes.
	//
	// The verdict. A buffer this stage decoded is text it read, so it can hold
	// credential-shaped bytes whatever its decoded prefix looks like, and
	// internal/hook blocks on that where it allows the undecoded class.
	//
	// Declaration is the axis the design keys on, and decode reads two of the
	// three marks: UTF-8's is a declaration it does not read. EF BB BF is a
	// byte-order mark by the same registry as FF FE, so such a buffer falls to
	// the default arm, its NUL is read raw, and it comes back SkippedBinary and
	// is allowed. Driven end to end -- the same key after a NUL under a UTF-8
	// mark exits 0, now with a notice naming the buffer rather than on an empty
	// stdout, while the no-NUL control denies at byte 29
	// rather than 26, the three bytes of the mark scanned as ordinary content,
	// which is what having no arm looks like from outside this package.
	//
	// So the gap is named rather than defined away. Saying the axis is whichever
	// declaration this build happens to route on would make the law true by
	// construction and unfalsifiable, which is how this one got through. Whether
	// decode should grow that arm is its own row.
	//
	// And the ambiguity in FF FE 00 00, which is the half no frequency argument
	// reaches. Those bytes are the UTF-32LE mark and equally a UTF-16LE mark
	// followed by U+0000; decode resolves them the way the Unicode standard
	// does, longer mark first. So before this constant existed the same UTF-16
	// buffer got two different verdicts depending on where its NUL sat -- a
	// leading one returned SkippedUTF32, which internal/hook blocks, and one
	// character later returned SkippedBinary, which it allows. The pair is
	// TestAUTF16NULIsNamedAsDeclaredWhereverItSits here and
	// TestADeclaredUTF16BufferWithANULBlocks in internal/hook.
	SkippedUTF16Binary Skip = "UTF-16: declared by a byte-order mark, and a NUL byte in the first 8 KiB of the decoded text"
	// ScannedRaw is SkippedBinary's buffer, matched anyway over its raw bytes
	// because BufferIncludingBinary was the entry point. See there for when
	// that is the right call and when it is not.
	//
	// It is a Skip and not Scanned, which is the half worth stating: the sniff
	// is still right that nothing decoded this. A NUL in the window means
	// either genuinely binary content or text in an encoding this build does
	// not read, and a raw match over the second finds nothing whatever is
	// written in it -- so the buffer is still one no caller may report as
	// read. What the raw pass adds is the first population, where the bytes
	// are the text and a credential in them is now found.
	ScannedRaw Skip = "binary: a NUL byte in the first 8 KiB, so this was matched as raw bytes and nothing decoded it"
)

// A Result is what the pipeline made of one buffer.
//
// Skipped sits beside Findings rather than folded into an error because both
// are ordinary outcomes and only one of them means the file was covered. A
// caller reading Findings alone cannot tell the two apart, which is the failure
// this whole tool is built around.
type Result struct {
	Findings []Finding
	Skipped  Skip
}

// Buffer runs the pipeline over buf and returns what survived, in the order
// the rules were given and by offset within each rule.
//
// An error blocks. A rule naming a check this package does not run is an
// internal error, and a scanner that shrugs at one reports a safety it is not
// providing. Disabled rules are skipped here rather than by the caller, so one
// place decides it.
func Buffer(path string, buf []byte, ruleset []rules.Rule) (Result, error) {
	text, source, skip := decode(buf)
	if skip != Scanned {
		return Result{Skipped: skip}, nil
	}
	findings, err := match(path, text, source, ruleset)
	if err != nil {
		return Result{}, err
	}
	return Result{Findings: findings}, nil
}

// rawLimit is how much of a buffer BufferIncludingBinary will match raw, and
// it is what stops that entry point being worse than the skip at any size. Past the timeout the hook
// is killed and writes nothing (docs/design/README.md, the timeout section), so
// an unbounded raw pass would turn a buffer the skip reports in 44ms into one
// nobody hears about at all -- trading a notice for silence, which is the one
// direction this package will not go. Above the limit the answer is
// SkippedBinary and the notice goes out, exactly as it does without this entry
// point, so coverage is added below the limit and nothing is taken away above
// it.
//
// 32 MiB is derived from the worst measured rate and then driven, rather than
// picked. A buffer carrying every keyword the shipped ruleset gates on
// prefilters nothing away and matches at 6.8 MiB/s (measured 2026-09-03; the
// 60-second crossing is around 410 MiB), which puts the limit at 4.7s of match
// loop. Driven end to end on a built binary, a buffer of exactly this size
// carrying every keyword and the key in its last bytes takes 4.3s of wall
// clock -- a fourteenfold margin inside the timeout, which is what makes "this
// cannot be what caused a kill" a reading rather than a likelihood.
//
// A size limit rather than a deadline, and the two turned out not to be
// alternatives. Nothing in this package can be interrupted -- the match loop
// and os.ReadFile both take no context, which internal/hook's
// fifo_unix_test.go says for the file-mode question -- so a deadline written
// here could only be a check between rules, and one pass over a 306 MiB buffer
// is the granularity that would defeat it. internal/hook carries the real one
// now, and it works by outrunning the scan rather than by stopping it.
//
// That does not retire this limit, because the two answer differently above
// their thresholds. Past the deadline the verdict is a block. Past this limit
// it is the allow the skip already gives, with the notice going out in 39ms --
// which is the right answer for the 306 MiB executable that is the commonest
// binary operand in the corpus, and a block is not.
const rawLimit = 32 << 20

// BufferIncludingBinary is Buffer for a caller whose buffer reaches the model
// whatever this returns.
//
// The binary skip is a cost trade and not a judgement about what the bytes are:
// one PNG was 55% of the benchmark corpus, so the pipeline declines a buffer
// whose sniff window holds a NUL rather than spend the match loop on it. That
// trades work against coverage, and where the bytes are already on their way
// there is no work to save -- the buffer has been read off disk, the harness is
// going to send it, and declining buys a faster verdict on a call that is
// letting the credential past. So this runs the match loop over the raw bytes
// and returns the sniff's answer beside the findings rather than instead of
// them.
//
// It is per reason and not per surface. Nothing here consults the event, no
// Skip changes what it means to internal/hook's blocks(), and a buffer that
// comes back ScannedRaw is allowed exactly as SkippedBinary is. What differs
// between callers is whether the trade above has anything left to trade, which
// is a fact about the caller's own population rather than a second verdict
// axis -- docs/design/README.md, "The verdict is per reason and not per
// surface", is the decision this must not reopen and the measurements are
// under "A buffer whose bytes cross anyway".
//
// The cost it declines to save is real where the population is large: the
// Claude Code binary, the commonest binary Bash operand in that corpus, is 306
// MiB and takes 36.5s of match loop against a 60-second hook timeout. That is
// why this is a second entry point rather than the only one.
//
// Only SkippedBinary. Every other Skip is a declaration the buffer made about
// itself that this build could not act on, two of them block, and matching
// their raw bytes would find nothing in any case -- a UTF-32 buffer's
// credential is three NULs to the byte.
//
// And only up to rawLimit, which is what keeps this from being worse than the
// skip it replaces. See there.
func BufferIncludingBinary(path string, buf []byte, ruleset []rules.Rule) (Result, error) {
	text, source, skip := decode(buf)
	switch {
	case skip == Scanned:
	case skip == SkippedBinary && len(buf) <= rawLimit:
		// decode reaches SkippedBinary from its default arm alone -- the
		// UTF-16 arm has SkippedUTF16Binary for its own NUL -- so nothing was
		// decoded, buf is the text, and source is already the identity it
		// returned.
		text, skip = buf, ScannedRaw
	default:
		return Result{Skipped: skip}, nil
	}
	findings, err := match(path, text, source, ruleset)
	if err != nil {
		return Result{}, err
	}
	return Result{Findings: findings, Skipped: skip}, nil
}

// match runs every enabled rule over text and returns what survived, in the
// order the rules were given and by offset within each rule. source maps an
// offset in text back to the offset in the file a finding has to report.
func match(path string, text []byte, source func(int) int, ruleset []rules.Rule) ([]Finding, error) {
	var findings []Finding
	for _, rule := range ruleset {
		if !rule.Enabled {
			continue
		}
		// The loader settles both of these before a Rule exists. They are
		// checked again because the alternative to an error is a panic, and a
		// panic leaves the process on an exit code the hook contract does not
		// block on -- the fail-open shape this whole tool is about.
		switch {
		case rule.Regex == nil:
			return nil, fmt.Errorf("rule %q: no compiled regex", rule.ID)
		case rule.Group < 0 || rule.Group > rule.Regex.NumSubexp():
			return nil, fmt.Errorf(
				"rule %q: group %d, but the regex has %d capture group(s)",
				rule.ID, rule.Group, rule.Regex.NumSubexp())
		}

		// The prefilter gates the credential family and nothing else. A pii
		// rule is pure-numeric with no literal to anchor on, which is one of
		// the reasons that family ships disabled.
		if rule.Family == rules.Credential && gates(rule.Keywords) &&
			!hasKeyword(text, rule.Keywords) {
			continue
		}

		// One rule at a time. Folding the patterns into a single alternation
		// is the obvious optimization and it runs at 0.5x in Go and 0.7x with
		// Rust's RegexSet: the DFA state space explodes and the lazy cache
		// thrashes on heterogeneous input. Two engines, same result, so it is
		// a property of the approach rather than of either implementation.
		// docs/design/language-choice.md section 2.
		for _, m := range rule.Regex.FindAllSubmatchIndex(text, -1) {
			lo, hi := m[2*rule.Group], m[2*rule.Group+1]
			if lo < 0 {
				// The group is in the pattern but took part in no match, which
				// an alternation makes ordinary.
				continue
			}
			ok, err := passes(rule, text, lo, hi)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			findings = append(findings, Finding{
				RuleID: rule.ID,
				Path:   path,
				// The digest is over the decoded bytes, so one secret written
				// in two encodings dedups to one key -- which is what a dedup
				// key is for. The offset is the field that has to name a place
				// in the file, and source is what maps it back.
				Offset: source(lo),
				Digest: digest(rule.ID, text[lo:hi]),
			})
		}
	}
	return findings, nil
}

// gates reports whether a keyword list can gate anything, which is not the
// same question as whether it is empty.
//
// A list naming no literal -- empty, or holding nothing but empty strings --
// makes hasKeyword false for every buffer, so treating it as a gate would skip
// the rule on every file. That is the failure this project is built around: a
// rule that scanned nothing reports the same clean result as a rule that
// scanned everything, and no output distinguishes them. So an uninterpretable
// keyword list runs the regex instead, which costs a full pass and cannot
// silence anything.
//
// Refusing such a list belongs in the loader, where a startup error names the
// rule. This is the safe reading for a Rule that reaches here anyway.
func gates(keywords []string) bool {
	for _, keyword := range keywords {
		if keyword != "" {
			return true
		}
	}
	return false
}

// passes runs every check the rule names against the candidate at buf[lo:hi].
// All of them have to pass and the first failure stops the rest: a check is a
// reason to drop a candidate, and there is nothing left to learn about one.
func passes(rule rules.Rule, buf []byte, lo, hi int) (bool, error) {
	if len(rule.Validators) == 0 {
		return true, nil
	}
	// The one copy of the value this package makes, and it is made only where
	// something is going to read it. A copy nothing reads is the hazard the
	// Finding's own shape exists to avoid, in a shorter-lived place.
	candidate := string(buf[lo:hi])
	for _, check := range rule.Validators {
		var ok bool
		switch check {
		case rules.Luhn:
			ok = validate.Luhn(candidate)
		case rules.CardPlaceholder:
			ok = validate.NotPlaceholderCard(candidate)
		case rules.AWSPlaceholder:
			ok = validate.NotPlaceholderAWSKeyID(candidate)
		case rules.JWTSampleKey:
			ok = validate.NotSampleJWT(candidate)
		case rules.Mod11:
			ok = validate.Mod11(candidate)
		case rules.Entropy:
			ok = validate.EntropyAtLeast(candidate, rule.Entropy)
		case rules.ReservedRange:
			ok = validate.PublicIPv4(candidate)
		case rules.ContextLabel:
			ok = validate.NearLabel(buf, lo, rule.Labels, validate.DefaultLabelWindow)
		default:
			// The loader refuses a name it does not know, so arriving here
			// means internal/rules grew a validator and this switch did not.
			// Falling through as a pass is the fail-open direction.
			return false, fmt.Errorf(
				"rule %q names check %q, which the pipeline does not run",
				rule.ID, check)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// digest is the dedup key a Finding carries in place of the value: the first
// eight bytes of sha256(rule id, NUL, value), hex. Sixty-four bits is past
// where a session's findings collide, and it is never emitted -- the reporting
// rule allows the rule id, the path and the offset, and nothing else.
//
// The rule id goes in the hash so two rules matching the same bytes stay two
// findings. The NUL between them is what keeps that true: concatenated
// directly, ("aws-", "key") and ("aws", "-key") hash the same, and the
// consequence is two findings silently merging into one. A rule id cannot
// contain a NUL, because it comes out of a JSON string this package never
// re-encodes, so the separator is unambiguous.
func digest(ruleID string, value []byte) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write(value)
	return hex.EncodeToString(h.Sum(nil)[:8])
}
