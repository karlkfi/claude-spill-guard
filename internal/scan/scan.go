// Package scan runs the pipeline over one buffer: skip binaries, gate the
// credential rules on a literal prefilter, match one rule at a time, and hand
// every candidate to the checks in internal/validate.
//
// The order is the point. Each stage exists to keep the next one off work it
// does not need to do, and the obvious way to write two of them inverts a
// measurement -- see IsBinary, hasKeyword, and the comment on the match loop
// in Buffer. docs/design/README.md, "Pipeline", is the specification.
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
	// Offset is where the captured group starts in the buffer, in bytes.
	Offset int
	// Digest is the dedup key, and it is why no field here holds the value.
	// The predecessor's Finding carried the secret beside a redacted copy; it
	// was used only as a dedup key and never printed, and the field's
	// existence was the hazard.
	Digest string
}

// Buffer runs the pipeline over buf and returns what survived, in the order
// the rules were given and by offset within each rule.
//
// An error blocks. A rule naming a check this package does not run is an
// internal error, and a scanner that shrugs at one reports a safety it is not
// providing. Disabled rules are skipped here rather than by the caller, so one
// place decides it.
func Buffer(path string, buf []byte, ruleset []rules.Rule) ([]Finding, error) {
	if IsBinary(buf) {
		return nil, nil
	}

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
			!hasKeyword(buf, rule.Keywords) {
			continue
		}

		// One rule at a time. Folding the patterns into a single alternation
		// is the obvious optimization and it runs at 0.5x in Go and 0.7x with
		// Rust's RegexSet: the DFA state space explodes and the lazy cache
		// thrashes on heterogeneous input. Two engines, same result, so it is
		// a property of the approach rather than of either implementation.
		// docs/design/language-choice.md section 2.
		for _, m := range rule.Regex.FindAllSubmatchIndex(buf, -1) {
			lo, hi := m[2*rule.Group], m[2*rule.Group+1]
			if lo < 0 {
				// The group is in the pattern but took part in no match, which
				// an alternation makes ordinary.
				continue
			}
			ok, err := passes(rule, buf, lo, hi)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			findings = append(findings, Finding{
				RuleID: rule.ID,
				Path:   path,
				Offset: lo,
				Digest: digest(rule.ID, buf[lo:hi]),
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
