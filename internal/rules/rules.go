// Package rules loads the ruleset. Rules are data: the shipped set is JSON and
// a project extends it, so everything a rule says is a string somebody typed,
// and every one of those strings is checked here rather than wherever it would
// otherwise be used.
//
// Loading fails closed. A rule that does not compile, names a check that does
// not exist, or carries a field the schema has no room for stops the binary at
// startup with a reason naming the rule. Skipping it instead is the fail-open
// shape this tool exists to avoid: a scanner missing a rule reports the same
// clean result as a scanner that checked everything. It is also why gitleaks is
// safe to borrow patterns from -- it compiles with stdlib regexp and no PCRE
// fallback, so a non-RE2 pattern panics at its startup rather than shipping.
//
// The schema is docs/design/README.md, "Rule schema".
package rules

import "regexp"

// Family is which half of the ruleset a rule belongs to. The prefilter gates
// credential rules on their keywords; pii rules have no literal to anchor on,
// which is one of the reasons they ship disabled.
type Family string

const (
	Credential Family = "credential"
	PII        Family = "pii"
)

// Validator names a check in internal/validate.
//
// A rule names every check that has to pass, including the two that take their
// configuration from a field of their own: `entropy` reads the rule's entropy
// floor and `context-label` reads its labels. Presence and configuration are
// deliberately separate. A numeric rule whose author wrote the labels and left
// the validator off is an ungated numeric regex, which is the shape that
// produced 5,679 matches and no credentials on the inherited ruleset, so
// naming the check is what turns that omission into a startup error instead of
// a silent one.
type Validator string

const (
	Luhn            Validator = "luhn"
	CardPlaceholder Validator = "card-placeholder"
	Mod11           Validator = "mod-11"
	Entropy         Validator = "entropy"
	ReservedRange   Validator = "reserved-range"
	ContextLabel    Validator = "context-label"
)

var validators = map[Validator]bool{
	Luhn:            true,
	CardPlaceholder: true,
	Mod11:           true,
	Entropy:         true,
	ReservedRange:   true,
	ContextLabel:    true,
}

// A Rule is one compiled pattern and everything the pipeline needs to decide
// whether a match is a finding. Every field is settled by the time this exists:
// the regex compiles, the group is one the regex has, the family and the
// validator names are ones this package knows.
type Rule struct {
	ID          string
	Family      Family
	Description string
	Regex       *regexp.Regexp
	Group       int
	Keywords    []string
	Labels      []string
	Entropy     float64
	Validators  []Validator
	Enabled     bool
}

// Uses reports whether the rule names v.
func (r Rule) Uses(v Validator) bool {
	for _, have := range r.Validators {
		if have == v {
			return true
		}
	}
	return false
}
