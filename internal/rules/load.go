package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// entry is a rule as it appears in the file. Every field but the id is a
// pointer so that compile can tell a field the file left out from one it set
// to the zero value: a rule that does not say whether it is enabled is refused
// rather than defaulted, and the same goes for a missing family or regex. The
// pointers used to serve a second purpose, letting a project override mention
// only the fields it changed. That override is retired -- there is one ruleset
// and it is the one compiled in -- and the nil check is the shipped set's own
// strictness, so the shape stays.
type entry struct {
	ID          string    `json:"id"`
	Family      *string   `json:"family"`
	Description *string   `json:"description"`
	Regex       *string   `json:"regex"`
	Group       *int      `json:"group"`
	Keywords    *[]string `json:"keywords"`
	Labels      *[]string `json:"labels"`
	Entropy     *float64  `json:"entropy"`
	Validators  *[]string `json:"validators"`
	Extent      *string   `json:"extent"`
	Enabled     *bool     `json:"enabled"`
}

// ruleset is the top level of the ruleset file: an object rather than a bare
// array, so a top-level key added later does not change the format.
type ruleset struct {
	Rules []entry `json:"rules"`
}

// shippedSet names the one ruleset in every error, so a rule author is told
// which file to go and edit. There used to be two roles here; the project
// ruleset is retired, and with it the merge that layered one over the other.
const shippedSet = "the shipped ruleset"

// Load decodes the shipped ruleset and compiles it. It takes bytes rather than
// a path because the caller that ships holds the set compiled into the binary,
// and a second source would be the override this package no longer has.
func Load(shipped []byte) ([]Rule, error) {
	base, err := decode(shippedSet, shipped)
	if err != nil {
		return nil, err
	}
	if len(base) == 0 {
		// Every check below passes over an empty ruleset, so this is what stops
		// a scanner reading clean because it found nothing to scan with.
		return nil, fmt.Errorf("%s: no rules", shippedSet)
	}

	rules := make([]Rule, 0, len(base))
	var problems []error
	for _, e := range base {
		rule, err := compile(e)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		rules = append(rules, rule)
	}
	if len(problems) > 0 {
		// Every problem at once. A rule author fixing them one run at a time is
		// a rule author who stops running the loader.
		return nil, errors.Join(problems...)
	}
	return rules, nil
}

// decode reads one ruleset file, rejecting anything the schema has no room for.
//
// DisallowUnknownFields is the load-bearing call. A misspelled field would
// otherwise be dropped in silence, and every field here is one that makes a
// rule stricter -- so the rule still loads, still compiles, still runs, and
// reports either nothing or everything. `window` is the field this catches by
// design: the proximity window is not per-rule, and a rule that sets one is
// told so rather than ignored.
func decode(name string, data []byte) ([]entry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var set ruleset
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: more than one value in the file", name)
	}
	seen := make(map[string]bool, len(set.Rules))
	for i, e := range set.Rules {
		if e.ID == "" {
			return nil, fmt.Errorf("%s: rule %d has no id", name, i)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("%s: two rules share the id %q", name, e.ID)
		}
		seen[e.ID] = true
	}
	return set.Rules, nil
}

// compile turns one entry into a Rule, or says why it cannot.
func compile(e entry) (Rule, error) {
	// Every string that came out of a file goes through %q, including the ones
	// inside a wrapped error. Anything this binary emits reaches a terminal and
	// the API both, so C0, DEL and the bidi overrides get escaped before they
	// are written -- and %w would not do it: regexp's own message puts the raw
	// pattern in backticks, measured.
	fail := func(format string, args ...any) (Rule, error) {
		return Rule{}, fmt.Errorf("rule %q: "+format, append([]any{e.ID}, args...)...)
	}
	switch {
	case e.Family == nil:
		return fail("no family")
	case e.Description == nil:
		return fail("no description")
	case e.Regex == nil:
		return fail("no regex")
	case e.Enabled == nil:
		return fail("does not say whether it is enabled")
	}

	family := Family(*e.Family)
	if family != Credential && family != PII {
		return fail("family %q is neither %q nor %q", *e.Family, Credential, PII)
	}

	// RE2 is the whole constraint list in one call: no lookaround, no
	// backreferences, and bounded repetition capped at 1000, so {1,1024} is
	// rejected here rather than silently truncated. Nine of the inherited rules
	// need rewriting for it -- docs/design/language-choice.md section 4 names
	// them.
	re, err := regexp.Compile(*e.Regex)
	if err != nil {
		return fail("regex does not compile: %q", err)
	}

	group := 0
	if e.Group != nil {
		group = *e.Group
	}
	if group < 0 || group > re.NumSubexp() {
		return fail("group %d, but the regex has %d capture group(s)", group, re.NumSubexp())
	}

	entropy := derefFloat(e.Entropy)
	if entropy < 0 {
		return fail("entropy floor %v, which no candidate can fall below", entropy)
	}

	keywords := deref(e.Keywords)
	if family == Credential && len(keywords) == 0 {
		return fail("family %q with no keywords, which is an ungated full-corpus "+
			"regex pass -- say so deliberately or give it keywords", Credential)
	}

	names := deref(e.Validators)
	checks := make([]Validator, 0, len(names))
	for _, n := range names {
		v := Validator(n)
		if !validators[v] {
			return fail("names a check that does not exist: %q", n)
		}
		checks = append(checks, v)
	}

	extent := Extent(derefString(e.Extent))
	if _, known := extentSymbols[extent]; extent != "" && !known {
		return fail("names an extent that does not exist: %q", *e.Extent)
	}

	rule := Rule{
		ID:          e.ID,
		Family:      family,
		Description: *e.Description,
		Regex:       re,
		Group:       group,
		Keywords:    keywords,
		Labels:      deref(e.Labels),
		Entropy:     entropy,
		Validators:  checks,
		Extent:      extent,
		Enabled:     *e.Enabled,
	}
	rule.Anchor, rule.Reach = anchor(*e.Regex, keywords)

	// Configuration with no check to read it is a setting that does nothing,
	// and both of these settings only ever make a rule stricter -- so the rule
	// loads, runs, and reports more than its author meant it to. That is the
	// direction the naming split exists to catch.
	if len(rule.Labels) > 0 && !rule.Uses(ContextLabel) {
		return fail("carries labels but does not name %q, so nothing reads them", ContextLabel)
	}
	if rule.Entropy > 0 && !rule.Uses(Entropy) {
		return fail("carries an entropy floor but does not name %q, so nothing reads it", Entropy)
	}

	// The other direction, and the worse one: a check named with configuration
	// that can never let it pass. The rule loads, compiles, runs on every file
	// and reports nothing, which is the reading a clean scan already has -- so
	// nothing downstream can tell it from a rule that checked and found
	// nothing. Neither of them is a regex that fails to compile, so the Compile
	// call above cannot catch either.
	if rule.Uses(ContextLabel) && !hasLabel(rule.Labels) {
		return fail("names %q with no label to look for, so it reports nothing", ContextLabel)
	}
	if rule.Uses(Entropy) {
		if extent != "" {
			// An extent widens the capture before any check reads it, and it
			// walks to the end of a class rather than to a bound -- so the
			// pattern's capture length is a floor on what entropy will be
			// measured over, not a ceiling, and reading it as one refuses a
			// rule that works. That is the direction maxCaptureBytes exists to
			// avoid. The alphabet is what still binds, and the extent declares
			// it.
			symbols := extentSymbols[extent]
			if ceiling := entropyCeiling(symbols); rule.Entropy > ceiling {
				return fail("entropy floor %v over a candidate the %q extent draws from "+
					"%d distinct byte value(s), which cannot carry more than %.4g bits, "+
					"so it reports nothing",
					rule.Entropy, extent, symbols, ceiling)
			}
		} else {
			reach, err := maxCaptureBytes(*e.Regex, group)
			if err != nil {
				return fail("%s", err)
			}
			symbols, err := captureSymbols(*e.Regex, group)
			if err != nil {
				return fail("%s", err)
			}
			// Length and alphabet each bound the distinct byte count, so the
			// smaller is the one that binds: a 32-byte hex capture reaches
			// log2(16) and not log2(32). The message names both, because which
			// of the two refused the rule is what its author has to change.
			if ceiling := entropyCeiling(min(reach, symbols)); rule.Entropy > ceiling {
				return fail("entropy floor %v over a group of at most %d byte(s) drawn from "+
					"%d distinct byte value(s), which cannot carry more than %.4g bits, "+
					"so it reports nothing",
					rule.Entropy, reach, symbols, ceiling)
			}
		}
	}
	return rule, nil
}

// hasLabel reports whether labels holds one NearLabel would search for. An
// empty string is not one: it matches nothing there, so a rule carrying only
// empty labels is as quiet as a rule carrying none, and
// validate.TestNearLabelWithNoUsableLabelsReportsNothing pins all three
// spellings of that.
func hasLabel(labels []string) bool {
	for _, l := range labels {
		if l != "" {
			return true
		}
	}
	return false
}

func deref(p *[]string) []string {
	if p == nil {
		return nil
	}
	return *p
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefFloat(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}
