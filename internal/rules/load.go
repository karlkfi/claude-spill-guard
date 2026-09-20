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

	// Read past presence into whether the list can gate. `[""]` clears a length
	// test and names nothing, so the prefilter's hasKeyword is false for every
	// buffer -- and the two things a consumer can do about that are opposites.
	// Treat the list as a gate and the rule is skipped on every file; read past
	// the length, as internal/scan's gates() does, and it costs the full pass
	// keywords exist to avoid. Neither is what the author wrote, and neither is
	// reachable from the rule file, so the loader settles it rather than
	// leaving each consumer to pick.
	keywords := deref(e.Keywords)
	if family == Credential && !namesALiteral(keywords) {
		return fail("family %q with no keyword naming a literal, which is an ungated "+
			"full-corpus regex pass -- an empty string is not a literal", Credential)
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
	// and every one of these only ever makes a rule stricter or cheaper -- so
	// the rule loads, runs, and reports more than its author meant it to. That
	// is the direction the naming split exists to catch.
	//
	// The third names no validator, because `keywords` is not read by one. The
	// prefilter reads it, and the prefilter gates the credential family and
	// nothing else, so a pii rule's keywords reach no stage at all. An author
	// who writes them has said "gate this on a literal" and been handed the
	// ungated full-corpus pass the prefilter exists to avoid -- the shape that
	// produced 5,679 matches and no credentials on the inherited ruleset --
	// with nothing in the output telling the two apart.
	//
	// It reads namesALiteral rather than a length, which is the same question
	// the credential clause above asks of the same field. A list holding
	// nothing but empty strings names no keyword, so there is no "gate this on
	// a literal" for the author to have meant, and refusing it here would
	// report a family problem where the field is simply spelled at its neutral
	// value -- which `"keywords": []` already is, and already loads.
	if len(rule.Labels) > 0 && !rule.Uses(ContextLabel) {
		return fail("carries labels but does not name %q, so nothing reads them", ContextLabel)
	}
	if rule.Entropy > 0 && !rule.Uses(Entropy) {
		return fail("carries an entropy floor but does not name %q, so nothing reads it", Entropy)
	}
	if namesALiteral(rule.Keywords) && rule.Family != Credential {
		return fail("family %q carries keywords, but the prefilter gates %q and "+
			"nothing else, so nothing reads them", rule.Family, Credential)
	}

	// The other direction, and the worse one: a check named with configuration
	// that can never let it pass. The rule loads, compiles, runs on every file
	// and reports nothing, which is the reading a clean scan already has -- so
	// nothing downstream can tell it from a rule that checked and found
	// nothing. Neither of them is a regex that fails to compile, so the Compile
	// call above cannot catch either.
	if rule.Uses(ContextLabel) && !namesALiteral(rule.Labels) {
		return fail("names %q with no label to look for, so it reports nothing", ContextLabel)
	}
	// A third direction, between the two: a check named with a value it can
	// read and do nothing with. EntropyAtLeast is `Shannon(s) >= min` and
	// Shannon is never negative, so a floor of zero admits every candidate --
	// the empty string, a run of one byte, a NUL. The rule loads, runs, and
	// gates on nothing, which is exactly what leaving the check off would have
	// given its author. A negative floor is refused above, so zero is the whole
	// of what is left here.
	//
	// `"entropy": 0.0` with the check *not* named is deliberately still
	// accepted, and not because the loader cannot tell it from an absent field
	// -- it can, which is why every field here is a pointer. It is accepted
	// because `"labels": []` with no `context-label` is accepted, and both are
	// one thing: a field spelled at its neutral value with nothing reading it.
	// Refusing one would owe the other the same answer, which is a wider
	// change than the rule this clause came from, and no rule is harmed by
	// either.
	if rule.Uses(Entropy) && rule.Entropy == 0 {
		return fail("names %q with no floor, and every candidate clears a floor of "+
			"zero, so it gates nothing", Entropy)
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

// namesALiteral reports whether a word-boundary literal list holds anything a
// reader would search for. An empty string is not one, and both readers agree:
// validate.NearLabel skips an empty label -- pinned in all three spellings by
// TestNearLabelWithNoUsableLabelsReportsNothing -- and scan's hasKeyword skips
// an empty keyword. So a rule carrying only empty strings is exactly as quiet
// as one carrying none, in either field.
//
// One function for both because it is one question. Where they differ is the
// consequence: labels that name nothing silence the rule, keywords that name
// nothing leave it ungated, and the loader refuses both rather than leaving
// each consumer to pick.
func namesALiteral(literals []string) bool {
	for _, l := range literals {
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
