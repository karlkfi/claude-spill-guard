package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// one wraps a single rule body in the file's top-level object, so a case can
// say only what it is testing.
func one(body string) []byte {
	return []byte(`{"rules": [` + body + `]}`)
}

// A complete credential rule, for cases that need one field changed.
const awsRule = `{
  "id": "aws-access-key-id",
  "family": "credential",
  "description": "AWS access key ID",
  "regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b",
  "group": 1,
  "keywords": ["AKIA", "ASIA", "A3T"],
  "entropy": 3.0,
  "validators": ["entropy"],
  "enabled": true
}`

func load(t *testing.T, shipped []byte) ([]Rule, error) {
	t.Helper()
	return Load(shipped, nil)
}

// quote renders a Go string as a JSON string literal, which for these patterns
// is the same escaping.
func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}

// field adds a key to the AWS rule, without removes one, and set replaces one.
// Each returns a rule body differing from a rule known to load in exactly the
// way the case is about, so a case that stops testing what it says it does
// panics rather than passing.
func field(kv string) string { return strings.Replace(awsRule, `{`, `{`+"\n  "+kv+`,`, 1) }

func without(kv string) string {
	if !strings.Contains(awsRule, "\n  "+kv) {
		panic("without() matched nothing: " + kv)
	}
	out := strings.Replace(awsRule, "\n  "+kv, "", 1)
	// Taking the last field out leaves the comma before it.
	return strings.Replace(out, ",\n}", "\n}", 1)
}

// The guard is on the input rather than on the result, because a case whose
// replacement equals what it replaces is a legitimate no-op.
func set(from, to string) string { return replace(awsRule, from, to) }

// replace is set() against a body that has already been edited once.
func replace(in, from, to string) string {
	if !strings.Contains(in, from) {
		panic("replace() matched nothing: " + from)
	}
	return strings.Replace(in, from, to, 1)
}

// labelled swaps the AWS rule onto the context-proximity check, taking the
// entropy floor off with it -- a floor left behind is a setting nothing reads,
// which the loader rejects first and for a different reason.
func labelled(validators string) string {
	return replace(without(`"entropy": 3.0,`), `"validators": ["entropy"]`, validators)
}

func TestLoadReadsEveryField(t *testing.T) {
	got, err := load(t, one(awsRule))
	if err != nil {
		t.Fatalf("Load() = %v, want no error", err)
	}
	if len(got) != 1 {
		t.Fatalf("Load() returned %d rules, want 1", len(got))
	}
	r := got[0]
	switch {
	case r.ID != "aws-access-key-id":
		t.Errorf("ID = %q", r.ID)
	case r.Family != Credential:
		t.Errorf("Family = %q", r.Family)
	case r.Description != "AWS access key ID":
		t.Errorf("Description = %q", r.Description)
	case r.Group != 1:
		t.Errorf("Group = %d", r.Group)
	case len(r.Keywords) != 3:
		t.Errorf("Keywords = %v", r.Keywords)
	case r.Entropy != 3.0:
		t.Errorf("Entropy = %v", r.Entropy)
	case !r.Uses(Entropy):
		t.Errorf("Validators = %v", r.Validators)
	case !r.Enabled:
		t.Error("Enabled = false")
	}
	if !r.Regex.MatchString("AKIA0000000000000000") {
		t.Error("the compiled regex does not match its own example")
	}
}

// The one decision in this package that is easy to get backwards. A rule that
// does not compile has to stop the binary, because skipping it produces the
// same clean scan as checking everything -- so this asserts the count as well
// as the error. A loader returning the one good rule beside the error would
// satisfy an err != nil check and still be the fail-open shape.
func TestARuleThatDoesNotCompileIsAStartupFailure(t *testing.T) {
	bad := set(`"id": "aws-access-key-id"`, `"id": "broken"`)
	bad = strings.Replace(bad, `"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
		`"regex": "(unclosed"`, 1)
	rules, err := load(t, one(awsRule+","+bad))
	if err == nil {
		t.Fatal("Load() = nil error, want a startup failure")
	}
	if len(rules) != 0 {
		t.Fatalf("Load() returned %d rules beside the error, want 0 -- a skipped "+
			"rule is the fail-open shape", len(rules))
	}
	if !strings.Contains(err.Error(), `"broken"`) {
		t.Errorf("the error does not name the rule: %v", err)
	}
}

// Both problems in one run. A rule author who has to fix them one at a time is
// a rule author who stops running the loader.
func TestLoadReportsEveryBadRule(t *testing.T) {
	first := set(`"id": "aws-access-key-id"`, `"id": "first"`)
	first = strings.Replace(first, `"family": "credential"`, `"family": "nonsense"`, 1)
	second := set(`"id": "aws-access-key-id"`, `"id": "second"`)
	second = strings.Replace(second, `"validators": ["entropy"]`, `"validators": ["nope"]`, 1)

	_, err := load(t, one(first+","+second))
	if err == nil {
		t.Fatal("Load() = nil error, want two")
	}
	for _, want := range []string{`"first"`, `"second"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s: %v", want, err)
		}
	}
}

// RE2 is the constraint list and regexp.Compile is the whole check. These pin
// that the three constraints the design names are enforced by it rather than
// assumed -- the repeat cap in particular is a number, and a number is worth a
// case on each side of it.
func TestRE2Constraints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		regex   string
		wantErr bool
	}{
		{"a negative lookbehind", `(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}`, true},
		{"a negative lookahead", `AKIA[A-Z0-9]{16}(?![A-Za-z0-9])`, true},
		{"a backreference", `(AKIA)\1`, true},
		{"bounded repetition one over the cap", `x{1,1001}`, true},
		{"the inherited {1,1024}", `x{1,1024}`, true},
		{"bounded repetition at the cap", `x{1,1000}`, false},
		{"a word boundary, which RE2 does have", `\bAKIA\b`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The entropy floor comes off, because every case here is about
			// what regexp.Compile accepts. \bAKIA\b captures four bytes and
			// four bytes cannot carry the AWS rule's 3 bits, so leaving the
			// floor on would fail that case for a reason the case is not about.
			body := replace(without(`"entropy": 3.0,`),
				`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
				`"regex": `+quote(tc.regex))
			body = replace(body, `"validators": ["entropy"]`, `"validators": []`)
			body = replace(body, `"group": 1`, `"group": 0`)
			_, err := load(t, one(body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load() = %v, want an error: %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"a field the schema has no room for", field(`"colour": "red"`), "colour"},
		{"a per-rule proximity window, which is the field this catches by design",
			field(`"window": 64`), "window"},
		{"no family", without(`"family": "credential",`), "no family"},
		{"no description", without(`"description": "AWS access key ID",`), "no description"},
		{"no regex", without(`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b",`), "no regex"},
		{"nothing saying whether it is enabled", without(`"enabled": true`), "enabled"},
		{"a family that is neither", set(`"family": "credential"`, `"family": "secrets"`), "neither"},
		{"a credential rule with empty keywords",
			set(`"keywords": ["AKIA", "ASIA", "A3T"]`, `"keywords": []`), "ungated"},
		{"a credential rule with the keywords left out entirely",
			without(`"keywords": ["AKIA", "ASIA", "A3T"],`), "ungated"},
		{"a check that does not exist",
			set(`"validators": ["entropy"]`, `"validators": ["luhn2"]`), "does not exist"},
		{"a group the regex does not have", set(`"group": 1`, `"group": 4`), "capture group"},
		{"a negative group", set(`"group": 1`, `"group": -1`), "capture group"},
		{"a negative entropy floor", set(`"entropy": 3.0`, `"entropy": -1`), "entropy floor"},
		{"labels nothing reads", set(`"validators": ["entropy"]`,
			`"validators": ["entropy"], "labels": ["ssn"]`), "nothing reads them"},
		{"an entropy floor nothing reads",
			set(`"validators": ["entropy"]`, `"validators": []`), "nothing reads it"},

		// A check named with configuration that can never let it pass. Each of
		// these loads, compiles, runs on every file and reports nothing, which
		// is what a clean scan looks like from the outside.
		{"context-label with no labels to look for",
			labelled(`"validators": ["context-label"]`), "no label to look for"},
		{"context-label with an empty list of labels",
			labelled(`"labels": [], "validators": ["context-label"]`), "no label to look for"},
		{"context-label with nothing but an empty label, which matches nothing",
			labelled(`"labels": [""], "validators": ["context-label"]`), "no label to look for"},
		{"an entropy floor above what an eight-byte group can carry",
			replace(set(`"entropy": 3.0`, `"entropy": 3.5`),
				`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
				`"regex": "([A-Za-z0-9]{8})"`), "cannot carry more than 3 bits"},
		{"an entropy floor above what any byte string can carry",
			replace(set(`"entropy": 3.0`, `"entropy": 9`),
				`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
				`"regex": "(.+)"`), "cannot carry more than 8 bits"},
		{"an entropy floor above what the group's alphabet can carry",
			replace(set(`"entropy": 3.0`, `"entropy": 4.5`),
				`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
				`"regex": "([a-f0-9]{32})"`), "16 distinct byte value(s)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, one(tc.body))
			if err == nil {
				t.Fatalf("Load() = nil error, want one naming %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load() = %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

// The bound is the longest string the group can capture, not the shortest, and
// the two disagree on every rule whose group is a range. A group matching 8 to
// 64 bytes carries 3 bits at its shortest and 6 at its longest, so a floor of 4
// is a rule that fires on a 16-byte capture -- and a loader that measured the
// shortest would refuse it at startup, which is a working rule taken out by the
// check meant to catch dead ones.
func TestAnEntropyFloorIsBoundedByTheLongestCapture(t *testing.T) {
	for _, tc := range []struct {
		name    string
		regex   string
		entropy string
		wantErr bool
	}{
		{"a range whose top clears the floor and whose bottom does not",
			`([A-Za-z0-9]{8,64})`, "4.0", false},
		{"a range whose top does not clear it either", `([A-Za-z0-9]{8,64})`, "6.5", true},
		{"an unbounded group over every byte, which reaches the 8-bit ceiling",
			`(.+)`, "7.9", false},

		// The comparison is >, so a floor sitting exactly on the ceiling is a
		// rule that fires: eight distinct bytes carry exactly 3 bits.
		{"a floor exactly on the ceiling", `([A-Za-z0-9]{8})`, "3.0", false},
		{"a floor one notch above it", `([A-Za-z0-9]{8})`, "3.01", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := replace(set(`"entropy": 3.0`, `"entropy": `+tc.entropy),
				`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
				`"regex": `+quote(tc.regex))
			_, err := load(t, one(body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load() = %v, want an error: %v", err, tc.wantErr)
			}
		})
	}
}

// Length is one bound on the distinct byte count and the alphabet is the other,
// so a group drawing on sixteen hex symbols carries 4 bits at any length. The
// first four cases are the shapes measured dead under a ceiling that read only
// the length: each loaded, compiled, ran on every file and reported nothing,
// which is what a clean scan looks like from outside.
func TestAnEntropyFloorIsBoundedByTheGroupsAlphabet(t *testing.T) {
	for _, tc := range []struct {
		regex   string
		entropy string
		wantErr bool
	}{
		{`([a-f0-9]{32})`, "4.5", true},
		{`([a-f0-9]{40})`, "4.5", true},
		{`(\d{16})`, "3.9", true},
		{`([A-Za-z0-9]{8,64})`, "5.98", true},

		// log2(16) exactly, which the comparison lets through.
		{`([a-f0-9]{32})`, "4.0", false},

		// A repeat and a star draw on the alphabet of what they repeat, so
		// length says 256 bytes and the group still carries one symbol.
		{`(x*)`, "0.1", true},
		{`((?:ab){1,3})`, "1.1", true},

		// The residual over-estimate, and the reason it is not a defect: the
		// union knows which symbols the group can emit, not which of them
		// co-occur in one match. Every string this matches is one repeated
		// symbol at Shannon 0, and it loads at a floor of 1.
		{`(a{6}|b{6})`, "1.0", false},
	} {
		t.Run(tc.regex+" at "+tc.entropy, func(t *testing.T) {
			body := replace(set(`"entropy": 3.0`, `"entropy": `+tc.entropy),
				`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
				`"regex": `+quote(tc.regex))
			_, err := load(t, one(body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load() = %v, want an error: %v", err, tc.wantErr)
			}
		})
	}
}

// The floor is read against the group the rule reports, not against the whole
// match. A rule capturing a wide window and reporting a short slice of it is
// the shape `group` exists for, and reading the window would let a floor
// through that the reported candidate can never reach.
func TestTheEntropyBoundReadsTheReportedGroup(t *testing.T) {
	body := replace(set(`"entropy": 3.0`, `"entropy": 3.5`),
		`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
		`"regex": "AKIA[A-Z0-9]{16}=([A-Z0-9]{8})"`)
	_, err := load(t, one(body))
	if err == nil {
		t.Fatal("Load() = nil error; the reported group is eight bytes, which cannot carry 3.5 bits")
	}
	if !strings.Contains(err.Error(), "8 byte(s)") {
		t.Errorf("Load() = %v, want an error measuring the group rather than the match", err)
	}
}

func TestEveryValidatorNameLoads(t *testing.T) {
	for _, v := range []Validator{
		Luhn, CardPlaceholder, Mod11, Entropy, ReservedRange, ContextLabel,
	} {
		t.Run(string(v), func(t *testing.T) {
			body := set(`"validators": ["entropy"]`, `"validators": [`+quote(string(v))+`]`)
			if v != Entropy {
				body = strings.Replace(body, "\n"+`  "entropy": 3.0,`, "", 1)
			}
			if v == ContextLabel {
				body = strings.Replace(body, `"validators": `,
					`"labels": ["ssn"],`+"\n  "+`"validators": `, 1)
			}
			if _, err := load(t, one(body)); err != nil {
				t.Errorf("Load() = %v, want no error", err)
			}
		})
	}
}

// A pii rule has no literal to anchor on, so empty keywords are what it looks
// like rather than a mistake.
func TestAPIIRuleNeedsNoKeywords(t *testing.T) {
	body := `{
  "id": "us-ssn",
  "family": "pii",
  "description": "US Social Security number",
  "regex": "\\b(\\d{3}-?\\d{2}-?\\d{4})\\b",
  "group": 1,
  "keywords": [],
  "labels": ["ssn", "social security"],
  "validators": ["context-label"],
  "enabled": false
}`
	got, err := load(t, one(body))
	if err != nil {
		t.Fatalf("Load() = %v, want no error", err)
	}
	if got[0].Enabled {
		t.Error("the pii rule loaded enabled")
	}
	if !got[0].Uses(ContextLabel) {
		t.Errorf("Validators = %v", got[0].Validators)
	}
}

func TestFileLevelRejections(t *testing.T) {
	for _, tc := range []struct {
		name    string
		shipped []byte
		want    string
	}{
		{"two rules sharing an id", one(awsRule + "," + awsRule), "share the id"},
		{"a rule with no id",
			one(strings.Replace(awsRule, "\n"+`  "id": "aws-access-key-id",`, "", 1)), "no id"},
		{"a second value after the object",
			[]byte(`{"rules": []} {"rules": []}`), "more than one value"},
		{"a top-level key the format has no room for",
			[]byte(`{"rules": [], "telemetry": true}`), "telemetry"},
		{"no rules at all", []byte(`{"rules": []}`), "no rules"},
		{"a bare array rather than the object", []byte(`[` + awsRule + `]`), "cannot unmarshal"},
		{"not json", []byte("rules: []"), "invalid character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.shipped)
			if err == nil {
				t.Fatalf("Load() = nil error, want one naming %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load() = %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

// The project file extends the shipped set rather than replacing it, so the
// interesting cases are what an override leaves alone.
func TestProjectOverrides(t *testing.T) {
	shipped := one(awsRule)

	t.Run("disabling a shipped rule without restating it", func(t *testing.T) {
		got, err := Load(shipped,
			one(`{"id": "aws-access-key-id", "enabled": false}`))
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("Load() returned %d rules, want 1", len(got))
		}
		if got[0].Enabled {
			t.Error("the override did not take")
		}
		if got[0].Description != "AWS access key ID" || got[0].Group != 1 {
			t.Errorf("the override dropped fields it did not mention: %+v", got[0])
		}
	})

	t.Run("adding a rule the shipped set does not have", func(t *testing.T) {
		added := set(`"id": "aws-access-key-id"`, `"id": "local"`)
		got, err := Load(shipped, one(added))
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		if len(got) != 2 || got[1].ID != "local" {
			t.Fatalf("Load() = %d rules, last %q; want the shipped one and then local",
				len(got), got[len(got)-1].ID)
		}
	})

	t.Run("an override for an id nothing ships, with fields missing", func(t *testing.T) {
		_, err := Load(shipped,
			one(`{"id": "typo-in-the-id", "enabled": false}`))
		if err == nil {
			t.Fatal("Load() = nil error, want one -- there is no rule to extend")
		}
		if !strings.Contains(err.Error(), "typo-in-the-id") {
			t.Errorf("the error does not name the id: %v", err)
		}
	})

	t.Run("an override whose regex does not compile", func(t *testing.T) {
		_, err := Load(shipped,
			one(`{"id": "aws-access-key-id", "regex": "(unclosed"}`))
		if err == nil {
			t.Fatal("Load() = nil error, want a startup failure")
		}
	})

	t.Run("a field the schema has no room for", func(t *testing.T) {
		_, err := Load(shipped,
			one(`{"id": "aws-access-key-id", "window": 32}`))
		if err == nil || !strings.Contains(err.Error(), "window") {
			t.Fatalf("Load() = %v, want an error naming window", err)
		}
	})
}

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	shipped := filepath.Join(dir, "spill-guard.json")
	project := filepath.Join(dir, "project.json")
	if err := os.WriteFile(shipped, one(awsRule), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("a project with no ruleset of its own", func(t *testing.T) {
		got, err := LoadFiles(shipped, project)
		if err != nil {
			t.Fatalf("LoadFiles() = %v, want no error", err)
		}
		if len(got) != 1 || !got[0].Enabled {
			t.Errorf("LoadFiles() = %+v", got)
		}
	})

	t.Run("a project ruleset that is there", func(t *testing.T) {
		if err := os.WriteFile(project,
			one(`{"id": "aws-access-key-id", "enabled": false}`), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := LoadFiles(shipped, project)
		if err != nil {
			t.Fatalf("LoadFiles() = %v, want no error", err)
		}
		if got[0].Enabled {
			t.Error("the project override did not take")
		}
	})

	// The binary that cannot find its own rules scans nothing, and scanning
	// nothing reports the same clean result as scanning everything.
	t.Run("no shipped ruleset", func(t *testing.T) {
		_, err := LoadFiles(filepath.Join(dir, "absent.json"), project)
		if err == nil {
			t.Fatal("LoadFiles() = nil error, want one")
		}
		if !strings.Contains(err.Error(), "shipped ruleset") {
			t.Errorf("LoadFiles() = %v", err)
		}
	})
}

// Everything this binary writes reaches a terminal and the API both, so a
// control character out of a rule file has to come back escaped. The regex is
// the case that needs saying: regexp's own message puts the raw pattern in
// backticks, so wrapping it with %w would carry the bytes through untouched.
func TestErrorsEscapeControlCharacters(t *testing.T) {
	// A C0 byte and a bidi override, the two classes the design names.
	const raw = "\a\u202e"
	for _, tc := range []struct {
		name string
		body string
	}{
		{"in a regex that does not compile",
			set(`"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\\b"`,
				`"regex": "(unclosed\u202e"`)},
		// An id alone is legal however it is spelled, so this one needs a
		// defect beside it to produce an error that names the id at all.
		{"in a rule id", strings.Replace(
			set(`"id": "aws-access-key-id"`, `"id": "ab\u202ec"`),
			`"family": "credential"`, `"family": "secrets"`, 1)},
		{"in a validator name",
			set(`"validators": ["entropy"]`, `"validators": ["nope\u202e"]`)},
		{"in a family", set(`"family": "credential"`, `"family": "nope\u202e"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, one(tc.body))
			if err == nil {
				t.Fatal("Load() = nil error, want one")
			}
			if strings.ContainsAny(err.Error(), raw) {
				t.Errorf("the error carries a raw control character: %q", err.Error())
			}
		})
	}
}

// The same, for an error the JSON decoder writes rather than this package.
func TestDecodeErrorsEscapeControlCharacters(t *testing.T) {
	const raw = "\a\u202e"
	for _, tc := range []struct {
		name    string
		shipped []byte
	}{
		{"a syntax error at a control byte", []byte("{\"rules\": \a}")},
		{"a field name nothing has room for", one(field(`"colour\u202e": "red"`))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.shipped)
			if err == nil {
				t.Fatal("Load() = nil error, want one")
			}
			if strings.ContainsAny(err.Error(), raw) {
				t.Errorf("the error carries a raw control character: %q", err.Error())
			}
		})
	}
}
