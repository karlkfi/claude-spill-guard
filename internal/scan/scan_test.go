package scan

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

// load builds the ruleset the way the binary does, so a fixture that the
// loader would refuse fails here rather than testing a rule that cannot exist.
func load(t *testing.T, ruleset string) []rules.Rule {
	t.Helper()
	loaded, err := rules.Load([]byte(ruleset), nil)
	if err != nil {
		t.Fatalf("the fixture ruleset does not load: %v", err)
	}
	return loaded
}

func scan(t *testing.T, path string, buf string, ruleset []rules.Rule) []Finding {
	t.Helper()
	got, err := Buffer(path, []byte(buf), ruleset)
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if got.Skipped != Scanned {
		t.Fatalf("the buffer was not read: %s", got.Skipped)
	}
	return got.Findings
}

func ids(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	return out
}

const awsRule = `{"rules": [{
	"id": "aws-access-key-id",
	"family": "credential",
	"description": "AWS access key ID",
	"regex": "\\b((?:AKIA|ASIA)[A-Z0-9]{16})\\b",
	"group": 1,
	"keywords": ["AKIA", "ASIA"],
	"enabled": true
}]}`

// key is AWS's documented access key ID, which the tables in this package use
// as the thing a rule has to find. It is named rather than written here, and
// testdata/corpus/README.md says why.
//
// A package-level var filled by TestMain rather than a value each test loads:
// three files and a dozen assertions read it, and threading a *testing.T
// through the name would rewrite all of them to say nothing new.
var key string

// stsKey is the same value on the prefix STS issues, which the prefilter's
// table needs to reach the second keyword in a list.
var stsKey string

// fatal adapts testvec's TB to TestMain, which has no *testing.T to fail. A
// vectors file this package cannot read is not a failure worth reporting per
// test -- every table below would be asserting on an empty string -- so it
// takes the binary down where the problem is.
type fatal struct{}

func (fatal) Helper() {}

func (fatal) Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func TestMain(m *testing.M) {
	vec := testvec.Load(fatal{})
	key = vec.Get(fatal{}, "aws-iam-example")
	stsKey = vec.Get(fatal{}, "aws-sts-example")
	os.Exit(m.Run())
}

func TestBufferReportsRuleIDPathAndOffset(t *testing.T) {
	ruleset := load(t, awsRule)
	buf := "aws_access_key_id = " + key + "\n"

	findings := scan(t, "config/aws.ini", buf, ruleset)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.RuleID != "aws-access-key-id" {
		t.Errorf("RuleID = %q, want %q", got.RuleID, "aws-access-key-id")
	}
	if got.Path != "config/aws.ini" {
		t.Errorf("Path = %q, want %q", got.Path, "config/aws.ini")
	}
	if want := strings.Index(buf, key); got.Offset != want {
		t.Errorf("Offset = %d, want %d", got.Offset, want)
	}
}

// The prefilter decides what the regex never sees, so the way to test it is a
// rule whose regex matches text its keywords do not cover. Both buffers match
// the pattern; only one carries a keyword.
func TestBufferPrefiltersTheCredentialFamily(t *testing.T) {
	ruleset := load(t, `{"rules": [{
		"id": "twenty-uppercase",
		"family": "credential",
		"description": "twenty uppercase characters",
		"regex": "\\b([A-Z0-9]{20})\\b",
		"group": 1,
		"keywords": ["AKIA"],
		"enabled": true
	}]}`)

	if findings := scan(t, "a", key, ruleset); len(findings) != 1 {
		t.Fatalf("the keyword is present and the regex matches, so this is the "+
			"control: got %d findings, want 1", len(findings))
	}
	other := strings.Repeat("Z", 20)
	if !regexp.MustCompile(`\b([A-Z0-9]{20})\b`).MatchString(other) {
		t.Fatalf("%q does not match the fixture's own pattern, so the case "+
			"below would pass whether or not the prefilter ran", other)
	}
	if findings := scan(t, "a", other, ruleset); len(findings) != 0 {
		t.Errorf("the regex matches and no keyword does, so the prefilter "+
			"should have skipped the rule: got %+v", findings)
	}
}

// The pii family has no literal to anchor on, so its rules are not gated on
// keywords even when the ruleset gives them some.
func TestBufferDoesNotPrefilterThePIIFamily(t *testing.T) {
	ruleset := load(t, `{"rules": [{
		"id": "public-ipv4",
		"family": "pii",
		"description": "public IPv4 address",
		"regex": "\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b",
		"group": 1,
		"keywords": ["nothing-in-the-buffer"],
		"validators": ["reserved-range"],
		"enabled": true
	}]}`)

	findings := scan(t, "a", "peer 8.8.8.8 and 192.168.1.1\n", ruleset)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (the reserved address is dropped by "+
			"its validator, not by a prefilter): %+v", len(findings), findings)
	}
}

// A keyword list naming no literal cannot gate, and the direction it fails in
// is the whole argument. Treating it as a gate skips the rule on every file,
// and a rule that scanned nothing reports what a rule that scanned everything
// reports. Measured on `internal/rules` at this commit: the loader refuses a
// credential rule with an empty list and accepts one holding [""], so the
// second of these is reachable from a rule file today.
func TestBufferDoesNotLetAnUngatableKeywordListSilenceARule(t *testing.T) {
	for _, keywords := range []string{`[""]`, `["", ""]`} {
		t.Run(keywords, func(t *testing.T) {
			ruleset := load(t, `{"rules": [{
				"id": "aws-access-key-id",
				"family": "credential",
				"description": "AWS access key ID",
				"regex": "\\b((?:AKIA|ASIA)[A-Z0-9]{16})\\b",
				"group": 1,
				"keywords": `+keywords+`,
				"enabled": true
			}]}`)
			if findings := scan(t, "a", key, ruleset); len(findings) != 1 {
				t.Errorf("got %d findings, want 1 -- a list naming no literal "+
					"has to leave the rule ungated, not silenced", len(findings))
			}
		})
	}
}

func TestBufferSkipsDisabledRules(t *testing.T) {
	ruleset := load(t, strings.Replace(awsRule, `"enabled": true`, `"enabled": false`, 1))
	if findings := scan(t, "a", key, ruleset); len(findings) != 0 {
		t.Errorf("a disabled rule produced %+v", findings)
	}
}

// A skip is reported, not performed quietly. The zero findings are half of the
// contract and the weaker half: they are what a file that was read and held
// nothing produces too.
func TestBufferSkipsBinariesAndSaysSo(t *testing.T) {
	ruleset := load(t, awsRule)
	got, err := Buffer("a.png", []byte("\x00"+key), ruleset)
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if len(got.Findings) != 0 {
		t.Errorf("a buffer with a NUL in it produced %+v", got.Findings)
	}
	if got.Skipped != SkippedBinary {
		t.Errorf("Skipped is %q, want %q", got.Skipped, SkippedBinary)
	}

	// The positive control on the assertion above: the same key with no NUL in
	// front of it reports Scanned and finds it, so an empty Skipped is a thing
	// this test can distinguish rather than the only answer it ever sees.
	got, err = Buffer("a.env", []byte(key), ruleset)
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if got.Skipped != Scanned || len(got.Findings) != 1 {
		t.Errorf("the control buffer reports Skipped %q and %d finding(s), "+
			"want Scanned and 1", got.Skipped, len(got.Findings))
	}
}

// Every check a rule names has to pass, and each one is reached from here --
// a validator wired to the wrong function is invisible until a rule uses it.
func TestBufferRunsEveryValidator(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rule    string
		buf     string
		wantIDs []string
	}{
		{"luhn drops a transcription error",
			`"regex": "\\b(\\d{16})\\b", "group": 1, "validators": ["luhn"]`,
			"4111111111111111 and 4111111111111112", []string{"r"}},
		{"card-placeholder drops a published test number",
			`"regex": "\\b(\\d{16})\\b", "group": 1, "validators": ["luhn", "card-placeholder"]`,
			"4111111111111111", nil},
		{"mod-11 drops a bad check character",
			`"regex": "\\b([0-9X]{9})\\b", "group": 1, "validators": ["mod-11"]`,
			"00000001X 000000010", []string{"r"}},
		{"entropy drops a low-entropy capture",
			`"regex": "\\b([A-Za-z0-9]{20})\\b", "group": 1, "entropy": 3.5, "validators": ["entropy"]`,
			"aaaaaaaaaaaaaaaaaaaa Xk92QmZ4Lp01WvBn7YtR", []string{"r"}},
		{"reserved-range drops a private address",
			`"regex": "\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b", "group": 1, "validators": ["reserved-range"]`,
			"10.0.0.1 and 8.8.8.8", []string{"r"}},
		{"context-label drops a numeric run with no label near it",
			`"regex": "\\b(\\d{9})\\b", "group": 1, "labels": ["ssn"], "validators": ["context-label"]`,
			"const bufSize = 655360000", nil},
		{"context-label keeps one that has a label near it",
			`"regex": "\\b(\\d{9})\\b", "group": 1, "labels": ["ssn"], "validators": ["context-label"]`,
			"ssn: 078051120", []string{"r"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ruleset := load(t, `{"rules": [{
				"id": "r", "family": "pii", "description": "d",
				"enabled": true, `+tc.rule+`}]}`)
			got := ids(scan(t, "a", tc.buf, ruleset))
			if strings.Join(got, ",") != strings.Join(tc.wantIDs, ",") {
				t.Errorf("got %d findings %v, want %v", len(got), got, tc.wantIDs)
			}
		})
	}
}

// Rules run separately and every match in a buffer is reported. A single
// alternation over the patterns is the shape this forecloses -- it runs at
// 0.5x, and it also loses which rule matched.
func TestBufferRunsEveryRuleOverEveryMatch(t *testing.T) {
	ruleset := load(t, `{"rules": [
		{"id": "aws", "family": "credential", "description": "d", "group": 1,
		 "regex": "\\b(AKIA[A-Z0-9]{16})\\b", "keywords": ["AKIA"], "enabled": true},
		{"id": "twenty", "family": "credential", "description": "d", "group": 1,
		 "regex": "\\b([A-Z0-9]{20})\\b", "keywords": ["AKIA"], "enabled": true}
	]}`)

	findings := scan(t, "a", key+" then "+key, ruleset)
	if want := []string{"aws", "aws", "twenty", "twenty"}; !reflect.DeepEqual(ids(findings), want) {
		t.Fatalf("got %v, want %v", ids(findings), want)
	}
	if findings[0].Offset == findings[1].Offset {
		t.Errorf("both matches of the same rule report offset %d", findings[0].Offset)
	}
}

// The group is what lets a rule capture a wider window than it reports, which
// is how RE2's missing lookaround is worked around.
func TestBufferReportsTheCapturedGroupRatherThanTheMatch(t *testing.T) {
	ruleset := load(t, `{"rules": [{
		"id": "r", "family": "pii", "description": "d", "enabled": true,
		"regex": "token=([A-Za-z0-9]{8})", "group": 1
	}]}`)

	buf := "  token=abcd1234;"
	findings := scan(t, "a", buf, ruleset)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if want := strings.Index(buf, "abcd1234"); findings[0].Offset != want {
		t.Errorf("Offset = %d, want %d -- the group starts after `token=`",
			findings[0].Offset, want)
	}
}

// The predecessor's Finding carried the secret beside a redacted copy. It was
// used only as a dedup key and never printed, and the field's existence was
// the hazard. This reads the struct rather than the fields it happens to have
// today, so a field added later fails here.
func TestFindingCarriesNoPartOfTheValue(t *testing.T) {
	ruleset := load(t, awsRule)
	findings := scan(t, "config/aws.ini", "key = "+key, ruleset)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	v := reflect.ValueOf(findings[0])
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if v.Field(i).Kind() != reflect.String {
			continue
		}
		got := v.Field(i).String()
		// Four characters, because a redacted window is the shape the design
		// refuses and any run that long is the secret leaking a piece at a time.
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(got, key[i:i+4]) {
				t.Errorf("Finding.%s = %q, which carries %q from the value",
					field.Name, got, key[i:i+4])
			}
		}
	}
}

func TestDigest(t *testing.T) {
	same := digest("rule-a", []byte(key))
	if got := digest("rule-a", []byte(key)); got != same {
		t.Errorf("digest is not stable: %q then %q", same, got)
	}
	if got := digest("rule-b", []byte(key)); got == same {
		t.Errorf("two rules over the same value share the digest %q, so one "+
			"would dedup the other away", got)
	}
	if got := digest("rule-a", []byte(key+"x")); got == same {
		t.Errorf("two values under one rule share the digest %q", got)
	}
	if len(same) != 16 {
		t.Errorf("digest %q is %d hex characters, want 16", same, len(same))
	}
	// Without a separator the two fields run together, so a rule id ending in
	// the byte a neighbouring value starts with produces one digest for two
	// findings -- and merging two findings into one is the silent direction.
	if a, b := digest("aws-", []byte("key")), digest("aws", []byte("-key")); a == b {
		t.Errorf("digest(%q, %q) and digest(%q, %q) are both %q", "aws-", "key",
			"aws", "-key", a)
	}
}

// Fail closed: an internal error blocks rather than returning what it managed
// to scan. Each of these is settled by the loader before a Rule exists, and
// the alternative to an error here is a panic, which exits on a code the hook
// contract does not block on.
func TestBufferFailsClosedOnAnUnusableRule(t *testing.T) {
	compiled := regexp.MustCompile(`(a)(b)`)
	for _, tc := range []struct {
		name string
		rule rules.Rule
		want string
	}{
		{"no compiled regex",
			rules.Rule{ID: "r", Family: rules.PII, Enabled: true},
			"no compiled regex"},
		{"a group the regex does not have",
			rules.Rule{ID: "r", Family: rules.PII, Enabled: true, Regex: compiled, Group: 3},
			"but the regex has 2 capture group(s)"},
		{"a negative group",
			rules.Rule{ID: "r", Family: rules.PII, Enabled: true, Regex: compiled, Group: -1},
			"but the regex has 2 capture group(s)"},
		{"a check the pipeline does not run",
			rules.Rule{ID: "r", Family: rules.PII, Enabled: true, Regex: compiled,
				Validators: []rules.Validator{"handwave"}},
			`names check "handwave"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Buffer("a", []byte("ab"), []rules.Rule{tc.rule})
			if err == nil {
				t.Fatalf("no error, and %d findings", len(got.Findings))
			}
			if got.Findings != nil {
				t.Errorf("an error came back with %d findings beside it", len(got.Findings))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// A disabled rule is skipped before any of that is read, so a ruleset carrying
// a broken rule nobody turned on still scans.
func TestBufferIgnoresAnUnusableRuleThatIsDisabled(t *testing.T) {
	broken := rules.Rule{ID: "r", Family: rules.PII}
	if _, err := Buffer("a", []byte("ab"), []rules.Rule{broken}); err != nil {
		t.Errorf("a disabled rule with no regex errored: %v", err)
	}
}
