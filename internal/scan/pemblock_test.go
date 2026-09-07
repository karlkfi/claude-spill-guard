package scan

import (
	"regexp"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
)

// private-key-block against literals, because two of the cases below cannot be
// corpus files. A CRLF fixture depends on what git does to it on checkout, and
// the prose case has to sit next to the key it is not, for either to mean
// anything.
//
// The body is the planted fixture's, so the only thing varying across the
// table is what sits between the header and it.
const pemBody = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpamts"

func privateKeyBlock(t *testing.T) []rules.Rule {
	t.Helper()
	for _, rule := range loadShipped(t) {
		if rule.ID == "private-key-block" {
			return []rules.Rule{rule}
		}
	}
	t.Fatal("the shipped ruleset carries no private-key-block rule")
	return nil
}

// genericOnly is the three shapes that separate the shipped step over
// Proc-Type and DEK-Info from the one considered beside it, which admits any
// `Name: value` line. Both tests below read them: one that the shipped rule is
// quiet on all three, and one that the alternative is not.
var genericOnly = []struct{ name, buf string }{
	{"a header, then a field RFC 1421 does not define, then a body",
		"-----BEGIN RSA PRIVATE KEY-----\nNote: the body is redacted\n" + pemBody + "\n"},
	{"a header, then an RFC 4716 Comment field, then a body",
		"-----BEGIN RSA PRIVATE KEY-----\nComment: exported by ssh-keygen\n" + pemBody + "\n"},
	{"a header, then a prose line ending in a colon, then a body",
		"-----BEGIN RSA PRIVATE KEY-----\nbase64:\n" + pemBody + "\n"},
}

// genericStep is the alternative shape, verbatim as it was measured. It ships
// nowhere, and it is compiled here for the reason corpus_test.go's `inherited`
// is compiled there: rules/README.md makes a claim about what it would report,
// and a claim with nothing that can fail is the shape this repository refuses.
var genericStep = regexp.MustCompile(
	`(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |SSH2 ENCRYPTED |ENCRYPTED )?PRIVATE KEY-----)` +
		`[\r\n]+(?:[A-Za-z][A-Za-z0-9-]*:[^\r\n]*[\r\n]+)*[A-Za-z0-9+/=]{32,}`)

// The named pair is tighter than the alternative, which is what makes the
// choice between them a measurement rather than a preference. The other half
// of it -- that the shipped rule stays quiet on these -- is three rows of the
// table below.
func TestTheGenericStepReportsWhatTheNamedPairDoesNot(t *testing.T) {
	set := privateKeyBlock(t)
	for _, tc := range genericOnly {
		t.Run(tc.name, func(t *testing.T) {
			if !genericStep.MatchString(tc.buf) {
				t.Errorf("the generic step does not report this, so it does not " +
					"separate the two shapes and rules/README.md is wrong to say it does")
			}
			got, err := Buffer("t", []byte(tc.buf), set)
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}
			if got.Skipped != Scanned {
				t.Fatalf("not read: %s", got.Skipped)
			}
			if len(got.Findings) != 0 {
				t.Errorf("the shipped rule reports this, so the two shapes agree here")
			}
		})
	}
}

// indentedOnly is the shipped rule with the leading whitespace made mandatory,
// so it matches what the widening newly admits and nothing the rule reported
// before it. Compiled here and shipped nowhere, for the reason genericStep
// above is compiled: the corpus is where the claim "the ruleset stays quiet"
// is settled, and a corpus holding no instance of a shape returns the same
// zero for a candidate that is right about it and one that is arbitrarily
// wrong. Read over both halves when Q76 was filed, this pattern gave 0 and 0 --
// which is what made three deliberately varied candidates agree.
var indentedOnly = regexp.MustCompile(
	`(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |SSH2 ENCRYPTED |ENCRYPTED )?PRIVATE KEY-----)` +
		`[\r\n]+(?:[ \t]*(?:Proc-Type|DEK-Info):[^\r\n]*[\r\n]+)*[ \t]+[A-Za-z0-9+/=]{32,}`)

func TestTheCorpusHoldsTheIndentedShape(t *testing.T) {
	control := []rules.Rule{{
		ID:          "private-key-block-indented-only",
		Family:      rules.Credential,
		Description: "what the indentation widening newly admits, as a control",
		Regex:       indentedOnly,
		Enabled:     true,
	}}
	clean := walk(t, "clean", control)
	planted := walk(t, "planted", control)
	t.Logf("indented bodies only: %d on the clean corpus, %d on the planted one",
		len(clean.findings), len(planted.findings))

	if len(planted.findings) == 0 {
		t.Error("no planted file carries an indented body, so the clean corpus's " +
			"zero says nothing about the indentation axis -- which is the reading " +
			"that let the axis go unexercised in the first place")
	}
	if len(clean.findings) != 0 {
		t.Errorf("an indented body is reportable in %d clean file(s):\n%s",
			len(clean.findings), report(clean.findings))
	}
}

// newlineOnlySeparator is the clause as it stepped from the header to the body
// before this widening: across `[\r\n]+` and nothing else, at both of the two
// places it steps. It ships nowhere and is compiled here for the reason
// genericStep and indentedOnly above are compiled -- a corpus holding no
// instance of a shape returns the same zero for a rule that is right about it
// and one that is arbitrarily wrong.
var newlineOnlySeparator = regexp.MustCompile(
	`(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |SSH2 ENCRYPTED |ENCRYPTED )?PRIVATE KEY-----)` +
		`[\r\n]+(?:[ \t]*(?:Proc-Type|DEK-Info):[^\r\n]*[\r\n]+)*[ \t]*[A-Za-z0-9+/=]{32,}`)

// What this widening newly admits, computed rather than approximated by hand:
// the files the shipped rule reports and the pattern above does not. An
// approximation can drift from the two patterns it stands between, and this
// cannot.
//
// Both halves are load-bearing. The planted count is what stops the clean
// corpus's zero being a reading over a corpus with no instance of the shape --
// which is what it was when Q143 was filed, and why the row refused to widen
// the rule on it.
func TestTheCorpusHoldsTheWhitespaceSeparatorShape(t *testing.T) {
	before := []rules.Rule{{
		ID:          "private-key-block-newline-separator-only",
		Family:      rules.Credential,
		Description: "the body clause as it stepped before the whitespace widening",
		Regex:       newlineOnlySeparator,
		Enabled:     true,
	}}
	shipped := privateKeyBlock(t)

	for _, half := range []string{"planted", "clean"} {
		now := walk(t, half, shipped)
		then := walk(t, half, before)
		newly := len(now.findings) - len(then.findings)
		t.Logf("%s: %d finding(s) now, %d before the widening, %d newly admitted",
			half, len(now.findings), len(then.findings), newly)

		switch half {
		case "planted":
			if newly < 1 {
				t.Error("no planted file separates the header from the body with " +
					"a whitespace-only line, so the clean corpus's zero says nothing " +
					"about this axis -- which is the reading that left the axis " +
					"unexercised in the first place")
			}
		case "clean":
			if newly != 0 {
				t.Errorf("the widening newly reports %d clean file(s):\n%s",
					newly, report(now.findings))
			}
			if len(now.findings) != 0 {
				t.Errorf("the shipped rule reports %d clean file(s):\n%s",
					len(now.findings), report(now.findings))
			}
		}
	}
}

// pemCase is one layout and whether the shipped rule reports it.
type pemCase struct {
	name string
	buf  string
	want bool
}

func TestPrivateKeyBlockAcrossThePEMLayouts(t *testing.T) {
	set := privateKeyBlock(t)
	cases := []pemCase{
		{"PKCS#8, body on the next line",
			"-----BEGIN PRIVATE KEY-----\n" + pemBody + "\n", true},
		{"the same with CRLF",
			"-----BEGIN PRIVATE KEY-----\r\n" + pemBody + "\r\n", true},
		{"PKCS#8 encrypted, which has no intervening headers",
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + pemBody + "\n", true},
		{"RFC 1421, Proc-Type and DEK-Info between header and body",
			"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n" +
				"DEK-Info: AES-128-CBC,7A1B2C3D4E5F60718293A4B5C6D7E8F9\n\n" + pemBody + "\n", true},
		{"the same with CRLF",
			"-----BEGIN RSA PRIVATE KEY-----\r\nProc-Type: 4,ENCRYPTED\r\n" +
				"DEK-Info: AES-128-CBC,7A1B2C3D4E5F60718293A4B5C6D7E8F9\r\n\r\n" + pemBody + "\r\n", true},
		{"Proc-Type alone, with no DEK-Info after it",
			"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\n" + pemBody + "\n", true},

		// The body's own indentation is what decides these, not the
		// header's: a key pasted into a YAML block scalar or an indented
		// Markdown fence carries whitespace in front of every line, and the
		// encryption headers of an encrypted one carry it too.
		{"indented, as a Kubernetes secret's block scalar puts it",
			"tls.key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  " + pemBody + "\n", true},
		{"indented RFC 1421, so the encryption headers are indented as well",
			"tls.key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  Proc-Type: 4,ENCRYPTED\n" +
				"  DEK-Info: AES-128-CBC,7A1B2C3D4E5F60718293A4B5C6D7E8F9\n\n  " + pemBody + "\n", true},
		{"the header indented and the body not",
			"    -----BEGIN RSA PRIVATE KEY-----\n" + pemBody + "\n", true},
		{"the body indented and the header not",
			"-----BEGIN RSA PRIVATE KEY-----\n    " + pemBody + "\n", true},
		{"indented with tabs rather than spaces",
			"\t-----BEGIN RSA PRIVATE KEY-----\n\t" + pemBody + "\n", true},

		// What sits between the header and the body, which the clause stepped
		// across as newlines only. A unified diff prefixes every context line
		// with a space, so a key quoted in one separates its header from its
		// body with a line carrying exactly that space.
		{"a separator line of spaces, then an indented body",
			"-----BEGIN RSA PRIVATE KEY-----\n   \n    " + pemBody + "\n", true},
		{"a separator line of spaces, then an un-indented body",
			"-----BEGIN RSA PRIVATE KEY-----\n   \n" + pemBody + "\n", true},
		{"a separator line of one space after DEK-Info, as a diff writes it",
			"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n" +
				"DEK-Info: AES-128-CBC,7A1B2C3D4E5F60718293A4B5C6D7E8F9\n \n" + pemBody + "\n", true},
		{"a separator line of tabs",
			"-----BEGIN RSA PRIVATE KEY-----\n\t\t\n" + pemBody + "\n", true},

		// The separator has to reach a line ending, which is what keeps this
		// row false. `[ \t\r\n]+` -- the one-character widening -- admits it,
		// and no PEM a toolchain writes puts the body on the header's line, so
		// admitting it would widen the rule further than the defect asked.
		{"the body on the header's own line",
			"-----BEGIN RSA PRIVATE KEY----- " + pemBody + "\n", false},

		{"prose quoting a header inline",
			"An unencrypted PKCS#1 key opens with `-----BEGIN RSA PRIVATE KEY-----`\n" +
				"and a PKCS#8 key with `-----BEGIN PRIVATE KEY-----`.\n", false},
		{"a header displayed on its own line, with prose under it",
			"-----BEGIN RSA PRIVATE KEY-----\n\nthen the encryption headers, then a\n" +
				"blank line, then lines of\n\n" + pemBody + "\n", false},
		{"a footer with no header",
			pemBody + "\n-----END RSA PRIVATE KEY-----\n", false},
		// testdata/corpus/clean/tls-runbook.md, verbatim, which displays both
		// the header and a body line indented by four with prose between them.
		// It is what stops the leading-whitespace arms above being written as
		// a window over anything printable, so it is the negative that has to
		// hold once those arms exist.
		{"a displayed header, prose under it, and an indented body line",
			"Laid out, with the body cut to a single line:\n\n" +
				"    -----BEGIN RSA PRIVATE KEY-----\n\n" +
				"then the encryption headers if the key has any, then a blank line, then lines\n" +
				"of\n\n    " + pemBody + "\n\nuntil the footer.\n", false},
	}

	// Appended rather than listed. Every shape that separates the two steps has
	// to be quiet under the shipped one, and a fourth added to genericOnly for
	// the comparison test would otherwise be gated there and absent here.
	for _, g := range genericOnly {
		cases = append(cases, pemCase{g.name, g.buf, false})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Buffer("t", []byte(tc.buf), set)
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}
			// A buffer nothing read reports the same empty Findings as a clean
			// one, and half this table wants empty -- so the negatives mean
			// nothing without this. It cannot fire on the rows as they stand,
			// which are all ASCII: insurance against a row that is not, rather
			// than a control doing work today.
			if got.Skipped != Scanned {
				t.Fatalf("not read: %s", got.Skipped)
			}
			if reported := len(got.Findings) > 0; reported != tc.want {
				t.Errorf("reported %v, want %v", reported, tc.want)
			}
			// The group is the header, so a finding points at the first byte
			// of it and never into the body.
			if len(got.Findings) > 0 {
				if at := strings.Index(tc.buf, "-----BEGIN"); got.Findings[0].Offset != at {
					t.Errorf("offset %d, want %d -- the capture is the header",
						got.Findings[0].Offset, at)
				}
			}
		})
	}
}
