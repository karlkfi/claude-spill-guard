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
			found, err := Buffer("t", []byte(tc.buf), set)
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}
			if len(found) != 0 {
				t.Errorf("the shipped rule reports this, so the two shapes agree here")
			}
		})
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

		{"prose quoting a header inline",
			"An unencrypted PKCS#1 key opens with `-----BEGIN RSA PRIVATE KEY-----`\n" +
				"and a PKCS#8 key with `-----BEGIN PRIVATE KEY-----`.\n", false},
		{"a header displayed on its own line, with prose under it",
			"-----BEGIN RSA PRIVATE KEY-----\n\nthen the encryption headers, then a\n" +
				"blank line, then lines of\n\n" + pemBody + "\n", false},
		{"a footer with no header",
			pemBody + "\n-----END RSA PRIVATE KEY-----\n", false},
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
			// nothing without this.
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
