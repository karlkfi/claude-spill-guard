package scan

import (
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

func TestPrivateKeyBlockAcrossThePEMLayouts(t *testing.T) {
	set := privateKeyBlock(t)
	for _, tc := range []struct {
		name string
		buf  string
		want bool
	}{
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
		{"a header, then a field RFC 1421 does not define, then a body",
			"-----BEGIN RSA PRIVATE KEY-----\nNote: the body is redacted\n" + pemBody + "\n", false},
		{"a footer with no header",
			pemBody + "\n-----END RSA PRIVATE KEY-----\n", false},
	} {
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
