package validate

import (
	"bytes"
	"strings"
	"testing"
)

// buf is the file, at is where the candidate starts, and the marker is how the
// case says which numeric run it means without counting bytes by hand.
func at(t *testing.T, buf, candidate string) int {
	t.Helper()
	i := strings.Index(buf, candidate)
	if i < 0 {
		t.Fatalf("candidate %q is not in %q", candidate, buf)
	}
	return i
}

func TestNearLabel(t *testing.T) {
	labels := []string{"phone", "ssn", "postal"}
	for _, tc := range []struct {
		name      string
		buf       string
		candidate string
		window    int
		want      bool
	}{
		{"a label and a colon", "ssn: 123456789", "123456789", DefaultLabelWindow, true},
		{"a label and an equals sign", "ssn=123456789", "123456789", DefaultLabelWindow, true},
		{"uppercase", "SSN: 123456789", "123456789", DefaultLabelWindow, true},
		{"mixed case", "Phone: 5551234567", "5551234567", DefaultLabelWindow, true},
		{"a quoted JSON key", `{"phone": "5551234567"}`, "5551234567", DefaultLabelWindow, true},
		{"an environment variable", "PHONE_NUMBER=5551234567", "5551234567", DefaultLabelWindow, true},
		{"one word between the label and the value", "phone number: 5551234567",
			"5551234567", DefaultLabelWindow, true},
		{"two words between the label and the value", "primary phone number: 5551234567",
			"5551234567", DefaultLabelWindow, true},
		{"block-style YAML, with the value on the next line", "ssn:\n  123456789",
			"123456789", DefaultLabelWindow, true},
		{"the label at the very start of the buffer", "ssn 123456789",
			"123456789", DefaultLabelWindow, true},
		{"a snake_case key", "patient_phone_number: 5551234567", "5551234567", DefaultLabelWindow, true},
		{"a label whose first byte is exactly at the window's edge",
			"ssn" + strings.Repeat(".", 7) + "1", "1", 10, true},

		// Everything below is a numeric run in real text with no label near it.
		// These are the 5,679 inherited matches, in miniature.
		{"a buffer constant", "const bufSize = 65536", "65536", DefaultLabelWindow, false},
		{"a Kubernetes NodePort", "  nodePort: 30443", "30443", DefaultLabelWindow, false},
		{"another NodePort", "  nodePort: 30080", "30080", DefaultLabelWindow, false},
		{"the amdgpu DKMS version string", "amdgpu-dkms 1:6.16.13.30300400-2341068",
			"30300400", DefaultLabelWindow, false},
		{"a label one byte outside the window", "ssn" + strings.Repeat(".", 8) + "1", "1", 10, false},
		{"a numeric key with a digit run, not a label", "sha256_len = 65536", "65536", DefaultLabelWindow, false},
		{"a label far outside the window",
			"ssn is a thing" + strings.Repeat(" ", 200) + "65536", "65536", DefaultLabelWindow, false},
		{"a label after the candidate rather than before", "65536 is not an ssn",
			"65536", DefaultLabelWindow, false},
		{"the label inside a longer word", "assn 123456789", "123456789", DefaultLabelWindow, false},
		{"the label as a prefix of a longer word", "ssnx 123456789", "123456789", DefaultLabelWindow, false},
		{"a word the label is a prefix of", "postalservice 30443", "30443", DefaultLabelWindow, false},
		{"a zero window", "ssn: 123456789", "123456789", 0, false},
		{"a negative window", "ssn: 123456789", "123456789", -1, false},
		{"a candidate at offset zero", "123456789", "123456789", DefaultLabelWindow, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NearLabel([]byte(tc.buf), at(t, tc.buf, tc.candidate), labels, tc.window)
			if got != tc.want {
				t.Errorf("NearLabel(%q, at %q, %v, %d) = %v, want %v",
					tc.buf, tc.candidate, labels, tc.window, got, tc.want)
			}
		})
	}
}

// A label whose own edge is punctuation carries its boundary with it, so it
// must still match against a word character on that side.
func TestNearLabelDoesNotDemandABoundaryPunctuationAlreadyGives(t *testing.T) {
	for _, tc := range []struct {
		name  string
		buf   string
		label string
		want  bool
	}{
		{"the label ends in punctuation and the value follows it", "ssn=1", "ssn=", true},
		{"the label ends in punctuation, inside a longer word", "assn=1", "ssn=", false},
		{"the label starts with punctuation", "-ssn 1", "-ssn", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := at(t, tc.buf, "1")
			if got := NearLabel([]byte(tc.buf), i, []string{tc.label}, DefaultLabelWindow); got != tc.want {
				t.Errorf("NearLabel(%q, %d, [%q]) = %v, want %v", tc.buf, i, tc.label, got, tc.want)
			}
		})
	}
}

// A rule with nothing to look for reports nothing. Asserted rather than
// assumed, because the other reading -- treat an empty list as "no gate" and
// admit everything -- turns one misconfigured rule back into the 5,679-match
// ruleset.
func TestNearLabelWithNoUsableLabelsReportsNothing(t *testing.T) {
	buf := []byte("ssn: 123456789")
	for _, labels := range [][]string{nil, {}, {""}} {
		if NearLabel(buf, 5, labels, DefaultLabelWindow) {
			t.Errorf("NearLabel with labels %q = true, want false", labels)
		}
	}
}

// The window must not read before the start of the buffer, and must not be
// derived from a candidate offset the caller got wrong.
func TestNearLabelHandlesOffsetsAtAndPastTheBufferEdge(t *testing.T) {
	buf := []byte("ssn: 1")
	for _, tc := range []struct {
		name string
		off  int
		want bool
	}{
		{"the last byte", len(buf) - 1, true},
		{"one past the last byte, which is a valid empty suffix", len(buf), true},
		{"two past the end", len(buf) + 1, false},
		{"a negative offset", -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NearLabel(buf, tc.off, []string{"ssn"}, DefaultLabelWindow); got != tc.want {
				t.Errorf("NearLabel(%q, %d) = %v, want %v", buf, tc.off, got, tc.want)
			}
		})
	}
}

// The window is measured from the candidate backwards, so growing it may only
// ever add labels. A search that walked forward, or one that measured from the
// label, would pass every case above and fail this.
func TestNearLabelIsMonotonicInTheWindow(t *testing.T) {
	buf := []byte("ssn" + strings.Repeat(" ", 40) + "123456789")
	i := bytes.Index(buf, []byte("123456789"))
	seen := false
	for w := 1; w <= 128; w++ {
		got := NearLabel(buf, i, []string{"ssn"}, w)
		if seen && !got {
			t.Fatalf("window %d = false after a smaller window matched", w)
		}
		seen = seen || got
	}
	if !seen {
		t.Fatal("no window up to 128 found a label 43 bytes back")
	}
}
