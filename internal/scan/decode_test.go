package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// encodeUTF16 builds a UTF-16 buffer with its byte-order mark, packing the code
// units by hand rather than through anything in decode.go. A fixture built by
// the decoder's own inverse would agree with it however either one is wrong.
func encodeUTF16(s string, bigEndian bool) []byte {
	out := []byte{0xFF, 0xFE}
	if bigEndian {
		out = []byte{0xFE, 0xFF}
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return out
}

// The prose in front of the key is deliberately not ASCII. Two bytes per
// character everywhere makes a doubled offset and a mapped one the same number,
// so a mapping that is not there passes.
const utf16Prose = "# ключ, вставленный из консоли\nAWS_ACCESS_KEY_ID="

func TestBufferReadsUTF16AndReportsOffsetsIntoTheFile(t *testing.T) {
	ruleset := load(t, awsRule)
	for _, tc := range []struct {
		name      string
		bigEndian bool
	}{
		{"little-endian, which is what Windows PowerShell writes", false},
		{"big-endian", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := encodeUTF16(utf16Prose+key+"\n", tc.bigEndian)
			got, err := Buffer("creds.env", buf, ruleset)
			if err != nil {
				t.Fatalf("Buffer: %v", err)
			}
			if got.Skipped != Scanned {
				t.Fatalf("the buffer was not read: %s", got.Skipped)
			}
			if len(got.Findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(got.Findings), got.Findings)
			}

			// The offset has to name a place in the file, so read the file's own
			// bytes at it. A decoded-buffer offset would land inside the prose
			// and this comparison is what says so.
			at := got.Findings[0].Offset
			want := encodeUTF16(key, tc.bigEndian)[2:]
			if at+len(want) > len(buf) || string(buf[at:at+len(want)]) != string(want) {
				t.Errorf("offset %d does not sit on the key: the file holds %q there,"+
					" and the key encodes to %q",
					at, clip(buf, at, len(want)), string(want))
			}
			// Independently of the walk: two bytes per code unit, after the mark.
			if wantAt := 2 + 2*len(utf16.Encode([]rune(utf16Prose))); at != wantAt {
				t.Errorf("offset is %d, want %d", at, wantAt)
			}
		})
	}
}

// The positive control on the arm above. The same text in UTF-8 is a case whose
// answer is already known -- it is the shape every other test in this package
// scans -- so a UTF-16 arm reporting one finding is the encoding being read
// rather than the rule being loose.
func TestTheUTF16FixtureIsTheSameCaseInUTF8(t *testing.T) {
	ruleset := load(t, awsRule)
	findings := scan(t, "creds.env", utf16Prose+key+"\n", ruleset)
	if len(findings) != 1 {
		t.Fatalf("got %d findings on the UTF-8 fixture, want 1: %+v", len(findings), findings)
	}
	if at := findings[0].Offset; at != len(utf16Prose) {
		t.Errorf("offset is %d, want %d", at, len(utf16Prose))
	}
}

// FF FE 00 00 opens with the whole UTF-16LE mark. Read as UTF-16 it decodes to
// interleaved NULs and reports offsets into a buffer that does not describe the
// file, so the longer mark has to win.
func TestBufferRefusesUTF32RatherThanReadingItAsUTF16(t *testing.T) {
	ruleset := load(t, awsRule)
	for _, tc := range []struct {
		name      string
		bom       []byte
		bigEndian bool
	}{
		{"little-endian", []byte{0xFF, 0xFE, 0x00, 0x00}, false},
		{"big-endian", []byte{0x00, 0x00, 0xFE, 0xFF}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := tc.bom
			for _, r := range "AWS_ACCESS_KEY_ID=" + key {
				if tc.bigEndian {
					buf = append(buf, byte(r>>24), byte(r>>16), byte(r>>8), byte(r))
				} else {
					buf = append(buf, byte(r), byte(r>>8), byte(r>>16), byte(r>>24))
				}
			}
			got, err := Buffer("creds.env", buf, ruleset)
			if err != nil {
				t.Fatalf("Buffer: %v", err)
			}
			if got.Skipped != SkippedUTF32 {
				t.Errorf("Skipped is %q, want %q", got.Skipped, SkippedUTF32)
			}
			if len(got.Findings) != 0 {
				t.Errorf("an unread buffer produced %+v", got.Findings)
			}
		})
	}
}

// UTF-16 with no mark is the gap the mark leaves standing, and it has to be a
// stated one: nothing in the bytes declares the encoding, so this reports the
// binary skip the NUL check actually took.
func TestBOMlessUTF16IsSkippedAndNamed(t *testing.T) {
	ruleset := load(t, awsRule)
	got, err := Buffer("creds.env", encodeUTF16(key, false)[2:], ruleset)
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if got.Skipped != SkippedBinary {
		t.Errorf("Skipped is %q, want %q", got.Skipped, SkippedBinary)
	}
}

func TestDecodeUTF16(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
		want string
	}{
		{"ascii", []byte{'a', 0, 'b', 0}, "ab"},
		{"outside the basic plane, as a surrogate pair",
			[]byte{0x3D, 0xD8, 0x00, 0xDE}, "\U0001F600"},
		{"a high surrogate with nothing after it",
			[]byte{0x3D, 0xD8}, "�"},
		{"a high surrogate followed by an ordinary character",
			[]byte{0x3D, 0xD8, 'a', 0}, "�a"},
		{"a low surrogate first", []byte{0x00, 0xDC, 'a', 0}, "�a"},
		{"a trailing odd byte, which is half of nothing",
			[]byte{'a', 0, 'b'}, "a"},
		{"empty", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(decodeUTF16(tc.buf, false)); got != tc.want {
				t.Errorf("decodeUTF16(%v) = %q, want %q", tc.buf, got, tc.want)
			}
		})
	}
}

// decodeUTF16 and utf16Source are one walk so that they cannot disagree. This
// is that claim made checkable: every byte of the decoded buffer maps back to
// the code unit it came out of.
func TestUTF16SourceAgreesWithTheDecodeAtEveryByte(t *testing.T) {
	const text = "aé中\U0001F600z"
	for _, bigEndian := range []bool{false, true} {
		body := encodeUTF16(text, bigEndian)[2:]
		if got := string(decodeUTF16(body, bigEndian)); got != text {
			t.Fatalf("the fixture does not round-trip: %q", got)
		}
		decoded, source := 0, 0
		for _, r := range text {
			for i := 0; i < utf8.RuneLen(r); i++ {
				if got := utf16Source(body, bigEndian, decoded+i); got != source {
					t.Errorf("bigEndian=%v: decoded byte %d of %q maps to %d, want %d",
						bigEndian, decoded+i, string(r), got, source)
				}
			}
			decoded += utf8.RuneLen(r)
			source += 2 * len(utf16.Encode([]rune{r}))
		}
	}
}

// The corpus half of the same assertion, over a file on disk rather than a
// fixture assembled in memory. The gate walks this file too; what it cannot see
// is where in it the finding points.
func TestThePlantedUTF16FixtureReportsAnOffsetIntoItself(t *testing.T) {
	name := "aws-access-key-id-utf16le.env"
	buf, err := os.ReadFile(filepath.Join(corpusRoot, "planted", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	got, err := Buffer(name, buf, loadShipped(t))
	if err != nil {
		t.Fatalf("scanning %s: %v", name, err)
	}
	if got.Skipped != Scanned {
		t.Fatalf("%s was not read: %s", name, got.Skipped)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got.Findings), got.Findings)
	}
	at := got.Findings[0].Offset
	want := encodeUTF16(key, false)[2:]
	if at+len(want) > len(buf) || string(buf[at:at+len(want)]) != string(want) {
		t.Errorf("offset %d does not sit on the key: %s holds %q there",
			at, name, clip(buf, at, len(want)))
	}
}

// clip is for a failure message, so it reports what is there rather than
// refusing when the offset runs off the end.
func clip(buf []byte, at, n int) string {
	if at > len(buf) {
		return "<past the end of the buffer>"
	}
	return strings.ToValidUTF8(string(buf[at:min(at+n, len(buf))]), "?")
}
