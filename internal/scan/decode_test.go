package scan

import (
	"os"
	"path/filepath"
	"runtime"
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
			if got := string(decodeUTF16(tc.buf, false, noLimit)); got != tc.want {
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
		if got := string(decodeUTF16(body, bigEndian, noLimit)); got != text {
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

// utf16FixtureKey is the planted UTF-16 file's own value, and it is deliberately
// not the one in aws-access-key-id.env beside it. Two fixtures sharing a literal
// makes every edit to one a silent break in the other, and testdata/corpus's own
// convention is a fabricated value per file.
//
// A planted fixture has to be found, so it cannot be marked by the string the
// ruleset rejects: AKIAIOSFODNN7EXAMPLE -- which `key` above still uses, and
// which is right there, because a unit test needs a regex match rather than
// every validator -- is dropped by aws-placeholder. This value carries the
// project's name instead, which a reader of a public security repo can grep
// and no issued credential would hold. It matters more here than elsewhere:
// the fixture has to be decoded before it can be read at all.
//
// The 0, 1, 8 and 9 are a second and weaker signal, resting on a base32
// property of real key IDs that nobody here has verified.
// testdata/corpus/README.md carries what was and was not measured, and why the
// rule stops at planted/.
//
// Shannon 3.7842 against the rule's floor of 3.0, and no EXAMPLE suffix, so
// aws-placeholder passes it once that check lands.
const utf16FixtureKey = "AKIA0SPILLGUARD98107"

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
	want := encodeUTF16(utf16FixtureKey, false)[2:]
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

func TestDecodeUTF16StopsAtTheLimit(t *testing.T) {
	// Three bytes out per rune, so no limit lands on a rune boundary and the
	// "at least" half of the contract is what is under test.
	body := encodeUTF16(strings.Repeat("é", 100), false)[2:]
	full := len(decodeUTF16(body, false, noLimit))
	for _, limit := range []int{0, 1, 5, 199, 200, 201} {
		got := len(decodeUTF16(body, false, limit))
		// The floor holds only where the buffer has that much to give. Past
		// that the input is exhausted, which is not the limit stopping short.
		if limit <= full && got < limit {
			t.Errorf("limit %d produced %d bytes, which is short -- a prefix "+
				"under the limit decides on less than IsBinary would read", limit, got)
		}
		if limit > full && got != full {
			t.Errorf("limit %d is past the %d bytes this buffer holds, and it "+
				"produced %d", limit, full, got)
		}
		if got > limit+utf8.UTFMax {
			t.Errorf("limit %d produced %d bytes, more than one rune past it", limit, got)
		}
	}
	if want := 200; full != want {
		t.Errorf("noLimit produced %d bytes, want %d", full, want)
	}
}

// A UTF-16 buffer whose text really does hold a NUL is binary, and the decode
// is what makes that a statement about the text rather than about the encoding.
func TestBufferSkipsAUTF16BufferThatDecodesToBinary(t *testing.T) {
	// Not at the very start: FF FE 00 00 is the UTF-32LE mark and takes another
	// branch, which is a different assertion.
	buf := append(encodeUTF16("a", false), 0x00, 0x00)
	got, err := Buffer("a.bin", buf, load(t, awsRule))
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if got.Skipped != SkippedBinary {
		t.Errorf("Skipped is %q, want %q", got.Skipped, SkippedBinary)
	}
}

// The other side of it: a NUL past the sniff window does not skip, and the text
// after the window is still decoded. Together with the test above this pins
// that the prefix decides and the whole buffer is what gets scanned.
func TestBufferReadsPastTheSniffWindowInAUTF16Buffer(t *testing.T) {
	text := strings.Repeat("a", sniffLimit+1) + "\x00" + key
	got, err := Buffer("a.env", encodeUTF16(text, false), load(t, awsRule))
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if got.Skipped != Scanned {
		t.Fatalf("Skipped is %q, want Scanned -- a NUL past the sniff window "+
			"is not what the window reads", got.Skipped)
	}
	if len(got.Findings) != 1 {
		t.Errorf("got %d findings, want 1 -- the buffer past the window was not "+
			"decoded", len(got.Findings))
	}
}

// A key past the sniff window, which every other offset assertion here is too
// small to reach.
//
// The limit that stops the decode at the window is threaded through decode, and
// the inversion that proves it exists -- restore noLimit -- cannot prove it is
// in the right place, because with noLimit the whole package is consistent
// again. Thread it into utf16Source as well and that walk covers a prefix
// rather than the body, so every offset past the window collapses to the
// prefix's length and nothing under 8 KiB notices. Written by
// sharp-tu-3b9ae2-41 in review of this PR and reproduced here.
func TestUTF16OffsetsHoldPastTheSniffWindow(t *testing.T) {
	prose := strings.Repeat("# padding, ключ ниже\n", 900) + "AWS_ACCESS_KEY_ID="
	buf := encodeUTF16(prose+key+"\n", false)

	// Both preconditions carry weight. The first says the file reaches past the
	// window; the second says the *decoded* key does, and it is the second that
	// makes the map do work a prefix walk cannot fake.
	if size := 2 * len(utf16.Encode([]rune(prose+key+"\n"))); size <= sniffLimit {
		t.Fatalf("the fixture body is %d bytes, inside the %d-byte window -- "+
			"this test would pass on a prefix walk", size, sniffLimit)
	}
	if at := len(prose); at <= sniffLimit {
		t.Fatalf("the key decodes at %d, inside the %d-byte window", at, sniffLimit)
	}

	got, err := Buffer("creds.env", buf, load(t, awsRule))
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if got.Skipped != Scanned {
		t.Fatalf("the buffer was not read: %s", got.Skipped)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(got.Findings))
	}

	at, want := got.Findings[0].Offset, encodeUTF16(key, false)[2:]
	t.Logf("file %d bytes, key decodes at %d, reported file offset %d",
		len(buf), len(prose), at)
	if at+len(want) > len(buf) || string(buf[at:at+len(want)]) != string(want) {
		t.Errorf("offset %d does not sit on the key: the file holds %q there",
			at, clip(buf, at, len(want)))
	}
	if wantAt := 2 + 2*len(utf16.Encode([]rune(prose))); at != wantAt {
		t.Errorf("offset is %d, want %d", at, wantAt)
	}
}

// The sniff window is decoded before the rest of the buffer, and this is what
// says so. Both halves are needed: the buffer is large, and the answer is in
// its first few bytes, so a decode that reads it all allocates on the order of
// the buffer while one that stops at the window allocates on the order of the
// window.
//
// The bound is loose deliberately. It is separating two magnitudes -- 8 KiB
// against 32 MiB -- rather than measuring an allocator, and a tight bound here
// would be a flake waiting for a Go release.
func TestDecodeSniffsBeforeDecodingTheRest(t *testing.T) {
	const size = 64 << 20
	buf := make([]byte, 0, size)
	buf = append(buf, 0xFF, 0xFE)
	buf = append(buf, 'a', 0x00, 0x00, 0x00) // one character, then a real NUL
	for len(buf) < size {
		buf = append(buf, 'a', 0x00)
	}

	// The control. Without it a small allocation reads as the sniff working
	// when it could just as well be a buffer that was never large.
	if full := len(decodeUTF16(buf[2:], false, noLimit)); full < 8<<20 {
		t.Fatalf("a full decode of the fixture is %d bytes, which is not large "+
			"enough for the bound below to separate anything", full)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	text, _, skip := decode(buf)
	runtime.ReadMemStats(&after)

	if skip != SkippedBinary {
		t.Fatalf("skip is %q, want %q -- nothing is being saved", skip, SkippedBinary)
	}
	if text != nil {
		t.Errorf("a skipped buffer came back with %d bytes of text", len(text))
	}
	const bound = 1 << 20
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > bound {
		t.Errorf("deciding to skip a %d-byte buffer allocated %d bytes, over a "+
			"bound of %d -- the whole buffer is being decoded before the sniff "+
			"reads its first 8 KiB", len(buf), allocated, bound)
	}
}
