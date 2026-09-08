package validate

import (
	"strings"
	"testing"
)

// token is a JWT whose three segments are exactly the lengths given. The first
// two open on `eyJ` because the format requires it, so the shortest either can
// be is eleven.
func token(header, payload, sig int) string {
	seg := func(n int) string { return "eyJ" + strings.Repeat("a", n-3) }
	return seg(header) + "." + seg(payload) + "." + strings.Repeat("b", sig)
}

// The walk has no upper bound, which is the whole of what this replaces. RE2
// caps a bounded repeat at 1000, so the pattern that used to carry the
// structure could not reach past 1,003 bytes into a segment -- driven, {8,1000}
// compiles and {8,1001} does not -- and a token with more claims than that went
// unmatched. None of these lengths is expressible in one bounded repeat.
func TestTheExtentHasNoCeiling(t *testing.T) {
	for _, tc := range []struct{ header, payload, sig int }{
		{36, 74, 43},
		{36, 1004, 43},   // one past the old segment ceiling
		{1004, 74, 43},   // the same, on the header
		{36, 20000, 43},  // a production access token with many claims
		{9000, 9000, 90}, // and both at once
	} {
		tok := token(tc.header, tc.payload, tc.sig)
		got, ok := JWTToken([]byte(tok), 0)
		if !ok {
			t.Errorf("header %d, payload %d, signature %d: no extent",
				tc.header, tc.payload, tc.sig)
			continue
		}
		if got != len(tok) {
			t.Errorf("header %d, payload %d, signature %d: extent ends at %d, want %d",
				tc.header, tc.payload, tc.sig, got, len(tok))
		}
	}
}

// Where the token ends is the half that decides precision, so it is driven
// against every byte class that can follow one rather than argued.
//
// The signature is the segment that makes this load-bearing. NotSampleJWT
// recomputes the HMAC over `header.payload` and compares it against the
// signature it was handed, so an end one byte short or one byte long is a
// comparison that fails, a published sample that stops being recognised, and a
// finding reported over a token anyone can look up. That failure is driven in
// TestATruncatedSignatureUnsuppressesAPublishedSample; this is what stops it
// arising.
func TestTheExtentEndsWhereTheTokenDoes(t *testing.T) {
	tok := token(36, 74, 43)
	for _, tail := range []struct {
		name string
		text string
	}{
		{"end of buffer", ""},
		{"newline", "\n"},
		{"space", " "},
		{"double quote", `"`},
		{"single quote", "'"},
		{"comma", ","},
		{"close paren", ")"},
		{"semicolon", ";"},
		// A sentence ending on the token. The dot is in no segment, and a walk
		// that took it would hand the checks a signature with a `.` on the end.
		{"full stop", "."},
		// Padding, which RFC 7515 forbids: far likelier a query string or a
		// shell assignment than part of the signature.
		{"equals", "="},
		{"backslash", "\\"},
		{"less than", "<"},
	} {
		t.Run(tail.name, func(t *testing.T) {
			got, ok := JWTToken([]byte(tok+tail.text), 0)
			if !ok {
				t.Fatal("no extent")
			}
			if got != len(tok) {
				t.Errorf("extent ends at %d, want %d -- it reached %q",
					got, len(tok), (tok + tail.text)[len(tok):got])
			}
		})
	}
}

// What the extent refuses, which is what makes the eleven-byte pattern in front
// of it safe to be that small. `eyJ` is base64url for the `{` any JSON object
// opens on, so it heads every encoded object in a tree and not only a token;
// the walk is the whole of what separates the two.
//
// The floors are the pattern's own, carried over: `eyJ` plus eight for the
// header and the payload, ten for the signature. They are the half of the old
// bounds that was about JWTs rather than about RE2.
func TestTheExtentRefusesWhatIsNotAWholeToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"a bare encoded object", "eyJhbGciOiJIUzI1NiJ9"},
		{"two segments and no signature", "eyJhbGciOiJIUzI1NiJ9.eyJhbGciOiJIUzI1"},
		{"a payload that is not an object", "eyJhbGciOiJIUzI1NiJ9.YWFhYWFhYWFh.bbbbbbbbbb"},
		{"a header under the floor", "eyJhbGci.eyJhbGciOiJIUzI1NiJ9.bbbbbbbbbb"},
		{"a payload under the floor", "eyJhbGciOiJIUzI1NiJ9.eyJhbGci.bbbbbbbbbb"},
		{"a signature under the floor", "eyJhbGciOiJIUzI1NiJ9.eyJhbGciOiJIUzI1NiJ9.bbbbbbbbb"},
		{"a dot where the payload should start", "eyJhbGciOiJIUzI1NiJ9..bbbbbbbbbb"},
		{"nothing at all", ""},
		{"not a token", "hello, world"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := JWTToken([]byte(tc.text), 0); ok {
				t.Errorf("extent ends at %d, want a refusal", got)
			}
		})
	}
}

// An extent is asked about a position, and a caller passing one outside the
// buffer is a bug this must not turn into a panic: internal/scan calls it from
// the match loop, and a panic leaves the process on an exit code the hook
// contract does not block on, which is the fail-open shape the whole tool is
// about.
func TestTheExtentRefusesAPositionOutsideTheBuffer(t *testing.T) {
	buf := []byte(token(36, 74, 43))
	for _, at := range []int{-1, len(buf), len(buf) + 1, len(buf) + 1000} {
		if _, ok := JWTToken(buf, at); ok {
			t.Errorf("at %d: an extent, want a refusal", at)
		}
	}
}
