package validate

// An extent is the other half of a check, and the half a bool cannot carry.
//
// A validator is asked whether the bytes a rule captured are a credential. An
// extent is asked where those bytes end, which is a question the regex answers
// today and can only answer within a bound: RE2 caps a repeat at 1000, so a
// pattern that has to reach past one segment of a token to know the token is
// there cannot reach further than a thousand bytes into it. The bound is Go's
// and not the secret's, and a token past it goes unmatched.
//
// So detection and extent come apart. The pattern establishes that something
// starts here, cheaply and within a bound; the extent walks forward from that
// start and says how far the thing runs, in a loop with no ceiling in it. The
// pipeline widens the capture to what the extent returns before any check runs,
// so every check sees the whole of what was found rather than a prefix of it.
//
// An extent may refuse, and that is what lets the pattern be small. Where the
// walk does not find the structure the rule is about, there is no candidate at
// that position at all -- which is the same answer a pattern carrying the whole
// structure would have given, arrived at without a bound.

// jwtSegmentBase64URL reports whether c is a byte a JWS segment is written
// with. RFC 7515 encodes every segment base64url with no padding, so the run is
// exactly this class and a byte outside it is where the token stops.
//
// `=` is deliberately not here. Padding is what RFC 7515 §2 forbids, and a
// trailing `=` after a token is far likelier to be a query string or a shell
// assignment than part of the signature -- so it terminates the walk, which is
// what keeps the extent from reaching into the text after the token.
func jwtSegmentBase64URL(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	}
	return false
}

// The minimum length of each segment, counted the way the shipped pattern
// counts: the header and the payload are `eyJ` plus at least eight more bytes,
// and the signature is at least ten. They are the pattern's own floors, carried
// here because the walk is what enforces them now.
//
// The floors are the whole of what the old bounds said that was not about RE2.
// Their ceilings were the engine's cap and nothing else -- 1,000 was the
// largest number that compiled, not a measurement of how long a token gets --
// so the walk keeps the floors and drops the ceilings.
const (
	jwtMinHeader  = len("eyJ") + 8
	jwtMinPayload = len("eyJ") + 8
	jwtMinSig     = 10
)

// JWTToken returns where the JWT that starts at buf[lo:] ends, or false where no
// whole token starts there.
//
// On a refusal the position it returns is still meaningful, and a caller that
// ignores it pays for it. It is how far the buffer is settled: no start between
// lo and that position can produce a token either, so the caller resumes there
// rather than at the next byte.
//
// That is what keeps the walk linear, and it is not an optimisation the caller
// could make for itself. Every start inside one segment run reaches the *same*
// end of that run, so it meets the same byte after it and the same segment
// after that -- a refusal there is a refusal for all of them, and a later start
// is only ever shorter. Without the skip a buffer of unbroken segment bytes
// carrying a hit every few bytes walks to the end of the run once per hit,
// which is quadratic where the bounded pattern this replaced was linear with a
// large constant. Measured 2026-09-07 on 64 KiB of `-eyJ` repeated, a hit every
// four bytes and every byte in the class: 266 ms without the skip against 578
// ms for the pattern as Q133 shipped it, which reads as a win and is one that
// loses at four times the size.
//
// It reads outside the capture, which is what an extent is for and what
// NearLabel already does in this package. Three segments separated by two dots,
// the first two opening on `eyJ` -- base64url for the `{` that starts the JSON
// object RFC 7519 requires of both -- and each segment at least as long as the
// floor above.
//
// Nothing here is bounded above. That is the point: the walk stops at the first
// byte outside the segment class, wherever that is, so a header or a payload
// carrying more claims than a thousand bytes will hold is measured rather than
// missed.
//
// The signature is the segment whose length is load-bearing for precision, and
// this is why the end has to be exact rather than generous. jwt-sample-key
// recomputes the HMAC over `header.payload` and compares it against the
// signature it was handed; hand it a signature with one byte missing, or one
// byte of the following text, and the comparison fails, the published sample
// stops being recognised as one, and it is reported as a credential. Ending the
// walk at the class boundary is what makes the signature the signature.
func JWTToken(buf []byte, lo int) (int, bool) {
	if lo < 0 || lo >= len(buf) {
		return 0, false
	}
	// The end of the header's run, which is what every refusal below reports:
	// it is the first position after lo that a different token could start at.
	header := jwtRun(buf, lo)
	if header-lo < jwtMinHeader || !jwtOpensOnObject(buf, lo) {
		return header, false
	}
	if header >= len(buf) || buf[header] != '.' {
		return header, false
	}
	payload := jwtRun(buf, header+1)
	if payload-(header+1) < jwtMinPayload || !jwtOpensOnObject(buf, header+1) {
		return header, false
	}
	if payload >= len(buf) || buf[payload] != '.' {
		return header, false
	}
	if end := jwtRun(buf, payload+1); end-(payload+1) >= jwtMinSig {
		return end, true
	}
	return header, false
}

// jwtRun is where the run of segment bytes starting at at ends.
//
// Its only exit is a byte test against a len(buf)-bounded index, which is what
// makes the end of the buffer the *same* terminator as a byte outside the
// class rather than a missing one. A walk with no ceiling is the shape that
// runs off the end of a buffer if its terminator can go absent, and this one's
// cannot -- so the property is about the loop rather than about today's
// callers, and a caller reaching it with a token that runs to EOF gets an end
// at len(buf) instead of a scan that never returns. That distinction is worth
// the sentence here because this scanner's budget blocks on expiry: a hang
// would surface as a verdict, not as a crash.
func jwtRun(buf []byte, at int) int {
	end := at
	for end < len(buf) && jwtSegmentBase64URL(buf[end]) {
		end++
	}
	return end
}

// jwtOpensOnObject reports whether the segment at at is base64url for text
// beginning `{`, which RFC 7519 requires of the header and the payload both.
func jwtOpensOnObject(buf []byte, at int) bool {
	return at+3 <= len(buf) && string(buf[at:at+3]) == "eyJ"
}
