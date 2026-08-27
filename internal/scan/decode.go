package scan

import (
	"bytes"
	"unicode/utf16"
	"unicode/utf8"
)

// The byte-order marks this stage reads. A BOM is a declaration the file makes
// about itself rather than an inference drawn from its bytes, which is what
// lets decoding run without reopening the question IsBinary stays out of: no
// side is taken on whether a buffer carrying no mark is text.
//
// The UTF-32 marks are here to be refused by name rather than decoded, and the
// order below is why they are tested first: FF FE 00 00 opens with the whole
// UTF-16LE mark, and the Unicode standard resolves that ambiguity the way this
// does, with the longer mark winning.
//
// Dropping these two cases does not let a UTF-32 file through -- measured, and
// it is the reason to say what the branch buys. Read as UTF-16 the file decodes
// to alternating NULs and the binary check takes it anyway, so what changes is
// the sentence: a user with a UTF-32 file is told the encoding this build does
// not read instead of being told their text is binary, which is a wrong answer
// that happens to end in the right place.
var (
	bomUTF32LE = []byte{0xFF, 0xFE, 0x00, 0x00}
	bomUTF32BE = []byte{0x00, 0x00, 0xFE, 0xFF}
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
)

// decode says what the match loop reads: the bytes to scan, a map from an
// offset in those bytes back to one in buf, and the reason there is nothing to
// scan at all.
//
// The map is the half that is easy to leave out. A finding reports a byte
// offset, and an offset into a decoded buffer is not an offset into the file on
// disk -- reported as one it sends a reader to the wrong place, which is a
// worse answer than the skip it replaces.
func decode(buf []byte) (text []byte, source func(int) int, skip Skip) {
	// Never nil, even on a path the caller is told not to read. A nil here
	// costs a panic, and a panic leaves the process on an exit code the hook
	// contract does not block on -- fail-open, from a defensive omission.
	source = func(at int) int { return at }

	switch {
	case bytes.HasPrefix(buf, bomUTF32LE), bytes.HasPrefix(buf, bomUTF32BE):
		return nil, source, SkippedUTF32
	case bytes.HasPrefix(buf, bomUTF16LE), bytes.HasPrefix(buf, bomUTF16BE):
		mark := len(bomUTF16LE)
		body, bigEndian := buf[mark:], bytes.HasPrefix(buf, bomUTF16BE)
		text = decodeUTF16(body, bigEndian)
		source = func(at int) int { return mark + utf16Source(body, bigEndian, at) }
	default:
		text = buf
	}

	// On the decoded bytes rather than the raw ones. Every ASCII character in a
	// UTF-16 buffer carries a NUL beside it, so reading raw is what made a whole
	// file class binary on its second byte. A NUL surviving the decode is a NUL
	// in the text.
	if IsBinary(text) {
		return nil, source, SkippedBinary
	}
	return text, source, Scanned
}

// utf16Unit reads the UTF-16 code unit at buf[at:at+2].
func utf16Unit(buf []byte, at int, bigEndian bool) rune {
	if bigEndian {
		return rune(buf[at])<<8 | rune(buf[at+1])
	}
	return rune(buf[at+1])<<8 | rune(buf[at])
}

// walkUTF16 calls visit with each rune in buf -- a UTF-16 buffer with its mark
// already removed -- and the offset in buf where that rune starts, stopping
// when visit returns false.
//
// decodeUTF16 and utf16Source are both this walk, which is the point. The two
// have to agree rune for rune or a finding's offset lands where the value is
// not, and agreement by construction is the only kind that cannot drift. Every
// rune handed out is one utf8.EncodeRune and utf8.RuneLen answer identically
// about, so the second is a running total of the first.
func walkUTF16(buf []byte, bigEndian bool, visit func(r rune, at int) bool) {
	// A trailing odd byte falls out of the bound and is dropped. It cannot be
	// half of anything, and the alternative is inventing a rune for it.
	for at := 0; at+1 < len(buf); {
		start := at
		r := utf16Unit(buf, at, bigEndian)
		at += 2
		if utf16.IsSurrogate(r) && at+1 < len(buf) {
			if paired := utf16.DecodeRune(r, utf16Unit(buf, at, bigEndian)); paired != utf8.RuneError {
				r, at = paired, at+2
			}
		}
		if !utf8.ValidRune(r) {
			// An unpaired surrogate, which utf8.EncodeRune would write U+FFFD
			// for anyway. Substituting here is what keeps RuneLen agreeing with
			// it, because RuneLen answers -1 for the same input.
			r = utf8.RuneError
		}
		if !visit(r, start) {
			return
		}
	}
}

// decodeUTF16 decodes buf, a UTF-16 buffer with its mark already removed, to
// UTF-8.
func decodeUTF16(buf []byte, bigEndian bool) []byte {
	// One output byte per code unit is exact for the ASCII-in-UTF-16 this stage
	// exists for, and a floor for everything else.
	out := make([]byte, 0, len(buf)/2)
	walkUTF16(buf, bigEndian, func(r rune, _ int) bool {
		out = utf8.AppendRune(out, r)
		return true
	})
	return out
}

// utf16Source maps an offset in what decodeUTF16 returned back to the offset in
// buf of the rune that produced it.
//
// The walk is linear in the offset and runs once per finding rather than once
// per buffer. Findings are rare by construction -- the clean corpus is pinned
// at zero -- so an index making this constant-time would charge every buffer to
// save the few that report anything.
func utf16Source(buf []byte, bigEndian bool, offset int) int {
	source, decoded := len(buf), 0
	walkUTF16(buf, bigEndian, func(r rune, at int) bool {
		decoded += utf8.RuneLen(r)
		if offset < decoded {
			source = at
			return false
		}
		return true
	})
	return source
}
