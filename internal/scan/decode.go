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
// the sentence a user gets: the encoding this build does not read, instead of a
// NUL in their decoded text, which is a wrong answer that ends in the right
// place.
//
// It is only the sentence now. FF FE 00 00 is genuinely both marks, so which
// one wins here used to decide block against allow -- the UTF-32 arm blocks and
// the binary skip does not. Since the UTF-16 arm returns SkippedUTF16Binary the
// two readings agree on the verdict and disagree only about which encoding to
// name, which is the most an ambiguity the standard leaves open should ever
// cost. TestAUTF16NULIsNamedAsDeclaredWhereverItSits is the pair.
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

		// The sniff window before the rest of it. IsBinary is the cheapest
		// stage and it is here to keep the expensive ones off work they do not
		// need to do, so decoding a whole buffer to find out whether to skip it
		// inverts the one thing the pipeline's order is for. Measured
		// 2026-08-27 on a 64 MiB UTF-16 buffer whose fourth character is a NUL:
		// 189 ms and 32 MiB allocated, every byte of it discarded, to learn
		// what the first four bytes said.
		//
		// A prefix is the same answer, not an approximation of it: IsBinary
		// reads at most sniffLimit bytes, so any prefix reaching sniffLimit
		// decides identically to the whole buffer.
		if IsBinary(decodeUTF16(body, bigEndian, sniffLimit)) {
			// Not SkippedBinary. The check is the same one; the buffer that
			// failed it declared an encoding first, and the constant is where
			// that survives -- see its comment for the two things keyed on it.
			return nil, source, SkippedUTF16Binary
		}
		return decodeUTF16(body, bigEndian, noLimit),
			func(at int) int { return mark + utf16Source(body, bigEndian, at) },
			Scanned

	default:
		// On the raw bytes, which is all there is for anything the arms above
		// did not decode. Every ASCII character in a UTF-16 buffer carries a NUL
		// beside it, so this is where UTF-16 written without a mark still lands.
		//
		// Not only undeclared buffers. A UTF-8 byte-order mark, EF BB BF,
		// declares an encoding and has no arm, so it lands here too and its NUL
		// is read raw -- measured, and allowed in silence. That is a fail-open
		// this stage owns and a row carries; it is named here so the comment
		// does not read as a claim that everything below is undeclared.
		if IsBinary(buf) {
			return nil, source, SkippedBinary
		}
		return buf, source, Scanned
	}
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

// noLimit decodes the whole buffer, for the limit argument below.
const noLimit = -1

// decodeUTF16 decodes buf, a UTF-16 buffer with its mark already removed, to
// UTF-8, stopping once the output reaches limit bytes.
//
// It stops after the rune that reaches the limit rather than before it, so the
// result is at least limit bytes whenever the input holds that much. That is
// the direction the caller needs: a prefix shorter than sniffLimit would decide
// on less than IsBinary reads.
func decodeUTF16(buf []byte, bigEndian bool, limit int) []byte {
	// One output byte per code unit is exact for the ASCII-in-UTF-16 this stage
	// exists for, and a floor for everything else.
	size := len(buf) / 2
	if limit >= 0 && limit < size {
		size = limit
	}
	out := make([]byte, 0, size)
	walkUTF16(buf, bigEndian, func(r rune, _ int) bool {
		out = utf8.AppendRune(out, r)
		return limit < 0 || len(out) < limit
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
