package scan

import "bytes"

// sniffLimit is how much of a buffer IsBinary reads, from
// docs/design/README.md under "Pipeline".
const sniffLimit = 8 << 10

// IsBinary reports whether buf is binary and should be skipped: a NUL byte in
// the first 8 KiB.
//
// This is the cheapest stage and it removes the most work. In the benchmark
// corpus of docs/design/language-choice.md one PNG was 55% of all bytes, and
// the regex pass runs at 1.0 MiB/s.
//
// A NUL byte and nothing else. Reading further, or deciding on a UTF-8
// validity check instead, would take a position the three language prototypes
// already disagreed on: Go keeps raw bytes where Rust and Python substitute
// U+FFFD, so the same file is text in one and not in another.
//
// decode runs ahead of this and hands it whatever came out, so a NUL reaching
// here is a NUL in the text rather than the other half of a UTF-16 character.
// UTF-16 written without a byte-order mark still lands here, and that is the
// remaining gap: nothing in such a buffer declares its encoding, and inferring
// one is the heuristic this check was chosen instead of.
func IsBinary(buf []byte) bool {
	if len(buf) > sniffLimit {
		buf = buf[:sniffLimit]
	}
	return bytes.IndexByte(buf, 0) >= 0
}
