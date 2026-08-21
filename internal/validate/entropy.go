package validate

import "math"

// Shannon returns the entropy of s in bits per byte, over the byte frequencies
// of s itself. Bytes rather than runes: the credentials this gates are ASCII
// base64, hex and base58, and a byte count is what "bits per character" means
// for them.
//
// The ceiling is log2 of the number of distinct bytes, so it is bounded by
// length as well as by content: no 8-character candidate can exceed 3 bits, and
// a floor above that rejects every rule whose captured group is that short.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// EntropyAtLeast reports whether s carries at least min bits per byte.
//
// The empty string has zero entropy, so any positive floor drops it. A rule
// with no floor omits the field and never calls this.
func EntropyAtLeast(s string, min float64) bool {
	return Shannon(s) >= min
}
