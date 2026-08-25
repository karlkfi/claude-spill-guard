package scan

import (
	"strings"
	"testing"
)

func TestHasKeyword(t *testing.T) {
	aws := []string{"AKIA", "ASIA", "ABIA", "ACCA", "A3T"}

	for _, tc := range []struct {
		name     string
		buf      string
		keywords []string
		want     bool
	}{
		{"the literal at the head of a real key",
			"AKIAIOSFODNN7EXAMPLE", aws, true},
		{"the literal after whitespace",
			"aws_access_key_id = AKIAIOSFODNN7EXAMPLE", aws, true},
		{"the literal after a quote",
			`{"key": "AKIAIOSFODNN7EXAMPLE"}`, aws, true},
		{"the second keyword in the list",
			"ASIAIOSFODNN7EXAMPLE", aws, true},
		{"lowercase text against an uppercase keyword",
			"akiaiosfodnn7example", aws, true},
		{"a keyword at the very end of the buffer",
			"the prefix is AKIA", aws, true},

		// The measured failure. `strings.Contains` finds `sk-` here, and on the
		// 259-file corpus of docs/design/language-choice.md section 2 two of the
		// three surviving hits were this shape.
		{"a keyword inside a longer word",
			"disk-containerd-0", []string{"sk-"}, false},
		{"a word-byte before an alphanumeric keyword",
			"MYAKIAIOSFODNN7EXAMPLE", aws, false},
		{"an underscore before it, which RE2's \\b counts as a word byte",
			"PREFIX_AKIAIOSFODNN7EXAMPLE", aws, false},
		{"a digit before it",
			"7AKIAIOSFODNN7EXAMPLE", aws, false},
		{"nothing resembling the keyword", "package main", aws, false},
		{"an empty buffer", "", aws, false},
		{"no keywords at all", "AKIAIOSFODNN7EXAMPLE", nil, false},
		{"an empty keyword, which gates nothing rather than everything",
			"package main", []string{""}, false},
		{"a keyword longer than the buffer", "AK", aws, false},

		// A keyword opening on punctuation carries its own boundary, so there
		// is nothing in front of it to require -- and requiring one at the far
		// end instead would reject every key, since the value continues there.
		{"a punctuation-led keyword after a word byte",
			"key=-sk-abcdef", []string{"-sk-"}, true},
		{"a keyword whose value continues into word bytes",
			"AKIAIOSFODNN7EXAMPLE", []string{"AKIA"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasKeyword([]byte(tc.buf), tc.keywords); got != tc.want {
				t.Errorf("hasKeyword(%q, %q) = %v, want %v",
					tc.buf, tc.keywords, got, tc.want)
			}
		})
	}
}

// The prefilter's boundary is not internal/validate's, and label.go's comment
// says so in as many words. This pins the byte the two disagree on, so a later
// reconciliation has to break a test rather than a measurement.
func TestIsWordByteCountsUnderscore(t *testing.T) {
	for _, c := range []byte("_0aZ") {
		if !isWordByte(c) {
			t.Errorf("isWordByte(%q) = false, want true", c)
		}
	}
	for _, c := range []byte("-. \n:/\x00") {
		if isWordByte(c) {
			t.Errorf("isWordByte(%q) = true, want false", c)
		}
	}
}

// One bad keyword destroys the prefilter, and the reason is the boundary: `AC`
// with a word byte in front of it is ordinary prose, and the corpus measurement
// went from 1.2% of files to 18.9% on exactly this.
func TestBroadKeywordStaysBoundedByProse(t *testing.T) {
	prose := "the MAC address, a PLACE, and the FACADE of a REACTOR"
	if hasKeyword([]byte(prose), []string{"AC"}) {
		t.Errorf("hasKeyword(%q, [AC]) = true; every AC there sits behind a "+
			"word byte, which is what the boundary is for", prose)
	}
	if !hasKeyword([]byte("ACCA"+strings.Repeat("X", 16)), []string{"AC"}) {
		t.Error("hasKeyword did not find AC at the head of a word")
	}
}
