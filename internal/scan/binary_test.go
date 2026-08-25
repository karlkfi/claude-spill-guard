package scan

import (
	"bytes"
	"testing"
)

func TestIsBinary(t *testing.T) {
	text := bytes.Repeat([]byte("package main\n"), 2000)
	if len(text) <= sniffLimit {
		t.Fatalf("the fixture is %d bytes, which does not reach past the sniff "+
			"limit of %d -- the cases below would not be testing the bound",
			len(text), sniffLimit)
	}

	withNULAt := func(at int) []byte {
		buf := append([]byte(nil), text...)
		buf[at] = 0
		return buf
	}

	for _, tc := range []struct {
		name string
		buf  []byte
		want bool
	}{
		{"ordinary source", text, false},
		{"empty", nil, false},
		{"a NUL at the very first byte", withNULAt(0), true},
		{"a NUL at the last byte the sniff reads", withNULAt(sniffLimit - 1), true},
		{"a NUL one byte past it", withNULAt(sniffLimit), false},
		{"a NUL far past it", withNULAt(len(text) - 1), false},
		{"a PNG header", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), true},
		{"UTF-8 that is not ASCII", []byte("клавиша = «ключ»\n"), false},
		{"a buffer shorter than the sniff limit, with a NUL", []byte("a\x00b"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBinary(tc.buf); got != tc.want {
				t.Errorf("IsBinary(...) = %v, want %v", got, tc.want)
			}
		})
	}
}
