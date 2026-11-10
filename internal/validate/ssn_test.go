package validate

import "testing"

// Every survivor is in area 000, which this check keeps by design and SSA never
// assigns, so the table holds no number anyone could have been issued. That
// costs it one direction: nothing here shows a near miss of 123-45-6789 in an
// issued area surviving.
func TestNotPlaceholderSSN(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{"the Woolworth wallet card", "078-05-1120", false},
		{"the 1940 pamphlet", "219-09-9999", false},
		{"the form-documentation example", "123-45-6789", false},
		{"area 666", "666-12-3456", false},
		{"group 00", "512-00-3456", false},
		{"serial 0000", "512-34-0000", false},
		{"all zeros", "000-00-0000", false},
		{"a run of ones", "111-11-1111", false},
		{"a run of eights", "888-88-8888", false},

		{"area 000, kept for the planted fixture", "000-12-3456", true},
		// Without these, a check on the last seven digits alone, or on group
		// and serial alone, would pass the three example rows above.
		{"the wallet card's group and serial in area 000", "000-05-1120", true},
		{"the documentation example's group and serial in area 000", "000-45-6789", true},
		{"one zero group digit is not group 00", "000-01-1111", true},

		{"no hyphens", "000123456", false},
		{"a letter", "000-12-345x", false},
		{"too long", "000-12-34567", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NotPlaceholderSSN(tc.candidate); got != tc.want {
				t.Errorf("NotPlaceholderSSN(%q) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}
