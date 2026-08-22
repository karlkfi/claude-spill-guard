package validate

import "testing"

// The survivors carry the claim here. A denylist tested only on the numbers it
// lists passes for a function that returns false, and the failure that would
// hide behind it -- a real card silently dropped -- is invisible from the
// outside: the scanner reports nothing, which is what it reports when a file is
// clean.
//
// Every survivor below was constructed here rather than lifted from anywhere: a
// body chosen or perturbed, then the one check digit that makes Luhn accept it.
// None of them appears in either table publishedTestCards is drawn from.
func TestNotPlaceholderCard(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{"the Visa number every payments README carries", "4111111111111111", false},
		{"Stripe's Visa number", "4242424242424242", false},
		{"a Mastercard test number", "5555555555554444", false},
		{"an Amex test number, 15 digits", "378282246310005", false},
		{"a Diners Club test number, 14 digits", "36227206271667", false},
		{"a UnionPay test number, 19 digits", "6205500000000000004", false},
		{"spaces, as a card is written", "4111 1111 1111 1111", false},
		{"hyphens, as a card is written", "4111-1111-1111-1111", false},

		{"sixteen zeros, which Luhn accepts", "0000000000000000", false},
		{"twelve zeros", "000000000000", false},
		{"a run of eights Luhn accepts", "8888888888888888", false},
		{"a run of twos at seventeen digits", "22222222222222222", false},
		{"a run of sixes at thirteen digits", "6666666666666", false},
		{"a run of zeros written with spaces", "0000 0000 0000 0000", false},

		{"a constructed Visa sharing a BIN with a listed number", "4012345678901239", true},
		// Without these two, every separator case above is a candidate that
		// wants dropping anyway, so treating ' ' and '-' as malformed rather
		// than stripping them would pass the whole table.
		{"a survivor written with spaces", "4012 3456 7890 1239", true},
		{"a survivor written with hyphens", "4012-3456-7890-1239", true},
		{"a constructed Mastercard", "5198765432109873", true},
		{"a constructed Amex, 15 digits", "378765432109876", true},
		{"one interior digit off the Visa test number", "4111111111111210", true},
		{"the Visa test number with a digit appended", "41111111111111113", true},
		{"the Amex test number with a digit appended", "3782822463100052", true},
		{"fifteen of sixteen digits the same, and unpublished", "1711111111111111", true},

		{"an empty candidate", "", false},
		{"a hex string a card regex must never reach", "4111111111111abc", false},
		{"dots, which are not the separators a card is written with", "4111.1111.1111.1111", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NotPlaceholderCard(tc.candidate); got != tc.want {
				t.Errorf("NotPlaceholderCard(%q) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}

// A card rule runs Luhn first, so an entry Luhn rejects is one this map can
// never be asked about. Nothing at runtime would notice: the dead entry sits
// there reading as coverage. This doubles as the transcription check on the
// list, and a strong one -- Luhn detects every single-digit error, and the only
// adjacent transposition it misses is 0 for 9.
func TestEveryDenylistEntryPassesLuhn(t *testing.T) {
	if len(publishedTestCards) == 0 {
		t.Fatal("publishedTestCards is empty; every other assertion here passes over nothing")
	}
	for card := range publishedTestCards {
		if !Luhn(card) {
			t.Errorf("Luhn(%q) = false; a denylist entry Luhn rejects is unreachable", card)
		}
	}
}

// The published numbers are dropped because they are listed, and the runs
// because they repeat. Neither reason should be doing the other's work, or
// removing one of them would go unnoticed.
func TestTheTwoReasonsAreSeparate(t *testing.T) {
	for card := range publishedTestCards {
		if repeatedDigit(card) {
			t.Errorf("%q is a repeated run, so listing it proves nothing", card)
		}
	}
	if publishedTestCards["0000000000000000"] {
		t.Error("sixteen zeros is listed; the degenerate rule is then untested by it")
	}
}
