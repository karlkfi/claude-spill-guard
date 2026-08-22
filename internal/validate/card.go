package validate

// publishedTestCards is the numbers a payment gateway hands a developer to
// paste into a sandbox. Every one of them passes Luhn -- they are built to --
// so a card rule naming only the checksum reports each of them as a finding.
//
// The list is the union of two primary "valid test card" tables, read
// 2026-08-22: Stripe's testing page (18 rows) and Braintree's (19), which share
// three entries. Gateway documentation rather than the networks' own, because a
// gateway's sandbox page is where the copy in a README came from.
//
// That table is the boundary, and the pages around it are not. Stripe alone
// publishes 149 distinct numbers once the decline, 3-D Secure and per-country
// matrices are counted, 148 of which pass Luhn, and the next gateway starts the
// argument again. What the rest cost is a measurement against the precision
// corpus rather than a guess here -- Q33 carries it.
//
// A number that fails Luhn is not listed, because nothing can reach here
// without passing one first. Stripe publishes exactly one, 4242424242424241,
// whose whole purpose is to fail the checksum.
var publishedTestCards = map[string]bool{
	// Visa
	"4000056655665556": true,
	"4005519200000004": true,
	"4009348888881881": true,
	"4012000033330026": true,
	"4012000077777777": true,
	"4012888888881881": true,
	"4111111111111111": true,
	"4217651111111119": true,
	"4242424242424242": true,
	"4500600000000061": true,

	// Mastercard
	"2223000048400011": true,
	"2223003122003222": true,
	"5105105105105100": true,
	"5200828282828210": true,
	"5555555555554444": true,

	// American Express, 15 digits
	"371449635398431": true,
	"378282246310005": true,

	// Discover
	"6011000990139424": true,
	"6011000991300009": true,
	"6011111111111117": true,
	"6011981111111113": true,

	// Diners Club, 14 and 16 digits
	"36227206271667":   true,
	"36259600000004":   true,
	"3056930009020004": true,

	// JCB
	"3530111333300000": true,
	"3566002020360505": true,

	// UnionPay, including a 19-digit number
	"6200000000000005":    true,
	"6200000000000047":    true,
	"6205500000000000004": true,
	"6221261111117766":    true,
	"6223164991230014":    true,
	"6243030000000001":    true,

	// Maestro
	"6304000000000000": true,

	// BCcard and DinaCard
	"6555900000604105": true,
}

// NotPlaceholderCard reports whether a payment card candidate is something
// other than a published test number or a run of one repeated digit.
//
// This is the second check a card rule names, beside Luhn. Luhn is a
// transcription check, so it accepts every number constructed to pass one --
// and those are the numbers a scanner meets. A rule naming the checksum alone
// flags every payments README it reads, which is the shape the inherited
// ruleset failed on: a check that looks discriminating, a rule that fires on
// documentation, and a reader who stops looking at the output.
//
// Separators are stripped first, exactly as Luhn strips them, so
// 4111 1111 1111 1111 is dropped and not merely 4111111111111111. Comparison is
// against the whole digit string: a listed number with a digit appended is a
// different candidate and survives.
//
// The degenerate rule is a run of one digit at any length, not a special case
// for zeros. Luhn accepts 13 of the 80 such runs between 12 and 19 digits --
// every length of zeros, plus 888888888888, 6666666666666, 8888888888888888,
// 22222222222222222 and 44444444444444444 -- so pinning 0000000000000000 on its
// own leaves five shapes through.
//
// The polarity is the package's: true means the candidate survives. A candidate
// carrying anything but digits and separators is malformed and returns false,
// so !NotPlaceholderCard(s) does not mean "s is a placeholder".
func NotPlaceholderCard(candidate string) bool {
	digits := cardDigits(candidate)
	if digits == "" || publishedTestCards[digits] {
		return false
	}
	return !repeatedDigit(digits)
}

// cardDigits strips the separators a card is written with and returns "" if
// anything else is present, which is the same reading of malformed that Luhn
// takes.
func cardDigits(candidate string) string {
	digits := make([]byte, 0, len(candidate))
	for i := 0; i < len(candidate); i++ {
		switch c := candidate[i]; {
		case c == ' ' || c == '-':
		case c >= '0' && c <= '9':
			digits = append(digits, c)
		default:
			return ""
		}
	}
	return string(digits)
}

// repeatedDigit reports whether every digit is the same one. A single digit is
// a run of one, and the empty string never reaches here.
func repeatedDigit(digits string) bool {
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			return false
		}
	}
	return true
}
