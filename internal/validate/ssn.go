package validate

// exampleNumbers is the published examples that format fixtures reach for. None
// is a never-assigned shape, so NotPlaceholderSSN has to name them.
//
// 078-05-1120 was printed on the sample card sold in Woolworth wallets from
// 1938, and 219-09-9999 in a 1940 Social Security Board pamphlet; both were
// claimed as real by enough people that SSA voided them. 123-45-6789 is the
// example in nearly every form's documentation. All three read from secondary
// sources, because ssa.gov's history pages return 403 here, and each was found
// labelled in real files: rules/README.md has the census.
var exampleNumbers = map[string]bool{
	"078-05-1120": true,
	"219-09-9999": true,
	"123-45-6789": true,
}

// NotPlaceholderSSN reports whether a us-ssn candidate, written ###-##-####, is
// something other than a published example, a run of one repeated digit, or a
// number SSA never assigns.
//
// SSA's own manual, POMS RM 10201.035, calls an SSN invalid when its area is
// 000, 666 or in the 900s, its group 00, or its serial 0000. The rule's regex
// already refuses the 900s. Area 000 is the one shape left to survive here, on
// purpose: the planted fixture has to be a value the rule finds and no one can
// hold, and over the 82 hit files the census read, keeping 000 matched blocked
// none that dropping it would have cleared, where keeping 666 blocked 8.
//
// The polarity is the package's: true means the candidate survives. Anything
// but nine digits in that layout is malformed and returns false.
func NotPlaceholderSSN(candidate string) bool {
	if len(candidate) != 11 || candidate[3] != '-' || candidate[6] != '-' {
		return false
	}
	area, group, serial := candidate[:3], candidate[4:6], candidate[7:]
	digits := area + group + serial
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	if area == "666" || group == "00" || serial == "0000" || exampleNumbers[candidate] {
		return false
	}
	return !repeatedDigit(digits)
}
