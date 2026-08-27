package validate

import "strings"

// awsExampleSuffix is how AWS marks a key ID in its own documentation:
// AKIAIOSFODNN7EXAMPLE on the IAM pages, ASIAIOSFODNN7EXAMPLE on the STS ones.
// The secret printed beside them, wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY,
// carries the same mark and is not suffixed by it -- no rule here matches an
// AWS secret, so nothing tests that string against this constant.
const awsExampleSuffix = "EXAMPLE"

// NotPlaceholderAWSKeyID reports whether an AWS access key ID candidate is
// something other than a value AWS publishes in its own documentation.
//
// This is the second check aws-access-key-id names, beside its entropy floor.
// The floor drops AKIAXXXXXXXXXXXXXXXX at 1.0219 bits per byte; AWS's own
// example measures 3.6842 against a floor of 3.0 and clears it by design,
// because it was written to look like a key. rules/README.md carries the
// measurement, and the argument for a suffix rather than a table.
//
// The polarity is the package's: true means the candidate survives.
func NotPlaceholderAWSKeyID(candidate string) bool {
	return !strings.HasSuffix(candidate, awsExampleSuffix)
}
