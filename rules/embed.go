// Package rules carries the shipped ruleset as bytes compiled into the binary,
// which is how docs/design/distribution.md settles version skew: a binary and
// a ruleset that cannot be separated cannot disagree.
//
// It is a package because `go:embed` reaches only inside its own directory --
// no `..` -- and the ruleset's location is fixed at rules/spill-guard.json,
// where it stays a JSON file somebody authors and reviews as JSON. So the
// directive comes to the data.
//
// internal/rules is the loader and this is the payload. Both are called
// `rules`; internal/hook imports this one as `embedded`.
package rules

import _ "embed"

// Shipped is rules/spill-guard.json verbatim, for internal/rules to decode.
//
//go:embed spill-guard.json
var Shipped []byte
