// Package version holds the release version this binary was built as.
//
// It is its own package so the two readers -- the `version` subcommand and the
// coverage record -- take it from one variable that one -X flag sets.
package version

// Version is overridden at release time with -ldflags -X, and is the tag
// without its leading v.
var Version = "dev"
