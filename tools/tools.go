//go:build tools

// Package tools pins the versions of the command-line tools this project's
// gates run, without those tools becoming dependencies of the binary.
//
// The build constraint is what makes it work: no ordinary build ever compiles
// this file, so the imports below exist only to give `go mod tidy` a reason to
// record each tool in *this* module's go.mod and go.sum. The runtime module at
// the repository root never sees them, which is the point -- `no-deps`
// requires the root go.mod to carry no require block at all, and a linter
// pinned there would take that promise away in exchange for something that
// only ever runs in CI.
//
// Run one at its pinned version with:
//
//	cd tools && go run github.com/rhysd/actionlint/cmd/actionlint ../.github/workflows/*.yml
//
// The pattern is the Go wiki's: https://go.dev/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
package tools

import (
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "github.com/rhysd/actionlint/cmd/actionlint"
	_ "golang.org/x/vuln/cmd/govulncheck"
)
