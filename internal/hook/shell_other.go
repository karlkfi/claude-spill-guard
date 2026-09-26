//go:build !unix

package hook

import "io/fs"

// The mode bits, where there is no access(2) to ask. Windows has no execute
// bit at all, so this is the reading that platform can support -- and whether
// a Bash tool call there reaches the harness's PowerShell provider, which
// would make the whole ladder the wrong question, is Q192.
func executableBy(_ string, mode fs.FileMode) bool {
	return mode.Perm()&0o111 != 0
}
