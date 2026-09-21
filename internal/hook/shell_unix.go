//go:build unix

package hook

import (
	"io/fs"
	"syscall"
)

// executableBy asks the kernel rather than reading the mode bits, because the
// two disagree under an ACL and one direction of that is an under-scan. Where
// Stat says executable and access(2) would refuse, the harness throws on
// spawning it, falls through to its own detection and may run zsh -- while a
// reading off the bits alone answers *bash* and expands under bash's rules.
// The other direction costs a coverage record and is harmless, which is why
// this is worth a build-tag split.
//
// X_OK is written out: syscall defines no X_OK on darwin, and the value is
// POSIX rather than a platform's.
func executableBy(path string, _ fs.FileMode) bool {
	return syscall.Access(path, 0x1) == nil
}
