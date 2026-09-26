package hook

import (
	"os"
	"path/filepath"
	"strings"
)

// The Bash tool's shell is not bash unless something on the machine names
// bash, and the expansion in glob.go is bash's. Claude Code picks the shell
// before it runs anything: CLAUDE_CODE_SHELL, then SHELL, each taken only when
// its path holds `bash` or `zsh` as a substring and is executable, and
// otherwise a fixed list over /bin, /usr/bin, /usr/local/bin and
// /opt/homebrew/bin ordered zsh first unless SHELL holds `bash`. Read out of
// the 2.1.270 CLI and the 2.1.275 the desktop app runs -- 882 bytes in each
// and alpha-equivalent, not byte-identical, since the minifier renames 10 of
// its 16 identifiers between builds -- and corroborated by 96 zsh tool shells in this
// machine's transcripts before a CLAUDE_CODE_SHELL was committed to settings.
// Since driven, by extracting the selection function and running it under
// jsc across nine environment arms, all nine agreeing. Q163 carries both.
//
// Both variables reach a hook: 57 in the environment Claude Code hands one,
// these two among them. That is the same environment an earlier drive read
// looking for a shell snapshot and reported no route in -- true of the
// snapshot, and the shell itself was in it.

// shellNames is the harness's own test for whether a variable names a shell at
// all: a substring over the whole path rather than a basename, so
// /opt/homebrew/bin/bash and a bash under a directory named for zsh both pass.
func shellNames(path string) bool {
	return strings.Contains(path, "bash") || strings.Contains(path, "zsh")
}

// executableFile is the harness's access(X_OK) test, asked the same way where
// the platform has one: shell_unix.go calls access(2) rather than reading the
// mode bits, because the two disagree under an ACL and one direction of that
// disagreement is an under-scan.
func executableFile(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && executableBy(path, info.Mode())
}

// toolShell is the path the harness will spawn, and the empty string where
// the ladder falls past both variables. Both reads are written out rather
// than looped over a list of names, because a Getenv the privacy gate cannot
// name is a read PRIVACY.md cannot declare.
func toolShell() string {
	for _, path := range []string{os.Getenv("CLAUDE_CODE_SHELL"), os.Getenv("SHELL")} {
		if shellNames(path) && executableFile(path) {
			return path
		}
	}
	return ""
}

// toolShellIsBash reports whether the Bash tool's shell is bash. One bit,
// rather than the path, because that is what the expansion turns on -- and
// reading the ladder for a bit is what lets a step it cannot settle answer
// *not certainly bash*, which puts the operand on the coverage record instead
// of expanding it under the wrong shell's rules.
//
// Two steps of the ladder are reproduced and the third is refused. Where
// CLAUDE_CODE_SHELL or SHELL names an executable shell, that is the shell the
// harness spawns, and this answers bash when the file it names is bash: the
// substring above decides whether the harness accepts the path, and what the
// file *is* decides how it globs, which the base name is the reading of. So a
// `sh` under a directory named for bash is spawned by the harness and is not
// bash here.
//
// Where neither variable names a shell, the harness falls to a fixed list,
// and that step is settled rather than unknown: the expression is name-major
// -- zsh at all four directories before bash at any of them, the two swapped
// when SHELL holds `bash` -- so no arrangement of the directories changes the
// answer. It is not reproduced anyway, because reproducing it could only turn
// a deferral into an expansion. The step reaches bash on two machines: one
// whose SHELL names a bash the harness could not spawn, and one with no zsh
// installed at all. Both already have nothing naming a usable shell, and the
// cost of answering false for them is a coverage record.
func toolShellIsBash() bool {
	path := toolShell()
	return path != "" && strings.Contains(filepath.Base(path), "bash")
}

// toolShellIsZsh is the same reading for zsh, the one other shell whose
// expansion glob.go has measured against bash's.
func toolShellIsZsh() bool {
	path := toolShell()
	return path != "" && strings.Contains(filepath.Base(path), "zsh")
}
