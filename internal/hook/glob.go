package hook

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
)

// A glob is expanded by bash before the command runs, against the same
// filesystem this process reads, so the file set is settled here in a way a
// directory operand's never is: no reader flag alters an argv the shell
// computed. What is assumed is the options bash expands under, and that is
// what the rest of this file guards.

// braceExpansion is the shape bash rewrites into several words before it
// globs: a `{` holding a `,` or a `..`, closed by `}`. Nothing here expands
// it, and passing the token through would Stat a file that does not exist and
// send nothing, so it is refused instead.
var braceExpansion = regexp.MustCompile(`\{[^{}]*(,|\.\.)[^{}]*\}`)

// posixClass is `[[:alpha:]]`, `[[=a=]]` or `[[.a.]]`, which filepath.Match
// reads as an ordinary class followed by a literal `]`.
var posixClass = regexp.MustCompile(`\[[:=.][^]]*[:=.]\]`)

var errCannotExpand = errors.New("a file operand is a glob this cannot expand, " +
	"so which files this command would read is not settled here")

func isGlob(operand string) bool { return strings.ContainsAny(operand, "*?[") }

// altersGlobbing reports whether a segment changes what a later pattern in the
// same string expands to. Every option bash globs under -- dotglob, nullglob,
// failglob, globstar, nocaseglob, extglob -- is set through `shopt`; `set -f`
// and `set -o noglob` turn expansion off; an assignment to GLOBIGNORE filters
// the set and turns dotglob on with it; `eval` and `source` can do any of
// those. A prefix assignment on the reading command is not here, because bash
// expands the operands before the prefix takes effect -- driven, `GLOBIGNORE=x
// printf '%s\n' d/*` prints the default set -- and neither is the environment,
// which bash 5.3.15 ignores for this variable. It runs whether or not the
// segment persists: `(shopt -s dotglob; cat *)` applies to the cat beside it.
func altersGlobbing(tokens []string) bool {
	head := bash.StripShKeywords(tokens)
	rest := bash.StripEnvPrefix(head)
	if len(rest) == 0 {
		for _, a := range head {
			if strings.HasPrefix(a, "GLOBIGNORE=") {
				return true
			}
		}
		return false
	}
	name := filepath.Base(rest[0])
	switch {
	case name == "shopt", poisonAllCmds[name]:
		return true
	case name == "set":
		for _, a := range rest[1:] {
			if a == "noglob" || (len(a) > 1 && (a[0] == '-' || a[0] == '+') && a[1] != '-' && strings.Contains(a, "f")) {
				return true
			}
		}
	case argAssignerCmds[name]:
		for _, a := range rest[1:] {
			if strings.HasPrefix(a, "GLOBIGNORE") {
				return true
			}
		}
	}
	return false
}

// expand is resolve for a list: the one path a literal names, or the files
// bash would hand the command for a pattern. globsAltered says an earlier
// segment changed the options the expansion assumes, which puts the pattern
// on the record instead.
func expand(operand, cwd string, cwdUnknown, globsAltered bool) ([]string, error) {
	path, err := resolve(operand, cwd, cwdUnknown)
	if err != nil || path == "" {
		return nil, err
	}
	if !isGlob(operand) {
		return []string{path}, nil
	}
	if globsAltered {
		return nil, errors.New("a file operand is a glob and an earlier command " +
			"changes how the shell expands one, so which files it names is not " +
			"settled here")
	}
	if !expandable(operand) {
		return nil, errCannotExpand
	}
	files, err := globFiles(path)
	if err != nil {
		return nil, err
	}
	// bash passes an unmatched pattern through as the literal word, and a
	// filename can carry a glob character: `app/[id]/page.tsx` is a Next.js
	// route, and filepath.Glob reads its `[id]` as a class that matches
	// nothing. So the literal is a file the command reads whenever it exists,
	// and it is included whether or not the pattern matched anything else --
	// the lexer has stripped the quotes that would have told `cat 'x[1].env'`
	// from `cat x[1].env`, so beside a real `x1.env` both are scanned. That
	// superset is Q92's class, and TestAQuotedGlobExpandsWhereBashWouldNot
	// pins it. Driven in review on the merge tree: before this the five
	// spellings of that read exited 0 with nothing scanned and nothing
	// recorded.
	if _, err := os.Stat(path); err == nil && !slices.Contains(files, path) {
		files = append(files, path)
	}
	return files, nil
}

// expandable is the structural check, on the operand as written rather than
// the path resolve returns, because resolve joins and cleans: `*/../x` reaches
// the filesystem as `x`, with the wildcard gone. A `.` or `..` after a
// wildcard is an entry name to filepath.Glob, which no directory lists, and a
// step bash resolves: `d/*/../x` is nothing there and `d/sub/../x` here. A
// trailing separator matches only directories in bash and nothing there, a
// doubled one is joined away so the elements would not line up, and a POSIX
// class is read as an ordinary class followed by a literal `]`. An unclosed
// `[` is a literal to bash and ErrBadPattern to Go -- but Glob reports that
// only on reaching an entry to match, so over an empty directory it is the
// empty set instead, and the check is made here so the answer does not turn
// on what the directory holds.
func expandable(operand string) bool {
	wild := false
	for i, e := range strings.Split(operand, "/") {
		if wild && (e == "." || e == "..") || e == "" && i > 0 {
			return false
		}
		if j := strings.IndexByte(e, '['); j >= 0 && (j+2 > len(e) || !strings.Contains(e[j+2:], "]")) {
			return false
		}
		wild = wild || isGlob(e)
	}
	return !posixClass.MatchString(operand)
}

// globFiles is filepath.Glob under bash's default options, which is what the
// Bash tool's shell runs with here: 62 of 62 bash shell snapshots restore
// dotglob, nullglob, failglob, globstar, nocaseglob and extglob unset, and
// Claude Code 2.1.260 unsets extglob itself after sourcing one. Where the two disagree
// under those options the pattern is translated, its matches are filtered, or
// it is refused. Driven on bash 5.3.15, 2026-09-06;
// TestTheExpansionAgreesWithBash carries the table.
//
// It stays an assumption because nothing at PreToolUse can read the snapshot
// the session sources: neither the payload nor the environment names one, and
// the filename carries no session id. Driven 2026-09-07, and the residual is
// in docs/design/README.md under "A glob operand is expanded".
func globFiles(pattern string) ([]string, error) {
	sep := string(filepath.Separator)
	elems := strings.Split(pattern, sep)
	// bash negates a class with `!` as well as `^`; filepath.Match reads a
	// leading `!` as a member.
	matches, err := filepath.Glob(strings.ReplaceAll(pattern, "[!", "[^"))
	if err != nil {
		return nil, errCannotExpand
	}
	kept := matches[:0]
	for _, m := range matches {
		// bash's default matches a leading `.` in a filename only against a
		// literal `.` at the start of the pattern element -- `*`, `?` and
		// `[.]` do not reach it -- and filepath.Glob matches all three.
		got := strings.Split(m, sep)
		if len(got) != len(elems) {
			return nil, errCannotExpand
		}
		hidden := false
		for i := range got {
			if strings.HasPrefix(got[i], ".") && !strings.HasPrefix(elems[i], ".") {
				hidden = true
			}
		}
		if !hidden {
			kept = append(kept, m)
		}
	}
	return kept, nil
}
