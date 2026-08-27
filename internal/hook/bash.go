package hook

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
	"github.com/karlkfi/claude-spill-guard/internal/readers"
)

// movesCwd are the builtins that change the working directory, so a relative
// operand after one of them names a file this cannot identify. Conservative in
// the direction that blocks: any of them means unresolvable, whether or not
// this particular invocation would have moved anywhere.
var movesCwd = map[string]bool{"cd": true, "pushd": true, "popd": true}

// maxSubstDepth bounds the command-substitution recursion. internal/bash
// returns only the outermost bodies and says the cap belongs to whoever drives
// the loop, which is here. Upstream's MAX_SUBST_DEPTH is 25 and this matches
// it: a backstop against unbounded work on a pathological input rather than a
// limit anything real reaches.
const maxSubstDepth = 25

// What a finding in a heredoc body is reported against. It has no path, like a
// prompt and a command string, and the label is fixed text.
const heredocLabel = "<heredoc>"

// bashTargets is everything a Bash call would send: the command string itself,
// and the contents of the files its readers are pointed at.
//
// Heredoc bodies need no case of their own as CONTENT. They are literal text
// inside the command string, and the command string is scanned whole -- the
// strip that keeps them away from the tokenizer happens inside Segments and
// does not reach what is scanned. TestAHeredocBodyIsScanned pins that, because
// it is true by a property of the caller rather than by anything here, and a
// change to how the command string is scanned would take it away in silence.
//
// They do need one as a source of OPERANDS. Measured against internal/bash on
// 2026-08-27, `cat <<EOF` with a `$(cat secrets.env)` in its body segments to
// `[cat]` alone and CommandSubstitutions over the own-level strip returns
// nothing, because the strip is what removed the body. Only Heredocs.Expanded
// still holds it -- the unquoted-delimiter bodies bash would evaluate.
//
// The same measurement moved the substitution walk off what the row assumed.
// Segments already flattens an unquoted `$(…)`: `echo $(echo $(cat deep.env))`
// comes back with `cat deep.env` as its own segment, at every depth, so the
// recursion buys nothing there. It is needed for the two shapes Segments does
// not reach -- a backtick substitution, whose tokens come back with the
// backticks still on them, and a substitution inside a heredoc body. A `$(…)`
// inside single quotes is correctly reached by neither.
//
// A command with no row in internal/readers contributes no operands. That is
// the design's stated limitation rather than a fail-closed case: the Bash
// surface is the command string and the file operands of the common readers,
// and a command that synthesizes a secret at run time was never catchable.
// What IS fail-closed is an operand of a command we know reads files and whose
// path we cannot settle -- there the scanner would report a clean result for a
// file it never opened.
func bashTargets(command, cwd string) ([]target, error) {
	targets := []target{{commandLabel, []byte(command)}}
	seen := make(map[string]bool)

	type job struct {
		text  string
		depth int
	}
	queue := []job{{command, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		segments, err := bash.Segments(cur.text)
		if err != nil {
			return nil, fmt.Errorf("the Bash command could not be read, so what "+
				"it would send is unknown: %w", err)
		}

		// Anything that moves the working directory changes what a later
		// relative operand means, and this port does not carry the tracker the
		// guards upstream key on. So a relative operand after one is a path
		// this cannot settle rather than one it can guess at.
		//
		// `cd` is not the only name for it. `pushd` and `popd` move too, and
		// bare `pushd` swaps the top two entries and moves as well -- driven,
		// a `pushd elsewhere && cat rel.env` resolved the operand against the
		// payload's cwd, scanned a file the command never reads, and allowed
		// the call with `cd` blocking the same shape in the same run.
		movedCwd := false
		for _, segment := range segments {
			tokens := bash.StripEnvPrefix(bash.StripShKeywords(segment.Tokens))
			if len(tokens) == 0 {
				continue
			}
			if movesCwd[filepath.Base(tokens[0])] {
				movedCwd = true
				continue
			}
			operands, known := readers.Files(tokens)
			if !known {
				continue
			}
			// A flag whose value is a file naming other files. The list itself
			// is an operand and is scanned; what it names cannot be known
			// without opening it, and scanning the list alone would report a
			// clean result for every file in it.
			if flags := readers.Indirect(tokens); len(flags) > 0 {
				return nil, fmt.Errorf("a file operand is named indirectly "+
					"through %q, so which files this command would read is not "+
					"settled here", strings.Join(flags, ", "))
			}
			// Safe to name: Files matched it, so this is one of the reader
			// table's own keys rather than anything the caller chose.
			command := filepath.Base(tokens[0])
			for _, operand := range operands {
				path, err := resolve(operand, cwd, movedCwd)
				if err != nil {
					return nil, fmt.Errorf("in the %q here, %w", command, err)
				}
				if path == "" || seen[path] {
					continue
				}
				seen[path] = true
				buf, err := os.ReadFile(path)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						// Nothing there sends nothing, and the command will
						// report its own error. Same reading as a Read of an
						// absent file.
						continue
					}
					return nil, fmt.Errorf("reading a file this command would "+
						"send: %w", err)
				}
				targets = append(targets, target{path, buf})
			}
		}

		if cur.depth >= maxSubstDepth {
			// Over-blocks the nested-`$(…)` case, whose operands Segments has
			// already flattened into this same pass. That is deliberate: at
			// this depth the walk stopped, and it cannot tell which of the
			// bodies below it were reached by the flattening and which were
			// backticks or heredoc bodies that were not.
			return nil, fmt.Errorf("the Bash command nests command substitutions "+
				"more than %d deep, so what the innermost would send was not "+
				"scanned", maxSubstDepth)
		}
		var docs bash.Heredocs
		stripped := bash.StripHeredocBodies(cur.text, &docs, true)
		bodies := bash.UnstrippedSubstBodies(cur.text, bash.CommandSubstitutions(stripped, true))
		// A heredoc body is not quoted text, so a substitution in one is live
		// whatever apostrophes the body carries -- which is why the scan over
		// it runs with quoting off.
		for _, body := range append(docs.Expanded, docs.Unterminated...) {
			bodies = append(bodies, bash.CommandSubstitutions(body, false)...)
		}
		for _, body := range bodies {
			queue = append(queue, job{body, cur.depth + 1})
		}
	}
	return targets, nil
}

// resolve turns one operand into a path this process can open, or says why it
// cannot. An empty path with no error means the operand names no file.
//
// Every refusal here is a file a reader is pointed at and this cannot identify.
// Skipping one would report a clean scan for content nothing looked at, which
// is the failure the whole project is built around, so each is an error.
//
// # None of these reasons names the operand, and that is the whole point
//
// A reason reaches the API. An unresolvable operand is a fragment of a command
// string the model wrote, and on this path nothing has been scanned yet -- the
// walk fails before the command string itself is looked at -- so quoting the
// operand sends content the scan never examined. `cat $HOME/<a key>` put the
// key in the refusal verbatim.
//
// Clipping it the way decode clips an event name does not work here, and the
// difference is worth stating because the first fix anyone reaches for is the
// one that already exists two files away. An event name is a short identifier
// whose interesting part is its head; a secret can sit anywhere in an operand
// and usually sits at the start (`cat $AKIA…` is 24 bytes). A bound loose
// enough to leave a real path legible keeps a whole key, and one tight enough
// to cut a key mangles every path. There is no bound that does both.
//
// So the reason names the category and the command, and never the token. The
// command is safe to name because Files has already matched it: it is one of
// the table's own keys, a closed set this repo authored, rather than anything
// the caller chose. What that costs is which operand on a command with several,
// and the reason reaching the API is what the cost buys.
func resolve(operand, cwd string, movedCwd bool) (string, error) {
	switch {
	case operand == "" || operand == "-":
		// `-` is stdin to every reader in the table, not a file.
		return "", nil
	case strings.ContainsAny(operand, "$`"):
		return "", errors.New("a file operand expands at run time, so what this " +
			"command would read cannot be known before it runs")
	case strings.ContainsAny(operand, "*?["):
		return "", errors.New("a file operand is a glob, so which files this " +
			"command would read is not settled here")
	case strings.HasPrefix(operand, "~"):
		// A bare `~` or `~/…` is the home directory, which is resolvable; a
		// `~user` prefix is not, and neither is a `~` with no HOME.
		if operand != "~" && !strings.HasPrefix(operand, "~/") {
			return "", errors.New("a file operand names another user's home, " +
				"which this cannot resolve")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New("a file operand is home-relative and there is " +
				"no home directory to resolve it against")
		}
		return filepath.Join(home, strings.TrimPrefix(operand, "~")), nil
	}

	if filepath.IsAbs(operand) {
		return operand, nil
	}
	if movedCwd {
		return "", errors.New("a file operand is relative and the command " +
			"changes directory first, so which file it names is not settled here")
	}
	if cwd == "" {
		return "", errors.New("a file operand is relative and the payload names " +
			"no working directory to resolve it against")
	}
	return filepath.Join(cwd, operand), nil
}
