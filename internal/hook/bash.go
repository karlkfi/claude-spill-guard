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

// cdSubst is the two substitutions a `cd` target may carry and still be
// followed, because their value is computable here without running anything:
// `$(pwd)` is the tracked directory itself and `$(git rev-parse
// --show-toplevel)` is its nearest ancestor holding a `.git` entry. Upstream's
// CD_SUBST. Anything else with a `$` in it is a target this cannot know.
var cdSubst = map[string]string{
	"$(git rev-parse --show-toplevel)": "toplevel",
	"$(pwd)":                           "pwd",
}

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

	// A body queued for a later pass starts from the directory its parent
	// ended in, or from none if the parent moved at all: a backtick or heredoc
	// body has no position relative to the cd, so it cannot be told whether it
	// runs before or after the move. The glob options are carried the same
	// way, for the same reason.
	type job struct {
		text         string
		depth        int
		dir          string
		dirUnknown   bool
		globsAltered bool
	}
	queue := []job{{command, 0, cwd, false, false}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		segments, err := bash.Segments(cur.text)
		if err != nil {
			return nil, fmt.Errorf("the Bash command could not be read, so what "+
				"it would send is unknown: %w", err)
		}

		// Ahead of the operands, because this refusal is not about them. A
		// command that writes the whole environment opens no file, so there is
		// nothing here for the loop below to find and nothing on disk for a
		// rule to match -- shape.go argues why that is a deny rather than a
		// gap. It runs on substitution bodies too, which is what this being
		// inside the queue loop buys: `echo $(env)` dumps as surely as `env`.
		if name := envDumped(segments); name != "" {
			return nil, &shapeRefusal{name}
		}

		// The directory a relative operand resolves against, advanced through
		// the segments in order: `cd a && cat x && cd b && cat y` reads x under
		// a and y under b, and a `$(…)` body Segments flattened sits after the
		// cd it follows. The tracker is upstream's, from the group loop in
		// bash-workspace-guard.py, and it loses the directory the same way -- a
		// move with no literal to follow marks it unknown, and a relative
		// operand after that is a path this cannot settle rather than one it
		// guesses at. Where this port loses it and upstream does not, follow
		// says so at the arm.
		dir, dirUnknown := cur.dir, cur.dirUnknown
		moved := false
		// Whether a pattern still expands under the options the shell started
		// with. glob.go says what changes them; once one has, every later
		// pattern in the string is a set this cannot compute.
		globsAltered := cur.globsAltered
		// The variables the string assigns, substituted into each segment
		// before anything reads it, as bash expands before it runs. vars.go
		// is the port and carries what it declines to resolve.
		v := newVars()
		// The and-or list, which says whether a conditional assignment or
		// move had run by the time a later segment does; vars.go has the rule.
		list := andOr{settled: true}
		for i, segment := range segments {
			list.enter(segment, v, &dirUnknown)
			sub := v.expand(segment.Tokens)
			inputs := v.expand(segment.Inputs)
			// The segment's own provenance reads the substituted copy too:
			// expand rebuilds token for token, so the two stay aligned, and no
			// substitution can move where quoting appeared in the word bash
			// lexed. What it does not cover is a word that becomes
			// assignment-shaped only after expansion -- `n=LC_ALL; $n=C cat f`
			// -- which is a second reading of the same head and a defect of its
			// own rather than this one seen from another side.
			if altersGlobbing(sub, segment.QuotedFrom) {
				globsAltered = true
			}
			switch names, observed := v.observe(segment.Tokens, sub, segment.QuotedFrom,
				list.persists(segment), list.binds(segment)); observed {
			case observedAssignments:
				list.assigned(segment, names)
				continue
			case observedLoopHeader:
				// A loop exits with its body's status, or 0 on an empty list,
				// and nothing here knows either -- so the list is unsettled the
				// way any other command unsettles it.
				list.ran()
				continue
			}
			k := bash.ShKeywordPeel(sub, segment.QuotedFrom)
			tokens := bash.StripEnvPrefix(sub[k:], segment.QuotedFrom[k:])
			if len(tokens) == 0 {
				continue
			}
			if kind, arg := classifyCd(tokens); kind != "" {
				moved = true
				dir, dirUnknown = follow(kind, arg, dir, dirUnknown, segment)
				list.moved(segment, dirUnknown)
				continue
			}
			list.ran()
			operands, known := readers.Files(tokens)
			if !known {
				continue
			}
			// A `<` target is a file the reader reads that Files cannot see:
			// Segments takes redirects out of the tokens first, so `cat <
			// deploy.env` reached here with no operand and crossed unread, past
			// content matching and the path refusal alike. It joins the operands
			// because everything below asks the same question of it. Known
			// readers only, every reader in the table, never a `<(…)`, and
			// docs/design/README.md, "An input redirect", has the week behind each.
			operands = append(operands, inputs...)
			// A flag whose value is a file naming other files. The list itself
			// is an operand and is scanned; what it names cannot be known
			// without opening it, and scanning the list alone would report a
			// clean result for every file in it.
			if flags := readers.Indirect(tokens); len(flags) > 0 {
				return nil, fmt.Errorf("a file operand is named indirectly "+
					"through %q, so which files this command would read is not "+
					"settled here", strings.Join(flags, ", "))
			}
			// Safe to name, and the argument has to be exact because this is
			// the one caller-derived string the reason carries. Files matched
			// on path.Base(tokens[0]), so this basename is a key of the reader
			// table or of its alias map -- two closed sets this repo authored.
			// The directories above it never reach here: measured, a `cat`
			// invoked as /tmp/<a key>/cat reports `cat`.
			command := filepath.Base(tokens[0])
			var paths []string
			for _, operand := range operands {
				// A `$f` bound to a `for f in <list>` stands for one path per
				// value bash iterates, and the loop body reads every one of
				// them, so every one is scanned. vars.go carries why that is
				// the file set the command sends rather than a walk of
				// anything, which is the reading the directory refusal below
				// turns on.
				cands, ok := v.candidates(operand)
				if !ok {
					return nil, fmt.Errorf("in the %q here, a file operand names loop "+
						"variables standing for more than %d paths, so which files this "+
						"command would read was not enumerated here", command,
						maxLoopCandidates)
				}
				for _, cand := range cands {
					expanded, err := expand(cand, dir, dirUnknown, globsAltered)
					if err != nil {
						return nil, fmt.Errorf("in the %q here, %w", command, err)
					}
					paths = append(paths, expanded...)
				}
			}
			for _, path := range paths {
				if seen[path] {
					continue
				}
				seen[path] = true
				info, err := os.Stat(path)
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
				// Only a regular file. os.ReadFile on a fifo blocks until
				// something writes, which hangs the call rather than deciding it --
				// neither answer this project chooses between, and nothing in the
				// transcript to say which was reached.
				//
				// A device is refused with it rather than skipped, against the way
				// the row leaned, so the traffic was measured instead of guessed.
				// Over 129,000 Bash calls in this machine's transcripts `/dev/*`
				// reaches a reader's operand list 12 times, all of them `/dev/null`
				// named as a filename by grep (11) or awk (1) -- the 18,509
				// ordinary ones are redirect targets, which Segments keeps in
				// Redirects, and the `<` subset this loop reads named `/dev/*` 0
				// times in 219 over the week to 2026-09-04. Skipping instead would claim
				// nothing crossed, and /dev/zero and /dev/random return bytes for
				// as long as anything reads, with no bound on os.ReadFile.
				//
				// os.Stat, not os.Lstat: it is the reading `cat` takes, and Lstat
				// reports a symlink to a fifo and one to a regular file
				// identically -- driven, both Lrwxr-xr-x where Stat separates them.
				// The path can be swapped between this and the open below. Closing
				// that needs an fd and an fstat, which O_NONBLOCK makes portable
				// only off Windows, and nothing in a session races its own hook.
				// A directory gets its own reason, because it is the whole of
				// the traffic this refuses in practice -- `grep -rn pat docs/`
				// and `rg pat docs/`, 7.1% of the calls that carry an operand --
				// and "not a regular file" leaves a user working out which kind
				// they hit. Before this guard the OS error said `is a directory`,
				// so one reason for every mode would be strictly less to go on
				// than the tree already had. The path stays out of it, as it does
				// in every reason resolve writes; the OS error named it only
				// because %w carried it.
				//
				// Walking instead was measured and refused. The argument that
				// used to decide it -- an overrunning walk allows the call --
				// is gone now that the scan has a budget, so what decides it is
				// that a walk reads a different file set from the one the
				// command would send: ripgrep honours .gitignore and skips
				// hidden files, and over one checkout `rg --files` reports 211
				// where a walk finds 11,815 and 1,132 findings in them. Making
				// the walk agree means re-implementing each reader's traversal,
				// which is the class this repo refuses by name for shell
				// parsing. docs/design/README.md, "A directory operand is
				// refused rather than walked", has the tables.
				//
				// The subject of that clause is this scanner and it is named,
				// because the shorter form was read as a claim about the
				// command. Nothing here parses a recursion flag -- `-rn`,
				// `-r`, `--recursive` and no flag at all reach this same
				// return, driven -- so a reason saying the command reads
				// rather than walks is false of every recursive form, and the
				// recursive form is the one this refusal meets. It cost a
				// friction report the day it was read that way, spent hunting
				// a flag parser that does not exist.
				if info.IsDir() {
					return nil, fmt.Errorf("in the %q here, a file operand names a "+
						"directory, and this scanner reads files rather than walking "+
						"a tree, so what that operand would send was not read -- name "+
						"the files instead", command)
				}
				if !info.Mode().IsRegular() {
					return nil, fmt.Errorf("in the %q here, a file operand names "+
						"something that is neither a file nor a directory, so what "+
						"this command would send cannot be read here", command)
				}
				// Ahead of the read, because not opening the file is the whole
				// of this refusal -- guarded.go carries why a path whose
				// contents the ruleset would not recognise is refused rather
				// than scanned and cleared.
				//
				// lastInPipeline for shape.go's reason, and it buys more here.
				// `cat .env | cut -d= -f1` sends the names alone, so refusing
				// it would fire on the careful form; and unlike `env`, the file
				// is a buffer, so the piped form is still read into targets
				// below and still matched against every rule. The careful form
				// keeps its content coverage rather than trading it away.
				if class := guardedClass(path); class != "" && lastInPipeline(segments, i) {
					return nil, &pathRefusal{path, class}
				}
				buf, err := os.ReadFile(path)
				if err != nil {
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
			queue = append(queue, job{body, cur.depth + 1, cur.dir, cur.dirUnknown || moved, globsAltered})
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
func resolve(operand, cwd string, cwdUnknown bool) (string, error) {
	switch {
	case operand == "" || operand == "-":
		// `-` is stdin to every reader in the table, not a file.
		return "", nil
	case strings.ContainsAny(operand, "$`"):
		return "", errors.New("a file operand expands at run time, so what this " +
			"command would read cannot be known before it runs")
	case braceExpansion.MatchString(operand):
		return "", errors.New("a file operand is a brace expansion, so which " +
			"files this command would read is not settled here")
	case strings.HasPrefix(operand, "~"):
		// A bare `~` or `~/…` is the home directory, which is resolvable; a
		// `~user` prefix is not, and neither is a `~` with no HOME.
		if operand != "~" && !strings.HasPrefix(operand, "~/") {
			return "", errors.New("a file operand names another user's home, " +
				"which this cannot resolve")
		}
		home := expandTilde(operand)
		if home == operand {
			return "", errors.New("a file operand is home-relative and there is " +
				"no home directory to resolve it against")
		}
		return home, nil
	}

	if filepath.IsAbs(operand) {
		return operand, nil
	}
	if cwdUnknown {
		return "", errors.New("a file operand is relative and the command " +
			"changes directory first to somewhere this cannot follow, so which " +
			"file it names is not settled here")
	}
	if cwd == "" {
		return "", errors.New("a file operand is relative and the payload names " +
			"no working directory to resolve it against")
	}
	return filepath.Join(cwd, operand), nil
}

// classifyCd is the port of upstream's classify_cd. It says what a cd-family
// segment does to the working directory:
//
//	"arg", path     cd or pushd to a literal target, resolvable here
//	"subst", kind   cd or pushd to a cdSubst substitution, for follow to compute
//	"unknown", ""   a move with nothing to follow: bare cd, `cd -`, popd,
//	                `pushd +N`, a `~user` or `$`-bearing target
//	"", ""          not a cd-family command
//
// Two targets are "unknown" here and "arg" upstream, because each puts the
// shell somewhere other than where the literal says and the literal is what
// follow would go to. `-P` resolves `..` through symlinks where filepath.Join
// resolves it lexically, which is bash's default and the only reading taken
// here. `pushd -n` rotates the stack and does not move at all. A backtick in
// the target is the third: upstream tests for `$` alone, and a backtick body
// comes through the lexer with the backticks still on it.
func classifyCd(tokens []string) (kind, arg string) {
	if len(tokens) == 0 {
		return "", ""
	}
	name := filepath.Base(tokens[0])
	if name != "cd" && name != "pushd" && name != "popd" {
		return "", ""
	}
	if name == "popd" {
		return "unknown", "" // stack not tracked
	}
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			if strings.Contains(t, "P") || (name == "pushd" && strings.Contains(t, "n")) {
				return "unknown", ""
			}
			continue // option flag, keep looking
		}
		if sub, ok := cdSubst[normalizeSubst(t)]; ok {
			return "subst", sub
		}
		t = expandTilde(t) // `cd ~/proj` tracks via home
		if strings.HasPrefix(t, "+") || strings.HasPrefix(t, "~") || strings.ContainsAny(t, "$`") {
			return "unknown", ""
		}
		return "arg", t
	}
	return "unknown", "" // bare `cd` -> $HOME
}

// follow moves the tracked directory the way the segment's cd would, or loses
// it. Four arms lose it here and keep it upstream, each in the direction that
// records the operand after it rather than resolving it against a directory
// the shell may not be in:
//
//   - a move inside a `case` arm, which ran only on a pattern match. Upstream
//     does not read arms at all; Segment.CaseArm carries why this does.
//   - a move in a subshell, a pipeline stage or a background job (Persists
//     false) reaches the commands inside that subshell and not the ones after
//     it, and which later segments are inside is not in the segment model.
//     Driven before any tracker existed: `pushd elsewhere && cat rel.env`
//     resolved rel.env against the payload's cwd, scanned a file the command
//     never reads, and allowed the call.
//   - a relative target while the directory is already lost has nothing to
//     join to. Upstream joins it to the stale one and calls it found.
//   - a target that is not a directory here. Under `;` the shell stays where
//     it was and under `&&` the next command never runs, and the operator is
//     not in the segment model either.
//   - CDPATH, in the environment or assigned on the segment, which bash
//     searches before the directory named. The hook and the tool inherit one
//     environment from Claude Code, so the reading here is the tool's.
func follow(kind, arg, dir string, unknown bool, segment bash.Segment) (string, bool) {
	switch {
	case !segment.Persists:
		return dir, true
	case segment.Conditional == "||", segment.CaseArm:
		return dir, true
	case kind == "arg":
		if !filepath.IsAbs(arg) {
			if unknown || dir == "" || os.Getenv("CDPATH") != "" || assigns(segment.Tokens, segment.QuotedFrom, "CDPATH") {
				return dir, true
			}
			arg = filepath.Join(dir, arg)
		}
		if info, err := os.Stat(arg); err != nil || !info.IsDir() {
			return dir, true
		}
		return arg, false
	case kind == "subst" && !unknown && dir != "":
		if arg == "pwd" {
			return dir, false
		}
		if top := gitToplevel(dir); top != "" {
			return top, false
		}
	}
	return dir, true
}

// assigns reports whether the segment's inline prefix assigns name.
func assigns(tokens []string, quotedFrom []int, name string) bool {
	for _, assignment := range envPrefix(tokens, quotedFrom) {
		if strings.HasPrefix(assignment, name+"=") {
			return true
		}
	}
	return false
}

// envPrefix is the inline `NAME=VALUE` assignments at the head of a segment.
// They are what StripEnvPrefix drops, so they are the head it did not return.
// Taking them by difference rather than by matching the shape again keeps the
// one assignment regex in internal/bash, which is a port and is not diverged
// from here -- and now the one reading of what a quoted word is, which is the
// whole of why `'SPILL_GUARD_OVERRIDE=x' cat f` no longer arms the hatch.
//
// Counted rather than sliced twice, because quotedFrom has to be cut by the
// same amount as tokens at each step and Go slicing carries neither along.
func envPrefix(tokens []string, quotedFrom []int) []string {
	k := bash.ShKeywordPeel(tokens, quotedFrom)
	head, headQF := tokens[k:], quotedFrom[k:]
	return head[:bash.EnvPrefixPeel(head, headQF)]
}

// expandTilde is upstream's expand_tilde: a leading `~` or `~/…` becomes the
// home directory, which bash resolves deterministically, and anything else
// comes back unchanged for the caller to refuse -- `~user`, `~+`, `~-`, or a
// `~` with no home to resolve against.
func expandTilde(tok string) string {
	if tok == "~" || strings.HasPrefix(tok, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, tok[1:])
		}
	}
	return tok
}

// normalizeSubst collapses the whitespace bash allows inside `$( … )` so a
// target compares against cdSubst's keys. A token that still matches no key is
// simply not whitelisted.
func normalizeSubst(tok string) string {
	t := strings.Join(strings.Fields(tok), " ")
	if strings.HasPrefix(t, "$( ") {
		t = "$(" + t[3:]
	}
	if strings.HasSuffix(t, " )") {
		t = t[:len(t)-2] + ")"
	}
	return t
}

// gitToplevel is the value `git rev-parse --show-toplevel` prints from start:
// the nearest ancestor, start included, holding a `.git` entry -- a directory
// for a checkout, a file for a worktree. Empty when no boundary is found, or
// when a git-discovery variable is set, since those move git's answer away
// from the plain walk. A filesystem walk and nothing else: os/exec is
// forbidden across this build graph, which is also why cdSubst is two long.
func gitToplevel(start string) string {
	// Three literal reads rather than a loop over the names, because the
	// privacy gate derives PRIVACY.md's list of what the binary reads from
	// the source, and a variable it cannot name is one the page cannot say.
	if os.Getenv("GIT_DIR") != "" || os.Getenv("GIT_WORK_TREE") != "" ||
		os.Getenv("GIT_CEILING_DIRECTORIES") != "" {
		return ""
	}
	for d := start; ; {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		} else if !errors.Is(err, fs.ErrNotExist) {
			return ""
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}
