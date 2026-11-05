// Package bash splits a Bash command string into the simple commands it runs,
// so a caller can find the file operands the readers -- `cat`, `head`, `tail`,
// `grep` -- are pointed at and scan those the way the Read tool's payload is
// scanned.
//
// It is a port of the shell parsing in karlkfi/claude-bouncer: the layers below
// Segments come from lib/bouncer_parse.py, shared by all five guards there, and
// Segments itself from the group loop in
// plugins/workspace-guard/scripts/bash-workspace-guard.py. First ported at tag
// workspace-guard/v1.11.0, commit 1d09ffef33bbb9632f714bc416e627b937353826;
// the quote provenance below tracks lib/bouncer_parse.py at
// 6cc585b2d977cdfe396acfcf19501eef34a61491.
//
// The pin is a revision a reader diffs against, so what is knowingly NOT
// ported has to be named beside it or that reader concludes the port is
// current. Three commits have touched lib/bouncer_parse.py since the 2026-08-24
// pin, measured 2026-09-09, and two of them are outstanding: #113 (05f69c0),
// which reads `NAME+=value` as an assignment -- a fail-open here, filed as
// Q168 -- and the substitution-span half of #109 (c368aca). #110's own
// peel-before-rebuild repair is unported too, and is Q167.
//
// claude-bouncer Q257 (abc788e) is ported: requote's double-quote hold and the matching arm
// in StripComments. So are the comment stripper's claude-bouncer Q254
// (e82fe12), Q264 (ea64a90) and Q217 (a3c9052) arms, read at 784fc36 (Q210).
// Q217's lexer half -- keeping `NAME[...]` whole in command position -- is
// ported too, read at 00c94bc (Q185). requote's ANSI-C decode and backtick rewrite
// (claude-bouncer Q225, b0e3fdc, and Q274, f440dbd) and StripComments' `$'…'`
// arm are ported too, from the same revision (Q211). split_groups' compound
// and function scopes (claude-bouncer Q272 and Q265) are ported, read at
// 00c94bc, with its `lastpipe` reading moved to the caller (Q212).
//
// Structural identity is the point, and it is a rule this repo states rather
// than a preference (CLAUDE.md, "Do not hand-roll shell parsing"). A segmenter
// fails silently in both directions -- one that under-splits hands back a
// command string as one blob and never sees the operand, so a `cat secrets.env`
// goes unscanned and reports clean; one that over-splits invents operands that
// are not paths. Neither shows up in output. Keeping the shape means a fix
// upstream can be read across by inspection, which a rewrite that happens to
// agree today loses the first time either side changes. So the function names,
// the ordering of the branches and the comments carrying each upstream issue
// number are kept, and every place Go forced a difference says so at the site:
// lex (no shlex in the standard library), matchWord (no anchored-at-offset
// regexp match), Heredocs (no default-None list argument), CommandSubstitutions
// and SegmentsOfStripped (no default argument -- upstream reads each as a
// keyword on one function), Segment.QuotedFrom and the two Peel functions
// beside the strips (no attribute on a Go string, so a token's quote
// provenance travels beside it rather than on it), and isDigits below. One
// difference is this repo's rather than Go's: Segment.Inputs records which of
// the redirects were `<`, and the field's comment carries why upstream has no
// need of it. So is the interrupted command below, which upstream has no need of
// because an unresolvable operand there refuses the whole call.
//
// The layers, in the order a command passes through them:
//
//	raw string -> StripComments, StripHeredocBodies   (text bash never lexes)
//	           -> CommandSubstitutions                 (bodies to recurse into)
//	           -> lex                                  (POSIX quoting)
//	tokens     -> splitOperatorRuns, glueDollarParen   (operator repair)
//	           -> Segments                             (the command boundaries)
//	           -> StripShKeywords, StripEnvPrefix      (find the real argv[0])
//
// Fail-safe direction: a parse that cannot be completed returns less, never
// more. Segments reports an error on unbalanced quotes so callers defer rather
// than guess, and an unterminated substitution or heredoc contributes nothing.
// That is not the fail-closed rule in reverse -- deciding what a segment MEANS
// is the caller's, and a caller that cannot read a command blocks it.
//
// The shared module also carries the operator groupings the other four guards
// key on (which operator joined two commands, which segment was backgrounded).
// Nothing here needs them, so they are not ported.
package bash

import (
	"cmp"
	"slices"
	"strings"
)

// A Segment is one simple command in a chain, with the redirect targets written
// beside it.
//
// A redirect target is collected into the segment it textually appears in, so
// it later resolves against THAT segment's working directory rather than the
// chain's original one -- which is what lets `cd /tmp && cat /dev/null > evil`
// name `/tmp/evil`.
type Segment struct {
	// Tokens is the command and its operands, redirects removed. QuotedFrom,
	// the last field, says where quoting first appeared in each of them.
	Tokens []string
	// Redirects is every redirect target written in this segment. A heredoc
	// delimiter and a here-string's content are not paths and are not here.
	Redirects []string
	// Inputs is the subset of Redirects written with `<`: a file the command
	// reads through a descriptor rather than by name, so a reader's operand
	// list is short of it. Upstream records the target alone, because its
	// question -- does this command touch a path outside the workspace -- has
	// the same answer for a read and a write. This repo's does not, so the
	// operator is kept here, at the one branch of the loop that sees it. `<<`
	// and `<<<` are not here for the reason above, and `<&` names a
	// descriptor. An explicit descriptor is not read: `3<in` opens in for
	// reading on fd 3, and which descriptor a command consumes is not
	// something the tokens say.
	Inputs []string
	// Persists is true only when a variable assignment in this segment
	// survives into later commands of the same string: at paren depth 0 (not a
	// subshell -- `(f=x); cat $f` does not set f), not a pipeline stage (each
	// side of `|` runs in a subshell), and not backgrounded (`f=x & …` assigns
	// in the background copy only).
	Persists bool
	// Conditional is the operator this segment is reached through when it is
	// `&&` or `||`, and empty otherwise: whether bash ran the segment turns on
	// the exit status of what came before it. Persists does not consult that
	// -- upstream's rule reads the separator after a segment and not the one
	// before it, so `false && P=/x; cat $P/f` assigns there. This repo's
	// resolver opens the file a path names, so it wants to know, and this is
	// the one field that carries it. Kept beside Persists rather than folded
	// into it so the ported rule stays upstream's and the consumer decides
	// what a conditional segment is worth; Inputs is the precedent.
	Conditional string
	// CaseArm is true for a segment bash runs only if a `case` pattern
	// matched: everything between the `)` that ends the first pattern and the
	// `esac` that closes the statement, patterns of later arms included. A
	// second field rather than a third value of Conditional, because an arm is
	// reached through a match rather than an operator, and a segment inside one
	// carries its own `&&` or `||` that folding would lose. Upstream has
	// neither the field nor the reading -- an arm it never enters costs it at
	// most a prompt -- where this resolver opens the file the arm's assignment
	// names: `case x in y) P=/case;; esac; cat $P/f` read `/case/f` on a call
	// where bash matched nothing (Q151).
	CaseArm bool
	// Pipe numbers the pipeline this segment belongs to, which is what tells a
	// `grep` filtering another command's output apart from a `grep` reading
	// ordinary files.
	Pipe int
	// QuotedFrom is Tokens' provenance, index for index: for each token, the
	// offset into it at which quoting or escaping first appeared, or NotQuoted.
	// Bash settles what a word is before removing its quotes, so this is what
	// separates the `SP=/x` that assigns from the `'SP=/x'` that names a
	// program bash cannot find, and the `if` that opens a compound statement
	// from the `'if'` that does not. Upstream keeps it on the token itself;
	// lex.go's NotQuoted has why Go cannot.
	QuotedFrom []int
	// Shells numbers each `(` the segment sits inside, outermost first, so two
	// sibling subshells at the same depth still read as different shells. A
	// bare `$(` reaches here as `$(` then `(`, so a substitution counts too,
	// and so does a process substitution's `<(`. Upstream's `shells`, which it
	// returns through split_groups' `scopes` out-parameter (its Q173); a field
	// here for the reason Pipe is one. A `{ … }`, loop, `if` or `case` piped
	// or backgrounded as a whole is a shell too (its Q272), and so is a
	// function body (its Q265), whose number Function names. The process
	// substitution is this port's, and upstream has no shell for it.
	Shells []int
	// Forked is true for a pipeline stage or a backgrounded command, which
	// bash runs in a child shell of its own, so a `cd` in it moves nothing
	// the next segment runs in. Upstream's `own`, negated so the zero value is
	// the common case.
	Forked bool
	// LastStage is true for a pipeline's last stage, and for the closer of a
	// compound that was one: `shopt -s lastpipe` runs that stage in the
	// current shell, so a `cd` there may move what follows. Upstream folds it
	// into `own`, as None while `lastpipe` may be on; it is a field here so
	// the caller decides whether it may be, which takes the environment as
	// well as the string (Q212).
	LastStage bool
	// Function names the function whose body this segment sits directly in,
	// and is empty otherwise. Defining one runs none of its body, so a `cd`
	// there moves the rest of the body and not what follows the definition;
	// a call to it is what moves the caller. Upstream's function_scope.
	Function string
	// Body names the innermost function whose body this segment sits in at
	// any depth, so it is Function or the function a subshell inside a body
	// belongs to: `cd () ( : )` defines cd, though none of its segments sits
	// directly in the body. This port's, and upstream has no field for it.
	Body string
	// StdoutAway is true when the redirects beside this segment leave fd 1 on
	// the shell's stderr, or on a descriptor this cannot follow, so the next
	// pipeline stage does not read what it prints: `>&2`, `1>&2`, `>&2 2>&1`
	// and `>/dev/stderr` all do, and `2>&1 >&2` and `>file` do not. They are
	// read left to right, as bash applies them. A compound piped as a whole
	// takes its closer's. This port's, and upstream has no question that
	// turns on where stdout goes.
	StdoutAway bool
}

// definitionPrefix is whether a function definition can stand behind word:
// any of leadingWords but a closer, which ends a command rather than leading
// one. `if f () { cd w; }; then` and `! f () { cd w; }` both define f, driven
// on bash 5.3.15. `time -p` is Q223's, and stops the run at `-p`.
func definitionPrefix(word string) bool {
	for _, closer := range compoundClosers {
		if word == closer {
			return false
		}
	}
	return leadingWords[word]
}

// compoundClosers maps the reserved word that opens each compound command to
// its closer. `for` and `select` are too, though shKeywords leaves them out.
var compoundClosers = map[string]string{"{": "}", "if": "fi", "case": "esac",
	"for": "done", "select": "done", "while": "done", "until": "done"}

// leadingWords are the reserved words after which the next word is still in
// command position. A closer is one too: `{ { a; } }` and `then { a; } fi` are
// both valid bash. Upstream's LEADING_WORDS; cmdPosKeywords is narrower
// because scanDollarParen's `case` reading is keyed on it.
var leadingWords = map[string]bool{"if": true, "then": true, "else": true,
	"elif": true, "do": true, "while": true, "until": true, "!": true,
	"time": true, "{": true, "}": true, "fi": true, "esac": true, "done": true}

// A compound is one compound command still open: upstream's frame. scope is
// the shell it opened, if any, and closerShell is set instead of closer for a
// function body written as `f () ( … )`, which the paren closes.
type compound struct {
	closer      string
	closerShell int
	scope       int
	first       int
	depth       int
}

// interrupted is the command a substitution sits inside, kept while its body is
// read. Bash expands a `$(…)`, `$((…))`, `<(…)` or `>(…)` to build the command's
// words, so the words after one belong to that command: `cat $(x) f` reads f.
// Upstream's loop flushes at the `(`, which leaves f a command name, and this
// repo's walk goes on past the unresolved `$(`, so f crossed with only a record
// for the substitution. It also ran `echo $(date) env` as `env`.
//
// So the body's segments come first, as bash runs them, and the command resumes
// at the `)` with everything its own separators decide: its operator, its
// pipeline, its subshells and its descriptors.
type interrupted struct {
	cur, curRedir, curInputs []string
	curQF                    []int
	pipe                     int
	prevSep, lead            string
	fds                      descriptors
	closed                   []compound
	closedParens             []int
	lastClose                bool
	cmdPos, compoundPos      bool
	shells                   int
	// word is whether the last of cur is the word the substitution sits in. A
	// redirect's target is not in cur, and a process substitution ends its word.
	word bool
}

// ProcessSubstitution is the word a `<(…)` or `>(…)` holds in its command. Bash
// hands the command one path for it, and without the word every operand after
// it moves: `grep <(x) f` would take f for grep's pattern. No file to open, so a
// caller drops it from what it reads, and a NUL so that no argument can spell it.
const ProcessSubstitution = "\x00<("

// opensSubstitution reports whether the `(` at tokens[i] is a substitution's
// rather than a subshell's. A `>` or `<` ahead of it was taken as the target of
// the redirect before it, in `> >(…)` and `< <(…)`.
func opensSubstitution(tokens []string, i int) bool {
	if i == 0 {
		return false
	}
	return strings.HasSuffix(tokens[i-1], "$(") || tokens[i-1] == ">" || tokens[i-1] == "<"
}

// descriptors is where fd 1 and fd 2 point while one segment's redirects are
// read: "pipe" and "err" for where they started, the next stage and the
// shell's stderr, "file" for a file or a closed descriptor, and "other" for a
// descriptor this cannot follow. The zero value is the start. Only those two
// are tracked, because only where fd 1 lands decides StdoutAway.
type descriptors struct{ out, err string }

func (d descriptors) stdout() string { return cmp.Or(d.out, "pipe") }
func (d descriptors) stderr() string { return cmp.Or(d.err, "err") }

func (d descriptors) away() bool { return d.stdout() == "err" || d.stdout() == "other" }

// apply reads one redirect, fd being the digit written before op or "".
func (d *descriptors) apply(fd, op, target string) {
	var v string
	switch {
	case op == "&>" || op == "&>>" || op == ">&" && fd == "" && !isDigits(target) && target != "-":
		// `>&file` is `&>file`.
		d.out = d.dest(target)
		d.err = d.out
		return
	case op == ">" || op == ">>" || op == ">|":
		v = d.dest(target)
	case op == ">&" && target == "1":
		v = d.stdout()
	case op == ">&" && target == "2":
		v = d.stderr()
	case op == ">&" && target == "-":
		v = "file"
	case op == ">&":
		v = "other"
	default:
		return
	}
	switch fd {
	case "", "1":
		d.out = v
	case "2":
		d.err = v
	}
}

// dest is where a redirect to path leaves a descriptor: on whatever fd 2 or
// fd 1 holds, for the device names bash and the kernel both serve, and on a
// file otherwise.
func (d descriptors) dest(path string) string {
	switch path {
	case "/dev/stderr", "/dev/fd/2":
		return d.stderr()
	case "/dev/stdout", "/dev/fd/1":
		return d.stdout()
	}
	return "file"
}

// conditional is the Conditional field for a segment reached through sep.
func conditional(sep string) string {
	if sep == "&&" || sep == "||" {
		return sep
	}
	return ""
}

// Segments splits one command string into its simple commands.
//
// Heredoc bodies are stripped from the raw string BEFORE lexing, so body text
// -- arbitrary data, possibly with unbalanced quotes -- never reaches the
// tokenizer. Comments are stripped next, with bash's own rule rather than
// shlex's. Heredoc stripping runs first so an unbalanced quote in a body cannot
// throw off StripComments' quote tracking for the rest of the command.
//
// A caller that also needs the heredoc bodies -- to scan them, or to find the
// substitutions bash would evaluate inside them -- calls StripHeredocBodies
// itself; this repeats that work rather than returning it, as the upstream
// does, because the two questions have different callers.
//
// An error means the command could not be read, and every caller treats that as
// "do not judge this string".
func Segments(cmd string) ([]Segment, error) { return segments(cmd, true) }

// SegmentsOfStripped is Segments for a string whose heredoc bodies have already
// been taken out. Upstream's tokenize_command takes a `heredocs` flag for the
// same caller; Go has no default argument, so it is a second name.
//
// Stripping twice is not idempotent, which is why the flag exists rather than
// the second pass simply finding nothing to do: the first pass leaves the
// `<<WORD` operator behind with its body and terminator gone, and a second one
// re-arms that operator and swallows everything after it as an unterminated
// body. Driven on this segmenter -- `cat <<EOF\nbody\nEOF\ncd sub && cat x`
// stripped own-level and re-stripped comes back as `cat` alone, with the `cd`
// and the read after it gone.
func SegmentsOfStripped(cmd string) ([]Segment, error) { return segments(cmd, false) }

func segments(cmd string, stripHeredocs bool) ([]Segment, error) {
	if strings.TrimSpace(cmd) == "" {
		return nil, nil
	}
	if stripHeredocs {
		cmd = StripHeredocBodies(cmd, nil, false)
	}
	tokens, quotedFrom, err := lexMarking(StripComments(cmd), true)
	if err != nil {
		return nil, err
	}
	tokens, quotedFrom = splitOperatorRuns(tokens, quotedFrom)
	tokens, quotedFrom = glueDollarParen(tokens, quotedFrom)

	var (
		segs      []Segment
		cur       []string
		curQF     []int
		curRedir  []string
		curInputs []string
		paren     int
		pipe      int
		prevSep   string
		// The subshells open at this point, numbered in the order they
		// opened, which is what Segment.Shells reports.
		shells []int
		opened int
		// Where a `case` pattern stands, upstream's pdepth and pstarted
		// (its Q273): the parens an extglob opened inside the pattern, and
		// whether the pattern has a word yet, without which its leading `(`
		// is bash's optional opener rather than a group.
		patDepth   int
		patStarted bool
		// One entry per open `case`, in the states scanDollarParen tracks it
		// in: "in" | "pat" | "body", and "next" for a later arm's pattern.
		// The two read against each other on purpose -- there the question
		// is which `)` closes a substitution, here it is which segments an arm
		// holds -- and neither is upstream's, whose group loop has no case
		// handling at all. Segment.CaseArm has what this costs and why the
		// port takes it.
		clauses []string
		// Whether the next word is where bash reads a command name, so `case`
		// in `echo case` stays an operand. cmdPosKeywords is the same set
		// scanDollarParen keys on.
		cmdPos = true
		// Upstream's compound tracking (its Q265 and Q272): the compounds
		// still open, the function whose header has been read and whose body
		// has not opened, the separator Forked judges a segment by -- which a
		// compound opening the segment takes over -- the compounds closed in
		// this segment, whose subshell the next separator decides, whether one
		// closed was a later stage, and upstream's cmd_pos.
		frames      []compound
		fn          string
		lead        string
		closed      []compound
		lastClose   bool
		compoundPos = true
		fnNames     = map[int]string{}
		// Where fd 1 and fd 2 point for the segment being read, and the
		// subshells open at this point -- the segment each began at, or -1
		// for a process substitution -- with those just closed, which the
		// separator after them pipes or does not.
		fds          = descriptors{}
		parenFirst   []int
		closedParens []int
		// The commands substitutions have interrupted, innermost last, and the
		// highest pipeline number handed out, since a resumed command takes
		// back a number the body's successors must not reuse.
		stack []interrupted
		pipes int
	)
	openSubstitution := func(word bool) {
		stack = append(stack, interrupted{cur, curRedir, curInputs, curQF, pipe, prevSep,
			lead, fds, closed, closedParens, lastClose, cmdPos, compoundPos, len(shells), word})
		cur, curQF, curRedir, curInputs = nil, nil, nil, nil
		fds, closed, closedParens, lastClose = descriptors{}, nil, nil, false
		pipes++
		pipe = pipes
		parenFirst = append(parenFirst, -1)
		paren++
		opened++
		shells = append(shells, opened)
		prevSep, lead = "(", "("
		cmdPos, compoundPos = true, true
	}
	for i := 0; i < len(tokens); {
		t := tokens[i]
		if quotedFrom[i] == gluedToClose {
			i++
			continue
		}
		// A reserved word ahead of the name can leave it in command position,
		// so `then f () { … }` is a definition; upstream's `len(cur) == 1` reads
		// it as a call and the body as the current shell (Q212).
		k := 0
		for k < len(cur) && definitionPrefix(cur[k]) && curQF[k] == NotQuoted {
			k++
		}
		if t == "(" && i+1 < len(tokens) && tokens[i+1] == ")" &&
			isOperator(t, quotedFrom[i], separators) &&
			isOperator(tokens[i+1], quotedFrom[i+1], separators) &&
			len(cur) == k+1 && len(curRedir) == 0 && !inPattern(clauses) &&
			!isReservedWord(cur[k], curQF[k]) && !strings.ContainsAny(cur[k], "=$`(") {
			// `f ()` heads a definition, and runs nothing.
			fn, cur, curQF = cur[k], cur[:k], curQF[:k]
			i += 2
			cmdPos, compoundPos = true, true
			continue
		}
		if isOperator(t, quotedFrom[i], separators) {
			if t == "(" && !inPattern(clauses) && opensSubstitution(tokens, i) {
				// `$((` is arithmetic, one word whatever it holds, and a caller
				// asking how many words `$(` becomes needs the difference.
				if n := len(cur); n > 0 && i+1 < len(tokens) && tokens[i+1] == "(" &&
					strings.HasSuffix(cur[n-1], "$(") {
					cur[n-1] += "("
				}
				target := i >= 2 && (isOperator(tokens[i-2], quotedFrom[i-2], redir) ||
					isOperator(tokens[i-2], quotedFrom[i-2], dup))
				openSubstitution(strings.HasSuffix(tokens[i-1], "$(") && !target)
				i++
				continue
			}
			empty := len(cur) == 0 && len(curRedir) == 0
			resume := false
			if !empty {
				persists := paren == 0 && !isPipe(prevSep) &&
					(t == ";" || t == "\n" || t == "&&" || t == "||")
				segs = append(segs, Segment{cur, curRedir, curInputs, persists,
					conditional(prevSep), inCaseArm(clauses), pipe, curQF,
					append([]int(nil), shells...), forked(lead, t),
					lastStage(lead, t, lastClose), "", "", fds.away()})
				cur, curQF, curRedir, curInputs = nil, nil, nil, nil
			}
			lastClose = false
			if isPipe(t) || t == "&" {
				// A compound piped or backgrounded as a whole runs in a
				// subshell, which only the separator after its closer says.
				for _, c := range closed {
					opened++
					for k := c.first; k < len(segs); k++ {
						sh := segs[k].Shells
						segs[k].Shells = slices.Insert(sh, min(c.depth, len(sh)), opened)
					}
				}
			}
			// A compound or subshell piped as a whole is one stage, so every
			// command in it writes to the next: `{ grep -r x d; } | f` and
			// `(a; grep -r x d) | f` feed f from grep, and a redirect on the
			// closer moves them all.
			if isPipe(t) {
				firsts := slices.Clone(closedParens)
				for _, c := range closed {
					firsts = append(firsts, c.first)
				}
				for _, first := range firsts {
					for k := first; k < len(segs); k++ {
						segs[k].Pipe = pipe
						segs[k].StdoutAway = segs[k].StdoutAway || fds.away()
					}
				}
			}
			if t != ")" {
				closedParens = nil
			}
			fds = descriptors{}
			closed = nil
			n := len(clauses)
			pattern := n > 0 && (clauses[n-1] == "pat" || clauses[n-1] == "next")
			switch {
			case pattern && t == "(":
				// A pattern's parens are pattern syntax and open no subshell:
				// read as one, the `)` after `y` closed the subshell around the
				// `case`, and a `cd` after the `esac` escaped it.
				if patStarted {
					patDepth++
				}
				patStarted = true
			case pattern && t == ")" && patDepth > 0:
				patDepth--
			case pattern && t == ")":
				// A case pattern's `)` needs no opener, so it is the one
				// separator that means something beyond the depth: it ends the
				// pattern and opens the arm. Read AFTER the flush above, so
				// the `case x in y` header -- which the same `)` terminates --
				// is not itself marked.
				clauses[n-1] = "body"
			case t == "(":
				parenFirst = append(parenFirst, len(segs))
				if fn != "" { // `f () ( … )`
					opened++
					shells = append(shells, opened)
					fnNames[opened] = fn
					frames = append(frames, compound{closerShell: opened + 1})
					fn = ""
				}
				paren++
				opened++
				shells = append(shells, opened)
			case t == ")":
				if paren > 0 {
					paren--
				}
				if n := len(parenFirst); n > 0 {
					if first := parenFirst[n-1]; first >= 0 {
						closedParens = append(closedParens, first)
					} else {
						resume = true
					}
					parenFirst = parenFirst[:n-1]
				}
				if len(shells) > 0 {
					if f := len(frames); f > 0 && frames[f-1].closerShell == shells[len(shells)-1] {
						shells = shells[:len(shells)-1]
						frames = frames[:f-1]
					}
					shells = shells[:len(shells)-1]
				}
			case empty && prevSep == ";" && (t == ";" || t == "&") &&
				n > 0 && clauses[n-1] == "body":
				// `;;`, `;&` or `;;&` ends an arm, and the words up to the
				// next unopened `)` are a pattern again.
				clauses[n-1] = "next"
				patDepth, patStarted = 0, false
			}
			// A body's output reaches the command as a file or as words rather
			// than down the pipe, so it numbers its own: `grep -r x d <(f)` is
			// not filtered by f, and `grep -r x d 2> >(f)` sends the matches
			// past it. What follows the `)` is in the command's pipeline again.
			// The rest of a word glued to the `)` is that word's, so `$(x)/cat`
			// ends in `/cat` and a caller can tell it from `$(x) /cat`. The word
			// holds a substitution, so nothing here can name what it opens.
			if resume {
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				cur, curRedir, curInputs, curQF = f.cur, f.curRedir, f.curInputs, f.curQF
				pipe, prevSep, lead, fds = f.pipe, f.prevSep, f.lead, f.fds
				closed, closedParens, lastClose = f.closed, f.closedParens, f.lastClose
				cmdPos, compoundPos = f.cmdPos, f.compoundPos
				i++
				if i < len(tokens) && quotedFrom[i] == gluedToClose {
					if n := len(cur); f.word && n > 0 && i+1 < len(tokens) {
						cur[n-1] += tokens[i+1]
					}
					i += 2
				}
				continue
			}
			// A subshell's parens open and close no pipeline: `f | (g)` pipes
			// f into g, and `(grep -r x d) | f` grep into f.
			if !isPipe(t) && t != "(" && t != ")" {
				pipes++
				pipe = pipes
			}
			prevSep, lead = t, t
			cmdPos, compoundPos = true, true
			i++
			continue
		}
		if isOperator(t, quotedFrom[i], redir) || isOperator(t, quotedFrom[i], dup) {
			// An fd number written immediately before a redirect or dup
			// operator (`2>file`, `2>&1`) tokenizes as a bare digit token
			// glued to the operator. The lexer drops the adjacency, so it lands
			// as the previous token; pop it so it does not leak as a positional
			// file argument. (A literal file NAMED `2` right before a redirect
			// is indistinguishable post-tokenization.)
			fd := ""
			if n := len(cur); n > 0 && isDigits(cur[n-1]) {
				fd = cur[n-1]
				cur, curQF = cur[:n-1], curQF[:n-1]
			}
			if i+1 < len(tokens) {
				fds.apply(fd, t, tokens[i+1])
			}
			if dup[t] {
				// `2>&1`, `2>&-`, `<&3`: the target is a bare fd number or `-`
				// (a duplication or close target, not a path) -- skip it. But
				// `>&file` (target is not a bare fd) redirects to a file, so
				// treat that target like any other redirect target.
				if i+1 < len(tokens) {
					if nxt := tokens[i+1]; !isDigits(nxt) && nxt != "-" {
						curRedir = append(curRedir, nxt)
					}
					i += 2
					continue
				}
				i++
				continue
			}
			if i+1 < len(tokens) {
				// `<<TAG` heredoc delimiter and `<<<STR` here-string content
				// are not file paths -- skip without recording a target.
				if t == "<<" || t == "<<<" {
					i += 2
					continue
				}
				curRedir = append(curRedir, tokens[i+1])
				// `<(cmd)` lexes as `<` and `(`, so upstream records the
				// paren as a target. It is a process substitution and not a
				// file, and the loop that reads Inputs would try to open it,
				// so it is kept out of Inputs and left in Redirects as it is.
				process := isOperator(tokens[i+1], quotedFrom[i+1], separators) && tokens[i+1] == "("
				if t == "<" && !process {
					curInputs = append(curInputs, tokens[i+1])
				}
				// Its body runs in a subshell, and its `)` still arrives
				// as a separator. Upstream counts neither, so that `)`
				// closes whatever subshell the command sits in, and the
				// segments after it, still inside, read as outside.
				if process {
					cur, curQF = append(cur, ProcessSubstitution), append(curQF, NotQuoted)
					openSubstitution(false)
				}
				i += 2
				continue
			}
			i++
			continue
		}
		// A pattern word runs nothing, so only the `esac` ending one can
		// close anything.
		if compoundPos && quotedFrom[i] == NotQuoted && (!inPattern(clauses) || t == "esac") &&
			(shKeywords[t] || t == "for" || t == "select") {
			if t == "function" && i+1 < len(tokens) {
				fn = tokens[i+1] // `function f [()]`
				if i+3 < len(tokens) && tokens[i+2] == "(" && tokens[i+3] == ")" {
					i += 4
				} else {
					i += 2
				}
				continue
			}
			if closer, ok := compoundClosers[t]; ok {
				c := compound{closer: closer, first: len(segs), depth: len(shells)}
				if fn != "" || isPipe(lead) {
					// A function body, or a later pipeline stage, which is the
					// subshell itself: the segment it opens is no stage of its
					// own.
					opened++
					shells = append(shells, opened)
					c.scope = opened
					if fn != "" {
						fnNames[opened] = fn
					}
				}
				frames = append(frames, c)
				lead = ""
			} else if f := len(frames); f > 0 && frames[f-1].closer == t {
				c := frames[f-1]
				frames = frames[:f-1]
				if j := slices.Index(shells, c.scope); c.scope != 0 && j >= 0 {
					shells = shells[:j]
					lastClose = lastClose || fnNames[c.scope] == ""
				} else if c.scope == 0 {
					closed = append(closed, c)
				}
			}
			fn = ""
			compoundPos = leadingWords[t]
		} else {
			fn, compoundPos = "", false
		}
		cur = append(cur, t)
		curQF = append(curQF, quotedFrom[i])
		opening := len(clauses) > 0 && clauses[len(clauses)-1] == "in"
		cmdPos = trackCase(&clauses, t, cmdPos)
		// The `in` that opens the first pattern is no word of it.
		patStarted = !opening || clauses[len(clauses)-1] != "pat"
		i++
	}
	if len(cur) > 0 || len(curRedir) > 0 {
		segs = append(segs, Segment{cur, curRedir, curInputs, paren == 0 && !isPipe(prevSep),
			conditional(prevSep), inCaseArm(clauses), pipe, curQF,
			append([]int(nil), shells...), forked(lead, ""),
			lastStage(lead, "", lastClose), "", "", fds.away()})
	}
	// An unterminated substitution: the commands it interrupted still ran.
	for n := len(stack) - 1; n >= 0; n-- {
		f := stack[n]
		if len(f.cur) > 0 || len(f.curRedir) > 0 {
			segs = append(segs, Segment{f.cur, f.curRedir, f.curInputs, false,
				conditional(f.prevSep), inCaseArm(clauses), f.pipe, f.curQF,
				append([]int(nil), shells[:min(f.shells, len(shells))]...), forked(f.lead, ""),
				lastStage(f.lead, "", f.lastClose), "", "", f.fds.away()})
		}
	}
	for k := range segs {
		shells := segs[k].Shells
		if n := len(shells); n > 0 {
			segs[k].Function = fnNames[shells[n-1]]
		}
		for n := len(shells) - 1; n >= 0 && segs[k].Body == ""; n-- {
			segs[k].Body = fnNames[shells[n]]
		}
	}
	return segs, nil
}

// forked and lastStage are upstream's stage_own, split: forked is the Forked
// field for a segment reached through lead and ended by sep, and lastStage
// the arm it returns None from while `lastpipe` may be on. lastClose says the
// segment closes a compound that was a later stage.
func forked(lead, sep string) bool {
	return isPipe(sep) || sep == "&" || isPipe(lead)
}

func lastStage(lead, sep string, lastClose bool) bool {
	return !isPipe(sep) && sep != "&" && (isPipe(lead) || lastClose)
}

// inPattern reports whether the innermost open `case` is reading a pattern.
func inPattern(clauses []string) bool {
	n := len(clauses)
	return n > 0 && (clauses[n-1] == "pat" || clauses[n-1] == "next")
}

// isPipe is upstream's PIPE_OPS. `|&` is `2>&1 |`, so its right side is a
// stage like any other: upstream's persistence rule and pipeline numbering
// test for `|` alone, and `P=/x; true |& P=/y; cat $P/f` read /y/f where
// bash reads /x/f, silently.
func isPipe(sep string) bool { return sep == "|" || sep == "|&" }

// trackCase advances the `case` clause states for one word token and reports
// whether the next word is still in command position. The three arms and their
// order are scanDollarParen's, which is what keeps the two readings the same:
// a clause waiting for its `in` sees nothing else, an `esac` closes the
// innermost clause that has one, and `case` opens one only in command
// position. An unterminated `case` leaves its clause open, so every segment
// after the pattern stays marked -- the fail-closed direction.
func trackCase(clauses *[]string, word string, cmdPos bool) bool {
	n := len(*clauses)
	state := ""
	if n > 0 {
		state = (*clauses)[n-1]
	}
	switch {
	case state == "in":
		if word == "in" {
			(*clauses)[n-1] = "pat"
		}
	case n > 0 && word == "esac":
		*clauses = (*clauses)[:n-1]
	case word == "case" && cmdPos:
		*clauses = append(*clauses, "in")
	}
	return cmdPos && cmdPosKeywords[word]
}

// inCaseArm reports whether any open `case` is past its first pattern, which
// is what makes the segment being flushed one bash runs only on a match. Any
// rather than the innermost: a nested `case` header sits inside the outer
// arm, and so does everything under it.
func inCaseArm(clauses []string) bool {
	for _, state := range clauses {
		if state == "body" || state == "next" {
			return true
		}
	}
	return false
}

// isDigits stands for Python's str.isdigit, which is what decides whether the
// token before a redirect is an fd number. It differs on non-ASCII digits --
// Python counts `²` and `٣`, this does not -- because an fd number is ASCII and
// the alternative is carrying a Unicode table for a case bash itself rejects.
// The cost of the difference either way is one token treated as an operand
// instead of an fd, or the reverse.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
