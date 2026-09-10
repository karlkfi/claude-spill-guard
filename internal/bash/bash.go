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
// need of it.
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

import "strings"

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
	tokens, quotedFrom, err := lex(StripComments(cmd))
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
		// One entry per open `case`, in the states scanDollarParen tracks it
		// in: "in" | "pat" | "body". The two read against each other on
		// purpose -- there the question is which `)` closes a substitution,
		// here it is which segments an arm holds -- and neither is upstream's,
		// whose group loop has no case handling at all. Segment.CaseArm has
		// what this costs and why the port takes it.
		clauses []string
		// Whether the next word is where bash reads a command name, so `case`
		// in `echo case` stays an operand. cmdPosKeywords is the same set
		// scanDollarParen keys on.
		cmdPos = true
	)
	for i := 0; i < len(tokens); {
		t := tokens[i]
		if isOperator(t, quotedFrom[i], separators) {
			if len(cur) > 0 || len(curRedir) > 0 {
				persists := paren == 0 && prevSep != "|" &&
					(t == ";" || t == "\n" || t == "&&" || t == "||")
				segs = append(segs, Segment{cur, curRedir, curInputs, persists,
					conditional(prevSep), inCaseArm(clauses), pipe, curQF})
				cur, curQF, curRedir, curInputs = nil, nil, nil, nil
			}
			switch t {
			case "(":
				paren++
			case ")":
				if paren > 0 {
					paren--
				}
				// A case pattern's `)` needs no opener, so it is the one
				// separator that means something beyond the depth: it ends the
				// pattern and opens the arm. Read AFTER the flush above, so
				// the `case x in y` header -- which the same `)` terminates --
				// is not itself marked. bash's optional `(` opener balanced
				// the depth just above, and a `)` in an arm's body finds the
				// clause already past "pat" and changes nothing.
				if n := len(clauses); n > 0 && clauses[n-1] == "pat" {
					clauses[n-1] = "body"
				}
			}
			if t != "|" {
				pipe++
			}
			prevSep = t
			cmdPos = true
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
			if n := len(cur); n > 0 && isDigits(cur[n-1]) {
				cur, curQF = cur[:n-1], curQF[:n-1]
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
				if t == "<" && tokens[i+1] != "(" {
					curInputs = append(curInputs, tokens[i+1])
				}
				i += 2
				continue
			}
			i++
			continue
		}
		cur = append(cur, t)
		curQF = append(curQF, quotedFrom[i])
		cmdPos = trackCase(&clauses, t, cmdPos)
		i++
	}
	if len(cur) > 0 || len(curRedir) > 0 {
		segs = append(segs, Segment{cur, curRedir, curInputs, paren == 0 && prevSep != "|",
			conditional(prevSep), inCaseArm(clauses), pipe, curQF})
	}
	return segs, nil
}

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
		if state == "body" {
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
