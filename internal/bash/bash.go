// Package bash splits a Bash command string into the simple commands it runs,
// so a caller can find the file operands the readers -- `cat`, `head`, `tail`,
// `grep` -- are pointed at and scan those the way the Read tool's payload is
// scanned.
//
// It is a port of the shell parsing in karlkfi/claude-bouncer: the layers below
// Segments come from lib/bouncer_parse.py, shared by all five guards there, and
// Segments itself from the group loop in
// plugins/workspace-guard/scripts/bash-workspace-guard.py. Ported at tag
// workspace-guard/v1.11.0, commit 1d09ffef33bbb9632f714bc416e627b937353826,
// where both files also stand at that repository's main.
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
// (no default argument), and isDigits below.
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
	// Tokens is the command and its operands, redirects removed.
	Tokens []string
	// Redirects is every redirect target written in this segment. A heredoc
	// delimiter and a here-string's content are not paths and are not here.
	Redirects []string
	// Persists is true only when a variable assignment in this segment
	// survives into later commands of the same string: at paren depth 0 (not a
	// subshell -- `(f=x); cat $f` does not set f), not a pipeline stage (each
	// side of `|` runs in a subshell), and not backgrounded (`f=x & …` assigns
	// in the background copy only).
	Persists bool
	// Pipe numbers the pipeline this segment belongs to, which is what tells a
	// `grep` filtering another command's output apart from a `grep` reading
	// ordinary files.
	Pipe int
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
func Segments(cmd string) ([]Segment, error) {
	if strings.TrimSpace(cmd) == "" {
		return nil, nil
	}
	tokens, err := lex(StripComments(StripHeredocBodies(cmd, nil, false)))
	if err != nil {
		return nil, err
	}
	tokens = glueDollarParen(splitOperatorRuns(tokens))

	var (
		segs     []Segment
		cur      []string
		curRedir []string
		paren    int
		pipe     int
		prevSep  string
	)
	for i := 0; i < len(tokens); {
		t := tokens[i]
		if separators[t] {
			if len(cur) > 0 || len(curRedir) > 0 {
				persists := paren == 0 && prevSep != "|" &&
					(t == ";" || t == "\n" || t == "&&" || t == "||")
				segs = append(segs, Segment{cur, curRedir, persists, pipe})
				cur, curRedir = nil, nil
			}
			switch t {
			case "(":
				paren++
			case ")":
				if paren > 0 {
					paren--
				}
			}
			if t != "|" {
				pipe++
			}
			prevSep = t
			i++
			continue
		}
		if redir[t] || dup[t] {
			// An fd number written immediately before a redirect or dup
			// operator (`2>file`, `2>&1`) tokenizes as a bare digit token
			// glued to the operator. The lexer drops the adjacency, so it lands
			// as the previous token; pop it so it does not leak as a positional
			// file argument. (A literal file NAMED `2` right before a redirect
			// is indistinguishable post-tokenization.)
			if n := len(cur); n > 0 && isDigits(cur[n-1]) {
				cur = cur[:n-1]
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
				i += 2
				continue
			}
			i++
			continue
		}
		cur = append(cur, t)
		i++
	}
	if len(cur) > 0 || len(curRedir) > 0 {
		segs = append(segs, Segment{cur, curRedir, paren == 0 && prevSep != "|", pipe})
	}
	return segs, nil
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
