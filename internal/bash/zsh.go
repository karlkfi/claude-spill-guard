package bash

import "strings"

// This file is this repo's rather than a port: upstream reads every shell as
// bash. Both readings are over the whole text, not a segment's head, because
// the shapes they look for need not sit where a command name does -- `builtin
// setopt globdots`, `function f { setopt globdots }` and `options[globdots]=on`
// each change zsh's globbing from a position no head peel reaches. A text lex
// cannot read returns true, which only ever costs a coverage record.

// GluedParen reports whether text holds an unquoted `(` straight after a word,
// which zsh reads as a glob qualifier on that word and bash as a syntax error.
// shlex splits `(` off as its own token, so `cat *(D)` lexes as `*` then `(`,
// while a quoted `'docs(queue): x'` stays one token and does not count. What
// cannot be told apart is `cat * (D)`, which neither shell runs.
func GluedParen(text string) bool {
	tokens, quotedFrom, err := lex(text)
	if err != nil {
		return true
	}
	for i := 1; i < len(tokens); i++ {
		if tokens[i] != "(" || quotedFrom[i] != NotQuoted {
			continue
		}
		prev := tokens[i-1]
		switch {
		// An array assignment, `arr=(a b)`, and a process substitution, `=(…)`
		// or `$(…)`. `=(` is one only at the start of a word, so `*=(D)` is a
		// qualifier on `*=` and counts.
		case quotedFrom[i-1] == NotQuoted && allPunct(prev),
			isReservedWord(prev, quotedFrom[i-1]),
			isAssignment(prev, quotedFrom[i-1]) && strings.HasSuffix(prev, "="),
			prev == "=", strings.HasSuffix(prev, "$"):
			continue
		}
		return true
	}
	return false
}

// ChangesZshOptions reports whether text can change an option zsh globs
// under: setopt, unsetopt, emulate, an assignment to the `options` array, or
// `set` with a flag, which in zsh sets any option -- `set -o globdots` and
// `set -4` both put dotfiles in `*`. Whole tokens, quoted or not, since zsh
// runs `'setopt'` as setopt; `grep options` names no assignment and does not
// count.
func ChangesZshOptions(text string) bool {
	tokens, _, err := lex(text)
	if err != nil {
		return true
	}
	for i, t := range tokens {
		switch {
		case t == "setopt", t == "unsetopt", t == "emulate",
			strings.HasPrefix(t, "options["), strings.HasPrefix(t, "options="),
			strings.HasPrefix(t, "options+="):
			return true
		case t == "set" && i+1 < len(tokens):
			next := tokens[i+1]
			if len(next) > 1 && (next[0] == '-' || next[0] == '+') && next[1] != '-' {
				return true
			}
		}
	}
	return false
}
