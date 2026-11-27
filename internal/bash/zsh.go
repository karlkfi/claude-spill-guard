package bash

import (
	"regexp"
	"strings"
)

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

// ZshOnlyWord names the first shape in text that zsh reads as a word naming
// files and the segmenter does not, or returns "". Each was driven on zsh 5.9
// printing a file the hook never opened:
//
//   - a `(` glued to a word, which GluedParen reads: an alternation,
//     `(k1|zz).env`, split as a subshell, and a qualifier on a word with no
//     glob in it, `a.txt(P:k1.env:)`, which expand never sees;
//   - a numeric range, `k<1-1>.env`, split as two redirects;
//   - an `=cmd` word, which zsh replaces with that command's path, and `=(…)`,
//     its file-backed process substitution, split as `=` and a subshell.
//
// The range is read off the text as well as the tokens, because the lexer
// keeps no whitespace and `cmd <1-1 >out` is two redirects in zsh too.
func ZshOnlyWord(text string) string {
	if GluedParen(text) {
		return "a `(` against a word, which zsh reads as an alternation or a glob qualifier"
	}
	tokens, quotedFrom, err := lex(text)
	if err != nil {
		return "a command this cannot lex"
	}
	for i, t := range tokens {
		if quotedFrom[i] == 0 {
			continue
		}
		switch {
		case t == "<" && i+2 < len(tokens) && tokens[i+2] == ">" &&
			quotedFrom[i+1] == NotQuoted && numericRange.MatchString(tokens[i+1]) &&
			strings.Contains(text, "<"+tokens[i+1]+">"):
			return "a `<n-m>` numeric range, which zsh reads as a glob"
		case t == "=" && i+1 < len(tokens) && tokens[i+1] == "(" && quotedFrom[i+1] == NotQuoted:
			return "an `=(…)` process substitution, which zsh reads as a file"
		case len(t) > 1 && t[0] == '=' && isNameByte(t[1]):
			return "an `=cmd` word, which zsh replaces with a command's path"
		}
	}
	return ""
}

var numericRange = regexp.MustCompile(`^[0-9]*-[0-9]*$`)

func isNameByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
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
