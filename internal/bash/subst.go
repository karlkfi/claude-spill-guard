package bash

import "strings"

// matchWord matches `[A-Za-z_][A-Za-z0-9_]*` at i, returning the word and the
// index just past it, or ok=false when i is not a word start.
//
// The Python calls a compiled regexp with a start offset. Go's regexp has no
// anchored-at-offset match, and slicing to hand it a substring would allocate
// on every byte of every scan, so this is the one place the port writes out
// what the pattern says.
func matchWord(text string, i int) (word string, end int, ok bool) {
	if i >= len(text) {
		return "", i, false
	}
	c := text[i]
	if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return "", i, false
	}
	end = i + 1
	for end < len(text) {
		c := text[end]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') {
			end++
			continue
		}
		break
	}
	return text[i:end], end, true
}

// scanCasePattern scans a `case` pattern list from start to the `)` that ends
// it.
//
// Returns the index just past that `)`, or ok=false when the text runs out
// first. A leading `(` is bash's optional pattern opener and is consumed
// without nesting, so `(a)` and `a)` end at the same place; parens written
// INSIDE the pattern -- an extglob `@(a|b)` -- do nest.
func scanCasePattern(text string, start int) (int, bool) {
	i, n, depth := start, len(text), 0
	if i < n && text[i] == '(' {
		i++
	}
	inSingle, inDouble := false, false
	for i < n {
		c := text[i]
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			i++
			continue
		}
		if inDouble {
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				inDouble = false
			}
			i++
			continue
		}
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				return i + 1, true
			}
			depth--
		}
		i++
	}
	return 0, false
}

// scanDollarParen scans a `$(` body from start (just past the `$(`) to its
// matching `)`.
//
// Returns the inner substring and the index just past the close, or ok=false if
// no balanced terminator is found. Paren nesting, single and double quotes, and
// backslash escapes inside the body are tracked so a `)` inside a quoted string
// or a nested `(…)`/`$(…)` does not close early. Quote tracking is flat (it does
// not recurse into nested substitutions); on the exotic input where that
// mis-locates the close, the body handed to the lexer is unbalanced and
// analysis defers for it -- fail-safe.
//
// A `case` clause is tracked too, because its pattern's `)` needs no opener: in
// `$(case $x in a) cmd;; esac)` the first `)` ends the pattern and only the last
// closes the substitution. Untracked, the body came back as `case $x in` and
// nothing the clause ran was ever scanned (Q81). Only bash 3.2 agrees with that
// reading; 5.x and zsh run the clause. The parenthesised form `(a)` already
// worked, since its opener balanced the terminator, which is what kept the gap
// to the bare form.
//
// A heredoc body is stepped over rather than read (Q109). It is data to bash,
// so an apostrophe in one is text -- read as syntax it opened a quoted run that
// never closed, and the scan ran off the end and returned no substitution at
// all. StripHeredocBodies does not always get there first: inside a `case`
// clause its own context tracking ends the substitution at the pattern's `)`,
// so the `<<` is never reached. A `<<<` here-string arms nothing, and `((…))` is
// stepped over whole so a shift is not mistaken for a redirection.
//
// Only a body whose terminator line is actually present is stepped over, and
// that is load-bearing rather than tidy. Callers run StripHeredocBodies first,
// so by the time this sees a `<<WORD` the body is usually already gone and the
// operator is all that is left; eating to end of input there -- which is what
// bash does to a genuinely unterminated body -- would swallow the `)` that
// closes the substitution and lose it entirely. Declining leaves the scan where
// it was, so the close is still found.
//
// `case` counts only in command position, so the operand in `echo case` stays
// an operand -- mistaking one for the keyword would swallow the real close and
// drop a substitution that reads fine today. A `)` at depth 0 still closes
// whatever the clause state says, which keeps a missed `esac` costing nothing.
func scanDollarParen(text string, start int) (string, int, bool) {
	i, n, depth := start, len(text), 0
	inSingle, inDouble := false, false
	cmdPos := true               // bash reads a command just past the `$(`
	var clauses []string         // one entry per open `case`: "in" | "pat" | "body"
	var pending []pendingHeredoc // delimiters armed, awaiting their bodies
	for i < n {
		c := text[i]
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			i++
			continue
		}
		if inDouble {
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				inDouble = false
			}
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' {
			i++
			if c == '\n' {
				cmdPos = true
				for len(pending) > 0 && i < n { // bodies start after this line
					p := pending[0]
					pending = pending[1:]
					end, closed := consumeHeredocBody(text, i, p.delim, p.stripTabs)
					if !closed {
						break // see the doc comment -- not ours to eat
					}
					i = end
				}
			}
			continue
		}
		if len(clauses) > 0 && clauses[len(clauses)-1] == "pat" {
			if word, end, ok := matchWord(text, i); ok && word == "esac" {
				clauses = clauses[:len(clauses)-1] // `case $x in esac` -- no clauses
				cmdPos = false
				i = end
				continue
			}
			end, ok := scanCasePattern(text, i)
			if !ok {
				return "", start, false
			}
			clauses[len(clauses)-1] = "body"
			cmdPos = true
			i = end
			continue
		}
		if c == '\\' {
			i += 2
			continue
		}
		if c == '\'' {
			inSingle = true
			cmdPos = false
			i++
			continue
		}
		if c == '"' {
			inDouble = true
			cmdPos = false
			i++
			continue
		}
		if c == ';' {
			cmdPos = true
			if len(clauses) > 0 && clauses[len(clauses)-1] == "body" {
				matched := false
				for _, term := range []string{";;&", ";;", ";&"} { // longest first
					if strings.HasPrefix(text[i:], term) {
						clauses[len(clauses)-1] = "pat"
						i += len(term)
						matched = true
						break
					}
				}
				if !matched {
					i++
				}
				continue
			}
			i++
			continue
		}
		if word, end, ok := matchWord(text, i); ok {
			state := ""
			if len(clauses) > 0 {
				state = clauses[len(clauses)-1]
			}
			switch {
			case state == "in":
				if word == "in" {
					clauses[len(clauses)-1] = "pat"
				}
			case word == "esac":
				if state == "body" {
					clauses = clauses[:len(clauses)-1]
				}
			case word == "case" && cmdPos:
				clauses = append(clauses, "in")
			}
			cmdPos = cmdPos && cmdPosKeywords[word]
			i = end
			continue
		}
		if c == '(' && i+1 < n && text[i+1] == '(' {
			i = skipBalancedParens(text, i) // `((…))` / `$((…))` arithmetic
			cmdPos = false
			continue
		}
		if c == '(' {
			depth++
			cmdPos = true
			i++
			continue
		}
		if c == ')' {
			if depth == 0 {
				return text[start:i], i + 1, true
			}
			depth--
			cmdPos = true
			i++
			continue
		}
		if c == '<' && i+1 < n && text[i+1] == '<' {
			if i+2 < n && text[i+2] == '<' { // `<<<` here-string, not heredoc
				i += 3
				continue
			}
			delim, stripTabs, _, end := scanHeredocDelim(text, i+2)
			i = end
			if delim != "" {
				pending = append(pending, pendingHeredoc{delim: delim, stripTabs: stripTabs})
			}
			cmdPos = false
			continue
		}
		cmdPos = c == '&' || c == '|' || c == '{'
		i++
	}
	return "", start, false
}

// scanBackticks scans a backtick body from start (just past the opening
// backtick) to the next unescaped backtick. Reports ok=false when the body is
// unterminated.
func scanBackticks(text string, start int) (string, int, bool) {
	for i, n := start, len(text); i < n; {
		switch text[i] {
		case '\\':
			i += 2
		case '`':
			return text[start:i], i + 1, true
		default:
			i++
		}
	}
	return "", start, false
}

// CommandSubstitutions extracts the command-substitution bodies bash would
// evaluate in text.
//
// Returns the inner command string of each `$(…)` and backtick substitution
// appearing in an UNQUOTED or DOUBLE-QUOTED context -- the two contexts where
// bash performs command substitution. A substitution inside single quotes is a
// literal and is skipped, matching bash; `$((…))` arithmetic (no command
// inside) is skipped too.
//
// Scans the RAW command string, never the tokens: the lexer strips the quotes,
// losing the single-versus-double distinction that decides whether a `$(…)` even
// substitutes. Only the OUTERMOST substitutions are returned -- a nested
// `$(… $(…) …)` is found by re-scanning the returned body, and the caller
// recurses -- with a depth cap of its own, which is the caller's because the
// recursion is. A substitution with no balanced terminator before end of input
// contributes nothing: fail-safe, a possible missed offender rather than a
// fabricated one.
//
// With quotes false a `'` or `"` is ordinary text and every substitution is
// live. That is how bash reads an unquoted heredoc body -- quoting does not
// apply inside one -- so the apostrophe in a `don't` must not switch the scanner
// off for the rest of the body (Q50). Backslash still escapes the next
// character, matching the body's own rule that a backslash quotes a following
// `$`, backtick, backslash, or newline.
//
// The Python defaults quotes to true. Go has no default argument, so every
// caller says which reading it wants.
func CommandSubstitutions(text string, quotes bool) []string {
	var bodies []string
	inSingle, inDouble := false, false
	for i, n := 0, len(text); i < n; {
		c := text[i]
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			i++
			continue
		}
		if c == '\\' { // escapes next byte (not in '')
			i += 2
			continue
		}
		if quotes && c == '\'' && !inDouble {
			inSingle = true
			i++
			continue
		}
		if quotes && c == '"' {
			inDouble = !inDouble
			i++
			continue
		}
		if c == '$' && i+1 < n && text[i+1] == '(' {
			if i+2 < n && text[i+2] == '(' {
				i = skipBalancedParens(text, i+1) // `$((…))` arithmetic
				continue
			}
			body, end, ok := scanDollarParen(text, i+2)
			if !ok {
				break // unterminated -> stop
			}
			bodies = append(bodies, body)
			i = end
			continue
		}
		if c == '`' {
			body, end, ok := scanBackticks(text, i+1)
			if !ok {
				break // unterminated -> stop
			}
			bodies = append(bodies, body)
			i = end
			continue
		}
		i++
	}
	return bodies
}

// UnstrippedSubstBodies swaps each substitution body in subs for its text in
// the raw cmd.
//
// subs comes from the heredoc-stripped string, which is the only scan that
// reads Q35 and Q50 right: a `<<'EOF'` body is literal, so a `$(…)` in one must
// not be found, and an apostrophe in an expanded body must not hide a real
// `$(…)` after it. Stripping leaves the `<<WORD` operator behind, though, and a
// body carrying a disarmed one is mis-read when the recursion strips it a
// second time -- the operator re-arms, its terminator line is long gone, and
// everything after the newline is swallowed as an unterminated body, so
// `echo "$(cat <<EOF … EOF … cat /outside)"` lost the read entirely (Q113).
//
// The raw text still has its terminator, so the recursion strips it correctly.
// A raw body is matched to a stripped one by stripping it back down, which is
// what keeps the two scans' disagreements out: a body only the RAW scan finds
// (the `<<'EOF'` literal) has no stripped counterpart to replace, and one only
// the stripped scan finds has no raw match and is left as it is, since a false
// positive on heredoc data would be worse.
//
// The raw scan runs over an own-level strip rather than over cmd itself.
// Scanning the raw string flat, an apostrophe in an EARLIER top-level heredoc
// body opened a quoted run that swallowed the rest of it (the Q50 mechanism),
// so the scan returned nothing, no body had a counterpart to swap in, and the
// Q113 defect survived with the caller judging a substitution whose contents it
// never saw (Q119). Dropping the top-level bodies first removes that text while
// leaving each substitution's own heredocs -- the terminators the recursion
// needs -- in place.
func UnstrippedSubstBodies(cmd string, subs []string) []string {
	if !strings.Contains(cmd, "<<") {
		return subs
	}
	raw := make(map[string]string)
	for _, body := range CommandSubstitutions(StripHeredocBodies(cmd, nil, true), true) {
		key := StripHeredocBodies(body, nil, false)
		if _, seen := raw[key]; !seen { // the Python's setdefault: first wins
			raw[key] = body
		}
	}
	out := make([]string, len(subs))
	for i, b := range subs {
		if r, ok := raw[b]; ok {
			out[i] = r
		} else {
			out[i] = b
		}
	}
	return out
}
