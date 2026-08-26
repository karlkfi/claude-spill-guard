package bash

import "strings"

// Heredocs is what StripHeredocBodies removes, for a caller that needs it back.
//
// The Python takes two optional list arguments and appends to whichever the
// caller passed. Go has no default-None parameter, so they arrive as one struct
// and a nil pointer means collect neither.
type Heredocs struct {
	// Expanded holds, in order, the raw text of each body whose delimiter
	// carries no quote and no backslash (`<<EOF`, not `<<'EOF'`). That is
	// bash's own expansion rule -- a quoted delimiter makes the body literal,
	// an unquoted one leaves `$(…)` live -- so a substitution scan over these
	// sees exactly the bodies bash would evaluate (Q35). They come back
	// separately rather than left in the returned string because a body is
	// data, not syntax: inline, the apostrophe in a `don't` would open a quote
	// for the rest of the scan and hide a live `$(…)` after it, in that body or
	// on a later command line (Q50).
	Expanded []string
	// Unterminated holds the bodies whose terminator line never appeared,
	// quoted or not. Bash swallows such a body to end of input and hands it
	// over as data, which is what this function does; a caller that would
	// rather keep judging text from a command that could never have run this
	// way reads them back out and scans them itself.
	Unterminated []string
}

// skipBalancedParens steps over a run of balanced parens beginning at start (a
// `(`). Returns the index just past the matching close, or end of string on
// imbalance. Used to skip `$((…))` arithmetic expansion, which contains no
// command to guard.
func skipBalancedParens(text string, start int) int {
	depth := 0
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(text)
}

// consumeHeredocBody skips a heredoc body starting at i (the first byte after
// the command line's newline) up to and including the terminator line, or end
// of input, and reports whether the terminator was actually found.
//
// Body lines are compared RAW -- no quote or expansion parsing -- so an
// apostrophe, an unbalanced quote, `</div>`, or `func(` in the body can never
// affect the scan. A line equals the terminator when it is exactly delim (for
// `<<-`, after stripping leading tabs). The returned index is just past the
// terminator's newline; on an unterminated body, len(text), matching bash,
// which swallows to end of input.
//
// Callers that judge a malformed command need the second return: bash hands an
// unterminated body to the command as data, but a caller reading a command that
// could never have run this way may prefer to keep inspecting the text rather
// than assume the friendlier reading.
func consumeHeredocBody(text string, i int, delim string, stripTabs bool) (int, bool) {
	n := len(text)
	for i < n {
		j := i
		for j < n && text[j] != '\n' {
			j++
		}
		line := text[i:j]
		if stripTabs {
			line = strings.TrimLeft(line, "\t")
		}
		if line == delim {
			if j < n {
				return j + 1, true // drop the terminator line
			}
			return n, true
		}
		if j < n {
			i = j + 1 // drop this body line
		} else {
			i = n
		}
	}
	return n, false
}

// StripComments removes unquoted `#` comments and folds backslash-newline
// continuations.
//
// shlex's built-in comment handling swallows the comment AND its trailing
// newline, merging the next line into the commented line's segment; it also
// starts a comment at a mid-word `#` (`file#1`), which bash does not. So
// comments are stripped here with bash's actual rule and shlex's own comment
// processing is disabled. The newline that ends a comment is kept.
//
// A continuation is dropped outright, the way POSIX joins a continued line
// before tokenizing. lex makes a newline a command boundary, so one left in
// place splits an `&&` chain written across lines into two statements and the
// chain reads as a `;` sequence.
func StripComments(cmd string) string {
	var out []byte
	inSingle, inDouble := false, false
	for i, n := 0, len(cmd); i < n; {
		c := cmd[i]
		if inSingle {
			out = append(out, c)
			inSingle = c != '\''
			i++
			continue
		}
		if !inDouble && c == '\'' {
			inSingle = true
			out = append(out, c)
			i++
			continue
		}
		if c == '\\' && i+1 < n { // escape survives both modes
			if cmd[i+1] == '\n' { // continuation -> one logical line
				i += 2
				continue
			}
			out = append(out, c, cmd[i+1])
			i += 2
			continue
		}
		if c == '"' {
			inDouble = !inDouble
			out = append(out, c)
			i++
			continue
		}
		if !inDouble && c == '#' &&
			(len(out) == 0 || isCommentPreceder(out[len(out)-1])) {
			for i < n && cmd[i] != '\n' { // keep the newline itself
				i++
			}
			continue
		}
		out = append(out, c)
		i++
	}
	return string(out)
}

// scanHeredocDelim reads a heredoc delimiter at i -- the index just past the
// `<<`.
//
// Returns the delimiter, whether the `<<-` tab-stripping form was used, whether
// any quoting appeared in it, and the index just past the delimiter word.
// Quoting is bash's expansion switch: `<<'EOF'` makes the body literal where
// `<<EOF` leaves its `$(…)` live. An empty delimiter arms nothing, matching bash
// on a `<<` with no word after it.
//
// Both raw-string scanners need this grammar -- StripHeredocBodies to drop the
// body, scanDollarParen to step over it -- so it lives here once. Two copies
// would be two readings of where a body starts.
func scanHeredocDelim(text string, i int) (delim string, stripTabs, quoted bool, end int) {
	n := len(text)
	if i < n && text[i] == '-' {
		i++
		stripTabs = true
	}
	for i < n && (text[i] == ' ' || text[i] == '\t') { // optional space before delim
		i++
	}
	var chars []byte
	for i < n && strings.IndexByte(" \t\n;|&()<>", text[i]) < 0 {
		switch d := text[i]; {
		case d == '\'':
			quoted = true
			i++
			for i < n && text[i] != '\'' {
				chars = append(chars, text[i])
				i++
			}
			if i < n {
				i++
			}
		case d == '"':
			quoted = true
			i++
			for i < n && text[i] != '"' {
				if text[i] == '\\' && i+1 < n {
					chars = append(chars, text[i+1])
					i += 2
					continue
				}
				chars = append(chars, text[i])
				i++
			}
			if i < n {
				i++
			}
		case d == '\\' && i+1 < n:
			quoted = true
			chars = append(chars, text[i+1])
			i += 2
		default:
			chars = append(chars, d)
			i++
		}
	}
	return string(chars), stripTabs, quoted, i
}

// One heredoc delimiter waiting for the body that starts after the next
// newline.
type pendingHeredoc struct {
	delim     string
	stripTabs bool
	quoted    bool
}

// One command-substitution context the raw-string scanner has entered, and the
// enclosing state it has to restore on the way out.
type substContext struct {
	term     byte
	inDouble bool
	pending  []pendingHeredoc
	depth    int
}

// StripHeredocBodies removes heredoc body text from the raw command string,
// before lexing.
//
// Bash slurps everything between the newline after a `<<WORD` / `<<-WORD`
// redirection and a line equal to WORD as literal stdin data. That body can
// hold anything -- apostrophes, `</div>`, `func(`, an odd number of quotes --
// none of it shell syntax. Left in place, the lexer either mis-tokenizes it
// (body text becomes phantom commands and file arguments) or, on an unbalanced
// quote, aborts the ENTIRE parse so a real redirect on the command line goes
// unchecked.
//
// Stripping the body from the RAW string up front (like StripComments) keeps
// the lexer's input to shell syntax only. The `<<WORD` operator and its
// delimiter stay on the command line, so the redirect handling in Segments and
// its `<<`-delimiter skip are unchanged; a trailing `<<EOF > out` redirect still
// parses. The body and its terminator line are dropped.
//
// Command-line quote state is tracked so a `<<` inside a quoted string is not
// mistaken for a heredoc. A `$(…)` or backtick body opens a FRESH quote
// context, as it does in bash, so a heredoc inside one is found even when the
// substitution itself sits in double quotes -- the shape a multi-paragraph
// commit message takes (`git commit -F "$(cat <<'MSG' … MSG\n)"`). Tracked
// flat, the enclosing `"` hid that `<<`, the body survived into the lexer, and
// an odd number of `"` in it aborted the parse of the WHOLE command, so a
// guarded path later on the line went unchecked. The `(` depth of each context
// is counted so a subshell's `)` does not end the substitution early. An
// unquoted `#` comment is skipped for `<<` detection (its text is left for
// StripComments to remove). Arithmetic `$((a<<b))` / `((a<<b))` regions are
// copied verbatim -- their `<<` is a shift, not a redirection, so they never arm
// a bogus delimiter. `<<<` here-strings are a distinct operator and never
// match. A `<<` with no delimiter word arms nothing; an unterminated body
// swallows to end of input, both matching bash.
//
// Every body is dropped either way; pass h to collect what went (see Heredocs).
//
// With ownLevelOnly, only the bodies armed at the top level of cmd are
// consumed and a substitution's own heredocs are copied through untouched. A
// caller re-scanning the raw string for substitution bodies needs both halves:
// the top level's data gone, since an apostrophe in one opens a quoted run that
// swallows the rest of the scan, and each body whole, since its terminator is
// what lets the next strip disarm it cleanly (Q119). The returned string is not
// itself re-strippable -- the top level's own `<<WORD` comes back disarmed, as
// it does by default -- so re-scan the bodies, never the result. The default
// strips every level, because the callers that hand it to the lexer need all of
// it gone.
func StripHeredocBodies(cmd string, h *Heredocs, ownLevelOnly bool) string {
	var out []byte
	inSingle, inDouble := false, false
	last := byte(0) // last emitted byte (word start)
	var pending []pendingHeredoc
	depth := 0 // unclosed `(` in this context
	var stack []substContext
	for i, n := 0, len(cmd); i < n; {
		c := cmd[i]
		if inSingle {
			out = append(out, c)
			last = c
			if c == '\'' {
				inSingle = false
			}
			i++
			continue
		}
		if c == '\\' && i+1 < n { // escapes, quoted or not
			out = append(out, c, cmd[i+1])
			last = cmd[i+1]
			i += 2
			continue
		}
		// A substitution body is parsed in its own quote context, so these two
		// openers are recognised whether or not a `"` is still open.
		if c == '$' && i+2 < n && cmd[i+1] == '(' && cmd[i+2] != '(' {
			stack = append(stack, substContext{')', inDouble, pending, depth})
			inDouble, pending, depth = false, nil, 0
			out = append(out, '$', '(')
			last = substOpen
			i += 2
			continue
		}
		if c == '`' {
			if len(stack) > 0 && stack[len(stack)-1].term == '`' { // closes the body it opened
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				inDouble, pending, depth = top.inDouble, top.pending, top.depth
				out = append(out, c)
				last = c
				i++
				continue
			}
			stack = append(stack, substContext{'`', inDouble, pending, depth})
			inDouble, pending, depth = false, nil, 0
			out = append(out, c)
			last = substOpen
			i++
			continue
		}
		if inDouble {
			out = append(out, c)
			last = c
			if c == '"' {
				inDouble = false
			}
			i++
			continue
		}
		if c == '\'' {
			inSingle = true
			out = append(out, c)
			last = c
			i++
			continue
		}
		if c == '"' {
			inDouble = true
			out = append(out, c)
			last = c
			i++
			continue
		}
		if c == '#' && (last == 0 || isCommentPreceder(last)) {
			for i < n && cmd[i] != '\n' { // comment: no `<<` detection
				out = append(out, cmd[i])
				i++
			}
			last = ')' // arbitrary non-word-start byte
			continue
		}
		if c == '(' && i+1 < n && cmd[i+1] == '(' {
			end := skipBalancedParens(cmd, i) // `((…))` / `$((…))` arithmetic
			out = append(out, cmd[i:end]...)
			last = ')'
			i = end
			continue
		}
		if c == '(' {
			depth++ // subshell -- not our terminator
			out = append(out, c)
			last = c
			i++
			continue
		}
		if c == ')' {
			if depth > 0 {
				depth--
			} else if len(stack) > 0 && stack[len(stack)-1].term == ')' {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				inDouble, pending, depth = top.inDouble, top.pending, top.depth
			}
			out = append(out, c)
			last = c
			i++
			continue
		}
		if c == '<' && i+1 < n && cmd[i+1] == '<' {
			if i+2 < n && cmd[i+2] == '<' { // `<<<` here-string, not heredoc
				out = append(out, '<', '<', '<')
				last = '<'
				i += 3
				continue
			}
			delim, stripTabs, quoted, end := scanHeredocDelim(cmd, i+2)
			out = append(out, cmd[i:end]...)
			i = end
			if delim != "" {
				pending = append(pending, pendingHeredoc{delim, stripTabs, quoted})
			}
			last = 'x'
			continue
		}
		if c == '\n' {
			out = append(out, '\n')
			last = '\n'
			i++
			if ownLevelOnly && len(stack) > 0 { // a substitution's own heredoc
				continue
			}
			for len(pending) > 0 && i < n {
				p := pending[0]
				pending = pending[1:]
				end, closed := consumeHeredocBody(cmd, i, p.delim, p.stripTabs)
				if h != nil && !p.quoted {
					h.Expanded = append(h.Expanded, cmd[i:end])
				}
				if h != nil && !closed {
					h.Unterminated = append(h.Unterminated, cmd[i:end])
				}
				i = end
			}
			continue
		}
		out = append(out, c)
		last = c
		i++
	}
	return string(out)
}
