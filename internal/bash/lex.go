package bash

import (
	"errors"
	"math"
	"regexp"
	"strings"
)

// Shell keywords that can precede the real command word in a compound
// statement.
var shKeywords = map[string]bool{
	"while": true, "until": true, "if": true, "then": true, "elif": true,
	"else": true, "do": true, "done": true, "fi": true, "case": true,
	"esac": true, "in": true, "time": true, "function": true, "!": true,
	"{": true, "}": true, "[[": true, "]]": true,
}

// Command separators and redirect operators, after shlex punctuation grouping.
// `|&` is bash's pipe-both-streams operator; omitting it splits `a |& b` into a
// `|` and a stray `&`, which reads as a backgrounded command that never ran.
var (
	separators = map[string]bool{
		"|": true, "|&": true, "||": true, "&&": true, "&": true,
		";": true, "\n": true, "(": true, ")": true,
	}
	redir = map[string]bool{
		">": true, ">>": true, "<": true, "<<": true, "<<<": true,
		">|": true, "&>": true, "&>>": true,
	}
	dup = map[string]bool{">&": true, "<&": true}
)

// Longest-first, so `&&` is matched before `&` when splitting an operator run.
// Two operators of the same length can never both match at one position, so
// the order within a length class does not matter -- which is what makes this
// deterministic where the Python builds it from a set.
var operators = []string{
	"<<<", "&>>",
	"|&", "||", "&&", ">>", "<<", ">|", "&>", ">&", "<&",
	"|", "&", ";", "\n", "(", ")", ">", "<",
}

// Every char shlex treats as punctuation. `\n` is included so a newline command
// boundary surfaces as its own token instead of being eaten as whitespace,
// merging the commands on either side.
const punctChars = ";()<>|&\n"

// Characters after which an unquoted `#` starts a comment, per bash: a `#` that
// begins a word. Mid-word (`file#1`) it is ordinary text.
const commentPreceders = " \t\n;|&()<>"

// The `last` value that leaves a scanner at a command position, where a `#`
// starts a comment -- what bash sees just inside a `$(` or a backtick.
const substOpen = '('

// nameRE is the variable name an assignment token opens with. It is the whole
// of what a regex can answer here: bash matches an array subscript's brackets
// by depth, so `FOO[a[0]]=x` is one subscript and RE2 has no recursion.
// assignmentEnd walks the rest.
var nameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// assignmentEnd reports the offset just past the `=` of an assignment token,
// or -1 for a token bash reads as a command name.
//
// The three spellings, driven on bash 5.3.15: `NAME=v`, `NAME+=v`, and
// `NAME[sub]=v` with or without the `+`. A subscripted prefix is peeled like
// any other -- `FOO[0]=x cat f` prints f, having written `FOO[0]: not a valid
// identifier` to stderr and left FOO alone -- so a reader behind one is a
// reader whose operands cross.
//
// The offset is what isAssignment compares quoting against, so it has to be
// the real end of the operator and not the end of a prefix of it.
func assignmentEnd(tok string) int {
	i := len(nameRE.FindString(tok))
	if i == 0 {
		return -1
	}
	if i < len(tok) && tok[i] == '[' {
		j := subscriptEnd(tok, i)
		if j < 0 {
			return -1
		}
		i = j
	}
	if i < len(tok) && tok[i] == '+' {
		i++
	}
	if i < len(tok) && tok[i] == '=' {
		return i + 1
	}
	return -1
}

// subscriptEnd reports the offset just past the `]` closing the subscript that
// opens at tok[open], or -1 when nothing closes it.
//
// Depth-counted, because bash's own scan is: `FOO[a[0]]=x` is an assignment
// and `FOO[a[b]=x` is a parse error the shell dies on rather than a command it
// runs. The first `]` at depth 0 closes, so `FOO[a]b]=x` and `FOO[]]=x` are
// command names -- driven, both report `command not found` and read no file.
//
// A `]` that is quoted, escaped, or inside a `$(…)`, `${…}` or backtick
// expansion does not count, so `FOO["a]b"]=x`, `FOO[a\]b]=x` and
// `FOO[${x:-]}]=x` each close at their last `]`. That needs the word as
// written, which in command position the lexer hands over whole (Q185);
// elsewhere the token is the stripped one. Upstream's _subscript_end.
func subscriptEnd(tok string, open int) int {
	depth := 0
	for i := open; i < len(tok); {
		c := tok[i]
		if strings.IndexByte("\\'\"`$", c) >= 0 {
			if i = skipQuoted(tok, i); i < 0 {
				return -1
			}
			continue
		}
		switch c {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return -1
}

// skipQuoted steps over the escape, quoted run or expansion starting at
// text[i], returning the index just past it or -1 when it never closes. A `$`
// that opens nothing is one character, as it is to bash, and so is the `$` of
// a `$'` inside double quotes. Upstream's _skip_quoted.
func skipQuoted(text string, i int) int {
	n, c := len(text), text[i]
	switch {
	case c == '\\':
		return min(i+2, n)
	case strings.HasPrefix(text[i:], "$'"):
		return ansiCEnd(text, i)
	case c == '\'':
		j := strings.IndexByte(text[i+1:], '\'')
		if j < 0 {
			return -1
		}
		return i + j + 2
	case c == '`':
		if _, end, ok := scanBackticks(text, i+1); ok {
			return end
		}
		return -1
	case c == '"':
		for i++; i < n; {
			if text[i] == '"' {
				return i + 1
			}
			if strings.IndexByte("\\`$", text[i]) >= 0 && !strings.HasPrefix(text[i:], "$'") {
				if i = skipQuoted(text, i); i < 0 {
					return -1
				}
				continue
			}
			i++
		}
		return -1
	case strings.HasPrefix(text[i:], "$(("):
		return skipBalancedParens(text, i+1)
	case strings.HasPrefix(text[i:], "$("):
		if _, end, ok := scanDollarParen(text, i+2); ok {
			return end
		}
		return -1
	case strings.HasPrefix(text[i:], "${"):
		depth := 0
		for i++; i < n; {
			if strings.IndexByte("\\'\"`$", text[i]) >= 0 {
				if i = skipQuoted(text, i); i < 0 {
					return -1
				}
				continue
			}
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
			i++
		}
		return -1
	}
	return i + 1
}

// NotQuoted is the QuotedFrom of a word no quoting or escaping touched.
//
// Bash settles what a word IS before it removes the quotes, so `'SP=/x'` is
// not an assignment and `'if'` is not a reserved word: the shell looks for a
// program of that name, fails to find one, and leaves the variable and the
// keyword alone. Both predicates below therefore read a word's provenance and
// not only its text.
//
// Upstream carries that provenance on the token, as a `QuotedStr` subclass of
// `str` with a `quoted_from` attribute, which Go cannot express -- a string
// carries no field, and putting the quotes back inside the token breaks six of
// lex's own cases, its callers being promised quote-stripped text. So it
// travels beside the token as a parallel list, index for index, and every
// function that peels a head takes both. That is the divergence; the rule it
// implements is upstream's.
//
// MaxInt rather than -1 so the comparison in isAssignment is total: a word
// nothing quoted is quoted later than any offset a match can end at.
const NotQuoted = math.MaxInt

// gluedToClose is the QuotedFrom of the empty token lexMarking writes between an
// unquoted `)` and a word glued to it. No word has this provenance, so nothing
// can spell one.
const gluedToClose = math.MinInt

// arithmeticOpen is the QuotedFrom of the empty token markArithmetic writes after
// the `((` of a `$((…))`.
const arithmeticOpen = math.MinInt + 1

// Unquoted is the provenance list for a caller that holds none, reading every
// word as though it were written without quotes -- which is what this repo did
// before the provenance existed.
//
// It is the test seam and has no shipped caller: every production path reaches
// tokens through Segments, which carries the real provenance. Exported because
// internal/hook's tests are another package and build token lists by hand. It
// exists rather than letting them write make([]int, n) because that zero value
// reads as "quoted at offset 0" -- the strictest answer there is -- so a
// hand-built list would silently assert the opposite of what the test means.
func Unquoted(n int) []int {
	qf := make([]int, n)
	for i := range qf {
		qf[i] = NotQuoted
	}
	return qf
}

// isAssignment reports whether bash would read tok as an inline assignment.
//
// The shape has to match AND nothing up to and including the `=` may have been
// quoted or escaped: `SP=x"y"` assigns, where `SP""=x` and `SP\=x` run a
// program. Comparing offsets rather than asking whether the word was quoted at
// all is the whole of the distinction -- `SP='a reason'` is quoted and is an
// assignment, and it is how the override's own documented form is written.
//
// A subscript is the exception to quoting before the `=` disarming it: bash
// peels `FOO["0"]=x` and `FOO['a']=x`, so quoting that starts strictly inside
// the subscript still assigns. Whether it ran on past the `]` is not recorded,
// so `FOO["0]"=x`, a syntax error to bash 5.3.15, peels here too -- the
// over-peel direction, which reads a command that never runs. Upstream's.
func isAssignment(tok string, quotedFrom int) bool {
	end := assignmentEnd(tok)
	if end < 0 {
		return false
	}
	if quotedFrom >= end {
		return true
	}
	open := len(nameRE.FindString(tok))
	if tok[open] != '[' {
		return false
	}
	return open < quotedFrom && quotedFrom < subscriptEnd(tok, open)-1
}

// AssignForm is how an assignment token spells itself, which is what decides
// what a caller may read off it. The name is the same in all three; the value
// and whether bash sets anything at all are not.
type AssignForm int

const (
	// AssignPlain is `NAME=v`: bash sets NAME to v, and a prefix exports it.
	AssignPlain AssignForm = iota
	// AssignAppend is `NAME+=v`: bash sets NAME to its old value plus v,
	// which this cannot see.
	AssignAppend
	// AssignSubscript is `NAME[sub]=v`, with or without the `+`. It wins over
	// the append it may also be, because it is the stronger refusal: what
	// `$NAME` reads afterwards depends on the subscript's VALUE, which can be
	// arithmetic, and as a command prefix bash sets nothing whatever.
	AssignSubscript
)

// SplitAssignment reads an assignment token as bash reads it: `NAME=v` gives
// ("NAME", AssignPlain, "v"), `NAME+=v` gives ("NAME", AssignAppend, "v") and
// `NAME[0]=v` gives ("NAME", AssignSubscript, "v").
//
// The name is what every caller wants and what none of them can Cut for. The
// operator's `+` and the subscript both sit on the name's side of the `=`, so
// a Cut holds `NAME+` or `NAME[0]` -- a name no read of `NAME` will find, so
// the caller tracks a variable nothing reads and leaves the real one on the
// map at a stale value. Every site recovering a name from an assignment goes
// through here for that reason.
//
// Ask it only of a token isAssignment accepts. A word with no `=` comes back
// whole as the name, so `SplitAssignment("CDPATH")` is ("CDPATH", AssignPlain,
// "") and a caller comparing names would match a bare `CDPATH` that assigns
// nothing. Every caller here reaches it through envPrefix, which yields only
// assignments, so nothing reaches that arm today.
//
// What each form MEANS is the caller's, and the two non-plain forms differ.
// An append's value is the old one plus the new, which this cannot see, so a
// caller tracking a value drops the name. A subscript is that and more: bash
// resolves `$NAME` as `${NAME[0]}`, so `FOO=old; FOO[1]=x` leaves `$FOO` at
// `old` while `FOO=old; FOO[0]=x` makes it `x` -- one syntactic shape, two
// answers, picked by a subscript this never evaluates. And as a command
// prefix it sets nothing at all: driven on bash 5.3.15, `FOO=old; FOO[0]=x
// cat f` runs cat, warns `FOO[0]: not a valid identifier`, and leaves `$FOO`
// at `old`. So a caller asking whether bash armed something by this name --
// internal/hook's override hatch is the one here -- must refuse the subscript
// where it accepts the append.
//
// `env(1)` is the exception on the append and has no site here. It is an
// external program with no append semantics -- driven on bash 5.3.15, `env
// FOO+=bar env` exports a variable literally called `FOO+` and leaves `FOO` at
// its old value, where the `export` builtin beside it appends.
// internal/readers' wrapper peel looks through an env prefix to the command
// behind it, and takes env's assignments by the `=` they hold, which is env's
// own rule -- so it never asks this function, and no caller needs the name
// split the other way.
func SplitAssignment(tok string) (name string, form AssignForm, value string) {
	name, value, _ = strings.Cut(tok, "=")
	if rest, ok := strings.CutSuffix(name, "+"); ok {
		name, form = rest, AssignAppend
	}
	if i := strings.IndexByte(name, '['); i >= 0 {
		return name[:i], AssignSubscript, value
	}
	return name, form, value
}

// isReservedWord reports whether bash would read tok as a shell keyword.
//
// Blunter than isAssignment on purpose: an assignment has an `=` for the
// quoting to sit after, and a keyword has no such split, so quoting any part of
// it is enough. It reads the offset rather than whether a quote CHARACTER
// appeared, because `\if` carries none and is still not the keyword.
func isReservedWord(tok string, quotedFrom int) bool {
	return quotedFrom == NotQuoted && shKeywords[tok]
}

// isOperator reports whether bash would read tok as an operator drawn from
// vocab.
//
// Blunt like isReservedWord and for the same reason: an operator has no split
// for the quoting to sit after, so quoting any part of it makes the word a
// word. `cat ';' f` hands `;` to cat, and a caller that reads it as a separator
// cuts the command there -- cat keeps no operands and `f` is read as a command
// name, so neither file is scanned.
//
// Use it for the vocab test that decides whether a token IS an operator. A test
// made after that decision -- which separator this is, whether a redirect is a
// dup -- reads the text, because the quoting question is settled by then.
//
// Upstream converts three membership tests in workspace-guard and this port
// takes two. The third is its `command_override`, which re-scans a raw token
// list against the separator vocabulary to find the hatch; override() here
// reads the hatch off a Segment instead, so there is no third site to convert
// and the two below cover it transitively.
func isOperator(tok string, quotedFrom int, vocab map[string]bool) bool {
	return quotedFrom == NotQuoted && vocab[tok]
}

// Reserved words after which bash reads another command, so a `case` following
// one is the keyword and not an argument (`if x; then case $y in ...`). Any
// other word ends command position: in `echo case`, `case` is a plain operand.
var cmdPosKeywords = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true,
	"while": true, "until": true, "do": true, "time": true,
}

// assignPosKeywords is that set for the lexer deciding whether an assignment
// word can follow: `! FOO[a b]=x cat f` and `{ FOO[a b]=x cat f; }` both peel.
var assignPosKeywords = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true,
	"while": true, "until": true, "do": true, "time": true, "!": true, "{": true,
}

// What lex reports where the Python raises ValueError. Every caller treats
// either as "defer": a command the lexer cannot read is one no scanner should
// judge, so the two are distinguished for the reader and never for the
// control flow.
var (
	errNoClosingQuote = errors.New("bash: no closing quotation")
	errNoEscapedChar  = errors.New("bash: no escaped character")
)

// The lexer's states, named as shlex names them so the two read against each
// other: ' ' between words, 'a' inside a word, 'c' inside a run of operator
// characters, a quote character inside that quote, the escape character just
// after a backslash. shlex uses None for end of input; 0 stands in for it here,
// and no state or input byte can collide with it.
const (
	stateSpace = ' '
	stateWord  = 'a'
	statePunct = 'c'
	stateEOF   = 0

	escapeChar = '\\'
)

// lex tokenizes text with bash's quoting and operator grouping.
//
// This is a port of CPython's shlex.read_token (3.14.7) restricted to the one
// configuration bouncer_parse.lex builds: posix=True, whitespace_split=True,
// punctuation_chars=';()<>|&\n', whitespace with '\n' removed so a newline
// command boundary surfaces as a token, and comment handling disabled because
// StripComments has already applied bash's actual rule -- shlex's own swallows
// the newline that ends a comment, merging the next line into the commented
// command, and starts a comment at a mid-word `#`, which bash does not.
//
// Go has no shlex, so this is the one layer that cannot be a line-for-line port
// of the Python. Two of shlex's inputs are dropped rather than transcribed,
// because under that configuration neither is observable:
//
//   - wordchars. In state ' ' a wordchar sets `token = c; state = 'a'`, and so
//     does the whitespace_split branch below it; the two are reached by
//     disjoint characters (wordchars has the punctuation characters removed,
//     and holds no quote, backslash or whitespace) and do the same thing. In
//     state 'a' the append condition is `wordchars or quotes or
//     (whitespace_split and not punctuation)`, whose first two disjuncts are
//     already subsumed -- a quote is taken by the posix branch above it, and no
//     wordchar is a punctuation character. So the set decides nothing, and
//     transcribing its hundred-odd Latin-1 characters would read as
//     load-bearing.
//   - commenters, which is empty, so both branches keying on it are dead.
//
// Both collapses hold only while lex's configuration is that one. A change to
// whitespace_split or commenters upstream is a change this port does not track,
// and is the reason they are named here rather than silently absent.
//
// Bytes rather than runes, which is not a third divergence: every character the
// state machine tests is ASCII, a UTF-8 continuation byte is 0x80-0xBF and so
// matches none of them, and both paths a non-ASCII byte can take append it to
// the current token. Invalid UTF-8 therefore survives byte for byte, where a
// []rune conversion would substitute U+FFFD and change the token.
func lex(text string) ([]string, []int, error) { return lexMarking(text, false) }

// lexMarking is lex, writing a gluedToClose token where a word starts straight
// after an unquoted `)` when closes is set. shlex drops the adjacency, which
// Segments needs: the `/x` of `$(pwd)/x` is part of the word the substitution
// is in, and `$(pwd) /x` is a word of its own.
func lexMarking(text string, closes bool) ([]string, []int, error) {
	l := &lexer{src: requote(text), state: stateSpace, cmdPos: true}
	var out []string
	var quotedFrom []int
	for {
		token, from, eof, err := l.readToken()
		if err != nil {
			return nil, nil, err
		}
		if eof {
			return out, quotedFrom, nil
		}
		out = append(out, token)
		quotedFrom = append(quotedFrom, from)
		// A run of punctuation pushes back only what is neither punctuation
		// nor whitespace, which is the first byte of a word.
		if closes && from == NotQuoted && len(l.pushback) > 0 && allPunct(token) &&
			strings.HasSuffix(token, ")") {
			out = append(out, "")
			quotedFrom = append(quotedFrom, gluedToClose)
		}
	}
}

// requote rewrites what POSIX quoting cannot read the way bash does, so a lexer
// that knows only POSIX quoting reads the same words.
//
// Each `$'…'` becomes the single-quoted word it decodes to (claude-bouncer
// Q225). Read raw, a backslash-escaped apostrophe inside one closed the run
// early, so `echo $'it\'s'; cat f` no longer lexed and every reader in the call
// deferred, and `cat $'f'` handed cat an operand that named no file. Each
// backtick substitution becomes a double-quoted run holding it verbatim, so it
// stays one word with what is glued to it: bash parses its body separately,
// and split on whitespace and operators it reached the readers as fragments
// (claude-bouncer Q274). Only an unquoted one of either is rewritten: inside
// double quotes `$'` is text and a backtick span is already one word, inside
// single quotes everything is.
//
// Inside double quotes bash parses a `$(…)`, backtick or `${…}` on its own, so
// a `"` inside one does not close the outer string. POSIX quoting closes it
// there, and on `"$(echo '"')"` the real closing `"` is then unbalanced and the
// lexer reports it -- which defers every reader in the call, not just the
// segment carrying the substitution (Q202 here, claude-bouncer Q257). Only then is
// each one copied with its `"` and `\` escaped. Where the flat reading lexes,
// it is kept: it spills a nested body's commands into the outer words, and
// upstream measured that holding every substitution changed verdicts on deep
// nesting, so every command that lexed before tokenizes as before.
//
// Upstream also takes a commenters argument, which lex's configuration leaves
// empty, so it is left out here as it is in shlexBalanced.
func requote(text string) string {
	flat := requoteOnce(text, false)
	if shlexBalanced(flat) {
		return flat
	}
	return requoteOnce(text, true)
}

// shlexBalanced reports whether lex reads text without errNoClosingQuote or
// errNoEscapedChar.
//
// Upstream decides this for shlex, and agreed with it on 400,000 random strings
// drawn from quotes, backslash, whitespace and operator characters. lex is a
// port of that state machine with commenters empty, so the commenter arm
// upstream carries is dead here and is left out.
func shlexBalanced(text string) bool {
	for i, n := 0, len(text); i < n; {
		switch text[i] {
		case '\\':
			if i+1 >= n {
				return false
			}
			i += 2
		case '\'':
			j := strings.IndexByte(text[i+1:], '\'')
			if j < 0 {
				return false
			}
			i += j + 2
		case '"':
			i++
			for i < n && text[i] != '"' {
				if text[i] == '\\' {
					i += 2
				} else {
					i++
				}
			}
			if i >= n {
				return false
			}
			i++
		default:
			i++
		}
	}
	return true
}

// requoteOnce is upstream's `_requote`. With hold set, each expansion inside
// double quotes is copied with `\` and `"` escaped, so the lexer keeps it as
// text inside the outer string; lex's escapedquotes handling takes each escape
// back out, so the token carries the expansion byte for byte.
func requoteOnce(text string, hold bool) string {
	var out strings.Builder
	inDouble := false
	for i, n := 0, len(text); i < n; {
		c := text[i]
		if c == '\\' {
			end := min(i+2, n)
			out.WriteString(text[i:end])
			i = end
			continue
		}
		if inDouble {
			end := -1
			if hold {
				end = dqExpansionEnd(text, i)
			}
			if end > 0 { // escaped to read as text (claude-bouncer Q257)
				out.WriteString(dqEscaper.Replace(text[i:end]))
				i = end
				continue
			}
			out.WriteByte(c)
			i++
			inDouble = c != '"'
			continue
		}
		switch c {
		case '"':
			inDouble = true
			out.WriteByte(c)
			i++
			continue
		case '\'':
			j := strings.IndexByte(text[i+1:], '\'')
			end := n
			if j >= 0 {
				end = i + j + 2
			}
			out.WriteString(text[i:end])
			i = end
			continue
		}
		if end := ansiCEnd(text, i); end > 0 {
			out.WriteString("'" + strings.ReplaceAll(ansiCDecode(text[i+2:end-1]), "'", `'\''`) + "'")
			i = end
			continue
		}
		if c == '`' {
			if _, end, ok := scanBackticks(text, i+1); ok {
				out.WriteString(`"` + dqEscaper.Replace(text[i:end]) + `"`)
				i = end
				continue
			}
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

// dqEscaper escapes a span so it reads as text inside a double-quoted run.
var dqEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

type lexer struct {
	src   string
	pos   int
	state byte
	token []byte
	// shlex's _pushback_chars: one character the word scanner read past and
	// the next token has to start from. A stack, as there.
	pushback []byte
	// Upstream's command-position tracking (its Q217): whether an assignment
	// word may stand next, whether the next word is a redirect's target,
	// the open `(` and `case` constructs, and whether a `time` just ran.
	cmdPos      bool
	redirTarget bool
	frames      []lexFrame
	afterTime   bool
}

// A lexFrame is an open `(`, holding the command position to restore at its
// `)`, or an open `case`, reading its head: state is "subject", "in", "pat"
// or "body", atStart whether a pattern has a word yet, and depth the parens an
// extglob opened inside one.
type lexFrame struct {
	isCase  bool
	saved   bool
	state   string
	atStart bool
	depth   int
}

// next is shlex's `instream.read(1)`, with ok=false for the empty string it
// returns at end of input.
func (l *lexer) next() (byte, bool) {
	if n := len(l.pushback); n > 0 {
		c := l.pushback[n-1]
		l.pushback = l.pushback[:n-1]
		return c, true
	}
	if l.pos >= len(l.src) {
		return 0, false
	}
	c := l.src[l.pos]
	l.pos++
	return c, true
}

// readToken is upstream's QuoteTrackingLexer.read_token over readWord, which is
// shlex's.
//
// bash keeps `NAME[...]` one word wherever an assignment can stand, however
// many spaces, operators or quotes the subscript holds (claude-bouncer Q217).
// shlex splits on those first, so the subscript is read here from the raw text
// before readWord sees it, and only in command position: `echo FOO[a;b]` is
// two commands to bash. The subscript keeps its quotes, which is what lets
// subscriptEnd close it where bash does; the rest of the word is readWord's,
// and its provenance is offset past the subscript.
func (l *lexer) readToken() (string, int, bool, error) {
	prefix := ""
	if l.cmdPos {
		prefix = l.readSubscript()
	}
	tok, from := "", NotQuoted
	if prefix == "" || l.wordContinues() {
		t, f, eof, err := l.readWord()
		if err != nil {
			return "", NotQuoted, false, err
		}
		if eof && prefix == "" {
			return "", NotQuoted, true, nil
		}
		tok, from = t, f
	}
	if from != NotQuoted {
		from += len(prefix)
	}
	glued := len(l.pushback) > 0
	if prefix != "" && tok == "" {
		glued = l.pos < len(l.src) && isPunct(l.src[l.pos])
	}
	out := prefix + tok
	l.trackCmdPos(out, from, glued)
	return out, from, false, nil
}

// readSubscript takes a `NAME[...]` from the raw text at the next word, or
// returns "" and moves nothing when no subscript stands there.
func (l *lexer) readSubscript() string {
	if l.state != stateSpace {
		return ""
	}
	pos := l.pos - len(l.pushback)
	for pos < len(l.src) && isSpace(l.src[pos]) {
		pos++
	}
	name := nameRE.FindString(l.src[pos:])
	open := pos + len(name)
	if name == "" || open >= len(l.src) || l.src[open] != '[' {
		return ""
	}
	end := subscriptEnd(l.src, open)
	if end < 0 {
		return ""
	}
	l.pushback = l.pushback[:0]
	l.pos = end
	return l.src[pos:end]
}

func (l *lexer) wordContinues() bool {
	return l.pos < len(l.src) && !isSpace(l.src[l.pos]) && !isPunct(l.src[l.pos])
}

// trackCmdPos is upstream's _track_cmd_pos. One stack holds both kinds of
// frame: a `(` keeps the position to restore at its `)`, so `diff <(true)
// FOO[a;b]` leaves FOO an operand, and a `case` reads its patterns, whose
// closing `)` has no opener and must not pop one.
func (l *lexer) trackCmdPos(tok string, quotedFrom int, glued bool) {
	top := len(l.frames) - 1
	isCase := top >= 0 && l.frames[top].isCase
	punct := quotedFrom == NotQuoted && tok != "" && allPunct(tok)
	if isCase && l.frames[top].state != "body" {
		l.trackCaseHead(top, tok, quotedFrom, punct)
		return
	}
	if punct {
		for i := 0; i < len(tok); i++ {
			switch tok[i] {
			case '(':
				l.frames = append(l.frames, lexFrame{saved: l.cmdPos})
				l.cmdPos, l.redirTarget = true, false
			case ')':
				if n := len(l.frames); n > 0 && !l.frames[n-1].isCase {
					l.cmdPos = l.frames[n-1].saved
					l.frames = l.frames[:n-1]
				} else {
					l.cmdPos = true
				}
			}
		}
		if isCase && (tok == ";;" || tok == ";&" || tok == ";;&") {
			l.frames[top].state, l.frames[top].atStart, l.frames[top].depth = "pat", true, 0
		}
		if strings.ContainsAny(tok, ";|\n") || tok == "&" || tok == "&&" {
			l.cmdPos, l.redirTarget = true, false
		} else if strings.ContainsAny(tok, "<>") && !strings.Contains(tok, "(") {
			l.redirTarget = true
		}
		l.afterTime = false
		return
	}
	if l.redirTarget {
		l.redirTarget = false
		return
	}
	if isDigits(tok) && glued { // the fd of `2>f`
		return
	}
	if l.afterTime && (tok == "-p" || tok == "--") { // `time -p FOO[a;b]=x cmd`
		return
	}
	reserved := isReservedWord(tok, quotedFrom)
	if l.cmdPos && reserved {
		if tok == "case" {
			l.frames = append(l.frames, lexFrame{isCase: true, state: "subject"})
			l.cmdPos = false
			return
		}
		if tok == "esac" && isCase {
			l.frames = l.frames[:top]
			l.cmdPos = false
			return
		}
	}
	l.afterTime = l.cmdPos && tok == "time" && reserved
	l.cmdPos = l.cmdPos && (isAssignment(tok, quotedFrom) || reserved && assignPosKeywords[tok])
}

// trackCaseHead is upstream's _track_case_head: the words of a `case` before
// a clause body -- the subject, `in`, and each pattern list up to the `)` that
// ends it.
func (l *lexer) trackCaseHead(at int, tok string, quotedFrom int, punct bool) {
	f := &l.frames[at]
	l.cmdPos = false
	if !punct {
		reserved := isReservedWord(tok, quotedFrom)
		switch {
		case f.state == "subject":
			f.state = "in"
		case f.state == "in" && reserved && tok == "in":
			f.state, f.atStart, f.depth = "pat", true, 0
		case f.state == "pat" && f.atStart && reserved && tok == "esac":
			l.frames = l.frames[:at]
		case f.state == "pat":
			f.atStart = false
		}
		return
	}
	if f.state != "pat" {
		return
	}
	for i := 0; i < len(tok); i++ {
		switch tok[i] {
		case '(':
			if f.atStart {
				f.atStart = false // `(x)`: the optional opener
			} else {
				f.depth++ // an extglob's own parens
			}
		case ')':
			if f.depth > 0 {
				f.depth--
			} else {
				f.state = "body"
				l.cmdPos = true
				return
			}
		case '|':
			f.atStart = false
		}
	}
}

// readWord is shlex's read_token.
func (l *lexer) readWord() (string, int, bool, error) {
	quoted := false
	escapedState := byte(stateSpace)
	// Where quoting or escaping first appears in the word being built, as an
	// offset into the STRIPPED token -- which is the text the caller receives,
	// so the two are read against each other without the caller reconstructing
	// anything. Taken at each transition into a quote or an escape, before the
	// quote characters are dropped, which is the order bash decides a word in.
	quotedFrom := NotQuoted
	mark := func() {
		if quotedFrom == NotQuoted {
			quotedFrom = len(l.token)
		}
	}
loop:
	for {
		c, ok := l.next()
		switch {
		case l.state == stateEOF:
			l.token = l.token[:0]
			break loop

		case l.state == stateSpace:
			if !ok {
				l.state = stateEOF
				break loop
			}
			switch {
			case isSpace(c):
				if len(l.token) > 0 || quoted {
					break loop
				}
			case c == escapeChar:
				mark()
				escapedState = stateWord
				l.state = c
			case isPunct(c):
				l.token = append(l.token[:0], c)
				l.state = statePunct
			case isQuote(c):
				mark()
				l.state = c
			default:
				l.token = append(l.token[:0], c)
				l.state = stateWord
			}

		case isQuote(l.state):
			quoted = true
			if !ok {
				return "", NotQuoted, false, errNoClosingQuote
			}
			switch {
			case c == l.state:
				l.state = stateWord
			case c == escapeChar && l.state == '"': // escapedquotes
				escapedState = l.state
				l.state = c
			default:
				l.token = append(l.token, c)
			}

		case l.state == escapeChar:
			if !ok {
				return "", NotQuoted, false, errNoEscapedChar
			}
			// In posix shells, only the quote itself or the escape character
			// may be escaped within quotes.
			if isQuote(escapedState) && c != l.state && c != escapedState {
				l.token = append(l.token, l.state)
			}
			l.token = append(l.token, c)
			l.state = escapedState

		default: // stateWord, statePunct
			if !ok {
				l.state = stateEOF
				break loop
			}
			switch {
			case isSpace(c):
				l.state = stateSpace
				if len(l.token) > 0 || quoted {
					break loop
				}
			case l.state == statePunct:
				if isPunct(c) {
					l.token = append(l.token, c)
					break
				}
				// shlex pushes back only a non-whitespace character here; the
				// branch above has already taken every whitespace one, so the
				// guard it writes is unreachable and is left out.
				l.pushback = append(l.pushback, c)
				l.state = stateSpace
				break loop
			case isQuote(c):
				mark()
				l.state = c
			case c == escapeChar:
				mark()
				escapedState = stateWord
				l.state = c
			case !isPunct(c):
				l.token = append(l.token, c)
			default:
				l.pushback = append(l.pushback, c)
				l.state = stateSpace
				if len(l.token) > 0 || quoted {
					break loop
				}
			}
		}
	}
	result := string(l.token)
	l.token = l.token[:0]
	if !quoted && result == "" {
		return "", NotQuoted, true, nil
	}
	return result, quotedFrom, false, nil
}

// shlex's whitespace, with the newline removed so a newline command boundary
// survives as a token.
func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' }

func isQuote(c byte) bool { return c == '\'' || c == '"' }

func isPunct(c byte) bool { return strings.IndexByte(punctChars, c) >= 0 }

func isCommentPreceder(c byte) bool {
	return strings.IndexByte(commentPreceders, c) >= 0
}

// splitOperatorRuns splits a glued operator-run token into its individual
// operators.
//
// shlex's punctuation_chars returns a run of adjacent operator characters as
// ONE token: `(cd x); …` tokenizes `);`, `((echo …` tokenizes `((`, `(…));`
// tokenizes `));`, a newline boundary glues as `;\n`/`|\n`/`\n\n`. None of
// those compound runs match the separator/redirect vocabulary the group loop
// keys on, so the command boundary is missed and the two commands merge into
// one segment -- the guarded command is then never isolated and the whole
// string defers (Q27), or (for newlines, Q18) the next line's tokens are read
// as file arguments.
//
// Splitting is applied ONLY to runs bash itself read as operators. Every byte
// being in punctChars is not enough -- `cat ';;' f` is a word, and decomposing
// it costs cat its operands -- so a quoted run is returned whole. That is
// isOperator's quoting half and not a call to it: a run's operator-ness is
// settled by decomposing it, not by a vocabulary lookup, so there is no vocab
// to pass. A quoted filename holding an operator character (or a newline) is
// left intact either way, since a token with non-punctuation bytes was never a
// candidate. Each run is consumed
// greedily longest-first, so `&>>` wins over `&>` over `&` and `<<<` over
// `<<`. Every single operator character is itself in the operator list, so the
// run always fully decomposes with no leftover.
//
// Each piece of a split run inherits the run's provenance, which is NotQuoted
// for every run that now reaches the loop -- a quoted one is returned whole
// above. So the old caveat is gone: there is no longer an offset into a WHOLE
// run being handed to a piece it does not describe.
//
// This is half the rule. A single-character run leaves this function
// byte-identical whether it was skipped or decomposed, so `cat ';'` is not
// fixed here at all: the quoted `;` reaches Segments' own vocabulary tests
// intact, and those ask isOperator too. Splitting covers only the
// multi-character runs.
func splitOperatorRuns(tokens []string, quotedFrom []int) ([]string, []int) {
	out := make([]string, 0, len(tokens))
	outQF := make([]int, 0, len(tokens))
	for i, t := range tokens {
		if t == "" || quotedFrom[i] != NotQuoted || !allPunct(t) {
			out = append(out, t)
			outQF = append(outQF, quotedFrom[i])
			continue
		}
		for j := 0; j < len(t); {
			matched := ""
			for _, op := range operators {
				if strings.HasPrefix(t[j:], op) {
					matched = op
					break
				}
			}
			if matched == "" {
				// Unreachable while punctChars holds exactly the single-byte
				// operators. Kept as a total-function guard: if that invariant
				// drifts, emit the remainder as one token and stop rather than
				// spin -- a merged segment defers, which is fail-safe, never a
				// silent allow.
				out = append(out, t[j:])
				outQF = append(outQF, quotedFrom[i])
				break
			}
			out = append(out, matched)
			outQF = append(outQF, quotedFrom[i])
			j += len(matched)
		}
	}
	return out, outQF
}

// markArithmetic marks each `$((` that bash reads as arithmetic. Splitting a run
// loses which parens touch, and `$( (x) )` is a substitution whose output can
// become several words, as is `$((x) )`: bash tries arithmetic and falls back
// when the two that close it do not touch.
func markArithmetic(tokens []string, quotedFrom []int) ([]string, []int) {
	out := make([]string, 0, len(tokens))
	outQF := make([]int, 0, len(tokens))
	for i, t := range tokens {
		if quotedFrom[i] != NotQuoted || !strings.HasPrefix(t, "((") ||
			!closesTogether(tokens[i:], quotedFrom[i:]) {
			out, outQF = append(out, t), append(outQF, quotedFrom[i])
			continue
		}
		out, outQF = append(out, "((", ""), append(outQF, NotQuoted, arithmeticOpen)
		if len(t) > 2 {
			out, outQF = append(out, t[2:]), append(outQF, NotQuoted)
		}
	}
	return out, outQF
}

// closesTogether reports whether the parens opened by tokens[0] close with their
// last two touching.
func closesTogether(tokens []string, quotedFrom []int) bool {
	depth := 0
	for i, t := range tokens {
		if quotedFrom[i] != NotQuoted || !allPunct(t) {
			continue
		}
		for j := range len(t) {
			switch t[j] {
			case '(':
				depth++
			case ')':
				if depth--; depth == 0 {
					return j > 0 && t[j-1] == ')'
				}
			}
		}
	}
	return false
}

func allPunct(t string) bool {
	for i := 0; i < len(t); i++ {
		if !isPunct(t[i]) {
			return false
		}
	}
	return true
}

// glueDollarParen re-attaches a `(` to a preceding word ending in `$`.
//
// `(` is a punctuation character, so `$(cmd)` tokenizes as `$` + `(` + … -- the
// lone `$` looks like a literal filename (bash treats a `$` not followed by a
// name, brace or paren as literal) and the command substitution would slip
// through. Gluing makes the word `$(`, which a caller's expansion test
// recognises as a runtime expansion, while the `(` is kept in the stream so
// segmentation, and the scanning of commands inside the substitution, are
// unchanged.
func glueDollarParen(tokens []string, quotedFrom []int) ([]string, []int) {
	out := make([]string, 0, len(tokens))
	outQF := make([]int, 0, len(tokens))
	for i, t := range tokens {
		if t == "(" && len(out) > 0 && strings.HasSuffix(out[len(out)-1], "$") {
			// The `$` word keeps its own provenance: the glue lengthens it and
			// cannot move where quoting first appeared in it.
			out[len(out)-1] += "("
		}
		out = append(out, t)
		outQF = append(outQF, quotedFrom[i])
	}
	return out, outQF
}

// StripEnvPrefix drops leading POSIX `NAME=VALUE` command-prefix assignments.
//
// `LC_ALL=C cat /etc/passwd` tokenizes with the assignment at index 0; without
// stripping, a lookup on the command name misses and the caller defers. Bash
// treats one or more such tokens at the start of a simple command as inline env
// exports -- the real command begins at the first non-assignment token.
func StripEnvPrefix(tokens []string, quotedFrom []int) []string {
	return tokens[EnvPrefixPeel(tokens, quotedFrom):]
}

// StripShKeywords drops leading shell reserved words that may prefix the real
// command.
//
// `until grep … /outside`, `if cat /outside`, `do tail /outside` (a loop-body
// group), `! grep …`, `time cat …`, `{ cat …; }`: bash recognises the reserved
// word in command position and the command follows it. Left in place, the
// leading keyword becomes tokens[0] and the lookup misses, so the whole segment
// defers -- a silent gap (Q28).
//
// Strip these BEFORE StripEnvPrefix, because bash's order in a simple command
// is reserved word(s), then inline env assignments, then the command name
// (`until LC_ALL=C grep …`).
func StripShKeywords(tokens []string, quotedFrom []int) []string {
	return tokens[ShKeywordPeel(tokens, quotedFrom):]
}

// ShKeywordPeel and EnvPrefixPeel report how many leading tokens the two strips
// above drop.
//
// Go's forced addition, named here rather than at one call site because three
// callers need it. Slicing a []string leaves the parallel provenance behind, and
// a caller holding a SECOND list aligned with tokens -- the substituted copy the
// resolver reads, or quotedFrom itself -- has to slice both by the same count.
// Upstream needs neither: its tokens carry their own provenance, so its strips
// return a list and lose nothing.
//
// quotedFrom must be at least as long as tokens. Unquoted builds one for a
// caller that has none; a shorter one is a construction error and panics here,
// which is the fail-closed direction -- the hook exits non-zero and blocks.
func ShKeywordPeel(tokens []string, quotedFrom []int) int {
	i := 0
	for i < len(tokens) && isReservedWord(tokens[i], quotedFrom[i]) {
		i++
		// bash reads these after `time` as part of the keyword, as lex does.
		if tokens[i-1] == "time" {
			for i < len(tokens) && quotedFrom[i] == NotQuoted && (tokens[i] == "-p" || tokens[i] == "--") {
				i++
			}
		}
	}
	return i
}

func EnvPrefixPeel(tokens []string, quotedFrom []int) int {
	i := 0
	for i < len(tokens) && isAssignment(tokens[i], quotedFrom[i]) {
		i++
	}
	return i
}
