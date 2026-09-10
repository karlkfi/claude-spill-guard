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

var assignmentRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

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
func isAssignment(tok string, quotedFrom int) bool {
	m := assignmentRE.FindStringIndex(tok)
	return m != nil && quotedFrom >= m[1]
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
func lex(text string) ([]string, []int, error) {
	l := &lexer{src: text, state: stateSpace}
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
	}
}

type lexer struct {
	src   string
	pos   int
	state byte
	token []byte
	// shlex's _pushback_chars: one character the word scanner read past and
	// the next token has to start from. A stack, as there.
	pushback []byte
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

func (l *lexer) readToken() (string, int, bool, error) {
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
