package hook

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// trailingPunct is stripped from the end of an `@` token one character at a
// time, and every prefix left that names an existing path is scanned.
//
// It is the whole ASCII punctuation set bar one, and being generous is the
// point rather than laziness. The two errors do not cost the same: trimming
// less than the harness leaves `@deploy.env-` naming nothing, so the file goes
// unscanned and is spliced anyway, while trimming more names a path that
// usually does not exist and costs one `os.Stat`. Only the first is a
// fail-open, and the full token is always tried before any prefix, so nothing
// that resolves today stops resolving.
//
// This was a hand-picked list of five characters and it shipped a majority
// fail-open. Driven 2026-08-28 against 2.1.238, one prompt naming nine files
// the harness spliced: `- & = + # \ %` were all trimmed by the harness and
// none of them was in the set, so eight of the nine went unscanned while a
// plain `@ok.txt` in the same prompt blocked. The rule is a punctuation set
// rather than a longest-existing-prefix search -- `@u1.txtZZZ` beside an
// existing `u1.txt` spliced nothing -- and repeats are trimmed, which is what
// `@u2.txt%%` settles.
//
// `/` is the exclusion, and it is the reason this is not simply
// `unicode.IsPunct`: stripping a trailing `/` would walk up out of the
// directory the token named, and `filepath.Join` already cleans it.
const trailingPunct = "!\"#$%&'()*+,-.:;<=>?@[\\]^_`{|}~"

// errFileUnreadable is every failure to read what a token named, and it names
// nothing of what it read.
//
// This is where the prompt surface parts company with the two older ones. A
// `Read` call's `file_path` is a path by contract and a `Bash` operand had to
// be an operand of a reader in a table this repo authored, so both sites quote
// the path an OS error carries and the design allows it. An `@` token is free
// text at any offset of anything a human pasted, and the walk fails before the
// prompt itself has been scanned -- so `@/root/<a key>/x` on a directory this
// process cannot traverse would put the key in the refusal, which reaches the
// API. There is no bound that leaves a real path legible and still cuts a key,
// for the reason bash.go's resolve gives, so the reason names the category and
// the surface and nothing else.
var errFileUnreadable = errors.New("a prompt names a file that could not be " +
	"read here, so what it would send was not scanned")

// promptTargets is everything a prompt would send: the text itself, and the
// contents of the files its `@` tokens name.
//
// The prompt is two things at once, the way a Bash command string is -- content
// to scan, and a carrier of file operands. Typing `@deploy.env` puts the file
// in front of the model and no hook runs for it, so `UserPromptSubmit` is the
// only place the crossing can be stopped; the token arrives here unexpanded,
// which is what makes resolving it possible at all. docs/design/README.md,
// "`@path` is an operand, not a hop", carries that measurement.
func promptTargets(prompt, cwd string) ([]target, error) {
	targets := []target{{promptLabel, []byte(prompt)}}
	seen := make(map[string]bool)
	for _, token := range atTokens(prompt) {
		for _, candidate := range candidates(token) {
			if strings.Trim(candidate, "./") == "" {
				// `@.` and `@..` splice nothing -- driven, no attachment of
				// any type, not even a directory one. Resolving them would
				// scan the working directory and its parent for no crossing,
				// and a filename in either listing matching a rule would be a
				// block on a prompt that sent nothing.
				continue
			}
			path, err := resolveAt(candidate, cwd)
			if err != nil {
				return nil, err
			}
			if seen[path] {
				continue
			}
			info, err := os.Stat(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					// A token naming nothing splices nothing -- measured,
					// `@secret` beside a file called secret.txt moves no bytes
					// -- so there is no crossing here to block. Same reading as
					// a Read of an absent file.
					continue
				}
				return nil, errFileUnreadable
			}
			seen[path] = true
			switch {
			case info.Mode().IsRegular():
				buf, err := os.ReadFile(path)
				if err != nil {
					return nil, errFileUnreadable
				}
				targets = append(targets, target{path, buf})
			case info.IsDir():
				buf, err := listing(path)
				if err != nil {
					return nil, err
				}
				targets = append(targets, target{path, buf})
			default:
				// A fifo or a device. os.ReadFile on one blocks for as long as
				// nothing writes, which would hang the session rather than
				// scan anything, so this refuses instead of opening it.
				return nil, errors.New("a prompt names something that is " +
					"neither a file nor a directory, so what it would send " +
					"cannot be read here")
			}
		}
	}
	return targets, nil
}

// atTokens returns the text after each `@` that could name a file, in the
// order the prompt carries them.
//
// # The grammar, driven rather than read
//
// Measured 2026-08-28 against Claude Code 2.1.238 on darwin/arm64, by running
// `claude -p` in a throwaway project and reading the `attachment` records of
// the transcript the run produced. A splice arrives as a record whose
// `attachment.type` is `file` and whose `filename` is the absolute path the
// harness itself resolved the token to -- which makes the harness its own
// oracle for this function, and internal/hook/testdata/prompt-oracle.json is
// that comparison kept where a test runs it.
//
// A token starts at an `@` preceded by nothing or by whitespace, and runs to
// the next whitespace. Thirty other preceding characters were driven -- the
// ASCII punctuation set and a letter -- and every one of them suppressed the
// splice: a letter, a backtick, a quote, a bracket, and a backslash, which is
// why an escape needs no case of its own here. There is no markdown awareness
// in it. An `@` token on its own line inside a fenced block splices, and one
// written after a backtick does not, and both are the same whitespace rule
// rather than two.
//
// Matching that rule rather than widening it is a decision the measurement
// earns, and it is about which *characters* are boundaries rather than which
// are not: a `foo@x.env` this treated as a token would over-block every prompt
// that mentions an address beside a real filename.
//
// # The boundary class is the harness's, and neither ASCII nor Go's is it
//
// This tested one byte against six ASCII characters and fail-opened twice
// before it was right, which is worth the space it takes to say why.
//
// First it missed U+00A0. `@ok.txt<NBSP>@t8.txt` splices t8.txt, and the ASCII
// rule saw a single token spanning both -- so it lost the NBSP-preceded file
// AND the one before it. An NBSP arrives from any paste out of a browser or a
// chat client.
//
// `unicode.IsSpace` was the obvious repair and it was still wrong, in the way
// worth generalising: the argument for it was that it is a strict superset of
// the six, so widening could not lose a boundary. True, and beside the point.
// The exposure is never a boundary the old rule had -- it is a boundary the
// HARNESS has and Go does not, and there is one: Unicode removed U+FEFF from
// White_Space in 4.0.1. Go implements the current standard correctly and the
// harness splits on U+FEFF anyway, so `<BOM>@deploy.env` at the head of a
// pasted prompt went unscanned. That is ordinary input too -- a BOM leads any
// text saved by a Windows editor.
//
// Driven 2026-08-28, both positions and both directions:
//
//	U+FEFF  harness splits, unicode.IsSpace false  -> the fail-open, fixed here
//	U+0085  harness does NOT split, IsSpace true   -> over-scan, left alone
//	U+3000  both split                             -> agree
//	U+200B  neither splits                         -> agree
//	U+00AD  neither splits                         -> agree
//
// Those five are what JavaScript's `\s` matches, which is Unicode White_Space
// plus U+FEFF and minus U+0085 -- so the two classes differ in exactly two
// codepoints, one each way, and only one of them can hide a file. That the
// harness tokenises with a JS regex is inferred from the five and not read
// from any source, so isSplitSpace adds the one measured codepoint rather than
// reimplementing `\s`: U+0085 stays a boundary here, which over-scans in the
// direction that cannot miss a crossing.
//
// The generalisable half is that `unicode.IsSpace` forecloses the question a
// hand-written table invites. Nobody asks where the standard library got its
// characters, and here the standard moved in 2003 and the harness did not.
//
// Invalid UTF-8 before an `@` decodes to RuneError, which is not a space, so a
// malformed byte suppresses the token. That is the conservative direction for
// a boundary check and is not measured either way.
func atTokens(prompt string) []string {
	var out []string
	for i := 0; i < len(prompt); i++ {
		if prompt[i] != '@' {
			continue
		}
		if i > 0 {
			prev, _ := utf8.DecodeLastRuneInString(prompt[:i])
			if !isSplitSpace(prev) {
				continue
			}
		}
		j := i + 1
		for j < len(prompt) {
			r, size := utf8.DecodeRuneInString(prompt[j:])
			if isSplitSpace(r) {
				break
			}
			j += size
		}
		if token := prompt[i+1 : j]; token != "" {
			out = append(out, token)
		}
		i = j
	}
	return out
}

// isSplitSpace reports whether r ends an `@` token, which is Go's whitespace
// plus the one codepoint the harness splits on and Go does not. See atTokens
// for the measurement and for why this is not a reimplementation of JS `\s`.
func isSplitSpace(r rune) bool {
	const bom = '\uFEFF'
	return unicode.IsSpace(r) || r == bom
}

// candidates is a token and every prefix of it left by stripping trailing
// punctuation, longest first. See trailingPunct for why every one is tried
// rather than only the shortest.
func candidates(token string) []string {
	out := []string{token}
	for s := token; s != ""; {
		if !strings.ContainsRune(trailingPunct, rune(s[len(s)-1])) {
			break
		}
		if s = s[:len(s)-1]; s != "" {
			out = append(out, s)
		}
	}
	return out
}

// resolveAt turns one candidate into a path this process can open, or says why
// it cannot.
//
// A prompt is not a shell, so there is nothing here to expand: a `$VAR` or a
// `*` in a token is literal, and the harness treats it that way -- `@*.txt`
// beside two matching files spliced neither. Such a token names a path that
// does not exist, which the caller skips, and skipping it is not a fail-open
// because nothing crossed.
//
// None of these reasons names the token, for the reason bash.go's resolve does
// not name an operand: this text reaches the API, and on this path nothing has
// been scanned yet -- the walk fails before the prompt itself is looked at --
// so quoting the token would send content the scan never examined.
func resolveAt(candidate, cwd string) (string, error) {
	// `@~/.zshrc` spliced /Users/<user>/.zshrc, so a file outside the project
	// is reachable this way and the prefix has to be expanded here too.
	//
	// Only that prefix. `@~<user>/.zshrc` spliced nothing on a run where the
	// same file was reachable, so the harness does not do `~user` -- and the
	// control for that reading is the positives case, where `@secret.txt` and
	// `@./secret.txt` produced two records for one file. The harness does not
	// dedup, so one record there is one splice rather than two collapsed.
	// Refusing `~user` instead would have blocked any prompt that writes `@~`
	// followed by a name, for a token that carries nothing.
	//
	// A bare `@~` is not in it: that spliced nothing at all, not even the home
	// directory's listing, so it falls through and names a literal `~` under
	// the working directory the way the harness leaves it.
	if strings.HasPrefix(candidate, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New("a prompt names a home-relative file and " +
				"there is no home directory to resolve it against")
		}
		return filepath.Join(home, strings.TrimPrefix(candidate, "~")), nil
	}
	if filepath.IsAbs(candidate) {
		return filepath.Clean(candidate), nil
	}
	if cwd == "" {
		return "", errors.New("a prompt names a relative file and the payload " +
			"names no working directory to resolve it against")
	}
	return filepath.Join(cwd, candidate), nil
}

// listing is what a directory token splices: the entry names one level down.
//
// `@nested` produced an attachment whose type is `directory` rather than
// `file`, carrying `inner.txt\ndeep` -- the names, one level, with nothing
// marking which of them are directories. Those names crossed, and a name
// carries a secret as readily as a line does, so they are scanned. The census
// this package's oracle takes is of `file` attachments, so a directory token
// is a case where this function and the harness are supposed to disagree.
//
// One level was the shape of the one directory measured, and is now measured
// as the rule. Driven 2026-09-01 on 2.1.251 against a three-level tree,
// `@deeper` carried `a\nLVL1.txt` and named neither LVL2.txt nor LVL3.txt: the
// harness names a subdirectory and does not descend into it. So neither does
// this.
//
// It does stop at 1000 entries, and this deliberately does not. Same run: 500
// and 1000 crossed whole, 1001 crossed as 1000 names plus a literal `… and 1
// more entries`, 3000 as 1000 plus `… and 2000 more entries`. That marker is
// the only thing the harness sent that os.ReadDir does not return, and it
// names no file. Capping this to match is the one edit the measurement invites
// and must not get: past 1000 the harness sends a subset, so reading the whole
// directory over-reads, and over-reading cannot report a clean result for a
// name that crossed.
//
// os.ReadDir rather than anything that filters: where the harness leaves an
// entry out this reports one the harness did not send, and where it added one
// this would miss it. Only the second direction can report a clean result for
// something that crossed. Nothing is filtered either way -- a dotfile and a
// dot-directory both crossed on the same run -- and the orders disagree, which
// costs nothing because a name is scanned wherever it sits.
func listing(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errFileUnreadable
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return []byte(strings.Join(names, "\n")), nil
}
