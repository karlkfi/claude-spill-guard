package hook

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// trailingPunct is stripped from the end of an `@` token one character at a
// time, and every prefix left that names an existing path is scanned.
//
// The harness trims here too -- `@plain.` and `@x,` both spliced with the
// punctuation gone -- and this set is wider than the five characters that
// measurement covers, because the two errors do not cost the same. Trimming
// less than the harness leaves `@deploy.env]` naming nothing, so the file goes
// unscanned and is spliced anyway. Trimming more names a path that usually
// does not exist, and where it does the cost is one extra file read. Only the
// first is a fail-open. `/` is deliberately not in the set: stripping it would
// walk up out of the directory the token named.
//
// The markup delimiters are in it for the same reason and were found the same
// way. A prompt writing a filename inside a code span puts a backtick at both
// ends, and the leading one already suppresses the splice -- but only the
// leading one is measured, so a token opened with whitespace and closed with a
// backtick is a shape nothing here has driven. Stripping it costs a candidate
// that does not exist.
const trailingPunct = ".,;:!?)]}>'\"`*_"

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
// earns. The fail-open direction would be a harness looser than this function,
// and thirty characters of the set that could have shown that came back the
// other way; a `foo@x.env` this treated as a token would over-block every
// prompt that mentions an address beside a real filename.
func atTokens(prompt string) []string {
	var out []string
	for i := 0; i < len(prompt); i++ {
		if prompt[i] != '@' || (i > 0 && !isPromptSpace(prompt[i-1])) {
			continue
		}
		j := i + 1
		for j < len(prompt) && !isPromptSpace(prompt[j]) {
			j++
		}
		if token := prompt[i+1 : j]; token != "" {
			out = append(out, token)
		}
		i = j
	}
	return out
}

// isPromptSpace reports whether b ends a token. A multi-byte rune's bytes are
// all >= 0x80, so testing one byte cannot split one.
func isPromptSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
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
// os.ReadDir rather than anything that filters: where the harness leaves an
// entry out this reports one the harness did not send, and where it added one
// this would miss it. Only the second direction can report a clean result for
// something that crossed.
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
