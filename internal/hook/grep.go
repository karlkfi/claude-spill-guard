package hook

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
	"github.com/karlkfi/claude-spill-guard/internal/rules"
	"github.com/karlkfi/claude-spill-guard/internal/scan"
	embedded "github.com/karlkfi/claude-spill-guard/rules"
)

// A recursive grep over a directory is the one reader whose input this hook
// cannot open, and its output is.
//
// The directory refusal in bash.go rests on two things: a walk reads a
// different file set from the one the command sends, and making it agree means
// re-implementing each reader's traversal. Neither reaches a scan of grep's
// OUTPUT, which is exactly what crosses -- so for grep the deny names a form
// that pipes it through `spill-guard filter`, and the filtered form is allowed
// with its directory operand unread here, because the filter reads what the
// walk produced.
//
// It is the largest class in the coverage log by a wide margin, as Q203
// counted it and this change did not re-take: of 2,400 records from 2026-09-07
// to 2026-10-01, 1,361 are a grep's directory operand, and of the 637 that
// replayed and parsed, 636 were recursive. The cost is a turn per unfiltered
// call, accepted 2026-10-01 against the 2026-09-05 measurement that made
// coverage failures defer.
//
// Position in the pipeline is the test, as it is for the `env` refusal: a
// filter stage after the grep in its own pipeline is the careful form. And the
// forms that print no matched text -- -q, -l, -L, -c -- are allowed bare,
// because nothing of a file's content crosses through them and they are the
// forms whose exit status a session tests, which a pipe would replace.
//
// A recursive grep with no file operand searches the working directory. It
// used to contribute no operands and cross silently, with nothing recorded;
// it is read as `.` now, so it reaches the same refusal.

// grepNames is the reader-table row and its aliases.
var grepNames = map[string]bool{"grep": true, "egrep": true, "fgrep": true}

// The short options that take a value, attached or in the next token. Once one
// is reached in a cluster the rest of the cluster is its value: `-rnA3`.
const grepShortValued = "ABCDdefm"

// grepLong is every long option GNU grep 3.x or the BSD grep macOS ships
// accepts, and whether it takes its value from the next token when no `=`
// carries it. `--color` and `--colour` take one only with `=`. Where the two
// greps disagree the consuming answer is kept: a consumed token is never read
// as a flag, so it can hide `-l` and leave a call refused that would have
// passed, and never the reverse.
var grepLong = map[string]bool{
	"--after-context": true, "--basic-regexp": false, "--before-context": true,
	"--binary": false, "--binary-files": true, "--byte-offset": false,
	"--bz2decompress": false, "--color": false, "--colour": false,
	"--context": true, "--count": false, "--decompress": false,
	"--dereference-recursive": false, "--devices": true, "--directories": true,
	"--exclude": true, "--exclude-dir": true, "--exclude-from": true,
	"--extended-regexp": false, "--file": true, "--files-with-matches": false,
	"--files-without-match": false, "--fixed-regexp": false,
	"--fixed-strings": false, "--group-separator": true, "--help": false,
	"--ignore-case": false, "--include": true, "--include-dir": true,
	"--initial-tab": false, "--invert-match": false, "--label": true,
	"--line-buffered": false, "--line-number": false, "--line-regexp": false,
	"--lzma": false, "--max-count": true, "--mmap": false,
	"--no-filename": false, "--no-group-separator": false,
	"--no-ignore-case": false, "--no-messages": false, "--null": false,
	"--null-data": false, "--only-matching": false, "--perl-regexp": false,
	"--quiet": false, "--recursive": false, "--regexp": true, "--silent": false,
	"--text": false, "--unix-byte-offsets": false, "--version": false,
	"--with-filename": false, "--word-regexp": false, "--xz": false,
}

// resolveLong names the long option a key stands for, or "" where this cannot
// say. getopt_long takes any unique prefix, so `--exclude-d` is `--exclude-dir`
// and consumes the token after it -- and matching keys exactly read that token
// as a flag, so `grep -r --exclude-d -l x d` was taken for `-l` and allowed
// with nothing recorded while grep printed the matched lines (Q203's review,
// driven on BSD grep 2.6.0).
func resolveLong(key string) string {
	if _, ok := grepLong[key]; ok {
		return key
	}
	found := ""
	for name := range grepLong {
		if strings.HasPrefix(name, key) {
			if found != "" {
				return ""
			}
			found = name
		}
	}
	return found
}

// grepQuietLong are the long spellings of the forms that print no matched text.
var grepQuietLong = map[string]bool{
	"--quiet": true, "--silent": true, "--files-with-matches": true,
	"--files-without-match": true, "--count": true,
}

// grepMode reads a grep's flags for whether it recurses and whether it prints
// matched text. Both GNU grep and the BSD grep macOS ships permute, so a flag
// after an operand counts: driven 2026-10-01, `grep hello d -r -l` on BSD grep
// 2.6.0 lists the file rather than reading `-l` as one.
func grepMode(tokens []string) (recursive, quiet bool) {
	unsure := false
	defer func() {
		if unsure {
			recursive, quiet = true, false
		}
	}()
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "--" {
			break
		}
		if strings.HasPrefix(tok, "--") {
			key, value, inline := strings.Cut(tok, "=")
			name := resolveLong(key)
			if name == "" {
				// Unknown or ambiguous: whether it consumed the next token is
				// not knowable, so nothing after it can be trusted to say the
				// call prints no text. Refused rather than allowed.
				unsure = true
				continue
			}
			switch {
			case name == "--recursive" || name == "--dereference-recursive":
				recursive = true
			case grepQuietLong[name]:
				quiet = true
			case name == "--directories":
				if !inline && i+1 < len(tokens) {
					value = tokens[i+1]
				}
				recursive = recursive || recurses(value)
			}
			if grepLong[name] && !inline {
				i++
			}
			continue
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			continue
		}
		for j := 1; j < len(tok); j++ {
			c := tok[j]
			switch c {
			case 'r', 'R':
				recursive = true
			case 'q', 'l', 'L', 'c':
				quiet = true
			}
			if strings.IndexByte(grepShortValued, c) >= 0 {
				value := tok[j+1:]
				if value == "" && i+1 < len(tokens) {
					i++
					value = tokens[i]
				}
				if c == 'd' && recurses(value) {
					recursive = true
				}
				break
			}
		}
	}
	return recursive, quiet
}

// recurses reads a `--directories` value. Both greps take an abbreviation of
// one here too, so anything that is not plainly `read` or `skip` is read as
// recursion, which refuses toward the filter rather than allowing.
func recurses(value string) bool {
	return value != "read" && value != "skip"
}

// filteredLater reports whether a stage after segment i in its own pipeline is
// `spill-guard filter`, with or without its flags.
//
// Any later stage rather than the last one: `grep -rn x . | spill-guard filter
// | head` sends only what the filter passed. The name is matched on its base so
// the absolute path a reason writes is recognised, and the tokens are peeled
// the way envDumped peels them.
func filteredLater(segments []bash.Segment, i int) bool {
	for _, later := range segments[i+1:] {
		if later.Pipe != segments[i].Pipe {
			continue
		}
		k := bash.ShKeywordPeel(later.Tokens, later.QuotedFrom)
		tokens := bash.StripEnvPrefix(later.Tokens[k:], later.QuotedFrom[k:])
		if len(tokens) < 2 || tokens[1] != "filter" {
			continue
		}
		name := filepath.Base(tokens[0])
		if name == "spill-guard" || name == "spill-guard.exe" ||
			filepath.ToSlash(tokens[0]) == self() {
			return true
		}
	}
	return false
}

// self is this binary's path, which is what filterCommand writes into a reason.
// It is recognised whatever it is called, because a reason naming a command
// this test then refuses hands the model a fix that loops -- which the test
// binary, named hook.test, did before this.
//
// Forward slashes, so a Windows path reads as Git Bash -- which is what the Bash
// tool runs there -- takes one: a backslash is an escape to it unquoted and a
// path separator only inside quotes. The comparison in filteredLater converts
// the token the same way, so either spelling of the path is recognised.
func self() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.ToSlash(path)
}

// A grepRefusal is a recursive grep over a directory, refused for its form:
// what it would send is output this cannot open ahead of the call, and the
// filtered form scans it where it is.
type grepRefusal struct {
	command string
	// rewrite is the whole command with the filter appended, or "" where
	// appending one to the string would not pipe this grep through it.
	rewrite string
}

func (r *grepRefusal) Error() string {
	return fmt.Sprintf("a recursive %q over a directory sends output nothing here "+
		"can read ahead of the call", r.command)
}

func (r *grepRefusal) body() string { return walked(r.command, r.rewrite) }

// filterCommand is how a reason spells the filter: this binary's own path, since
// nothing says `spill-guard` is on PATH, quoted for the shell where it needs it.
func filterCommand() string {
	path := self()
	if path == "" {
		return "spill-guard filter"
	}
	return shellQuote(path) + " filter"
}

// shellQuote leaves a path of ordinary characters as it is and single-quotes
// anything else, so the command a reason names runs as written.
func shellQuote(s string) string {
	for _, c := range s {
		if !(c == '/' || c == '.' || c == '_' || c == '-' || c == '+' || c == ':' ||
			c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// filteredRewrite appends the filter to command, or returns "" where that
// would not put this grep's output through it.
//
// Appending pipes the string's last pipeline, so the grep has to be in it, and
// the string has to end where a `|` can follow: not after a `;` the trim does
// not reach, a `&`, or a comment, and not across lines, where a heredoc or a
// second command may sit after the grep. Anything else gets the instruction
// without the rewrite rather than a rewrite that does something else.
//
// It is the one place a reason here carries the caller's own string, so two
// more conditions keep it to a string that is safe to repeat. Every rune is
// printable, which excludes C0, DEL and the bidi overrides that %q escapes
// everywhere else -- escaping would change the command, so a string needing it
// gets no rewrite. And the string matches no rule: the refusal is reached before
// scanCall scans the command, so a key written into the pattern would otherwise
// go back out in the reason.
func filteredRewrite(command string, segments []bash.Segment, i int) string {
	if segments[i].Pipe != segments[len(segments)-1].Pipe {
		return ""
	}
	trimmed := strings.TrimRight(strings.TrimSpace(command), ";")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" || strings.ContainsAny(trimmed, "#\n") ||
		strings.HasSuffix(trimmed, "&") || strings.HasSuffix(trimmed, "|") {
		return ""
	}
	for _, r := range trimmed {
		if !unicode.IsPrint(r) {
			return ""
		}
	}
	set, err := rules.Load(embedded.Shipped)
	if err != nil {
		return ""
	}
	if got, err := scan.Buffer(commandLabel, []byte(trimmed), set); err != nil ||
		got.Skipped != scan.Scanned || len(got.Findings) > 0 {
		return ""
	}
	rewrite := "set -o pipefail; " + trimmed + " | " + filterCommand()
	if !allFiltered(rewrite) {
		return ""
	}
	return rewrite
}

// allFiltered reports whether every recursive grep the string runs has a filter
// stage after it, which is the test the refusal applies.
//
// The rewrite is checked against it rather than trusted, because appending a
// stage pipes the last pipeline and a grep can sit somewhere that is not:
// `echo $(grep -r x .)` segments the grep into the string's own list, and the
// rewrite of it was refused in turn -- driven, before this check existed -- so
// the model would have been handed a fix that loops.
func allFiltered(command string) bool {
	segments, err := bash.Segments(command)
	if err != nil {
		return false
	}
	for i, segment := range segments {
		k := bash.ShKeywordPeel(segment.Tokens, segment.QuotedFrom)
		tokens := bash.StripEnvPrefix(segment.Tokens[k:], segment.QuotedFrom[k:])
		if len(tokens) == 0 || !grepNames[filepath.Base(tokens[0])] {
			continue
		}
		if recursive, quiet := grepMode(tokens); recursive && !quiet &&
			!filteredLater(segments, i) {
			return false
		}
	}
	return true
}

// grepToolTargets is what a Grep tool call would send.
//
// The tool is ripgrep run inside the harness, so there is no pipeline to put a
// filter in and no command to rewrite: a search in `content` mode over a
// directory is refused, and the reason names the Bash form that pipes the same
// search through the filter. The other two modes, `files_with_matches` and
// `count`, return paths and numbers and no line of any file, which is the
// argument that exempts `-l` and `-c` above. A path naming one file is the case
// that needs no walk at all, so that file is read and scanned whole, the way a
// Read of it is.
//
// An absent mode is read as `content`: nothing here knows the tool's default,
// and refusing costs a turn where the other reading would let a search's
// lines cross unread.
//
// The pattern is scanned, as a Bash command string is: it is text the call
// carries, and a key typed into one is a key in the transcript.
func grepToolTargets(in grepToolInput, cwd string) ([]target, error) {
	var targets []target
	if in.Pattern != nil {
		targets = append(targets, target{patternLabel, []byte(*in.Pattern)})
	}
	mode := "content"
	if in.OutputMode != nil && *in.OutputMode != "" {
		mode = *in.OutputMode
	}
	if mode == "files_with_matches" || mode == "count" {
		return targets, nil
	}
	path := cwd
	if in.Path != nil && *in.Path != "" {
		path = expandTilde(*in.Path)
		if !filepath.IsAbs(path) {
			if cwd == "" {
				return nil, errors.New("the Grep call names a relative path and " +
					"the payload carries no working directory to resolve it against")
			}
			path = filepath.Join(cwd, path)
		}
	}
	if path == "" {
		return nil, errors.New("the Grep call names no path and the payload " +
			"carries no working directory, so where it searches is unknown")
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Nothing there sends nothing, as for a Read of an absent file.
			return targets, nil
		}
		return nil, fmt.Errorf("reading the path this Grep call searches: %w", err)
	}
	if info.IsDir() {
		return nil, &grepToolRefusal{}
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("the Grep call names something that is neither " +
			"a file nor a directory, so what it would send cannot be read here")
	}
	if class := guardedClass(path); class != "" {
		return nil, &pathRefusal{path, class}
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the file this Grep call searches: %w", err)
	}
	return append(targets, target{path, buf}), nil
}

// What a finding in a Grep call's pattern is reported against.
const patternLabel = "<pattern>"

// A grepToolRefusal is a Grep tool search in content mode over a directory.
type grepToolRefusal struct{}

func (r *grepToolRefusal) Error() string {
	return "a Grep search in content mode over a directory sends output nothing " +
		"here can read ahead of the call"
}

func (r *grepToolRefusal) body() string { return searched() }
