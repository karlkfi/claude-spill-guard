package readers

import (
	"path"
	"regexp"
	"strings"
)

// A command wrapper runs the word after its own options as the command, so a
// reader behind one is a reader whose operands cross: `command cat f`, `nice
// cat f` and `sudo -u root cat f` each print f. Looked up by the wrapper's name
// they have no row, and Files reported them as commands nobody has a table for
// -- no operands, no record, and the file allowed unread (Q196).
//
// This is a port of claude-bouncer's wrapper peel at 784fc36: the grammar from
// lib/bouncer_wrappers.py, and _peel_one, peel_wrappers and the tables beside
// them from plugins/workspace-guard/scripts/bash-workspace-guard.py. Each row is
// the wrapper's own option grammar, written as a closed list so an option the
// wrapper lacks reads differently from one nobody recorded: short flags taking
// no value, short flags taking one (attached or the next word), short flags
// whose value is attached or absent, and long options as `none`, `req` or
// `opt`. `external` marks a separate program, so a `cd` behind it moves
// nothing; only `command` and `builtin` run the shell's own.
//
// The rows are upstream's union of the BSD and GNU usage, read there from sudo
// 1.9.17p2, macOS env/nice/stdbuf/time/caffeinate, GNU coreutils 9.11,
// util-linux 2.41.5 and OpenBSD doas.
//
// Upstream's peel also returns the files a wrapper opens itself -- `time -o`,
// `xargs -a`, `flock`'s lock file, `doas -C` -- because its question includes
// writes. None of those reads crosses: `time -o` and `flock` write, `doas -C`
// prints a verdict rather than the file, and `xargs -a` hands its file's
// contents to the command as arguments, which makes the peel opaque anyway. So
// that half is not ported.
type wrapper struct {
	shortNone, shortVal, shortOpt string
	long                          map[string]string
	external                      bool
}

var commonLong = map[string]string{"help": "none", "version": "none"}

func withCommon(m map[string]string) map[string]string {
	out := map[string]string{"help": "none", "version": "none"}
	for k, v := range m {
		out[k] = v
	}
	return out
}

var wrappers = map[string]wrapper{
	"env": {"iv0", "uCSPa", "", withCommon(map[string]string{
		"ignore-environment": "none", "null": "none", "unset": "req",
		"chdir": "req", "split-string": "req", "argv0": "req",
		"block-signal": "opt", "default-signal": "opt", "ignore-signal": "opt",
		"list-signal-handling": "none", "debug": "none"}), true},
	// Upstream reads sudo's `-h` as taking a value, because sudo 1.8.8 through
	// 1.9.17 ran the command under a host given that way (CVE-2025-32462).
	"sudo": {"AbBEeHiKklnNPSsVv", "acCDghprRtTuU", "", withCommon(map[string]string{
		"askpass": "none", "auth-type": "req", "background": "none",
		"bell": "none", "close-from": "req", "chdir": "req",
		"preserve-env": "opt", "edit": "none", "group": "req",
		"set-home": "none", "host": "req", "login": "none",
		"remove-timestamp": "none", "reset-timestamp": "none",
		"list": "none", "non-interactive": "none", "no-update": "none",
		"preserve-groups": "none", "prompt": "req", "chroot": "req",
		"role": "req", "stdin": "none", "shell": "none", "type": "req",
		"command-timeout": "req", "other-user": "req", "user": "req",
		"validate": "none", "login-class": "req"}), true},
	"nice":  {"", "n", "", withCommon(map[string]string{"adjustment": "req"}), true},
	"nohup": {"", "", "", commonLong, true},
	"timeout": {"fpv", "ks", "", withCommon(map[string]string{
		"foreground": "none", "preserve-status": "none", "verbose": "none",
		"kill-after": "req", "signal": "req"}), true},
	"stdbuf": {"", "ioe", "", withCommon(map[string]string{
		"input": "req", "output": "req", "error": "req"}), true},
	"setsid": {"cfw", "", "", withCommon(map[string]string{
		"ctty": "none", "fork": "none", "wait": "none"}), true},
	"ionice": {"t", "cnpPu", "", withCommon(map[string]string{
		"class": "req", "classdata": "req", "pid": "req", "pgid": "req",
		"uid": "req", "ignore": "none"}), true},
	"chrt": {"abdfimoprRv", "DPT", "", withCommon(map[string]string{
		"all-tasks": "none", "batch": "none", "deadline": "none",
		"fifo": "none", "idle": "none", "max": "none", "other": "none",
		"pid": "none", "rr": "none", "reset-on-fork": "none",
		"verbose": "none", "sched-runtime": "req", "sched-period": "req",
		"sched-deadline": "req"}), true},
	"taskset": {"acp", "", "", withCommon(map[string]string{
		"all-tasks": "none", "cpu-list": "none", "pid": "none"}), true},
	"doas":       {"Lns", "Cau", "", map[string]string{}, true},
	"caffeinate": {"dimsu", "tw", "", map[string]string{}, true},
	// flock's `-c` is read as a word after the lock file, so it is off the row.
	"flock": {"sexnoFu", "wE", "", withCommon(map[string]string{
		"shared": "none", "exclusive": "none", "unlock": "none",
		"nonblocking": "none", "nb": "none", "timeout": "req", "wait": "req",
		"conflict-exit-code": "req", "close": "none", "no-fork": "none",
		"verbose": "none", "fcntl": "none"}), true},
	"unbuffer": {"p", "", "", map[string]string{}, true},
	// `time` as a reserved word is peeled by internal/bash; this row is the
	// program, `/usr/bin/time -p cat f`, whose options the keyword does not take.
	"time": {"aphlqvV", "fo", "", withCommon(map[string]string{
		"append": "none", "portability": "none", "quiet": "none",
		"verbose": "none", "format": "req", "output": "req"}), true},
	"xargs": {"0prtxo", "aEIdLnPsJRS", "eil", withCommon(map[string]string{
		"null": "none", "arg-file": "req", "delimiter": "req", "eof": "opt",
		"replace": "opt", "max-lines": "opt", "max-args": "req",
		"max-procs": "req", "max-chars": "req", "interactive": "none",
		"verbose": "none", "exit": "none", "no-run-if-empty": "none",
		"open-tty": "none", "process-slot-var": "req",
		"show-limits": "none"}), true},
	"command": {"pvV", "", "", map[string]string{}, false},
	"builtin": {"", "", "", map[string]string{}, false},
	"exec":    {"cl", "a", "", map[string]string{}, true},
}

// shortLong names the short flags whose meaning the peel acts on, by the long
// spelling the rest of it keys on.
var shortLong = map[string]map[byte]string{
	"env":     {'C': "chdir", 'S': "split-string"},
	"time":    {'o': "output", 'V': "version"},
	"xargs":   {'a': "arg-file"},
	"ionice":  {'p': "pid", 'P': "pgid", 'u': "uid"},
	"command": {'v': "lookup", 'V': "lookup"},
	"sudo": {'D': "chdir", 'R': "chroot", 'i': "login", 'e': "edit",
		'l': "list", 'U': "other-user", 'v': "validate",
		'K': "remove-timestamp", 'V': "version"},
	"doas":    {'C': "config", 'L': "remove-timestamp", 's': "shell-alone"},
	"chrt":    {'p': "pid", 'm': "max"},
	"taskset": {'p': "pid"},
}

// Options after which the wrapper runs no command: the operands are names to
// look up (`command -v`) or process ids (`ionice -p`), or it prints and exits.
// `doas -C` checks a config and exits, and is here for the same reason.
var runsNothing = map[string]bool{
	"help": true, "version": true, "lookup": true, "pid": true, "pgid": true,
	"uid": true, "list": true, "other-user": true, "validate": true,
	"remove-timestamp": true, "shell-alone": true, "max": true, "config": true,
}

var (
	// A scheduling priority, which `chrt` takes before the command.
	priorityRE = regexp.MustCompile(`^[+-]?\d+$`)
	// `nice -5` and `nice --5`, the obsolete adjustment spelling both GNU and
	// BSD still take.
	niceLegacyRE = regexp.MustCompile(`^-[-+]?\d+$`)
	// Upstream's EXPANSION_RE: a word the shell rewrites before the wrapper
	// sees it. Upstream also tests for its substitution marker, which never
	// reaches a token here -- internal/hook marks substitutions only in the
	// copy its directory tracker reads.
	expansionRE = regexp.MustCompile("\\$[A-Za-z0-9_{(#?$!@*-]|`")
)

// maxPeel bounds the loop, which an `env -S` splice could otherwise keep
// growing.
const maxPeel = 16

// Peel is the command a simple command runs once its wrappers are peeled.
type Peel struct {
	// Argv is that command, empty when the wrappers run none.
	Argv []string
	// Opaque is true when the command's operands are not all in the string --
	// `xargs` appends its input -- or when a wrapper's grammar was lost to an
	// option outside its row or a word the shell expands. Lost grammar is not
	// guessed past: Argv starts at the first later word naming a reader or a
	// wrapper, and a caller treats the operands as unsettled.
	Opaque bool
	// External is true when a wrapper on the way is a separate program, so a
	// `cd` it runs moves nothing in the shell.
	External bool
	// Builtin is true when the last wrapper peeled is `builtin`, which
	// restricts the command to the shell's own builtins. No reader is one, so `builtin cat f` is bash's
	// `not a shell builtin` and reads nothing. Upstream judges Argv behind it
	// anyway, which costs its question nothing; here it would block a file no
	// command opens, which is the precision this project is measured on.
	Builtin bool
	// Chdirs are the directories a wrapper moves the command into, `env -C`
	// and `sudo -D`, in order. An empty one is a directory nothing here can
	// know: `sudo -i` runs in the target user's home, and an `env` whose
	// grammar was lost may have been a `-C`.
	Chdirs []string
}

// PeelWrappers reads the wrappers off the head of tokens, which a caller has
// already stripped of reserved words and inline assignments.
func PeelWrappers(tokens []string) Peel {
	argv := tokens
	var p Peel
	lost, appends := false, false
	for range maxPeel {
		if len(argv) == 0 {
			break
		}
		name := path.Base(argv[0])
		w, ok := wrappers[name]
		if !ok {
			break
		}
		p.External = p.External || w.external
		appends = appends || name == "xargs"
		// Only the last wrapper peeled decides: `builtin command cat f` runs
		// command, which runs cat.
		p.Builtin = name == "builtin"
		rest, read := peelOne(name, w, argv[1:], &p.Chdirs)
		if rest == nil {
			argv = nil
			break
		}
		if !read {
			lost = true
			rest = scanForCommand(rest)
		}
		argv = rest
	}
	p.Argv = argv
	p.Opaque = lost || appends
	return p
}

// scanForCommand is tokens from the first word naming a reader or a wrapper,
// for a peel whose grammar was lost. Taking the first such word can only start
// the command too early, which reads more words as operands.
func scanForCommand(tokens []string) []string {
	for i, t := range tokens {
		name := path.Base(t)
		if _, ok := lookup(name); ok && !unreadableWord(t) {
			return tokens[i:]
		}
		if _, ok := wrappers[name]; ok && !unreadableWord(t) {
			return tokens[i:]
		}
	}
	return []string{}
}

// unreadableWord reports whether the shell rewrites t before the wrapper sees
// it, so it may become no word or several.
func unreadableWord(t string) bool { return expansionRE.MatchString(t) }

// longOption is the long option key names in table: an exact match, or a
// prefix of exactly one, which is what getopt_long accepts.
func longOption(key string, table map[string]string) (string, bool) {
	if _, ok := table[key]; ok {
		return key, true
	}
	hit, n := "", 0
	for k := range table {
		if strings.HasPrefix(k, key) {
			hit, n = k, n+1
		}
	}
	return hit, key != "" && n == 1
}

// peelOne reads one wrapper's options and operands off args. It returns the
// command the wrapper runs and true, nil and true when it runs none, or the
// words from the one it could not read and false.
func peelOne(name string, w wrapper, args []string, chdirs *[]string) ([]string, bool) {
	canon := shortLong[name]
	i, n, edit := 0, len(args), false
	lost := func(words []string) ([]string, bool) {
		if name == "env" {
			*chdirs = append(*chdirs, "") // it may have been a `-C`
		}
		return append(append([]string{}, words...), args[i:]...), false
	}
	for i < n {
		t := args[i]
		if strings.HasPrefix(t, "$") || strings.HasPrefix(t, "`") {
			return lost(nil) // may expand to a flag
		}
		if t == "--" {
			i++
			break
		}
		if t == "-" && name == "env" { // `env -` is `env -i`
			i++
			continue
		}
		if !strings.HasPrefix(t, "-") || t == "-" {
			break
		}
		if name == "nice" && niceLegacyRE.MatchString(t) {
			i++
			continue
		}
		var opt, val string
		hasVal := false
		if strings.HasPrefix(t, "--") {
			key, v, eq := strings.Cut(t[2:], "=")
			o, ok := longOption(key, w.long)
			if !ok {
				return lost(nil)
			}
			arity := w.long[o]
			if arity == "none" && eq {
				return lost(nil)
			}
			if arity == "req" && !eq {
				if i+1 >= n {
					return nil, true // the wrapper errors out
				}
				v, eq = args[i+1], true
				i++
			}
			opt, val, hasVal = o, v, eq
			i++
		} else {
			for j := 1; j < len(t); j++ {
				ch := t[j]
				if strings.IndexByte(w.shortNone, ch) >= 0 {
					flag := canon[ch]
					if runsNothing[flag] {
						return nil, true
					}
					if flag == "login" {
						*chdirs = append(*chdirs, "") // the target user's home
					}
					edit = edit || flag == "edit"
					continue
				}
				if strings.IndexByte(w.shortOpt, ch) >= 0 {
					break
				}
				if strings.IndexByte(w.shortVal, ch) < 0 {
					return lost(nil)
				}
				opt = string(ch)
				if c, ok := canon[ch]; ok {
					opt = c
				}
				val, hasVal = t[j+1:], true
				if val == "" {
					if i+1 >= n {
						return nil, true
					}
					val = args[i+1]
					i++
				}
				break
			}
			i++
		}
		if runsNothing[opt] {
			return nil, true
		}
		if hasVal && unreadableWord(val) {
			// An `env -S` value is the command itself, so its words are kept.
			if opt == "split-string" {
				return lost(strings.Fields(val))
			}
			return lost(nil)
		}
		switch opt {
		case "chroot":
			// No path behind `sudo -R` means what it says on this disk.
			return lost(nil)
		case "login":
			*chdirs = append(*chdirs, "")
		case "edit":
			edit = true
		case "chdir":
			*chdirs = append(*chdirs, val)
		case "split-string":
			// `env -S` splits its value into words by env's own rules and
			// runs them. Upstream splits with shlex; with no shell-word
			// splitter in this package, a value carrying a quote or an escape
			// is read as lost rather than split, which defers where upstream
			// would have judged.
			if strings.ContainsAny(val, "'\"\\") {
				return lost(strings.Fields(val))
			}
			args = append(strings.Fields(val), args[i:]...)
			i, n = 0, len(args)
		}
	}
	if edit {
		return nil, true // `sudo -e` edits its operands and runs nothing
	}
	switch name {
	case "env", "sudo":
		// env(1) is not the shell: any operand holding `=` is an assignment.
		// sudo's is_envar is the same rule, except that a word starting with
		// `/` or `=` is the command.
		for i < n && strings.Contains(args[i], "=") &&
			!(name == "sudo" && strings.ContainsAny(args[i][:1], "/=")) {
			if unreadableWord(args[i]) {
				return args[i:], false
			}
			i++
		}
	case "timeout", "taskset", "chrt", "flock":
		// The duration, the CPU mask, the priority, or the lock file.
		if i >= n {
			return nil, true
		}
		if unreadableWord(args[i]) {
			return args[i:], false
		}
		if name == "chrt" && !priorityRE.MatchString(args[i]) {
			return args[i:], true // no priority to skip
		}
		if name == "flock" {
			if i+1 >= n {
				return nil, true // `flock FD` locks, runs nothing
			}
			if args[i+1] == "-c" || args[i+1] == "--command" {
				if n != i+3 {
					return nil, true // usage error
				}
				return []string{"sh", "-c", args[i+2]}, true
			}
		}
		i++
	}
	if i >= n {
		return nil, true
	}
	return args[i:], true
}
