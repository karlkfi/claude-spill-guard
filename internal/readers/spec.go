// Package readers decides which tokens of one simple command name files the
// command READS. internal/bash splits a command string into its simple
// commands and says nothing about what the tokens mean; this is the layer that
// answers `cat a b` has two operands, `grep pat f` has one and the token
// before it is a pattern, and `sort -o out in` has one that is not `out`.
//
// It is a port of the argument table in karlkfi/claude-bouncer,
// plugins/workspace-guard/scripts/bash-workspace-guard.py -- SPEC, ALIASES,
// OUTPUT_POSITIONALS, and the _split_args/files_in_command pair beside them.
// Ported at workspace-guard/v1.11.0, the version internal/bash was taken from,
// so the two layers agree about the same upstream.
//
// The rows were extracted from that file structurally rather than retyped. A
// spec entry naming the wrong argument position produces a scanner that reads
// the wrong file, reports clean, and looks like it ran, and 22 rows carrying
// some 200 flags is more than a transcription survives. What is hand-written
// here is the read/write split, which is the part that is not upstream's.
//
// # Where this repo's question differs from upstream's
//
// workspace-guard asks which files a command touches, writes included. This
// asks what content is about to leave the machine, which is the reads. The
// divergence is not a filter over upstream's answer -- it changes what belongs
// in the table -- so it is recorded at each site rather than left to be
// inferred from behaviour:
//
//   - cp, mv, tee and rm have no row. Every operand they take is a write, and
//     `cp inside outside` is an offender upstream and not a spill here: the
//     bytes land in a file, not in the model's context. The `unlink` alias
//     goes with rm.
//   - `sort -o OUT`, `sort --output OUT` and `base64 -o OUT` move out of their
//     row's fileFlags and into its consume list. The flag names a file the
//     command writes, so it is not an operand -- but deleting the entry is the
//     wrong edit, and a test caught it: an unknown flag is assumed to take no
//     argument, so OUT then falls through as a positional and lands in the
//     read list, which is the opposite of the intent. Consuming the value is
//     what removes it.
//   - `uniq IN OUT` and `xxd IN OUT` write their second positional, so
//     firstOutput marks where a row's operands stop being reads.
//   - Upstream's WRITE_MODE_FLAGS is deliberately NOT ported. There, `sed -i`
//     and friends make a check stricter, so its matching is loose on purpose
//     -- a false positive downgrades a silent allow to a prompt and never the
//     reverse. Here the polarity inverts: honouring a write-mode flag would
//     EXEMPT an operand from being scanned, so a loose match would wave a real
//     spill through. `sed -i f` therefore keeps f as a read. That over-scans a
//     command whose output goes to a file rather than to the model, which is
//     the safe direction and the only one this project accepts.
//
// A program or pattern file -- `grep -f patterns`, `sed -f script`, `awk -f
// prog` -- is kept as a read for the same reason. Its contents reach the tool
// rather than the model, so scanning it is over-scanning; a file of patterns
// that trips a credential rule is somebody grepping for a credential, and
// blocking that is not the wrong answer.
//
// # What it cannot resolve, which is the caller's problem
//
// `sort --files0-from=LIST`, `wc --files0-from=LIST` and `file --files-from
// LIST` name a file whose CONTENTS are the paths the command then reads. LIST
// itself is returned as a read. The files it names are not, and cannot be
// without reading it. Unresolved is not the same as absent, which is why Files
// reports it rather than returning a short list.
package readers

// flagFiles is a flag that takes tokens, some of which are files: how many it
// consumes, and which of those are paths. `jq --rawfile VAR FILE` consumes two
// and the file is the second.
type flagFiles struct {
	consumed int
	files    []int
}

// A spec is one command's argument layout.
type spec struct {
	// consume maps a flag to how many following tokens are its value. Those
	// tokens are never file operands.
	consume map[string]int
	// fileFlags maps a flag to the tokens it takes and which of them are read.
	fileFlags map[string]flagFiles
	// prog is how many leading positionals are a program or a pattern rather
	// than a file. `grep pat f` has one.
	prog int
	// suppressProg names the flags that move the program elsewhere. With any
	// of them present, prog drops to 0 and the first positional is a file.
	suppressProg []string
	// skipAssignments drops `VAR=value` positionals, which awk takes as
	// variable assignments between file operands.
	skipAssignments bool
	// firstOutput is the index, among the positional operands, of the first
	// one the command writes rather than reads; -1 when every one is a read.
	// `uniq IN OUT` is 1.
	firstOutput int
}

// specs is the table. Only readers are here -- see the package comment for
// what upstream carries that this does not, and why.
var specs = map[string]spec{
	"awk": {
		consume:         map[string]int{"--assign": 1, "--field-separator": 1, "-F": 1, "-v": 1},
		fileFlags:       map[string]flagFiles{"--file": {1, []int{0}}, "-f": {1, []int{0}}},
		prog:            1,
		suppressProg:    []string{"-f", "--file"},
		skipAssignments: true,
		firstOutput:     -1,
	},
	"base64": {
		consume:     map[string]int{"--wrap": 1, "-b": 1, "-o": 1, "-w": 1},
		fileFlags:   map[string]flagFiles{"-i": {1, []int{0}}},
		firstOutput: -1,
	},
	"cat": {
		firstOutput: -1,
	},
	"cut": {
		consume:     map[string]int{"--bytes": 1, "--characters": 1, "--delimiter": 1, "--fields": 1, "--output-delimiter": 1, "-b": 1, "-c": 1, "-d": 1, "-f": 1},
		firstOutput: -1,
	},
	"diff": {
		consume:     map[string]int{"--changed-group-format": 1, "--context": 1, "--exclude": 1, "--exclude-from": 1, "--group-format": 1, "--horizon-lines": 1, "--ifdef": 1, "--ignore-matching-lines": 1, "--label": 1, "--line-format": 1, "--new-group-format": 1, "--new-line-format": 1, "--old-group-format": 1, "--old-line-format": 1, "--show-function-line": 1, "--starting-file": 1, "--tabsize": 1, "--unchanged-group-format": 1, "--unchanged-line-format": 1, "--unified": 1, "--width": 1, "-C": 1, "-D": 1, "-F": 1, "-I": 1, "-L": 1, "-S": 1, "-U": 1, "-W": 1, "-X": 1, "-x": 1},
		fileFlags:   map[string]flagFiles{"--from-file": {1, []int{0}}, "--to-file": {1, []int{0}}},
		firstOutput: -1,
	},
	"file": {
		consume:     map[string]int{"--exclude": 1, "--exclude-quiet": 1, "--magic-file": 1, "--parameter": 1, "--separator": 1, "-F": 1, "-P": 1, "-e": 1, "-m": 1},
		fileFlags:   map[string]flagFiles{"--files-from": {1, []int{0}}, "-f": {1, []int{0}}},
		firstOutput: -1,
	},
	"grep": {
		consume:      map[string]int{"--binary-files": 1, "--color": 1, "--colour": 1, "--exclude": 1, "--include": 1, "--max-count": 1, "--regexp": 1, "-A": 1, "-B": 1, "-C": 1, "-D": 1, "-d": 1, "-e": 1, "-m": 1},
		fileFlags:    map[string]flagFiles{"--file": {1, []int{0}}, "-f": {1, []int{0}}},
		prog:         1,
		suppressProg: []string{"-e", "--regexp", "-f", "--file"},
		firstOutput:  -1,
	},
	"head": {
		consume:     map[string]int{"--bytes": 1, "--lines": 1, "-c": 1, "-n": 1},
		firstOutput: -1,
	},
	"hexdump": {
		consume:     map[string]int{"-e": 1, "-n": 1, "-s": 1},
		fileFlags:   map[string]flagFiles{"-f": {1, []int{0}}},
		firstOutput: -1,
	},
	"jq": {
		consume:      map[string]int{"--arg": 2, "--argjson": 2, "--indent": 1},
		fileFlags:    map[string]flagFiles{"--from-file": {1, []int{0}}, "--rawfile": {2, []int{1}}, "--slurpfile": {2, []int{1}}, "-f": {1, []int{0}}},
		prog:         1,
		suppressProg: []string{"-f", "--from-file"},
		firstOutput:  -1,
	},
	"rg": {
		consume:      map[string]int{"--after-context": 1, "--before-context": 1, "--color": 1, "--colors": 1, "--context": 1, "--context-separator": 1, "--dfa-size-limit": 1, "--encoding": 1, "--engine": 1, "--field-context-separator": 1, "--field-match-separator": 1, "--glob": 1, "--hostname-bin": 1, "--iglob": 1, "--max-columns": 1, "--max-count": 1, "--max-depth": 1, "--max-filesize": 1, "--path-separator": 1, "--pre": 1, "--regex-size-limit": 1, "--regexp": 1, "--replace": 1, "--sort": 1, "--sortr": 1, "--type": 1, "--type-add": 1, "--type-clear": 1, "--type-not": 1, "-A": 1, "-B": 1, "-C": 1, "-E": 1, "-M": 1, "-T": 1, "-e": 1, "-g": 1, "-m": 1, "-r": 1, "-t": 1},
		fileFlags:    map[string]flagFiles{"--file": {1, []int{0}}, "--ignore-file": {1, []int{0}}, "-f": {1, []int{0}}},
		prog:         1,
		suppressProg: []string{"-e", "--regexp", "-f", "--file"},
		firstOutput:  -1,
	},
	"sed": {
		consume:      map[string]int{"--expression": 1, "--line-length": 1, "-e": 1, "-l": 1},
		fileFlags:    map[string]flagFiles{"--file": {1, []int{0}}, "-f": {1, []int{0}}},
		prog:         1,
		suppressProg: []string{"-e", "--expression", "-f", "--file"},
		firstOutput:  -1,
	},
	"sort": {
		consume:     map[string]int{"--batch-size": 1, "--buffer-size": 1, "--compress-program": 1, "--field-separator": 1, "--key": 1, "--output": 1, "--parallel": 1, "--random-source": 1, "--temporary-directory": 1, "-S": 1, "-T": 1, "-k": 1, "-o": 1, "-t": 1},
		fileFlags:   map[string]flagFiles{"--files0-from": {1, []int{0}}},
		firstOutput: -1,
	},
	"tail": {
		consume:     map[string]int{"--bytes": 1, "--lines": 1, "-c": 1, "-n": 1},
		firstOutput: -1,
	},
	"uniq": {
		consume:     map[string]int{"--check-chars": 1, "--skip-chars": 1, "--skip-fields": 1, "-f": 1, "-s": 1, "-w": 1},
		firstOutput: 1,
	},
	"wc": {
		fileFlags:   map[string]flagFiles{"--files0-from": {1, []int{0}}},
		firstOutput: -1,
	},
	"xxd": {
		consume:     map[string]int{"-R": 1, "-c": 1, "-cols": 1, "-g": 1, "-groupsize": 1, "-l": 1, "-len": 1, "-n": 1, "-name": 1, "-o": 1, "-s": 1, "-seek": 1},
		firstOutput: 1,
	},
	"yq": {
		consume:      map[string]int{"--arg": 2, "--argjson": 2},
		fileFlags:    map[string]flagFiles{"--from-file": {1, []int{0}}, "--rawfile": {2, []int{1}}, "--slurpfile": {2, []int{1}}, "--split-exp-file": {1, []int{0}}, "-f": {1, []int{0}}},
		prog:         1,
		suppressProg: []string{"-f", "--from-file", "--expression"},
		firstOutput:  -1,
	},
}

// aliases are commands whose argument shape another row already describes.
// Upstream's `unlink` -> `rm` is dropped with rm itself.
var aliases = map[string]string{
	"bzcat":   "cat",
	"cmp":     "cat",
	"egrep":   "grep",
	"fgrep":   "grep",
	"gawk":    "awk",
	"gzcat":   "cat",
	"less":    "cat",
	"mawk":    "awk",
	"more":    "cat",
	"nl":      "cat",
	"od":      "cat",
	"rev":     "cat",
	"strings": "cat",
	"tac":     "cat",
	"xzcat":   "cat",
	"zcat":    "cat",
}

// lookup returns the spec for a command name, following one alias hop.
func lookup(name string) (spec, bool) {
	if target, ok := aliases[name]; ok {
		name = target
	}
	s, ok := specs[name]
	return s, ok
}
