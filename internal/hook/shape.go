package hook

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
)

// The environment is the one place a secret reaches the model with nothing for
// this scanner to open.
//
// Both answers the design gives for a Bash call are content answers: scan the
// command string, and scan the files its reader operands resolve to. `env`
// defeats both. The values live in the tool process's own environment, so at
// PreToolUse there is no buffer anywhere on disk to match, and PostToolUse
// cannot withhold a result -- measured, and the reason nothing is catchable
// after the fact. A scanner that only matches values is structurally blind to
// it, and no rule added to rules/spill-guard.json would change that.
//
// So this refuses the call on its shape instead, and the reason carries the
// filtered form. That is the whole of the control: the model reads a deny
// reason and applies the fix, and nobody is interrupted.
//
// # The threat model is accident, not an adversary
//
// A session that wants a value writes `printenv AWS_SECRET_ACCESS_KEY` and
// gets it. Nothing here stops that, and this repo has already settled that a
// control the scanned content can talk its way past is worthless -- CLAUDE.md,
// "No in-band bypass tag", is the same argument one level down. What a shape
// deny stops is the ordinary case: a session reaching for `env` while
// debugging a PATH problem, and writing every variable into a transcript that
// keeps them.
//
// Measured 2026-08-31 on one machine: a Bash tool process carries 58
// environment variables, and CLAUDE_CODE_MESSAGING_TOKEN is one of them --
// put there by the harness, in neither of the 2 that settings.json injects,
// so no config change removes it.
//
// # It may not fire on the careful form
//
// That is the bar, and it is why this is a segment property rather than a
// grep for a command name. Over 443 transcript files in the seven days to
// 2026-08-31 there were 0 bare environment dumps and 18 `env` calls, every
// one of them already filtered: `env | cut -d= -f1`, `env | grep -E …`,
// `env | wc -l`. A rule keyed on the name denies all 18 and is worse than no
// rule, because a guard that fires on the careful form teaches the session to
// stop being careful. The fix this writes into a reason is what sessions here
// already write unprompted.
//
// The zero is weak evidence and the row that filed this says so: one machine,
// one week, one operator whose habits are already careful is the population
// least likely to produce the accident. It is a fail-closed control for a
// shape nobody has met, not a response to a spill. The consequence is the
// measured half -- 58 variables, one of them a harness-issued token, into a
// file that keeps them.
//
// # What it does not reach, and why that is not repaired by widening
//
// Only the bare form of each command. `env -0` and `env -u FOO` still dump,
// `os.environ.items()` still reads the whole map, and none of them fires here.
// Widening to catch them costs the property above: every option this learns to
// see is another way to be wrong about a form somebody wrote on purpose, and
// the accident this exists for is the bare one. Under-firing on a deliberate
// spelling is a stated limitation. Firing on `env | cut -d= -f1` would be a
// defect.
//
// A rewrite is not the answer either. PreToolUse accepts `updatedInput`
// alongside the decision, so this could turn `env` into `env | cut -d= -f1`
// and allow it silently -- and then the transcript would record a command
// nobody issued. Every measurement in this repo was taken by driving a real
// hook and reading what reached a transcript, so the record saying what ran is
// what the whole verification posture rests on. A deny that names the fix
// costs one turn and leaves it honest.

// A refusal is a call stopped for what it would do rather than for anything a
// rule matched in it.
//
// One interface for two arguments that share only their verdict shape: this
// one, where the bytes exist nowhere a scanner could look, and guarded.go's,
// where they exist in a file whose contents no shipped rule would recognise.
// Run reads it in place of failed(), whose sentence -- nothing scanned this
// call -- is true of both and is the reason for neither.
type refusal interface {
	error
	// body is what the model is told, in verdict.go's voice.
	body() string
}

// A shapeRefusal is a call refused because the bytes it would send exist only
// in the tool process.
//
// It travels as an error because that is the channel bashTargets already has
// for "do not allow this".
type shapeRefusal struct{ command string }

func (r *shapeRefusal) body() string { return dumped(r.command) }

func (r *shapeRefusal) Error() string {
	return fmt.Sprintf("a %q here would send the whole environment, which is "+
		"not a thing this can open and scan", r.command)
}

// envDumped names the command of the first segment that would write the whole
// environment where the model reads it, or "" when this command has none.
func envDumped(segments []bash.Segment) string {
	for i, segment := range segments {
		if !lastInPipeline(segments, i) {
			continue
		}
		tokens := bash.StripEnvPrefix(bash.StripShKeywords(segment.Tokens))
		if len(tokens) == 0 {
			continue
		}
		// The name is safe to carry into a reason for bash.go's reason: the
		// switch below returns true only for a name equal to one of this
		// file's own literals, so what reaches the reason comes from a closed
		// set this repo authored rather than from the call.
		if name := filepath.Base(tokens[0]); dumpsEverything(name, tokens) {
			return name
		}
	}
	return ""
}

// lastInPipeline reports whether nothing consumes this segment's output.
//
// This is the careful-form test, and it is the reason Segment.Pipe exists:
// `env | cut -d= -f1` segments to a bare `env` and a `cut`, so a check over
// one segment's tokens cannot tell the dump from the filter. Position within
// the pipeline can -- an `env` with a stage after it is writing to that stage,
// and one with nothing after it is writing to the tool result, which is the
// crossing this refuses.
//
// Redirects are not consulted, so `env > vars.txt` fires. Segment.Redirects
// records the target and not which descriptor was redirected, so `env
// 2>/dev/null` is indistinguishable from it -- and reading any redirect as a
// filter would wave through the commonest careless spelling there is.
func lastInPipeline(segments []bash.Segment, i int) bool {
	for _, later := range segments[i+1:] {
		if later.Pipe == segments[i].Pipe {
			return false
		}
	}
	return true
}

// dumpsEverything reports whether these tokens print every variable.
//
// Bare, in every arm. `printenv PATH` names one, `set -euo pipefail` sets
// options, `declare -p FOO` prints one, `env FOO=1 make` runs a command --
// each of those is a different call that happens to share a name, and none of
// them writes the environment anywhere.
func dumpsEverything(name string, tokens []string) bool {
	switch name {
	case "env", "printenv", "set":
		return len(tokens) == 1
	case "export":
		// Bare `export` lists the exported variables with their values, the
		// same output `export -p` is asked for explicitly.
		return len(tokens) == 1 || (len(tokens) == 2 && tokens[1] == "-p")
	case "declare", "typeset":
		return len(tokens) == 2 && tokens[1] == "-p"
	case "python", "python3", "node":
		return dumpsFromScript(tokens)
	}
	return false
}

// dumpsFromScript reads an interpreter's inline script for a whole-environment
// reference.
//
// The command string is already scanned as content, and that finds a value a
// rule knows. It cannot find this: `print(dict(os.environ))` names no secret
// and emits every one of them.
func dumpsFromScript(tokens []string) bool {
	for i := 1; i < len(tokens)-1; i++ {
		switch tokens[i] {
		case "-c", "-e", "--eval":
			if wholeEnvironment(tokens[i+1]) {
				return true
			}
		}
	}
	return false
}

// The two spellings of the environment as an object, for the two interpreters
// the row that filed this named. Ruby's ENV and Perl's %ENV are not here: both
// are bare words that appear in ordinary text, so matching them would need a
// language the tokens do not say they are in.
var environmentObjects = []string{"os.environ", "process.env"}

// wholeEnvironment reports whether an inline script reads the environment
// rather than one variable out of it.
//
// The discriminator is the character after the object. `os.environ['PATH']`,
// `os.environ.get('PATH')` and `process.env.PATH` all pick one and are the
// careful form; `dict(os.environ)` and `console.log(process.env)` take the
// map. So a following `[` or `.` declines and anything else fires.
//
// That reads `os.environ.items()` as careful, which it is not. It is the same
// under-fire as `env -0` above and is left for the same reason: `.keys()` is
// on the other side of that line and is genuinely careful, so separating them
// means knowing which methods of two languages' environment objects return
// values. The accident is `print(os.environ)`.
func wholeEnvironment(script string) bool {
	for _, object := range environmentObjects {
		for i := 0; i < len(script); {
			j := strings.Index(script[i:], object)
			if j < 0 {
				break
			}
			after := i + j + len(object)
			rest := strings.TrimLeft(script[after:], " \t")
			if !strings.HasPrefix(rest, "[") && !strings.HasPrefix(rest, ".") {
				return true
			}
			i = after
		}
	}
	return false
}
