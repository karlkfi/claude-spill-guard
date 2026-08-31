// Package hook is what Claude Code invokes. It reads a hook payload on stdin,
// decides what of the call can be scanned, runs internal/scan over that, and
// writes a verdict.
//
// The fail-closed inversion this project makes against its sibling guards is
// decided here or nowhere. They fail silent, on the grounds that a hook on
// every call must never be the reason ordinary work breaks; a secret scanner
// cannot afford that trade, because one that fails quietly reports a safety it
// is not providing. So every internal error blocks with a reason, and so does a
// buffer the pipeline declined to read. The one exception is the binary skip,
// which the design chose with a measurement rather than for want of a decoder;
// blocks() is where that is argued, and it is the only silence here that is not
// a scan which ran.
//
// Two events reach it. UserPromptSubmit and PreToolUse can withhold content;
// PostToolUse cannot, measured, so nothing is catchable after the fact. The
// two do not take the same block encoding -- see verdict.go, where getting
// that wrong is a call that runs with no warning anywhere.
//
// The ruleset is the one compiled into the binary. A project ruleset at
// .claude/spill-guard.json is in the design and is not read here: it is a file
// the model can write, so wiring it up is a question about a bypass rather
// than a loader change, and it has a row of its own.
//
// The design's other escape hatch is wired, in override.go. It is read from
// command position on a Bash call and nowhere else, and it downgrades a block
// to a confirmation rather than to an allow -- so the one thing this tool
// exists to provide, a moment where somebody is told a credential is about to
// leave the machine, survives the hatch being used.
package hook

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	"github.com/karlkfi/claude-spill-guard/internal/scan"
	embedded "github.com/karlkfi/claude-spill-guard/rules"
)

// The PreToolUse tools this package knows how to scan, which is the whole set.
// hooks.json's matcher has to name these and only these: a matcher naming a
// tool that is not here delivers calls this package waves through, and a hook
// that runs and scans nothing is the failure this project indicts its
// predecessor for.
const (
	ToolRead = "Read"
	ToolBash = "Bash"
)

// What a finding is reported against when there is no file. The design lets a
// finding carry a path, and a prompt and a command string do not have one, so
// these stand in that field. Fixed text, so nothing from the call reaches the
// model through the label itself.
const (
	promptLabel  = "<prompt>"
	commandLabel = "<command>"
)

// Run is the `hook` subcommand. It returns the process exit code.
func Run(stdin io.Reader, stdout, stderr io.Writer) int {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return refuse(stderr, fmt.Errorf("%w: stdin could not be read: %v", errNoEvent, err))
	}
	call, event, err := decode(raw)
	if err != nil {
		return refuse(stderr, err)
	}

	// The scan runs either way. The override decides what a match does, never
	// whether this package looks -- a hatch that skipped the pipeline would
	// hand the human a confirmation prompt with nothing in it to confirm, and
	// what is in it is the whole of what an approval is worth.
	why, overridden := override(call, event)
	if overridden && why == "" {
		return deny(stdout, stderr, event, blockedLead+noReasonGiven)
	}

	findings, skips, err := scanCall(call, event)
	if err != nil {
		return decide(stdout, stderr, call, event, overridden, failed(err))
	}
	// Ahead of the findings, because found() says what the matches in this call
	// are, and a buffer nothing opened makes that a claim about coverage rather
	// than a report of one.
	//
	// Through decide, not deny: every other block this package writes can be
	// downgraded to a confirmation, and one that cannot is a class of refusal
	// with no way past it and nothing saying so. The design asks for it too --
	// "the reason names a remedy: convert the file, or override".
	if len(skips) > 0 {
		return decide(stdout, stderr, call, event, overridden, unread(skips))
	}
	if len(findings) == 0 {
		return 0
	}
	return decide(stdout, stderr, call, event, overridden, found(findings))
}

// decide writes the verdict for a call that cannot simply be allowed: a block,
// or the confirmation an override downgrades it to.
//
// The downgrade runs one way only. Every path that reaches here would have
// blocked, so the override can turn a block into a prompt and can never turn
// anything into an allow -- an overridden call that scans clean exits 0 above,
// as it would have without one.
func decide(stdout, stderr io.Writer, call payload, event Event, overridden bool, body string) int {
	if !overridden {
		return deny(stdout, stderr, event, blockedLead+body)
	}
	// A confirmation that reaches nobody is not a confirmation. Blocking here
	// takes nothing from the user -- an unanswerable ask stops the call too --
	// and it sends the reason to the model rather than stalling the session.
	if call.PermissionMode == bypassPermissions {
		return deny(stdout, stderr, event, blockedLead+unattended+body)
	}
	// confirm refuses an event it has no encoding for, so this cannot emit the
	// shape that is accepted and ignored on UserPromptSubmit. Its error lands
	// on exit 2, which blocks.
	if err := confirm(stdout, event, confirmLead+body); err != nil {
		return refuse(stderr, err)
	}
	return 0
}

// The one permission mode with nobody in it. Named rather than inlined because
// the set having exactly one member is a measurement, not an oversight.
const bypassPermissions = "bypassPermissions"

// scanCall runs the pipeline over everything the call would have sent, and
// reports what it found beside what it declined to read.
//
// Targets come before the ruleset because a call with nothing to scan needs no
// rules, and compiling the set is the fixed cost of every invocation.
//
// The loop runs to the end rather than returning at the first unread buffer. A
// call naming several files should name every one of them that went unread, and
// by here they are all in memory anyway.
func scanCall(call payload, event Event) ([]scan.Finding, []skipped, error) {
	buffers, err := targets(call, event)
	if err != nil || len(buffers) == 0 {
		return nil, nil, err
	}
	set, err := rules.Load(embedded.Shipped, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("loading the compiled-in ruleset: %w", err)
	}
	var findings []scan.Finding
	var skips []skipped
	for _, t := range buffers {
		got, err := scan.Buffer(t.label, t.buf, set)
		if err != nil {
			return nil, nil, err
		}
		if blocks(got.Skipped) {
			skips = append(skips, skipped{t.label, got.Skipped})
			continue
		}
		findings = append(findings, got.Findings...)
	}
	return findings, skips, nil
}

// A skipped is one buffer the pipeline declined to read, carried with the label
// a finding in it would have been reported against so a verdict can name it.
type skipped struct {
	label string
	why   scan.Skip
}

// blocks reports whether a skip reason means this call cannot be allowed.
//
// The axis is the one the decode stage already runs on: a byte-order mark is a
// declaration the buffer makes about itself, and a NUL in the sniff window is an
// inference drawn from its bytes. What blocks is a buffer that declared itself
// text and this build could not read.
//
// SkippedUTF32 is that. The class is text by declaration, so credential-shaped
// bytes can be in it, and internal/scan skips it because no measurement said the
// class was worth decoding -- a capability this build does not have rather than
// a trade it made. Blocking costs close to nothing, because close to nothing is
// written in UTF-32, and the reason names a remedy the user can act on.
//
// SkippedBinary is the trade, and it was taken against a measurement: one PNG
// was 55% of the benchmark corpus. Denying every image read is not a
// convenience cost -- a hook that does it gets uninstalled, and an uninstalled
// scanner enforces nothing at all, which lands on the same side of the ledger as
// failing open.
//
// That argument is about Read, and a reason is all this function is given, so it
// governs a Bash operand and a prompt `@` target on a case that was never about
// them. Keying the verdict on the surface as well was measured rather than
// argued: over 1,580 local transcripts, 21 of 40,416 Bash operands are binary
// and every one is an executable or an image opened on purpose, and the only
// binary `@` targets in 881 prompt tokens are 4 fixtures this repo wrote. A
// split would fire 25 times and be wrong 23 of them, so the surface stays out.
// docs/design/README.md, "The verdict is per reason and not per surface", has
// the table and what the corpus cannot answer.
//
// The class is not all non-text, and it holds two text populations rather than
// one. UTF-16 written with no mark is the design's stated gap
// (docs/design/README.md, "Pipeline" step 2): nothing in such a buffer declares
// anything, so separating it is the heuristic the NUL check was chosen instead
// of. The second did declare itself -- a UTF-16 mark whose decoded sniff window
// holds a U+0000 -- and internal/scan classifies it as binary on purpose, after
// decoding it, on the rule that a NUL in the decoded text is a statement about
// the text rather than about the encoding. That is pinned on the trunk by
// TestBufferSkipsAUTF16BufferThatDecodesToBinary and predates this verdict.
//
// So the second population satisfies the description of what blocks and is
// allowed anyway, because internal/scan routes on decoded content where this
// routes on declaration, and the two disagree for exactly that case. One Skip
// constant is standing for two situations, and splitting it is a decode-stage
// change rather than a verdict one. Q91 carries it, with the measurement.
//
// Anything else blocks. A Skip this switch does not know is internal/scan having
// grown a reason internal/hook was not taught, and allowing it would be the
// fail-open direction -- the reading passes() already takes in the pipeline for
// a validator name it does not run.
func blocks(why scan.Skip) bool {
	switch why {
	case scan.Scanned, scan.SkippedBinary:
		return false
	default:
		return true
	}
}

// A target is one buffer to scan and what a finding in it is reported against.
type target struct {
	label string
	buf   []byte
}

// targets is everything of this call that can be scanned before it is sent.
//
// No targets means there was nothing to scan, which is a different answer from
// an error and is why the two are separate returns. An error means something
// that should have been scannable could not be read, and that blocks.
func targets(call payload, event Event) ([]target, error) {
	switch event {
	case UserPromptSubmit:
		if call.Prompt == nil {
			return nil, errors.New("the UserPromptSubmit payload carries no prompt")
		}
		// The prompt text, and the files its `@` tokens name. Typing one
		// splices a file into the model's context with no hook of any kind
		// running for it, so this event is where that crossing is stopped or
		// nowhere -- see prompt.go.
		return promptTargets(*call.Prompt, call.CWD)
	case PreToolUse:
		return toolTargets(call)
	default:
		// decode returns errNoEvent rather than an event this switch does not
		// handle, so reaching here means the two disagree.
		return nil, fmt.Errorf("no scan defined for event %q", event)
	}
}

func toolTargets(call payload) ([]target, error) {
	// A tool this package has no strategy for is a matcher wider than the
	// scanner, and it is judged below. A payload that names no tool at all is
	// a different thing: there is nothing to decide with, so it blocks.
	if call.ToolName == nil || *call.ToolName == "" {
		return nil, errors.New("the PreToolUse payload names no tool, so what " +
			"the call would send cannot be decided")
	}
	switch *call.ToolName {
	case ToolRead:
		var in readInput
		if err := unmarshalToolInput(ToolRead, call.ToolInput, &in); err != nil {
			return nil, err
		}
		if in.FilePath == nil || *in.FilePath == "" {
			return nil, errors.New("the Read call names no file_path")
		}
		// Claude Code sends an absolute path -- driven 2026-08-27 against
		// 2.1.238, where it resolved one the model had only named. A relative
		// one would resolve against this process's directory rather than the
		// tool's, so a miss here would be a hit there and the file would go
		// unscanned.
		if !filepath.IsAbs(*in.FilePath) {
			// The path is not named, for the reason bash.go's resolve does not
			// name an operand. The design allows a reason to carry a path this
			// binary resolved and attempted to open, and a relative file_path
			// is neither: nothing was scanned before this refusal, so quoting
			// it would send content the scan never examined. That `file_path`
			// is a path by contract where an operand is a command-string token
			// does not change what has happened to it here, which is nothing.
			return nil, errors.New("the Read call names a relative file_path, " +
				"which this cannot resolve to the file the tool would open")
		}
		info, err := os.Stat(*in.FilePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// A file that is not there sends nothing, so allowing the call
				// claims no safety that is missing -- the tool reports its own
				// error, which is more use than this one's. Every other read
				// failure is a file that exists and went unchecked.
				return nil, nil
			}
			return nil, fmt.Errorf("reading the file this call would send: %w", err)
		}
		// Only a regular file, for bash.go's reason: os.ReadFile on a fifo
		// blocks until something writes it, which hangs the call instead of
		// deciding it. os.Stat follows a symlink the way the tool does, so a
		// link to a fifo is caught; os.Lstat would report the link and could
		// not tell it from a link to a regular file.
		//
		// The decision that was close on the Bash surface is not close here.
		// A `/dev/null` operand is a real idiom there and had to be weighed;
		// a Read call carries one path, chosen because the model wants what
		// is in it, and a device is not that. So this refuses the whole class
		// with no carve-out to argue about.
		if !info.Mode().IsRegular() {
			return nil, errors.New("the Read call names something that is not a " +
				"regular file, so what it would send cannot be read here")
		}
		buf, err := os.ReadFile(*in.FilePath)
		if err != nil {
			return nil, fmt.Errorf("reading the file this call would send: %w", err)
		}
		return []target{{*in.FilePath, buf}}, nil
	case ToolBash:
		var in bashInput
		if err := unmarshalToolInput(ToolBash, call.ToolInput, &in); err != nil {
			return nil, err
		}
		if in.Command == nil {
			return nil, errors.New("the Bash call names no command")
		}
		// The command string, and the files its readers are pointed at.
		// internal/readers is what decides which token of a segment is a path.
		return bashTargets(*in.Command, call.CWD)
	default:
		// Not a tool this package scans. The set above is closed and named so
		// that hooks.json's matcher can be held to it; a tool arriving here is
		// a matcher wider than the scanner, which is a configuration question
		// rather than a call to judge.
		return nil, nil
	}
}

// deny writes the event's block encoding, which blocks whatever this then
// exits with. Exit 0 is deliberate: on exit 2 stdout is discarded and the
// model is told the hook errored, so the reason never arrives.
func deny(stdout, stderr io.Writer, event Event, reason string) int {
	if err := block(stdout, event, reason); err != nil {
		// Nothing usable reached stdout, so nothing there blocks anything.
		return refuse(stderr, err)
	}
	return 0
}

// refuse blocks on exit 2, the signal that needs no event to encode. It is
// what is left when the payload does not say which event this is, or when the
// verdict could not be written -- both cases where there is no shape to write
// a decision object in.
//
// The reason travels on stderr, which the model receives wrapped in a hook
// error prefix. %q because it reaches a terminal too, and neither an OS error
// string nor a field echoed out of the payload is this binary's own text.
func refuse(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "spill-guard: blocked, and nothing scanned this call "+
		"for secrets: %q\n", err.Error())
	return 2
}
