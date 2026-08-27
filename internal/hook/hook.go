// Package hook is what Claude Code invokes. It reads a hook payload on stdin,
// decides what of the call can be scanned, runs internal/scan over that, and
// writes a verdict.
//
// The fail-closed inversion this project makes against its sibling guards is
// decided here or nowhere. They fail silent, on the grounds that a hook on
// every call must never be the reason ordinary work breaks; a secret scanner
// cannot afford that trade, because one that fails quietly reports a safety it
// is not providing. So every internal error blocks with a reason, and the only
// silence this package produces is a scan that ran and found nothing.
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

	findings, err := scanCall(call, event)
	if err != nil {
		return deny(stdout, stderr, event, failed(err))
	}
	if len(findings) == 0 {
		return 0
	}
	return deny(stdout, stderr, event, found(findings))
}

// scanCall runs the pipeline over everything the call would have sent.
//
// Targets come before the ruleset because a call with nothing to scan needs no
// rules, and compiling the set is the fixed cost of every invocation.
func scanCall(call payload, event Event) ([]scan.Finding, error) {
	buffers, err := targets(call, event)
	if err != nil || len(buffers) == 0 {
		return nil, err
	}
	set, err := rules.Load(embedded.Shipped, nil)
	if err != nil {
		return nil, fmt.Errorf("loading the compiled-in ruleset: %w", err)
	}
	var findings []scan.Finding
	for _, t := range buffers {
		got, err := scan.Buffer(t.label, t.buf, set)
		if err != nil {
			return nil, err
		}
		findings = append(findings, got...)
	}
	return findings, nil
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
		return []target{{promptLabel, []byte(*call.Prompt)}}, nil
	case PreToolUse:
		return toolTargets(call)
	default:
		// decode returns errNoEvent rather than an event this switch does not
		// handle, so reaching here means the two disagree.
		return nil, fmt.Errorf("no scan defined for event %q", event)
	}
}

func toolTargets(call payload) ([]target, error) {
	switch call.ToolName {
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
			return nil, fmt.Errorf("the Read call names a relative file_path, "+
				"which this cannot resolve to the file the tool would open: %q",
				*in.FilePath)
		}
		buf, err := os.ReadFile(*in.FilePath)
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
		return []target{{*in.FilePath, buf}}, nil
	case ToolBash:
		var in bashInput
		if err := unmarshalToolInput(ToolBash, call.ToolInput, &in); err != nil {
			return nil, err
		}
		if in.Command == nil {
			return nil, errors.New("the Bash call names no command")
		}
		// The command string only. Its file operands are the other half of the
		// Bash surface and they need a per-command table of which argument is
		// a path, which internal/bash does not decide and this does not have.
		return []target{{commandLabel, []byte(*in.Command)}}, nil
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
