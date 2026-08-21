# Privacy

## The scanner

spill-guard runs entirely on your machine. It has **no network capability at
all** — not disabled, absent. The binary's import graph contains no `net`, no
`net/http`, and no `os/exec`, and a CI job over `go list -deps` fails the build
if one appears. There is no telemetry, no crash reporting, no update check, and
no remote or shared rule source.

The hook reads a JSON payload on stdin and writes a decision on stdout. It
reads:

- the tool call's arguments from the hook payload — a command string, a file
  path, or a `Write` body
- the file named by a `Read`, or by a file operand of a common reader in a
  `Bash` command, so it can be scanned before its contents enter the
  conversation
- `rules/spill-guard.json` shipped with the plugin
- `.claude/spill-guard.json` under the project root, when it exists
- the `SPILL_GUARD_*` environment variables

It keeps no state between invocations and writes no files.

## What leaves the process

A finding carries a **rule ID, a path, and a byte offset**. Not the matched
text, and not a redacted window of it either.

That is a deliberate restriction rather than a default. A hook's stderr reaches
the model, and the model's context goes to the API — so an 8-character redacted
fragment is 8 characters of the secret sent to exactly the place this tool
exists to keep it away from. Internally, findings are deduplicated by a
truncated hash. The raw value never enters a struct that outlives the match.

## Scope

spill-guard reduces the chance that a credential reaches the API by accident. It
is a net, not a wall:

- It cannot see the output of an arbitrary shell command before that command
  runs.
- It detects by local heuristics, so it misses secrets that look like ordinary
  text.
- The override is one environment variable, by design.

Treat it as a backstop for the mistake, not as a control that makes it safe to
keep credentials where a session can read them.
