: << 'CMDBLOCK'
@echo off
REM Cross-platform polyglot launcher for the spill-guard binary.
REM
REM On Windows cmd.exe runs the batch portion below. On Unix the shell reads
REM the first line as a no-op heredoc opener, discards everything down to the
REM CMDBLOCK terminator, and falls through to the POSIX tail at the bottom of
REM this file. The structure is branch-guard's run-python-hook.cmd, kept
REM recognisably the same so a fix there transfers.
REM
REM Why this file exists at all: hooks.json cannot invoke spill-guard directly.
REM An absent binary makes the shell exit 127 and a non-executable one makes it
REM exit 126, and only exit 2 blocks a tool call -- so the hook would be
REM installed, silent, and enforcing nothing, with nothing in the transcript.
REM Both codes were driven end to end; the table is in docs/design/README.md
REM under "The exit-code contract, measured". exit-status-guard shipped that
REM bug at 126 in its 1.0.0 and the guard never fired once.
REM
REM So when this cannot resolve a binary it DENIES, by writing a deny decision
REM object to stdout. That blocks whatever the process then exits with, which
REM is the one spelling that fails closed on its own. Not exit 2: on exit 2
REM stdout is discarded and the model is told the hook errored, so the reason
REM never arrives. Exit 0 is deliberate and is the whole point of the file.
REM
REM Resolution order, from docs/design/distribution.md: SPILL_GUARD_BIN, then
REM PATH, then the default install location, then deny.
REM
REM The batch half stays straight-line: no parenthesized blocks and no nested
REM cmd. `where` answers whether PATH holds one and Windows resolves it, rather
REM than this file capturing a path so cmd.exe can resolve it a second time.
REM
REM Every argument is passed through untouched, and so is stdin -- the hook
REM payload arrives there. This file decides which binary runs and nothing
REM else; hooks.json chooses the subcommand.

setlocal

if not defined SPILL_GUARD_BIN goto :try_path
if exist "%SPILL_GUARD_BIN%" goto :run_explicit
REM The value is deliberately not echoed here. A Windows path may carry a
REM command separator or a redirect, and cmd.exe parses those before REM ever
REM sees the line -- which is why no comment in this file contains one either.
echo run-spill-guard.cmd: SPILL_GUARD_BIN names a path that does not exist. >&2
goto :deny_explicit

:run_explicit
"%SPILL_GUARD_BIN%" %*
exit /b %ERRORLEVEL%

:try_path
for /f "delims=" %%P in ('where spill-guard 2^>nul') do (
    "%%P" %*
    exit /b %ERRORLEVEL%
)

if exist "%LOCALAPPDATA%\spill-guard\bin\spill-guard.exe" goto :run_default
echo run-spill-guard.cmd: no spill-guard.exe on PATH or under LOCALAPPDATA. >&2
goto :deny_missing

:run_default
"%LOCALAPPDATA%\spill-guard\bin\spill-guard.exe" %*
exit /b %ERRORLEVEL%

REM Both reasons below are fixed strings. Nothing from the environment is
REM interpolated into either, because a permissionDecisionReason reaches the
REM model verbatim -- a path or a variable's value spliced in there is text an
REM attacker controls arriving where the model reads instructions. It is also
REM why neither names SPILL_GUARD_OVERRIDE: telling the model how to proceed
REM without a scan is handing it the bypass.

:deny_explicit
echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"spill-guard: blocked. SPILL_GUARD_BIN names a path that is not a runnable spill-guard, so nothing scanned this call for secrets. This launcher does not fall back to PATH when SPILL_GUARD_BIN is set: an explicit path that does not work is a configuration error, not a reason to run some other binary. Fix the path or unset the variable, then start a new session."}}
exit /b 0

:deny_missing
echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"spill-guard: blocked. The spill-guard binary was not found, so nothing scanned this call for secrets. Install it and start a new session: scoop bucket add karlkfi https://github.com/karlkfi/scoop-bucket then scoop install spill-guard, or download install.ps1 from the latest release and run it. A scanner that cannot run blocks rather than passing quietly -- silence from this hook is supposed to mean checked."}}
exit /b 0
CMDBLOCK

# --- POSIX path -------------------------------------------------------------
# Everything above is a no-op heredoc under sh. The comment block at the top of
# the batch section is the argument for this whole file; it is not repeated.
#
# This runs under /bin/sh, so the prologue is POSIX: no `set -o pipefail` and
# no `shopt -s inherit_errexit`, neither of which exists here. The script has
# no pipeline and exactly one command substitution, whose failure is handled by
# the `if` it sits in -- which is the hole inherit_errexit exists to close.

set -eu

deny() {
    # A deny object on stdout blocks whatever this exits with, and the reason
    # reaches the model byte-identical. Exit 0 rather than 2: exit 2 discards
    # stdout, and 1, 9 and 127 are the codes a launcher that FAILED produces,
    # which is the state this deny exists to be distinguishable from.
    printf '%s\n' "$1"
    exit 0
}

# -f as well as -x, because a directory is executable and exec'ing one leaves
# the shell on 126 -- the fail-open code this file exists to prevent, one level
# up from where it was measured.
usable() {
    if [ -f "$1" ] && [ -x "$1" ]; then
        return 0
    fi
    return 1
}

DENY_EXPLICIT='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"spill-guard: blocked. SPILL_GUARD_BIN names a path that is not a runnable spill-guard, so nothing scanned this call for secrets. This launcher does not fall back to PATH when SPILL_GUARD_BIN is set: an explicit path that does not work is a configuration error, not a reason to run some other binary. Fix the path or unset the variable, then start a new session."}}'

DENY_MISSING='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"spill-guard: blocked. The spill-guard binary was not found, so nothing scanned this call for secrets. Install it and start a new session: brew install karlkfi/tap/spill-guard, or download install.sh from the latest release and run it. A scanner that cannot run blocks rather than passing quietly -- silence from this hook is supposed to mean checked."}}'

if [ -n "${SPILL_GUARD_BIN:-}" ]; then
    if usable "$SPILL_GUARD_BIN"; then
        exec "$SPILL_GUARD_BIN" "$@"
    fi
    # Named on stderr rather than in the reason: stderr is where a human
    # debugging this looks, and the reason is read by the model.
    printf 'run-spill-guard.cmd: SPILL_GUARD_BIN is %s, which is not an executable file\n' \
        "$SPILL_GUARD_BIN" >&2
    deny "$DENY_EXPLICIT"
fi

if found=$(command -v spill-guard 2>/dev/null) && usable "$found"; then
    exec "$found" "$@"
fi

default="${HOME:-}/.local/bin/spill-guard"
if [ -n "${HOME:-}" ] && usable "$default"; then
    exec "$default" "$@"
fi

printf 'run-spill-guard.cmd: no spill-guard on PATH and none at %s\n' "$default" >&2
deny "$DENY_MISSING"
