#!/usr/bin/env python3
"""Drive the shipped plugin through a real `claude` that makes real tool calls.

Everything else here hands the hook a payload this repository wrote. This runs
the Claude Code binary, loads `hooks/hooks.json` as a plugin, and points the
binary at a fake of the Messages API on a loopback port, which answers with one
`tool_use`. So the shell the harness picks, the spawn, the payload and the
verdict's effect on the tool call are all the harness's own. The key is a dummy
and nothing leaves the runner, so a fork's pull request can run it.

It is what established that a Windows machine with no Git Bash scanned nothing:
hooks.json's command was a PowerShell parse error, exit 1, and only exit 2 blocks.
A workflow rather than a gate, for the reason check-prompt-oracle.py is: Claude
Code is not in the tier `make doctor` requires.

Every arm reads the outcome from what the fake was sent. A tool_result holding
the planted key is the key crossing, whatever the hook said.

    check-hook-harness.py --claude PATH --binary PATH [--no-git-bash]
    check-hook-harness.py --claude PATH --binary PATH --no-git-bash --wiring FILE

--wiring is the mutation control. It takes a wiring measured to scan nothing and
requires the key to cross, so this script is known to be able to see that.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLANTED = ROOT / "testdata" / "corpus" / "planted" / "aws-access-key-id.env"
KEY = re.compile(r"A(?:KIA|SIA)[A-Z0-9]{16}")
BLOCKED = "spill-guard: blocked"
TIMEOUT = 90


def events(kind_and_body):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n"
                   for e in kind_and_body).encode()


def reply(call):
    """One assistant turn: the wanted tool call, or the text that ends the run."""
    if call:
        block = {"type": "tool_use", "id": "toolu_fake0000000000000001",
                 "name": call["name"], "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(call["input"])}
        stop = "tool_use"
    else:
        block = {"type": "text", "text": ""}
        delta = {"type": "text_delta", "text": "done"}
        stop = "end_turn"
    return events([
        {"type": "message_start", "message": {
            "id": "msg_fake", "type": "message", "role": "assistant",
            "model": "claude-fake", "content": [], "stop_reason": None,
            "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}},
        {"type": "content_block_start", "index": 0, "content_block": block},
        {"type": "content_block_delta", "index": 0, "delta": delta},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
         "usage": {"output_tokens": 1}},
        {"type": "message_stop"},
    ])


class Run:
    """What one `claude -p` sent the fake, and what its transcript recorded."""

    def __init__(self, requests, called, errors, state):
        self.requests = requests
        self.called = called
        self.errors = errors
        self.state = state
        self.tools = requests[0]["tools"] if requests else []
        self.results = [str(block.get("content"))
                        for request in requests
                        for message in request["messages"] or []
                        if isinstance(message.get("content"), list)
                        for block in message["content"]
                        if block.get("type") == "tool_result"]

    @property
    def crossed(self):
        return any(KEY.search(result) for result in self.results)

    @property
    def blocked(self):
        return any(BLOCKED in result for result in self.results)

    def __str__(self):
        return (f"{len(self.requests)} request(s), tool called: {self.called}, "
                f"key crossed: {self.crossed}, blocked: {self.blocked}, "
                f"non-blocking hook errors: {len(self.errors)}")


def path_without_spill_guard():
    """PATH with every directory holding a spill-guard removed, so the missing
    binary is missing on a machine that has one installed too."""
    return os.pathsep.join(
        entry for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and not any((Path(entry) / name).exists()
                             for name in ("spill-guard", "spill-guard.exe")))


def drive(claude, plugin, cwd, call=None, prompt="hello", env_extra=None):
    """Run one session against a fresh fake and a fresh HOME."""
    requests = []
    called = []

    class Fake(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("content-length", 0)))
            body = json.loads(raw) if raw else {}
            data, kind = b'{"input_tokens":1}', "application/json"
            if "/v1/messages" in self.path and "count_tokens" not in self.path:
                tools = sorted(t.get("name") for t in body.get("tools") or [])
                requests.append({"tools": tools, "messages": body.get("messages")})
                wanted = call if call and call["name"] in tools and not called else None
                if wanted:
                    called.append(wanted["name"])
                data, kind = reply(wanted), "text/event-stream"
            self.send_response(200)
            self.send_header("content-type", kind)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    home = Path(tempfile.mkdtemp(prefix="harness-home-"))
    env = dict(os.environ)
    env.pop("SPILL_GUARD_BIN", None)
    env.update({
        "PATH": path_without_spill_guard(),
        "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}",
        "ANTHROPIC_API_KEY": "fake-loopback-key",
        "HOME": str(home), "USERPROFILE": str(home), "LOCALAPPDATA": str(home),
        "XDG_STATE_HOME": str(home / "state"),
        "CLAUDE_CONFIG_DIR": str(home / ".claude"),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
    })
    env.update(env_extra or {})
    argv = [claude, "-p", prompt, "--plugin-dir", str(plugin), "--output-format", "text"]
    if call:
        argv += ["--allowedTools", call["name"]]
    subprocess.run(argv, env=env, cwd=cwd, capture_output=True, timeout=TIMEOUT,
                   stdin=subprocess.DEVNULL, check=False)
    server.shutdown()

    errors = []
    for transcript in (home / ".claude").rglob("*.jsonl"):
        for line in transcript.read_text(encoding="utf-8", errors="replace").splitlines():
            attachment = json.loads(line).get("attachment")
            if isinstance(attachment, dict) and attachment.get("type") == "hook_non_blocking_error":
                errors.append(str(attachment.get("stderr")))
    log = home / "state" / "spill-guard" / "coverage.jsonl"
    state = log.read_text(encoding="utf-8") if log.exists() else ""
    shutil.rmtree(home, ignore_errors=True)
    return Run(requests, bool(called), errors, state)


def install_plugin(into, wiring):
    plugin = into / "plug in"  # A space, as a Windows profile path often has.
    plugin.mkdir()
    shutil.copytree(ROOT / ".claude-plugin", plugin / ".claude-plugin")
    (plugin / "hooks").mkdir()
    shutil.copy2(ROOT / "hooks" / "run-spill-guard.cmd", plugin / "hooks")
    shutil.copy2(wiring, plugin / "hooks" / "hooks.json")
    return plugin


def control(claude, plugin, cwd, binary):
    """A wiring measured to scan nothing must let the key cross, here."""
    planted = {"name": "Read", "input": {"file_path": str(cwd / "planted.txt")}}
    got = drive(claude, plugin, cwd, planted, env_extra={"SPILL_GUARD_BIN": binary})
    print(f"shell-form wiring, Read of the planted file: {got}")
    findings = []
    if not got.called:
        findings.append("the fake never got the tool call, so this control saw nothing")
    if not got.crossed:
        findings.append("the key did not cross under a wiring measured to let it, so "
                        "this script cannot tell a broken install from a working one")
    if not any("ParserError" in error or "Unexpected token" in error for error in got.errors):
        findings.append(f"no PowerShell parse error was recorded, so this is not the "
                        f"failure that was measured: {got.errors!r}")
    return findings


def arms(claude, plugin, cwd, binary, no_git_bash):
    findings = []
    real = {"SPILL_GUARD_BIN": binary}
    key = KEY.search(PLANTED.read_text(encoding="utf-8")).group(0)

    def read(name):
        return {"name": "Read", "input": {"file_path": str(cwd / name)}}

    def must_block(what, got):
        print(f"{what}: {got}")
        if not got.called:
            findings.append(f"{what}: the fake never got the tool call, so this "
                            f"blocked nothing -- {got}")
        elif got.crossed or not got.blocked:
            findings.append(f"{what}: the hook did not stop it -- {got}")

    def must_stop_prompt(what, got):
        print(f"{what}: {got}")
        if got.requests:
            findings.append(f"{what}: the prompt reached the API -- {got}")

    clean = drive(claude, plugin, cwd, read("clean.txt"), env_extra=real)
    print(f"Read of a clean file: {clean}")
    # The positive control for every prompt arm below: an empty request list
    # means the prompt was stopped only if a clean session does send one.
    if not clean.requests or not clean.called or clean.blocked:
        findings.append(f"a clean Read did not go through, so a block below "
                        f"proves nothing -- {clean}")
    # The second half of what the wiring has to do: a spelling that fails under
    # one shell would still block under the other and record this on every call.
    if clean.errors:
        findings.append(f"a clean call records a hook error, which a person would "
                        f"see on every call: {clean.errors[:1]!r}")

    has_ps, has_bash = "PowerShell" in clean.tools, "Bash" in clean.tools
    print(f"tools offered: Bash={has_bash} PowerShell={has_ps}")
    if no_git_bash and (has_bash or not has_ps):
        # The precondition that the mutation bit, read from the harness itself
        # rather than from whether a directory was renamed.
        findings.append(f"Git Bash was meant to be out of reach and the harness "
                        f"offered Bash={has_bash} PowerShell={has_ps}, so nothing "
                        f"here drove the PowerShell path")
    if not no_git_bash and not has_bash:
        findings.append("Git Bash was meant to be reachable and Bash was not offered")

    must_block("Read of the planted file",
               drive(claude, plugin, cwd, read("planted.txt"), env_extra=real))
    must_block("Read of the planted file by a non-ASCII path",
               drive(claude, plugin, cwd, read("ключ.txt"), env_extra=real))
    must_stop_prompt("a prompt carrying the key",
                     drive(claude, plugin, cwd, prompt=f"look at {key}", env_extra=real))
    must_stop_prompt("the binary missing",
                     drive(claude, plugin, cwd, read("clean.txt")))

    if has_bash:
        must_block("a Bash reader over the planted file", drive(
            claude, plugin, cwd,
            {"name": "Bash", "input": {"command": "cat planted.txt", "description": "read"}},
            env_extra=real))
    if has_ps:
        must_block("a PowerShell command carrying the key", drive(
            claude, plugin, cwd,
            {"name": "PowerShell", "input": {"command": f"Write-Output {key}",
                                             "description": "print"}},
            env_extra=real))
        # The stated limit, pinned. A reader table moves this arm to must_block,
        # and until then the record is what stands between it and silence.
        gap = drive(claude, plugin, cwd,
                    {"name": "PowerShell", "input": {"command": "Get-Content planted.txt",
                                                     "description": "read"}},
                    env_extra=real)
        print(f"a PowerShell reader over the planted file: {gap}")
        if '"tool":"PowerShell"' not in gap.state:
            findings.append(f"a PowerShell call this cannot read left no coverage "
                            f"record, so the gap is silent -- {gap}")
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--claude", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--no-git-bash", action="store_true")
    parser.add_argument("--wiring")
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="harness-"))
    cwd = work / "project"
    cwd.mkdir()
    (cwd / "planted.txt").write_bytes(PLANTED.read_bytes())
    (cwd / "ключ.txt").write_bytes(PLANTED.read_bytes())
    (cwd / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    plugin = install_plugin(work, args.wiring or ROOT / "hooks" / "hooks.json")

    if args.wiring:
        findings = control(args.claude, plugin, cwd, args.binary)
    else:
        findings = arms(args.claude, plugin, cwd, args.binary, args.no_git_bash)
    for finding in findings:
        print(f"hook-harness: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("hook-harness: every arm did what it must")
    return 0


if __name__ == "__main__":
    sys.exit(main())
