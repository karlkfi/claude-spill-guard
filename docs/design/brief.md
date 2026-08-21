# Origin brief

Kept as written, on 2026-08-20, before this repo existed. It is the input the
design in [`README.md`](README.md) responds to, not a plan of record — where the
two disagree, the design is the later thinking. `secret-scanner-analysis.md`,
which it refers to as sitting alongside it, is now
[`language-choice.md`](language-choice.md).

---

Build a local secret/PII scanner for Claude Code hooks, in Go, in a new repo.

## Context

This replaces `coo-quack/sensitive-canary` (Node/TypeScript). That plugin is not
malicious — it audits clean — but it has three problems worth a rewrite: it needs
Node ≥22.6 and fails *open* silently on older Node, its ruleset has a ~28%
file-level false-positive rate with zero true positives on real infra
repositories, and its `Finding` struct carries the raw secret value alongside the
redacted one.

The goal: nothing sensitive ever leaves the machine. Detection is local
heuristics only — no network calls, ever, for any reason.

**Language is already decided: Go.** Do not re-benchmark or re-litigate this. The
analysis, with all supporting measurements, is in `secret-scanner-analysis.md`
(alongside this prompt) — put it in the new repo as `docs/design/language-choice.md`
before you start, so the reasoning ships with the code. Short version: Go was chosen
over Rust and Python because `regexp` is stdlib (zero third-party dependencies,
which matches the threat model and is verifiable by users), because it
cross-compiles to macOS/Windows/Linux from any machine with no setup, and because
it has the cheapest per-invocation fixed cost (7.0 ms vs Rust's 12.1 ms). Rust is
3.5x faster at scanning; that was judged not to matter, because the ruleset is the
bottleneck, not the engine.

## Hard requirements

1. **Zero third-party runtime dependencies.** `regexp` and `encoding/json` are
   stdlib. Test-only deps are fine. This is a stated product property, not a
   preference — enforce it in CI.
2. **Single static binary**, cross-compiled for darwin/arm64, darwin/amd64,
   linux/amd64, linux/arm64, windows/amd64. All five build from one machine.
3. **No network capability whatsoever.** No `net/http`, no `net`. Enforce with a
   CI check on the import graph, not just review.
4. **Fail closed, and make failing closed actually work.** The Node version exits
   9 on an unsupported flag, which the harness does not treat as blocking, so it
   silently checks nothing. A static binary removes that class — but still verify
   the harness's exit-code contract empirically rather than trusting docs, and add
   a self-test subcommand that proves the hook is live.
5. **Never put a raw secret in a struct that outlives the match.** Carry a hash
   for dedup. Output rule ID, file, and offset — consider not emitting even a
   redacted fragment, since stderr reaches the API.
6. **Escape control characters** in all output (terminal-injection defense).
7. **No in-band bypass tags.** A magic string that disables the scanner is a
   prompt-injection surface, because any content the model reads can contain it.
   Use a config file or env var the model cannot write.

## The real work is the ruleset

On 257 real text files the inherited ruleset produced 5,679 matches across 9
rules, **all of them PII noise, zero credential hits**. Examples:

- `pii-postal-code` is `\b\d{5}(?:-\d{4})?\b` — matches `65536` and Kubernetes
  NodePorts like `30443`.
- `pii-phone-cn` flagged `0400-2341068` **268 times**; it is a slice out of the
  amdgpu driver version string `1:6.16.13.30300400-2341068`.
- `pii-ipv4-public` is `\b\d{1,3}(?:\.\d{1,3}){3}\b` — matches `10.0.0.1` and
  `0.0.0.0` despite `public` in the name. That one is a correctness bug.

Design for precision from the start:

- **Checksum validators** — Luhn for cards, mod-11 for national IDs.
- **Context gating** — require a nearby label (`phone:`, `ssn=`) before a bare
  numeric run counts as anything.
- **Entropy thresholds** for high-entropy credential candidates.
- **Exclude reserved ranges** — RFC1918, loopback, link-local, documentation
  ranges.
- **Per-rule enablement**, with the numeric PII family defaulting to **off**.
- Borrow from **gitleaks**' ruleset. It is RE2-clean by construction (verified: no
  PCRE dependency, uses stdlib `regexp`, so a non-RE2 rule would panic at
  startup).

## Known traps — do not rediscover these

- **RE2 has no lookaround or backreferences.** 9 of the 76 inherited rules use
  them and need rewriting: `twilio-sid`, `openai-key`, `square-access-token`,
  `mapbox-token`, `sentry-org-token`, `jwt`, `env-assignment`, `pii-email`,
  `pii-ssn`. Most are `(?<![A-Za-z0-9])X(?![A-Za-z0-9])` boundary guards —
  capture a wider window and post-filter in code.
- **RE2 caps bounded repetition at 1000.** `connection-string` uses `{1,1024}`;
  change it to `{1,1000}`.
- **Do not fold many patterns into one alternation.** Measured at 0.5x — the DFA
  state space explodes and the lazy-DFA cache thrashes on heterogeneous input.
  Run patterns separately. (Rust's `RegexSet` fails the same way, 0.7x.)
- **A literal keyword prefilter is worth ~280x** (280 MiB/s vs 1.0 MiB/s) — but
  use word boundaries, not `strings.Contains`. Naive matching hits `sk-` inside
  `disk-`, and a single broad keyword like `"AC"` took the hit rate from 1.2% to
  18.9% on real files. Note it can only gate the credential rules; numeric PII
  patterns have no literal to anchor on.
- **Skip binary files** (NUL byte in the first 8 KiB). In the test corpus one PNG
  was 55% of all bytes.

## Benchmarking rules, if you benchmark at all

- Never benchmark on a repeated chunk. It overstated one engine by 10x because
  the DFA cache stays warm and literal prefilters skip everything.
- Use real heterogeneous files.
- Verify match counts are identical before comparing any two timings.
- Measure fixed startup cost separately from throughput; below ~8 KB of input it
  dominates completely.

## Non-goals

- Do not build a server, daemon, or any persistent process.
- Do not add telemetry, crash reporting, or update checks.
- Do not support remote or shared rule configuration.
- Do not aim for gitleaks-level rule coverage in v1. Ten precise rules beat
  seventy noisy ones — the inherited ruleset's problem is precision, not recall.

## How to start

Plan before writing code. Propose the repo layout, the rule schema, the
prefilter/scan/validate pipeline, and the CI shape (including the zero-dependency
and no-network enforcement). Get the plan approved, then implement.

Branch naming: `<github-username>/<description>`. Use `gh api user --jq '.login'`
if unsure.
