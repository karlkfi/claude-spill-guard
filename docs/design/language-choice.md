# Local secret/PII scanner: language and architecture analysis

Measured 2026-08-19/20. Everything below is a direct measurement on the host
described in [Environment](#environment) unless explicitly marked **UNVERIFIED**.

Origin: a security audit of the `coo-quack/sensitive-canary` Claude Code plugin
(v0.8.1, Node/TypeScript) and a decision about rewriting it in a compiled language.

---

## 1. Conclusion

**Build it in Go.** Not because Go is faster — it is the slowest of the three
engines tested — but because the two properties that actually decide this project
are supply chain and distribution, and Go wins both outright.

The performance difference between languages is not the bottleneck. All three
produced **byte-identical false positives** on real files. The ruleset is the
defect.

### Decision table

```
                              Go            Rust         winner
scan, real files          1.1 MiB/s     3.9 MiB/s        Rust 3.5x
fixed cost per invocation    7.0 ms       12.1 ms         Go 1.7x
  startup                    5.1 ms        1.2 ms
  compile 66 rules           1.9 ms       10.9 ms
rules that compile           66/76         67/76          Rust +1
3rd-party deps for regex         0             5          Go
cross-compile to macOS      zero setup   needs Xcode SDK  Go
build time (cold)             ~1 s         11.6 s         Go
```

Crossover: Go is faster end-to-end below **~8 KB** of input; Rust above.
Solving `7.0 + 909x = 12.1 + 256x` gives `x ≈ 0.0078 MiB`.

### Why Go, in order of weight

1. **Zero third-party dependencies.** `regexp` and `encoding/json` are stdlib.
   For a tool whose entire premise is that nothing leaves the machine, an empty
   supply chain is a property you can state to users and they can verify in an
   afternoon. Rust needs 5 crates before you write a line. This was also the
   audited Node plugin's single strongest property — worth preserving.
2. **Distribution.** A hook runs on *users'* machines. Go cross-compiles to every
   target from any machine. Rust cannot link macOS without Apple's SDK.
3. **Cheaper per invocation**, which is the axis a hook lives on.

### When Rust would be the right call instead

If you weight "cannot silently mishandle an error" above supply chain and
distribution. Rust's sum types with exhaustive matching, `Result`-forced error
handling, and `#![forbid(unsafe_code)]` are real advantages for a tool whose
failure mode is *silently missing a secret*. That is a defensible flip, not a
wrong one. Mitigate the distribution problem with macOS CI runners or
`cargo-zigbuild`.

**Python is not recommended** but is viable: 1.8 MiB/s (between Go and Rust),
24 ms fixed cost, and preinstalled almost everywhere. It loses on distribution
(you inherit the user's interpreter and version skew) and on typing/tooling.

---

## 2. Findings that overturned earlier conclusions

Recorded because each one was a confident claim killed by measurement. Anyone
continuing this work should not re-derive them.

### 2.1 `RegexSet` does not help — the headline reason for Rust is dead

Rust's `RegexSet` matches N patterns in a single pass over the haystack
(verified from docs: "report the matching regexes using a *single pass through
the haystack*"). It needs no literal anchor, so it looked like the answer to the
numeric PII rules that a keyword prefilter cannot gate.

On real files it is **slower** than running the patterns separately:

```
real repo (257 text files, 1.01 MiB)     time      throughput
  Rust, 66 separate patterns            0.256 s     3.9 MiB/s
  Rust, RegexSet single pass            0.368 s     2.7 MiB/s   0.7x
```

Go's equivalent — folding 66 patterns into one alternation — fails the same way:

```
Go, 8 MiB synthetic                66 separate   1 joined    ratio
  match-heavy, full scan              6.264 s     11.837 s    0.5x
  clean/no-match, full scan           6.563 s     11.627 s    0.6x
  match-heavy, first-match only       5.581 s      0.001 s    3835x  <- artifact
```

The 3835x is **pure early-exit** — `MatchString` returns at the first hit near
byte 50. On a full scan the folded automaton is ~2x slower.

**Mechanism:** folding N patterns explodes the DFA state space; the lazy-DFA
cache thrashes on heterogeneous content and falls back to NFA simulation.
Repetitive synthetic input keeps the cache warm and hides this entirely. Two
independent engines, same result — this is a property of the approach.

### 2.2 Synthetic benchmarks overstated Rust by ~10x

```
                   synthetic 8 MiB      real repo text 1.01 MiB
  Rust             47–68 MiB/s               3.9 MiB/s
  Python            2.5–2.8 MiB/s            1.8 MiB/s
  Go                1.2 MiB/s                1.1 MiB/s
```

Synthetic said Rust was ~40x Go. Real files say 3.5x. Synthetic also said Go was
2.3x slower than Python; real files say 1.6x. **Do not benchmark this workload on
a repeated chunk** — the payload was a 176-byte block repeated 47,662 times, which
is close to a best case for DFA caching and literal prefilters.

### 2.3 Binary files silently wrecked the first real-repo run

A single 2.16 MiB PNG was **55% of the corpus bytes**. Rust and Python expand
invalid UTF-8 to U+FFFD; Go keeps raw bytes — so the three were not scanning the
same input. Contaminated numbers (1.5 / 1.2 / 1.0 MiB/s) compressed the spread to
near-nothing. Skip binaries (NUL byte in first 8 KiB); a secret scanner should
anyway.

### 2.4 Go is slower than Python at regex, and speed does not fix ReDoS

Go's `regexp` (RE2) is slower than CPython's backtracking `re` on this workload.
And CPython's SRE **polls for signals**, so `SIGALRM` *can* interrupt a running
match — measured on `(a+)+$` against `"a"*40 + "!"`, wall clock landed exactly on
the 0.5 s alarm. The ReDoS argument for a compiled RE2 engine is weaker than it
looks. RE2's linear-time guarantee is still the cleaner design, but it is not the
emergency the Node implementation's `vm.runInThisContext` timeout implied.

### 2.5 The keyword prefilter is real but far more fragile than it looks

Original synthetic claim was rigged — the payload and the keyword list had the
same author, so "zero keywords hit" could not have come out otherwise.

Against real files:

```
keyword list                      files hit   %
full (60, as originally written)     49/259   18.9
trimmed (58, no "AC"/"key-")          3/259    1.2
```

`"AC"` alone drove 18.9% by matching ordinary prose in workflow files. Of the 3
survivors, 2 are false: `sk-` matched inside `disk-containerd-…`.

**The prefilter is genuinely fast** — 255–307 MiB/s vs 1.0 MiB/s for the regex
pass, roughly 280x. But:

- It needs word boundaries, not naive `strings.Contains`.
- It is exquisitely sensitive to keyword quality; one bad entry destroys it.
- **It only gates the credential half of the ruleset.** The PII rules are
  pure-numeric with no literal to anchor on, and they are 100% of the noise.

---

## 3. The actual defect: the ruleset

On 257 real text files: **71 files flagged (27.6%), 5,679 matches, 9 rules — and
zero credential rules among them.** Every single match is PII noise.

```
pii-phone-cn      2533     pii-postal-cn       8
pii-ipv4-public   1522     pii-phone-de        4
pii-phone-kr      1441     pii-steuer-id-de    3
pii-postal-code    169     pii-brn-kr          3
                           pii-phone-it        1
```

### Worked examples

```
rule              regex                                                   matches
pii-phone-cn      (?:\+86[-\s]?)?(?:1[3-9]\d{9}|0\d{2,3}[-\s]?\d{7,8})   0400-2341068
pii-phone-kr      (?:\+82[-\s]?)?(?:01[016789]|0\d{1,2})[-\s]?\d{3,4}...  0300400-2341
pii-postal-code   \b\d{5}(?:-\d{4})?\b                                    65536, 30443
pii-ipv4-public   \b\d{1,3}(?:\.\d{1,3}){3}\b                             10.0.0.1
```

- `0400-2341068` was flagged **268 times** as a Chinese phone number. It is a
  slice out of the amdgpu DKMS version string `1:6.16.13.30300400-2341068`.
- `pii-postal-code` matches `65536` (a buffer constant) and `30080`/`30443`
  (Kubernetes NodePorts).
- `pii-ipv4-public` matches `10.233.0.1`, `10.0.0.1`, `0.0.0.0` — RFC1918 and
  unspecified addresses, despite `public` in its name. **A correctness bug**, not
  merely noise.

### What this implies for the rewrite

A 27.6% file-level false-positive rate with zero true positives is not a tuning
problem, it is a design problem. Numeric-only PII patterns cannot be made precise
by regex alone. Required:

- **Checksum validators** — Luhn for cards, mod-11 for many national IDs.
- **Context gating** — require a nearby label (`phone:`, `ssn=`) before a bare
  numeric run counts.
- **Entropy thresholds** for high-entropy credential candidates.
- **Exclusion of reserved ranges** — RFC1918/loopback/link-local for IP rules.
- **Word boundaries** on prefilter keywords.
- **Per-rule enablement**, defaulting the numeric PII family to off.

---

## 4. Regex engine compatibility

Neither RE2 (Go) nor Rust's `regex` supports lookaround or backreferences.
Of the plugin's 76 rules:

```
engine        compiles   fails
Go / RE2        66/76      10   (9 lookaround + 1 repeat-count cap)
Rust regex      67/76       9   (9 lookaround)
```

The 9 lookaround rules, identical in both: `twilio-sid`, `openai-key`,
`square-access-token`, `mapbox-token`, `sentry-org-token`, `jwt`,
`env-assignment`, `pii-email`, `pii-ssn`.

Go's extra rejection is `connection-string`: `invalid repeat count: {1,1024}` —
RE2 caps bounded repetition at 1000. **Fix is `{1,1000}`, one character.** Rust
has a configurable `size_limit` rather than a hard cap, so it accepts it.

Rewriting the 9 lookaround rules is required work in either language. Most are
`(?<![A-Za-z0-9])X(?![A-Za-z0-9])` boundary guards, expressible by capturing a
wider window and post-filtering in code.

**gitleaks' ruleset is RE2-clean by construction** — verified: its `go.mod` has no
PCRE or `regexp2` dependency and it uses stdlib `regexp`, so a non-RE2 rule would
panic at startup rather than ship. It is a safe ruleset to borrow from.

---

## 5. Design requirements carried over from the audit

The audited plugin was **safe to install** — no malicious behaviour, zero runtime
dependencies, only filesystem write is `/dev/tty`, verified SLSA provenance,
SHA-pinned CI actions, 782 tests. Preserve these properties. The items below are
what to change.

### Fail-closed is an availability risk that also fails open

The plugin exits 2 (block) on internal error. But it requires Node ≥22.6 for
`--experimental-strip-types`, and on Node 18 it exits **9** — not 2 — so the hook
**fails open silently**: installed, checking nothing, reporting nothing. A single
static binary removes this entire class of failure.

> **UNVERIFIED:** that Claude Code treats only exit 2 as blocking is from
> documentation, not measurement. The exit-9 behaviour *was* measured. Confirm the
> harness's treatment of other non-zero codes before relying on it.

### Redaction must happen before anything is emitted

The plugin's `Finding` carries both `matchRedacted` and the raw `secretValue`.
Tracing showed `secretValue` is used only as a dedup key and never printed — but
the field's existence is a standing hazard. **Do not put the raw value in the
finding struct.** Carry a hash for dedup.

Note that an 8-char redacted fragment (`min(4, floor(len/8))` chars each end)
still reaches the API via stderr. Consider emitting only rule ID, file, and
offset.

### Other carried-over requirements

- **Escape control characters** in any output — terminal-injection defense.
- **Distinguish human-typed text from runtime-written text** when deciding what
  to scan.
- **Avoid in-band bypass tags.** A magic string that disables the scanner is a
  prompt-injection surface: any content the model reads can contain it.

---

## 6. Environment

```
CPU     AMD Ryzen 7 PRO 7840U (16 threads)
Kernel  6.18.33.2-microsoft-standard-WSL2
Go      1.26.5
Rust    1.98.0, regex crate 1.13.1
Python  3.12.3
Corpus  a private infrastructure-as-code repo (Ansible/K8s/docs),
        257 text files, 1.01 MiB, binaries excluded
```

All three implementations agreed exactly on the real corpus — 257 files scanned,
71 flagged, 5,679 matches — which is what makes the throughput comparison
controlled.

### Reproduction notes

- Extract the RE2-compatible subset first and benchmark **that identical set** in
  every language. An early run compared 75 Python patterns against 66 Go ones.
- Verify match counts are identical across languages before comparing times.
- Use real heterogeneous files, not repeated chunks (§2.2).
- Skip binaries (§2.3).
- Measure fixed cost separately from throughput; for a per-invocation hook it
  dominates below ~8 KB.

---

## 7. Claims deliberately left unverified

- **macOS `/usr/bin/python3` is an Xcode stub** — from recall, no macOS available.
  Materially affects any "Python is preinstalled" argument.
- **Claude Code's treatment of non-zero, non-2 exit codes** — documentation only
  (§5).
- **`cargo-zigbuild` / macOS CI runners** as the Rust distribution fix — plausible
  and widely used, not tested here.
