# Every gate this project runs, and the one list they are all derived from.
#
# GATES is the source of truth. `make check` runs it, `make list-gates` prints
# it, the job list in .github/workflows/tests.yml is asserted against it, and
# the table in CLAUDE.md is generated from it. A derived list that can go stale
# silently is worse than honest copies, because it reads as authoritative --
# so `make gate-drift` fails until every one of those agrees, and it is itself
# a gate.
#
# Adding a gate: one name in GATES, one `<name>.desc`, one target, one job in
# the workflow (plus its mutation control), then `make gates`.

PYTHON ?= python3

GATES := doctor gate-drift job-drift status-drift privacy-drift hooks-check launcher script-modes vendor docs release-claims release-scope release-notes channel-claims plugin-version queue action-pins test precision self-scan no-deps no-network vulns cross-compile

doctor.desc         := scripts/check-tools.sh runs, and every required tool is present
gate-drift.desc     := the gate list, the CI job list and the table in CLAUDE.md still agree
job-drift.desc      := every job in the workflows nothing derives is one somebody declared, with a reason
status-drift.desc   := the README's status table still says what the tree can actually do
privacy-drift.desc  := PRIVACY.md still says what the hook reads and writes, against the manifest, the source and a driven binary
hooks-check.desc    := every tracked git hook is executable, so none is silently inert
launcher.desc       := the hook launcher is executable in the index, resolves a binary, and denies when it cannot
script-modes.desc   := a shebang and the executable bit travel together, in the index, both ways
vendor.desc         := every vendored copy still hashes to the digest scripts/README.md declares
docs.desc           := every relative link in the repo markdown resolves
release-claims.desc := the prose holds whether or not a release exists, and the state is readable
release-scope.desc  := no release-scope record survives the release it was written for
release-notes.desc  := every published release body is still the notes file it came from
channel-claims.desc := no message names an install channel that does not exist
plugin-version.desc := the two plugin manifests carry the same version, so a release can be delivered
queue.desc          := the backlog store format holds, every filed id holds a claim, no index is committed
action-pins.desc    := every `uses:` in every workflow names an immutable revision, not a tag
test.desc           := gofmt, go vet and go test
precision.desc      := the shipped ruleset stays quiet on the clean corpus and finds every planted secret
self-scan.desc      := no tracked file trips the scanner except the corpus and a named list that says why
no-deps.desc        := go.mod requires nothing and the build graph is this module plus stdlib
no-network.desc     := the build graph reaches no net, net/http or os/exec
vulns.desc          := govulncheck finds no known vulnerability the build graph calls
cross-compile.desc  := all five shipped targets build from one runner

# Single-quote a value for the shell, so a description carrying an apostrophe
# does not close the quoting early.
sq = '$(subst ','\'',$(1))'

HOOKS_DIR := .githooks

# Which of `queue.py lint`'s notes are promoted to failures. The split is the
# `queue` job's decision, argued in its comments in the workflow. The first
# three are decidable from the files in front of you and bind wherever this
# runs.
#
# stale-citation is here with a cost that is accepted rather than absent, and
# the workflow states it in full. What it catches on a branch is a citation
# the branch's own diff invalidated -- correct when written, moved by an edit
# in the same PR. What no event split reaches is a citation a *sibling* moved:
# the branch stays green, because the pointer is correct against the tree in
# front of it, and main reddens on the merge. So this narrows that hole rather
# than closing it, and MERGED=true on the trunk is still what catches the rest.
#
# The cost is any pointer describing the merged tree rather than this branch --
# a file a sibling adds, a fragment it adds, a line number only right once it
# lands. All four of the class's checks behave alike here, because lint sees
# one tree: which check fires depends on how the trees differ, and which side
# reddens depends only on which tree the author wrote against. So no arm split
# separates the cost from the benefit. Repair is `exhibit:` or waiting. Q67 is
# the open question about a marker that expires, not a split.
#
# What counts as drifted is a separate question again: `--citation-window`
# decides that and promotion cannot reach it. Q30 settles the value at 10.
QUEUE_STRICT := --strict blocked-opener --strict deferred-trigger \
                --strict empty-store --strict stale-citation

# The one class the merged tree has to answer. A row may legitimately link an
# item a sibling PR is still filing: both branches are correct and only the one
# carrying the link is red. MERGED=true on a push to main, and `make queue
# MERGED=true` is how a local run sees what the trunk sees.
QUEUE_STRICT_MERGED := --strict dangling-link

MERGED ?= false
queue_strict = $(QUEUE_STRICT) $(if $(filter true,$(MERGED)),$(QUEUE_STRICT_MERGED))

.DEFAULT_GOAL := help
.PHONY: help check list-gates print-gates gates status privacy hooks $(GATES)

help:
	@printf 'spill-guard\n\n'
	@printf '  make check        run every gate, reporting all failures\n'
	@printf '  make list-gates   name every gate and what it covers\n'
	@printf '  make <gate>       run one gate\n'
	@printf '  make gates        refresh the generated gate table in CLAUDE.md\n'
	@printf '  make status       refresh the generated status table in README.md\n'
	@printf '  make privacy      refresh the generated read/write block in PRIVACY.md\n'
	@printf '  make hooks        install the pre-commit hook (git core.hooksPath)\n'
	@printf '  make doctor       report which required tools are missing, and how to get them\n\n'
	@$(MAKE) --no-print-directory list-gates

# Every gate runs even when an earlier one fails, so one run reports the whole
# tree. Stopping at the first failure is how a contributor fixes one thing,
# re-runs, and finds the next -- which is the shape every check script in
# scripts/ already refuses.
check:
	@rc=0; \
	for g in $(GATES); do \
		printf '\n=== %s ===\n' "$$g"; \
		$(MAKE) --no-print-directory MERGED=$(MERGED) "$$g" || rc=1; \
	done; \
	printf '\n'; \
	if [ "$$rc" -ne 0 ]; then \
		printf 'check: at least one gate failed\n' >&2; \
	else \
		printf 'check: every gate passed\n'; \
	fi; \
	exit "$$rc"

list-gates:
	@printf '%-14s %s\n' 'GATE' 'WHAT IT COVERS'
	@$(foreach g,$(GATES),printf '%-14s %s\n' $(call sq,$(g)) $(call sq,$($(g).desc));)

# Tab-separated, for scripts/gates.py. Asking make rather than parsing the
# Makefile keeps one parser: make's own.
print-gates:
	@$(foreach g,$(GATES),printf '%s\t%s\n' $(call sq,$(g)) $(call sq,$($(g).desc));)

gates:
	$(PYTHON) scripts/gates.py

# The README's status section is a set of machine-decidable facts written as
# prose, so it decays the way every hand-kept copy does and nothing re-reads
# it. Same split as `gates`: this rewrites, `status-drift` asserts.
status:
	$(PYTHON) scripts/check-status.py

# PRIVACY.md's list of what the hook reads and writes was hand-kept, and every
# bullet was wrong through two releases with every gate green. Same split
# again: this rewrites, `privacy-drift` asserts.
privacy:
	$(PYTHON) scripts/check-privacy.py

# Tracked hooks, so the store gates run before a commit rather than at review.
# --no-verify skips them; a hook is a fast local echo of CI, not a second
# authority.
hooks:
	git config core.hooksPath $(HOOKS_DIR)
	@printf 'hooks: core.hooksPath = %s\n' "$$(git config core.hooksPath)"
	@printf 'hooks: %s runs `make queue` before every commit\n' '$(HOOKS_DIR)/pre-commit'

# Runs `command -v` and nothing else, so it works on a fresh clone with none
# of the tools present -- which is the point of it and the easy half to lose.
# The pinned linters are not in its list: they live in tools/go.mod and run
# through `cd tools && go run <path>`, so Go is what a contributor needs.
doctor:
	bash scripts/check-tools.sh

gate-drift:
	$(PYTHON) scripts/gates.py --check

# gate-drift's neighbour, over the workflows it does not read. That one's list
# is derived from GATES, so it can only disagree with a generator; release.yml
# and prompt-oracle.yml have no generator, so their jobs are declared, with a
# reason each. Two gates rather than one because the claims fail differently: a
# derived list cannot go stale, and a declared one goes stale the moment
# somebody adds a job and does not say what it is for.
job-drift:
	$(PYTHON) scripts/check-workflow-jobs.py

status-drift:
	$(PYTHON) scripts/check-status.py --check

privacy-drift:
	$(PYTHON) scripts/check-privacy.py --check

hooks-check:
	$(PYTHON) scripts/check-githooks.py

# The third mode gate, and the widest. `hooks-check` asks whether git will run
# a tracked hook and `launcher` asks whether Claude Code can run one file; this
# asks the whole index whether a shebang and the bit agree, which is the rule
# scripts/README.md has stated since Q56 and nothing has ever read. Of the 15
# entry points added to scripts/ since that straightening, 3 arrived at 644 and
# none was noticed afterwards -- so this closes the only moment the rule can be
# got right, which is when the file is written. That count is main at 6857e68;
# scripts/README.md says why the revision is named and why this gate's own
# script sits outside it.
script-modes:
	$(PYTHON) scripts/check-script-modes.py

# Not covered by hooks-check, which scopes to .githooks and asks what git will
# run. This file is invoked by Claude Code, and a launcher at mode 644 passes
# every other gate here while the guard never fires once.
launcher:
	$(PYTHON) scripts/check-launcher.py

vendor:
	$(PYTHON) scripts/check-vendor.py

docs:
	$(PYTHON) scripts/check-doc-links.py

# The second gate whose oracle is off this machine. `gh release list` is the
# only reader that sees a draft, and a draft publishes no assets, so a tag
# alone is the wrong answer for prose about what a user can download.
#
# Three arms, because the property is that the prose is true in *either* state
# and the real-state arm can only ever read one of them. Reading the state the
# machine happens to be in is what let a sentence pass every local gate and
# redden CI on push: `already` beside `shipped` is a completed-aspect claim
# with no release, and a release exists, so the real-state arm called it
# true. The forced arms take no reading at all -- 0.248s and 0.249s here
# against 0.913s for the one that goes to the network -- so what this costs is
# half a second and nothing off the machine.
#
# Not a MERGED-shaped opt-in, which is the other shape this repository has for
# a gate that is weaker locally. That split exists for a class a branch cannot
# settle: `queue` tolerates a link to a row a sibling is still filing, and
# `release-notes` cannot repair a divergence from a pull request either way.
# Nothing here is event-dependent -- a branch failing a forced arm fails it on
# `main` too -- so there is no weaker answer for the default to be.
#
# The real-state arm's verdict on the prose is implied by the other two, since
# the state it reads is one of them. What it uniquely covers is that the state
# can be read at all -- the arm of the mutation control that breaks both
# readers and requires the check to say so rather than assume a direction. Do
# not drop it as redundant.
release-claims:
	@rc=0; \
	$(PYTHON) scripts/check-release-claims.py || rc=1; \
	$(PYTHON) scripts/check-release-claims.py --assume-release none || rc=1; \
	$(PYTHON) scripts/check-release-claims.py --assume-release released || rc=1; \
	exit "$$rc"

# The same two facts release-claims reads, one join further on: which versions
# a release exists for, and what the tree still carries for each. A plan doc or
# a `vX.Y.Z` label outliving its tag is the failure, and it is silent -- the
# record reads as current and nothing else opens it.
release-scope:
	$(PYTHON) scripts/check-release-scope.py

# The invariant docs/releases/README.md states, re-read after the tag rather
# than only at it. Only the merged tree can answer it: while a notes edit is an
# open pull request the divergence is the proposal, and no pull request can
# repair it either way, because the repair is `gh release edit`. So this reports
# on a branch and fails on `main` -- the split `queue` already makes for a class
# a branch cannot settle, and here it fires at the same merge that creates the
# divergence rather than one merge later.
release-notes:
	$(PYTHON) scripts/check-release-notes.py $(if $(filter true,$(MERGED)),--merged)

# Reads only what the install scripts and the launcher print. The tap named in
# install.sh's own header is deliberate -- it is the argument for the refusal's
# wording -- so a pattern over the file flags the thing the file exists to say.
channel-claims:
	$(PYTHON) scripts/check-channel-claims.py

# Without --version, which is the half a pull request can check: only a tag
# knows the number, and the release job is what passes it.
plugin-version:
	$(PYTHON) scripts/check-plugin-version.py

queue:
	@rc=0; \
	$(PYTHON) scripts/vendor/claude-skills/queue.py lint $(queue_strict) || rc=1; \
	$(PYTHON) scripts/vendor/claude-skills/queue.py claims --strict || rc=1; \
	$(PYTHON) scripts/check-queue-index.py || rc=1; \
	exit "$$rc"

# Reads the workflows through the YAML parser in tools/, not a regex: a
# `uses:` inside a comment or a `run:` block is not a mapping key, and this
# repository's own workflow has both.
action-pins:
	$(PYTHON) scripts/check-action-pins.py

test:
	$(PYTHON) scripts/check-go.py

# The gate the design calls the one that matters most. Recall regressions get
# reported by whoever missed a secret; precision regressions are invisible
# until the noise has trained everyone to ignore the tool. check-precision.py
# runs the corpus tests and asserts each of them reported, because `go test
# -run` exits 0 when it matches nothing.
precision:
	$(PYTHON) scripts/check-precision.py

self-scan:
	$(PYTHON) scripts/check-self-scan.py

no-deps:
	$(PYTHON) scripts/check-supply-chain.py no-deps

no-network:
	$(PYTHON) scripts/check-supply-chain.py no-network

# The one gate whose oracle is off this machine: govulncheck reads the
# advisory database at vuln.go.dev. check-vulns.py tells that failing apart
# from a finding, so a third party being down never reads as a CVE.
vulns:
	$(PYTHON) scripts/check-vulns.py

cross-compile:
	$(PYTHON) scripts/cross-compile.py
