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

GATES := doctor gate-drift status-drift hooks-check launcher vendor docs queue action-pins test no-deps no-network vulns cross-compile

doctor.desc        := scripts/check-tools.sh runs, and every required tool is present
gate-drift.desc    := the gate list, the CI job list and the table in CLAUDE.md still agree
status-drift.desc  := the README's status table still says what the tree can actually do
hooks-check.desc   := every tracked git hook is executable, so none is silently inert
launcher.desc      := the hook launcher is executable in the index, resolves a binary, and denies when it cannot
vendor.desc        := every vendored copy still hashes to the digest scripts/README.md declares
docs.desc          := every relative link in the repo markdown resolves
queue.desc         := the backlog store format holds, every filed id holds a claim, no index is committed
action-pins.desc   := every `uses:` in every workflow names an immutable revision, not a tag
test.desc          := gofmt, go vet and go test
no-deps.desc       := go.mod requires nothing and the build graph is this module plus stdlib
no-network.desc    := the build graph reaches no net, net/http or os/exec
vulns.desc         := govulncheck finds no known vulnerability the build graph calls
cross-compile.desc := all five shipped targets build from one runner

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
# The cost is one arm. A row citing a file a sibling PR *adds* cannot resolve
# here, so a correct pointer reddens the branch carrying it with no repair but
# `exhibit:` or waiting. `--strict` names a class rather than an arm, so that
# arm cannot be left behind. Q67 is the split.
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
.PHONY: help check list-gates print-gates gates status hooks $(GATES)

help:
	@printf 'spill-guard\n\n'
	@printf '  make check        run every gate, reporting all failures\n'
	@printf '  make list-gates   name every gate and what it covers\n'
	@printf '  make <gate>       run one gate\n'
	@printf '  make gates        refresh the generated gate table in CLAUDE.md\n'
	@printf '  make status       refresh the generated status table in README.md\n'
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

status-drift:
	$(PYTHON) scripts/check-status.py --check

hooks-check:
	$(PYTHON) scripts/check-githooks.py

# Not covered by hooks-check, which scopes to .githooks and asks what git will
# run. This file is invoked by Claude Code, and a launcher at mode 644 passes
# every other gate here while the guard never fires once.
launcher:
	$(PYTHON) scripts/check-launcher.py

vendor:
	$(PYTHON) scripts/check-vendor.py

docs:
	$(PYTHON) scripts/check-doc-links.py

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
