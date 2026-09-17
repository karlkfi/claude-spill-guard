#!/usr/bin/env python3
"""Every workflow job this repository runs is one somebody declared.

`gate-drift` already reconciles `tests.yml`, because that file's job list is
*derived*: `GATES` in the Makefile is the source of truth and the jobs are one
per gate plus one mutation control each, so a missing job is a disagreement
with a generator. Nothing derives `release.yml` or `prompt-oracle.yml`. Each
job there exists for its own reason, so the list has to be declared -- and
until it was, a job deleted from either file went unnoticed by anything.

The symptom is the one this repository names at the top of its own workflow: a
job that does not run reports no check, which reads identically to one that
passed. Deleting `published-release-verify` takes away the only exercise the
signature path gets outside a tag and removes a green tick nobody was reading,
rather than producing a red one. The two `*-mutation-control` jobs are worse
again -- each exists to fail, so each is a job whose absence is invisible by
construction.

**Declared, not derived, and that is the whole difference.** A derived list
cannot go stale; it can only disagree. A declared one goes stale the moment
somebody adds a job and does not come here, which is why this asserts both
directions and why the declaration carries a reason per job. A reason is what
makes a deletion a decision: removing the job means removing the line that says
what it was for.

`tests.yml` is named below and deliberately not checked here. Two gates reading
one file would each report half an answer, and `gate-drift`'s is the stronger
half, since it reconciles against the generator rather than against a copy.

A workflow this has never heard of is refused rather than skipped. That is the
direction a declared list fails in silently: a fourth file lands, nothing here
names it, and a check whose whole subject is "is every job accounted for"
accounts for none of that file's and still exits 0.

**The unit is the job key, and a matrix leg is not one.** Five of the eight
check runs release.yml posts are legs, and a leg's rendered name is not its YAML
key -- `install-dry-run (windows-latest)` is one job here and three check runs
there. So narrowing `os: [ubuntu-latest, macos-latest, windows-latest]` to one
entry deletes the macOS and Windows exercise of the install scripts and this
still exits 0, which is this gate's own symptom one level down. It is a gap
rather than a decision: `tools/cmd/workflow`'s job model is `{Name, Runs}` and
carries no matrix, so closing it means extending the Go parser, and Q174 holds
it. Read a declared reason as describing what the job is *for*, not as a claim
about which legs run -- `install-dry-run` says "on Linux, macOS and Windows"
and nothing here holds that half.
"""

import sys

import workflow_model

# The workflow `gate-drift` owns. Named rather than skipped by absence, so
# deleting it from that gate does not quietly hand it to no one.
DERIVED = {
    ".github/workflows/tests.yml":
        "derived from GATES in the Makefile; `gate-drift` reconciles it",
}

# Every job the other workflows run, and what each is for. The reason is the
# part that makes this more than a name list: a deletion has to take the
# sentence with it, and a reviewer reading the diff sees what was given up.
DECLARED = {
    ".github/workflows/release.yml": {
        "dry-run":
            "builds every shipped archive from the pinned GoReleaser on each "
            "pull request, so a config that cannot build is caught before a "
            "tag spends a version number",
        "dry-run-mutation-control":
            "drops a target, corrupts an archive and edits checksums.txt in "
            "both directions, and requires the dry run to fail on each",
        "install-dry-run":
            "runs install.sh and install.ps1 against a served dist directory "
            "on Linux, macOS and Windows, and asserts the binary they install "
            "runs",
        "install-dry-run-mutation-control":
            "stops an install script comparing the digest and requires the "
            "install to fail",
        "published-release-verify":
            "verifies the signature on whatever /releases/latest serves -- the "
            "only exercise the verification path gets outside a tag, and the "
            "path the release job depends on",
        "release":
            "the tag job: builds, signs, attests, uploads to a draft, and "
            "checks the published assets and body as a consumer would",
    },
    ".github/workflows/prompt-oracle.yml": {
        "prompt-oracle":
            "re-takes the `@` token census against a pinned `claude`, which is "
            "a workflow rather than a make gate because Claude Code is not in "
            "the tier `make doctor` requires",
    },
}


def main():
    files = workflow_model.load()

    findings = []
    checked = 0
    derived_seen = []
    for path, entry in sorted(files.items()):
        if path in DERIVED:
            derived_seen.append(path)
            continue
        declared = DECLARED.get(path)
        if declared is None:
            findings.append(
                f"{path} is a workflow this check does not know. Add its jobs "
                f"to DECLARED in scripts/check-workflow-jobs.py with a reason "
                f"each, or to DERIVED if something else reconciles it. Until "
                f"one of those happens nothing here reads that file, and a job "
                f"deleted from it would be invisible")
            continue

        found = [job["name"] for job in entry["jobs"]]
        # The parser exits rather than returning a model with no jobs, so an
        # empty list here would be a workflow that genuinely declares none --
        # which is not a thing this repository has, and would silently satisfy
        # the "nothing extra" half below.
        if not found:
            findings.append(
                f"{path} modelled with no jobs at all, so neither direction "
                f"below could have failed")
            continue

        checked += len(found)
        for name in sorted(n for n in declared if not declared[n].strip()):
            findings.append(
                f"{path} declares `{name}` with an empty reason, so the "
                f"declaration is a name list after all. The reason is what "
                f"makes a deletion a decision -- write one line saying what "
                f"the job is for, so removing it means removing that line")
        for name in sorted(set(declared) - set(found)):
            findings.append(
                f"{path} no longer runs `{name}`, which is declared as: "
                f"{declared[name]}. A job that does not run reports no check, "
                f"and no check reads the same as a passing one -- so restore "
                f"it, or delete the declaration and say in the commit why the "
                f"coverage it names is no longer wanted")
        for name in sorted(set(found) - set(declared)):
            findings.append(
                f"{path} runs `{name}` and nothing declares it. Add it to "
                f"DECLARED in scripts/check-workflow-jobs.py with one line "
                f"saying what it is for, so its deletion later is a decision "
                f"rather than an accident")

    for path in sorted(set(DERIVED) - set(files)):
        findings.append(
            f"{path} is left to another gate in scripts/check-workflow-jobs.py "
            f"and is not a workflow file any more, so this is crediting "
            f"coverage that does not exist: {DERIVED[path]}")

    for path in sorted(set(DECLARED) - set(files)):
        findings.append(
            f"{path} is declared here and is not a workflow file any more, so "
            f"every job under it went unchecked")

    if not checked and not findings:
        print(f"job-drift: {len(files)} workflow(s) modelled and not one job "
              f"among the declared ones, so nothing above could have failed",
              file=sys.stderr)
        return 1

    for entry in findings:
        print(f"job-drift: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} disagreement(s) between the workflows and "
              f"the declarations in scripts/check-workflow-jobs.py.",
              file=sys.stderr)
        return 1

    print(f"job-drift: {checked} job(s) across "
          f"{len(files) - len(derived_seen)} workflow(s), every one declared; "
          f"{len(derived_seen)} left to the gate that derives it. A matrix "
          f"leg is not a job here -- see the module docstring")
    return 0


if __name__ == "__main__":
    sys.exit(main())
