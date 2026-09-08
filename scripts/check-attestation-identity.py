#!/usr/bin/env python3
"""Verify an archive's build provenance, and assert the identity it carries.

`gh attestation verify` exits 0 and, once its output is redirected, prints
nothing at all -- measured 2026-09-07 against the published v0.3.0 assets: exit
0, zero bytes. So a release job that calls it is asserting the exit status and
the archive count beside it, and nothing about what the attestation said.

That is the same shape as the cosign check next door, and it has the same
failure mode: a flag that stops narrowing what it accepts still exits 0. cosign
v3 turning `--output-signature` into a no-op is what that cost here once
already. `--format=json` is the answer, because it produces a value to compare
rather than a status to trust.

The value is the certificate's subject, which is the identity of the workflow
that minted the attestation. It is spelled exactly as cosign's
`--certificate-identity` spells it, so both verifiers in that job now assert the
same string:

    https://github.com/<owner>/<repo>/.github/workflows/release.yml@<ref>

Both copies of the provenance are checked, because they can disagree. The
attestations API is one place and the `spill-guard_<version>.intoto.jsonl` asset
is another, and a bundle uploaded truncated or from the wrong run passes the
first and fails the second.

## Why the ref is pinned here and was not before

`--signer-workflow` matches the certificate subject as a prefix, so the bare
`<owner>/<repo>/.github/workflows/release.yml` this used to pass accepts that
workflow at *any* ref. Measured 2026-09-07 against the published v0.3.0
attestation: bare exits 0, `...release.yml@refs/tags/v0.3.0` exits 0, and
`...release.yml@refs/heads/main` exits 1. So appending the ref pins it, and the
release job's own comment -- "the identity is pinned to this workflow at this
tag" -- was true of the cosign call under it and not of these two.

`--cert-identity` would say the same thing and cannot be used alongside
`--signer-workflow`: `gh` refuses the pair outright, so this pins through the
flag it already passes and asserts the value out of the JSON regardless. The
flag narrows inside the verifier; reading the subject back is what says the flag
was enforced.

Exits 1 and reports every disagreement, so one run says all of them.
"""

import argparse
import json
import subprocess
import sys

SUBJECT = ("verificationResult", "signature", "certificate",
           "subjectAlternativeName")


def identity(repository, workflow, ref):
    """The certificate subject a GitHub Actions keyless attestation carries."""
    return f"https://github.com/{repository}/{workflow}@{ref}"


def subjects(payload, where):
    """Every certificate subject in a `--format=json` payload.

    Anything that is not a non-empty list of objects carrying the full path is
    an exit rather than an empty set: a comparison against nothing passes, and
    passing over nothing is the reading this script exists to refuse.
    """
    if not isinstance(payload, list) or not payload:
        sys.exit(f"attestation-identity: {where} returned no attestation "
                 f"objects, so there is no identity here to compare and the "
                 f"check below would pass over nothing.")
    found = set()
    for i, entry in enumerate(payload):
        node = entry
        for key in SUBJECT:
            if not isinstance(node, dict) or key not in node:
                sys.exit(f"attestation-identity: {where} attestation {i} "
                         f"carries no {'.'.join(SUBJECT)}, so `gh` reported a "
                         f"shape this does not know how to read. That is a "
                         f"check that could not run, not one that passed.")
            node = node[key]
        if not isinstance(node, str) or not node:
            sys.exit(f"attestation-identity: {where} attestation {i} carries "
                     f"an empty certificate subject.")
        found.add(node)
    return found


def verify(artifact, repository, signer, bundle=None):
    """Run the verification and return its parsed JSON, or exit saying why."""
    cmd = ["gh", "attestation", "verify", artifact,
           "--repo", repository, "--signer-workflow", signer, "--format=json"]
    where = "the attestations API"
    if bundle is not None:
        cmd[3:3] = ["--bundle", bundle]
        where = f"the attached bundle {bundle}"
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"attestation-identity: {artifact} did not verify against "
              f"{where} as {signer}.", file=sys.stderr)
        print(proc.stdout + proc.stderr, file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(proc.stdout), where
    except json.JSONDecodeError as err:
        sys.exit(f"attestation-identity: {where} verified {artifact} and its "
                 f"--format=json output could not be parsed ({err}). The exit "
                 f"status alone is what this check exists not to rely on.")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifact", required=True,
                        help="the archive whose provenance is being checked")
    parser.add_argument("--bundle", required=True,
                        help="the attached .intoto.jsonl, checked as well as "
                             "the attestations API")
    parser.add_argument("--repository", required=True,
                        help="owner/name, as GITHUB_REPOSITORY spells it")
    parser.add_argument("--ref", required=True,
                        help="the ref the attestation was minted at, as "
                             "GITHUB_REF spells it: refs/tags/vX.Y.Z")
    parser.add_argument("--workflow", default=".github/workflows/release.yml",
                        help="the workflow that attests, repository-relative")
    args = parser.parse_args(argv[1:])

    want = identity(args.repository, args.workflow, args.ref)
    signer = f"{args.repository}/{args.workflow}@{args.ref}"

    findings = []
    for bundle in (None, args.bundle):
        payload, where = verify(args.artifact, args.repository, signer, bundle)
        got = subjects(payload, where)
        if got != {want}:
            findings.append(f"{where} verified {args.artifact} and the "
                            f"attestation was minted by "
                            f"{', '.join(sorted(got))}, not by {want}")

    if findings:
        for line in findings:
            print(f"attestation-identity: {line}", file=sys.stderr)
        print(f"\n`--signer-workflow` matches the certificate subject as a "
              f"prefix, so a value that stopped pinning the ref accepts this "
              f"workflow at any ref. That is what reading the subject back "
              f"catches.", file=sys.stderr)
        return 1

    print(f"attestation-identity: {args.artifact} verifies through the "
          f"attestations API and against the attached bundle, both minted by "
          f"{want}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
