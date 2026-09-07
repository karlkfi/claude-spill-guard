#!/usr/bin/env python3
"""Verify a release's cosign signature, and prove the check can reject.

`cosign verify-blob` over `checksums.txt` is the assertion that ties a release
to this repository. It is pinned with `--certificate-identity`, so a signature
minted from a branch, from another workflow, or from a fork is a valid Sigstore
signature that must not verify as this release's.

That check exits 0 and prints `Verified OK`, and every flag that narrows what it
accepts is a flag that can stop narrowing. Which is not hypothetical here:
cosign v3 defaults `--new-bundle-format` to true, which turned
`--output-signature` and `--output-certificate` into no-ops and broke
`v0.1.0-rc.1`. A flag that quietly stops being enforced looks exactly like one
that passed.

So this runs four verifications rather than one, and the last three are the
point:

  positive     the identity this release was signed under. Must verify. It is
               the precondition for everything below -- against a bundle that
               does not verify at all, three rejections prove nothing.

  a branch     the same workflow at refs/heads/<branch>
  a workflow   a different workflow in this repository, at this ref
  a fork       this workflow, at this ref, under another owner

Each of the three must be rejected, and rejected *on the identity*. That second
half is what stops this being a control that passes because it never ran: an
empty `--certificate-identity` also exits non-zero, on `--certificate-identity
or --certificate-identity-regexp is required`, so a control reading only the
exit status is satisfied by a cosign that never looked at the bundle. Only the
`no matching CertificateIdentity found` text says the identity was compared and
did not match.

Measured 2026-09-07 against the published v0.3.0 assets, cosign v3.1.3: the
positive arm exits 0 `Verified OK`; all three negatives exit 1 naming both the
SAN expected and the SAN found; the empty identity exits 1 on the `is required`
message, which is the arm this script's text-matching refuses to count.

The release job calls this on a tag, against what it just published. The
`published-release-verify` job calls it on every pull request, against the last
release that was published -- which is what makes this file, and the invocation
shape the release depends on, something a pull request exercises rather than
something first executed on a permanent version number.

Exits 1 and reports every arm that did not do what it must, so one run says all
of them.
"""

import argparse
import shutil
import subprocess
import sys

OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# The flags the signature is read back with. cosign v3 signs into a Sigstore
# bundle by default, so `--bundle` and `--new-bundle-format` are what read one.
# Written once because the negative arms have to be the positive arm with the
# identity changed and nothing else -- a control invoking cosign differently
# from the check it controls is testing a different command.
BUNDLE_FLAGS = ["--new-bundle-format"]

# cosign's own words for "I compared the certificate's subject and it was not
# the one you named". Any other refusal -- a missing bundle, an unreadable
# blob, an identity that was never passed -- is this script failing to ask the
# question rather than cosign answering it.
REJECTED_ON_IDENTITY = "no matching CertificateIdentity found"


def identity(repository, workflow, ref):
    """The SAN a GitHub Actions keyless signature carries, as cosign sees it."""
    return f"https://github.com/{repository}/{workflow}@{ref}"


def verify(bundle, blob, ident):
    """Run the verification. Returns (exit status, combined output)."""
    proc = subprocess.run(
        ["cosign", "verify-blob", "--bundle", bundle, *BUNDLE_FLAGS,
         "--certificate-identity", ident,
         "--certificate-oidc-issuer", OIDC_ISSUER, blob],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def wrong_identities(repository, workflow, ref):
    """The three identities this release must not verify under.

    Each is the real one with a single component replaced, so what a rejection
    establishes is that cosign read that component. `main` is spelled here
    rather than read from the repository because the arm is about a ref that is
    not this tag, and any branch name serves.
    """
    owner, _, name = repository.partition("/")
    other_workflow = ("/".join(workflow.split("/")[:-1] + ["tests.yml"])
                      if "/" in workflow else "tests.yml")
    return [
        ("a branch", identity(repository, workflow, "refs/heads/main")),
        ("another workflow", identity(repository, other_workflow, ref)),
        ("a fork", identity(f"{owner}-fork/{name}", workflow, ref)),
    ]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bundle", required=True,
                        help="the Sigstore bundle, checksums.txt.sigstore.json")
    parser.add_argument("--blob", required=True,
                        help="the signed file, checksums.txt")
    parser.add_argument("--repository", required=True,
                        help="owner/name, as GITHUB_REPOSITORY spells it")
    parser.add_argument("--ref", required=True,
                        help="the ref the signature was minted at, as "
                             "GITHUB_REF spells it: refs/tags/vX.Y.Z")
    parser.add_argument("--workflow",
                        default=".github/workflows/release.yml",
                        help="the workflow that signs, repository-relative")
    args = parser.parse_args(argv[1:])

    if shutil.which("cosign") is None:
        sys.exit("signature-identity: cosign is not on PATH, so nothing here "
                 "could establish that this release was signed by anyone. That "
                 "is a missing tool and not a passing check.")

    real = identity(args.repository, args.workflow, args.ref)
    wrong = wrong_identities(args.repository, args.workflow, args.ref)

    # A derived identity that collides with the real one would be verified
    # rather than rejected, and the arm would report a failure it caused
    # itself. The reachable way in is a --ref of refs/heads/main.
    collisions = [label for label, ident in wrong if ident == real]
    if collisions:
        sys.exit(f"signature-identity: the {', '.join(collisions)} arm derives "
                 f"the identity this release was signed under, so it would be "
                 f"asserting that a correct signature is rejected. Nothing was "
                 f"checked.")

    status, output = verify(args.bundle, args.blob, real)
    if status != 0:
        # Two refusals, reported apart because a caller has to be able to tell
        # them apart. A wrong identity is cosign answering the question; a
        # missing bundle is cosign never being asked it, and a control that
        # accepts either as "refused" is satisfied by a file that is not there.
        # Which is measured: driving this job's steps with no `published/`
        # directory, a single shared message let the mutation control below
        # pass against a checksums.txt that had never been downloaded.
        if REJECTED_ON_IDENTITY in output:
            print(f"signature-identity: {args.blob} does not verify under "
                  f"{real}, which is the identity this release was signed "
                  f"with. cosign compared the certificate subject and it was "
                  f"not that one.", file=sys.stderr)
        else:
            print(f"signature-identity: cosign could not carry out the "
                  f"verification of {args.blob} at all, so nothing here is a "
                  f"statement about an identity -- this is a check that did "
                  f"not run rather than a signature that did not verify.",
                  file=sys.stderr)
        print(output, file=sys.stderr)
        return 1
    print(f"signature-identity: {args.blob} verifies under {real}")

    findings = []
    for label, ident in wrong:
        status, output = verify(args.bundle, args.blob, ident)
        if status == 0:
            findings.append(f"{ident} ({label}) verified against "
                            f"{args.blob}, and it is not the identity this "
                            f"release was signed under")
        elif REJECTED_ON_IDENTITY not in output:
            findings.append(f"{ident} ({label}) was refused, and not on the "
                            f"identity -- cosign never said "
                            f"`{REJECTED_ON_IDENTITY}`, so what this arm "
                            f"observed is some other failure: "
                            f"{output.strip().splitlines()[-1] if output.strip() else '(no output)'}")
        else:
            print(f"signature-identity: rejected {label}, on the identity")

    if findings:
        for line in findings:
            print(f"signature-identity: {line}", file=sys.stderr)
        print(f"\nThe signature over {args.blob} is what ties this release to "
              f"{args.repository}. A verification that cannot reject a "
              f"signature minted somewhere else is not checking that.",
              file=sys.stderr)
        return 1

    print(f"signature-identity: {len(wrong)} identities this release was not "
          f"signed under were each rejected on the identity")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
