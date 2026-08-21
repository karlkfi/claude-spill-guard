## What

## Why

## Release note

<!--
One sentence for the next release's notes, in the terms someone deciding whether
to upgrade would use. Write it here, now, while you are the only person who
knows what changed -- reconstructing this at tag time from commit subjects is
the expensive half of cutting a release, and it under-reports removals badly.

Say `NONE` for anything that ships in no artifact: tests, CI, docs, refactors.
That is a real answer, not a skipped field.

Open with `action required:` if upgrading needs a manual step.
-->

```release-note
NONE
```

## Verification

<!--
For a rule change, both directions, since both fail silently: the rule still
fires on the secret it was written for, and still stays quiet on the clean
corpus. A rule with only a positive case is how a scanner starts flagging
Kubernetes NodePorts as postal codes.

Then the part that makes a green run mean something -- what you broke, and what
went red when you broke it. A new assertion that has never failed is not yet
evidence.
-->
