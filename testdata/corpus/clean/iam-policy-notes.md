# Reading the IAM examples in the AWS docs

Everyone hits this once: the policy snippets in AWS's documentation carry a key
ID and a secret, and it is not obvious at a glance that they are inert. They
are. AWS uses the same pair on every page.

## The pair

The access key ID is `AKIAIOSFODNN7EXAMPLE` and the secret is
`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`. Both carry `EXAMPLE`, which is how
AWS marks a value that authenticates against nothing — the key ID ends there,
the secret has `KEY` after it. A credential you generate yourself carries no
such mark, so it is the fastest way to tell a docs paste from a real one.

You will also meet `ASIAIOSFODNN7EXAMPLE` on the STS pages. `ASIA` is the
prefix for a temporary session key; the body is the same example string.

## What the console gives you

```
[default]
region = us-east-2
output = json
```

Credentials go in `~/.aws/credentials`, mode 0600, and never in this
repository. `aws configure` writes both files for you.

## Rotating

1. Create the second key in the console while the first is still active.
2. Deploy it, confirm the workload is using it, then deactivate the first.
3. Delete the deactivated key after a week. Deactivating is reversible and
   deleting is not.

If a key reaches a commit it is burned, whatever the scanner said. Rotate it
before you rewrite the history.
