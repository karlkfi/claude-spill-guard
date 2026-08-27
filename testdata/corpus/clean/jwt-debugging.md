# Debugging a bearer token

The gateway rejects a request with 401 and no body, which tells you nothing.
Decode the token before you go looking at the gateway.

## The sample token

Paste this into jwt.io and you will see the three panes fill in. It is the
token on the debugger's own front page, so it is the one to try first when you
want to know whether the tool is working rather than whether your token is:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Header, payload, signature, separated by dots. The header says `HS256`, the
payload carries `sub`, `name` and `iat`, and the signature is over the first
two with the secret `your-256-bit-secret`.

## Decoding yours without a website

```
cut -d. -f2 <<<"$TOKEN" | base64 -d 2>/dev/null | jq .
```

The padding is stripped in a JWT, so `base64 -d` complains and still prints the
object. Read `exp` first — an expired token is the answer more often than
anything else in there.

## What the panes do not tell you

The debugger verifies a signature only if you give it the key. Without one it
decodes and shows you the claims, which is enough to tell an expiry from a
scope problem and not enough to tell a forged token from a real one.
