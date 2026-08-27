# Payments integration

Sandbox only. Every number and key on this page is published by the gateway
for exactly this purpose, so none of it is a credential and none of it should
ever be reported by a scanner.

## Test keys

Set these in `.env.local`. They are the publishable and secret keys from the
dashboard's test mode, and they are inert against the live API:

```
STRIPE_PUBLISHABLE_KEY=pk_test_51H8sQ2LkT9vXbRmZ4nWpJdYcAe
STRIPE_SECRET_KEY=sk_test_51H8sQ2LkT9vXbRmZ4nWpJdYcAe
```

## Test card numbers

| Card | Number | Behaviour |
|---|---|---|
| Visa | 4242 4242 4242 4242 | succeeds |
| Visa (debit) | 4000 0566 5566 5556 | succeeds |
| Mastercard | 5555 5555 5555 4444 | succeeds |
| Amex | 3782 8224 6310 005 | succeeds |
| Discover | 6011 1111 1111 1117 | succeeds |
| Visa | 4000 0000 0000 0002 | declined, generic |

Any future expiry and any three-digit CVC works. The Amex row takes four
digits.

## Amounts

Amounts are in the smallest currency unit, so a 655.36 charge is 65536.
