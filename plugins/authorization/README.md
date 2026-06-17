# authorization plugin — token / budget screen

Reference PRE_PAYMENT_GUARD plugin for the **authorization** plane: verify the
agent's pay token and check the spend is within budget — offline, no pre-signing
network hop.

Contributed by **LemonCake** ([per #2533](https://github.com/x402-foundation/x402/issues/2533)),
aligned to the common verdict envelope in [`../../spec/pre-payment-guard.md`](../../spec/pre-payment-guard.md).

## What it screens

A LemonCake **Pay Token** is an HS256 JWT whose claims carry the budget and
expiry, so authorization is a pure function of the token plus the runner's
ledger — no network. The plugin:

- **declares** `amount_usd`, `payToken` (input fields it reads);
- reads `effective_budget_remaining` and `now` from shared **`ctx`** — the live
  remaining budget is the ledger's truth, threaded by the runner, not a token
  claim, so a multi-call token composes across plugins without a re-fetch;
- **keys_off_raw:** none — token verification is over the token claims, not the
  mutable payload, so no upstream plugin's `mutations` can change what is
  authorized.

## Verdicts

| Outcome | verdict | reason | entities |
|---|---|---|---|
| valid token, spend ≤ remaining | `admit` | — | — |
| expired (`exp` ≤ `now`) | `deny` | `pay token expired` | `token_state:expired` |
| revoked (`jti` in revocation set) | `deny` | `pay token has been revoked` | `token_state:revoked` |
| signature fails / malformed | `deny` | `pay token rejected: …` | `token_state:invalid_signature` |
| spend > remaining budget | `deny` | `spend X exceeds remaining budget Y` | `token_state:budget_exceeded` |

It **never populates `mutations`** — authorization does not rewrite the payload.
The `token_state` finding (the exact field LemonCake's gateway returns) is
carried in `entities` so the precise cause survives into the common envelope.

## Implementation notes

HS256 verification is implemented over the **stdlib** (`hmac`/`hashlib`), so the
plugin has **no third-party dependency** and the expiry check reads the
runner-supplied `now` instead of a wall clock — both required for an offline,
byte-reproducible conformance set.

## Conformance

5 vectors in [`../../conformance/authorization/vectors.json`](../../conformance/authorization/vectors.json),
each carrying the `input`, its canonical JCS bytes (`input_jcs` + sha256), the
per-call `ctx`, and the `expected` verdict. Reproduce offline (stdlib only, no
install):

```bash
PYTHONPATH=plugins/authorization python conformance/verify.py conformance/authorization/vectors.json
# -> PASS: 5 vectors reproduced byte-identical
```

Regenerate after a plugin change with
[`../../conformance/authorization/generate.py`](../../conformance/authorization/generate.py).
