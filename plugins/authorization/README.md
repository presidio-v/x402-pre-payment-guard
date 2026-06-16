# authorization plugin — token / budget screen (placeholder)

Reference PRE_PAYMENT_GUARD plugin for the **authorization** plane: verify the
agent's pay token and check the spend is within budget — offline, no pre-signing
network hop.

To be contributed by **LemonCake** ([per #2533](https://github.com/x402-foundation/x402/issues/2533)),
aligned to the common verdict envelope in [`../../spec/pre-payment-guard.md`](../../spec/pre-payment-guard.md).

Expected shape:

- **declares:** `amount_usd`, `payToken`, and `effective_budget_remaining` (from shared `ctx`)
- **keys_off_raw:** none expected (token verification is over the token claims, not mutable payload)
- **screen → verdict:**
  - valid token, within budget → `admit`
  - expired / revoked / budget exceeded → `deny` + `reason`
  - never populates `mutations` (authorization does not rewrite the payload)

Drop the plugin here plus a `conformance/authorization/vectors.json` in the same
format as the payload set (`input` + `input_jcs` + `expected`), and `conformance/verify.py`
will need a small dispatch to load this plugin for its suite.
