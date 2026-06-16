# PRE_PAYMENT_GUARD — plugin interface (working draft v0)

A documented hook an x402 agent SDK calls **before signing a payment**. Independent
screens — payload PII, authorization/budget, inbound-challenge detection, replay —
plug in behind one interface, run at the same chokepoint, and compose without each
re-implementing it. Origin: [x402-foundation/x402#2332 / #2533](https://github.com/x402-foundation/x402/issues/2533) (shape 2).

This is a working draft, proven against two independent implementations
(payload + authorization) before being proposed to the Foundation.

## Plugin contract

```
declares: string[]                 # input fields this plugin reads
keys_off_raw: string[]             # declared fields whose RAW (pre-mutation) value
                                   # a security control keys off (may be empty)
screen(input, ctx) -> verdict
```

- `input` — the union of all plugins' `declares`, assembled by the runner from the
  payment request (e.g. `resource_url`, `description`, `reason`, `extra`,
  `amount_usd`, `payToken`).
- `ctx` — shared context the runner threads through: `effective_budget_remaining`,
  prior plugins' verdicts. A plugin that needs nothing from it ignores it.
- A plugin declaring the fields it reads means it **cannot grow a hidden dependency**
  on an undeclared field, and the assembled union stays auditable.

## Verdict envelope

```jsonc
{
  "verdict": "admit" | "deny",
  "reason":    "string",                       // optional; human-readable cause
  "entities":  ["string"],                     // optional; labels/findings
  "mutations": { "<field>": <value> }          // optional; rewritten field values
}
```

One envelope for every plugin. A plugin populates only what applies:

| Outcome | verdict | entities | mutations |
|---|---|---|---|
| clean / pass | `admit` | — | — |
| refuse | `deny` | findings | — |
| **rewrite, then allow** | `admit` | findings | changed fields |
| flag only | `admit` | findings | — |

The **`mutations`** field is load-bearing: a screen is not always binary. A payload
PII screen in redact mode *admits but rewrites the payload* (strips the SSN from the
memo, lets the payment through clean). An authorization plugin never rewrites, so it
simply omits `mutations` — same envelope.

## Runner rules

1. **Assemble** `input` as the union of every registered plugin's `declares`.
2. **Run** each plugin's `screen(input, ctx)`; thread `ctx` (budget remaining, prior
   verdicts) so plugins compose without re-fetching.
3. **Aggregate: block-if-any-denies.** Any `deny` blocks the payment; surface its
   `reason`.
4. **Apply mutations** from `admit` verdicts to the payload that gets signed.
5. **Mutation-ordering rule (required).** Mutations accumulate into what is signed,
   but any plugin that computes a security key off raw input MUST declare those fields
   in `keys_off_raw` and read their **pre-mutation** values. Rationale: a payload
   screen rewrites the resource URL, but a replay fingerprint or a pay-to allowlist
   that keys off the *redacted* URL collapses distinct user-specific URLs into one
   `<EMAIL_ADDRESS>` token and produces false replay hits. (Lesson from the
   presidio-hardened-x402 gateway.)

## Conformance

Each plugin ships a vector set: for every vector, the `input`, its canonical JCS
bytes (RFC 8785; ASCII string/object safe band = `json.dumps(sort_keys, separators)`),
and the `expected` verdict envelope. `conformance/verify.py` re-runs the plugin and
asserts byte-equality — an independent, offline reproduction, no trust in the
recorded values and no network.

## Reference plugins

- **payload** — `plugins/payload/`, presidio-hardened-x402 PII screen. Complete, 5 vectors.
- **authorization** — `plugins/authorization/`, JWT pay-token / budget check. Contributed by LemonCake (placeholder).
