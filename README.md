# x402-pre-payment-guard

A pre-signing **plugin interface** for x402 agent payments. Independent screens —
payload PII, authorization/budget, and more — plug in behind one contract, run at the
same chokepoint **before a payment is signed**, and compose without each one
re-implementing the chokepoint.

Working draft from [x402-foundation/x402#2533](https://github.com/x402-foundation/x402/issues/2533)
(the `PRE_PAYMENT_GUARD` extension point, shape 2). Goal: prove the interface against
two independent implementations, then propose it to the x402 Foundation.

## Why

A single chokepoint, several orthogonal questions:

- **payload** — what PII is in the metadata I'm about to send? *(this repo: presidio reference plugin)*
- **authorization** — may I spend this, within budget, with a valid token? *(this repo: LemonCake reference plugin)*
- inbound-challenge, replay, mandate — same hook, more plugins.

None subsumes the others; all want to run before signing. The interface lets each be a
pure, offline-verifiable screen returning one common **verdict envelope**.

## Contract (one line)

```
declares: string[]   keys_off_raw: string[]   screen(input, ctx) -> { verdict, reason?, entities?, mutations? }
```

Full spec: [`spec/pre-payment-guard.md`](spec/pre-payment-guard.md). The `mutations`
field is the key generalization — a screen can *admit but rewrite the payload* (redact),
not just admit/deny.

## Layout

```
spec/pre-payment-guard.md                 # the interface
plugins/payload/                          # reference payload PII screen (complete)
plugins/authorization/                    # reference token/budget screen (complete — LemonCake)
conformance/verify.py                     # runner: re-run a plugin's vectors, assert byte-identical verdicts
conformance/payload/vectors.json          # 5 payload vectors
conformance/authorization/vectors.json    # 5 authorization vectors
```

## Quickstart

```bash
# authorization suite — stdlib only, no install:
PYTHONPATH=plugins/authorization python conformance/verify.py conformance/authorization/vectors.json
# -> PASS: 5 vectors reproduced byte-identical

# payload suite — needs the presidio reference plugin:
pip install presidio-hardened-x402
PYTHONPATH=plugins/payload python conformance/verify.py conformance/payload/vectors.json
```

Run `python conformance/verify.py` with both plugin dirs on `PYTHONPATH` and no
path arg to verify every suite at once; a suite whose plugin isn't importable is
skipped, not failed.

## Status

| Plugin | Owner | State |
|---|---|---|
| payload | presidio-v | complete — plugin + 5 conformance vectors |
| authorization | LemonCake | complete — plugin + 5 conformance vectors |

Two independent implementations now run behind one verdict envelope — the bar
this repo set before proposing the interface to the x402 Foundation. MIT.
