# payload plugin — PII screen

Reference PRE_PAYMENT_GUARD plugin: scans x402 payment metadata for PII before
signing. Thin adapter over [`presidio-hardened-x402`](https://github.com/presidio-v/presidio-hardened-x402)'s
`PIIFilter` (regex mode by default; the `[nlp]` extra enables the spaCy NER pipeline).

- **declares:** `resource_url`, `description`, `reason`, `extra`
- **keys_off_raw:** none (the screen computes no security key; its mutations are safe to thread downstream)
- **modes → verdict:**
  - `block` → `deny` + `entities`
  - `redact` (default) → `admit` + `entities` + `mutations` (rewritten fields)
  - `warn` → `admit` + `entities`

A pure, offline function of its declared inputs — no network, no `ctx` dependency —
which is what makes its verdicts byte-reproducible in the conformance set.

```bash
pip install presidio-hardened-x402
PYTHONPATH=plugins/payload python conformance/payload/generate.py   # regenerate vectors
PYTHONPATH=plugins/payload python conformance/verify.py             # verify
```

See [`payload_plugin.py`](payload_plugin.py) and the spec at
[`../../spec/pre-payment-guard.md`](../../spec/pre-payment-guard.md).
