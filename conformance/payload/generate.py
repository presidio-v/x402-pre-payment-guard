#!/usr/bin/env python3
"""Generate the payload-plugin conformance vectors by running the reference
plugin on a fixed set of inputs. Re-run after a plugin change:

    pip install presidio-hardened-x402
    PYTHONPATH=plugins/payload python conformance/payload/generate.py

Each vector carries the input, its canonical JCS bytes (RFC 8785 safe band:
json.dumps with sorted keys), and the expected verdict envelope the plugin
returns. `conformance/verify.py` re-runs the plugin and asserts byte-equality,
so a pass is an independent offline reproduction of every verdict.
"""

import hashlib
import json
from pathlib import Path

from payload_plugin import PayloadScreenPlugin


def jcs(obj) -> str:
    # RFC 8785 safe band for ASCII string/dict inputs (matches action-ref spec).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


CASES = [
    {
        "id": "clean-admit",
        "pii_action": "redact",
        "input": {
            "resource_url": "https://api.merchant.example/v1/invoice",
            "description": "Monthly API access — tier 2",
            "reason": "subscription renewal",
            "extra": {"order_id": "ord_8842"},
        },
    },
    {
        "id": "redact-description-ssn",
        "pii_action": "redact",
        "input": {
            "resource_url": "https://api.merchant.example/v1/invoice",
            "description": "Payout for customer SSN 219-09-9999",
            "reason": "vendor settlement",
            "extra": {"order_id": "ord_8843"},
        },
    },
    {
        "id": "redact-extra-email",
        "pii_action": "redact",
        "input": {
            "resource_url": "https://api.merchant.example/v1/invoice",
            "description": "Monthly API access",
            "reason": "subscription renewal",
            "extra": {"memo": "receipt to alice@example.com", "order_id": "ord_8844"},
        },
    },
    {
        "id": "block-ssn",
        "pii_action": "block",
        "input": {
            "resource_url": "https://api.merchant.example/v1/invoice",
            "description": "Payout for customer SSN 219-09-9999",
            "reason": "vendor settlement",
            "extra": {},
        },
    },
    {
        "id": "warn-clean-allows-but-flags",
        "pii_action": "warn",
        "input": {
            "resource_url": "https://api.merchant.example/v1/invoice",
            "description": "Contact support at admin@example.com",
            "reason": "dispute",
            "extra": {},
        },
    },
]


def main() -> None:
    vectors = []
    for c in CASES:
        plugin = PayloadScreenPlugin(pii_action=c["pii_action"])
        verdict = plugin.screen(c["input"])
        canonical = jcs(c["input"])
        vectors.append(
            {
                "id": c["id"],
                "description": f"pii_action={c['pii_action']}",
                "config": {"pii_action": c["pii_action"]},
                "declares": plugin.declares,
                "input": c["input"],
                "input_jcs": canonical,
                "input_jcs_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                "expected": verdict,
            }
        )

    suite = {
        "suite": "pre-payment-guard-payload-v1",
        "plugin": "payload (presidio-hardened-x402 PIIFilter, regex mode)",
        "vectors": vectors,
    }
    out = Path(__file__).resolve().parent / "vectors.json"
    out.write_text(json.dumps(suite, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} vectors -> {out}")
    for v in vectors:
        print(f"  {v['id']:32} -> {v['expected']}")


if __name__ == "__main__":
    main()
