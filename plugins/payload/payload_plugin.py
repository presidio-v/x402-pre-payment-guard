"""Reference PRE_PAYMENT_GUARD plugin: payload PII screening.

Implements the plugin contract from ``spec/pre-payment-guard.md``:

    declares: list[str]                      # input fields this plugin reads
    screen(input, ctx) -> verdict            # the verdict envelope

It is a thin adapter over ``presidio-hardened-x402``'s ``PIIFilter`` (regex
mode by default; ``[nlp]`` extra enables the spaCy NER pipeline). Install:

    pip install presidio-hardened-x402

The plugin is a pure, offline function of its declared inputs — no network, no
shared-context dependency — which is what makes its verdicts byte-reproducible
in the conformance set.
"""

from __future__ import annotations

from typing import Any

from presidio_x402 import PIIFilter


class PayloadScreenPlugin:
    """PII screen over x402 payment metadata.

    Three configured outcomes map onto the common verdict envelope:

    * ``block``  -> ``deny``  + ``entities``                 (refuse the payment)
    * ``redact`` -> ``admit`` + ``entities`` + ``mutations`` (rewrite, then allow)
    * ``warn``   -> ``admit`` + ``entities``                 (flag only, no rewrite)

    A clean payload returns a bare ``admit``.
    """

    name = "payload"
    declares = ["resource_url", "description", "reason", "extra"]
    # Fields whose RAW (pre-mutation) value a security control keys off. The
    # payload plugin computes no such key itself, but it declares none so the
    # runner knows its mutations are safe to thread downstream. (See the
    # mutation-ordering rule in spec/pre-payment-guard.md.)
    keys_off_raw: list[str] = []

    def __init__(self, pii_action: str = "redact", entities: list[str] | None = None) -> None:
        if pii_action not in ("block", "redact", "warn"):
            raise ValueError(f"pii_action must be block|redact|warn, got {pii_action!r}")
        self.pii_action = pii_action
        self._entities = entities
        self._filter = PIIFilter(mode="regex", entities=entities) if entities else PIIFilter(mode="regex")

    def screen(self, input: dict[str, Any], ctx: dict[str, Any] | None = None) -> dict[str, Any]:
        resource_url = input.get("resource_url", "") or ""
        description = input.get("description", "") or ""
        reason = input.get("reason", "") or ""
        extra = input.get("extra", {}) or {}

        clean_url, clean_desc, clean_reason, found = self._filter.scan_payment_fields(
            resource_url, description, reason
        )
        clean_extra, extra_found = self._filter.scan_dict(extra)
        entities = sorted({e.entity_type for e in (list(found) + list(extra_found))})

        if not entities:
            return {"verdict": "admit"}

        reason_str = "PII detected: " + ", ".join(entities)

        if self.pii_action == "block":
            return {"verdict": "deny", "reason": reason_str, "entities": entities}

        if self.pii_action == "warn":
            return {"verdict": "admit", "entities": entities}

        # redact: admit, but return the rewritten fields the runner applies pre-signing
        mutations: dict[str, Any] = {}
        if clean_url != resource_url:
            mutations["resource_url"] = clean_url
        if clean_desc != description:
            mutations["description"] = clean_desc
        if clean_reason != reason:
            mutations["reason"] = clean_reason
        if clean_extra != extra:
            mutations["extra"] = clean_extra
        return {"verdict": "admit", "entities": entities, "mutations": mutations}
