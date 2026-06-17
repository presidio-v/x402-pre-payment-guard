"""Reference PRE_PAYMENT_GUARD plugin: authorization / budget screening.

Implements the plugin contract from ``spec/pre-payment-guard.md``:

    declares: list[str]                      # input fields this plugin reads
    keys_off_raw: list[str]                  # declared fields a security key uses RAW
    screen(input, ctx) -> verdict            # the verdict envelope

It answers the *authorization* plane's question — "may I spend this, within
budget, with a valid token?" — over a LemonCake **Pay Token**: an HS256 JWT
carrying the budget and expiry as claims so the check is offline (no pre-signing
network hop). Origin: LemonCake, per x402-foundation/x402#2533.

Two facts the screen needs come from different places, mirroring how the live
gateway works:

* the **token** (``payToken``) and the **spend** (``amount_usd``) are *input*
  fields the plugin declares;
* the **live remaining budget** (``effective_budget_remaining``) is threaded by
  the runner through ``ctx`` — it is the ledger's truth, not a token claim, so a
  multi-call token's remaining headroom composes across plugins without a
  re-fetch. ``now`` (verification time) is threaded the same way so the screen is
  a pure, deterministic function of its inputs — which is what makes its verdicts
  byte-reproducible in the conformance set.

The token claim ``budget_usd`` records the *original* cap at mint time and is
informational here; enforcement is against ``ctx.effective_budget_remaining``.

HS256 verification is implemented over the stdlib (``hmac``/``hashlib``) rather
than a JWT library, so the plugin has **no third-party dependency** and the
expiry check reads the runner-supplied ``now`` instead of a wall clock — both
necessary for an offline, deterministic conformance reproduction.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


class InvalidToken(Exception):
    """Raised when a Pay Token's structure or signature does not verify."""


def _decode_hs256(token: str, secret: str) -> dict[str, Any]:
    """Verify an HS256 JWT signature and return its claims.

    Pure stdlib, constant-time signature compare. Raises ``InvalidToken`` on any
    structural or signature failure — the caller maps that to a ``deny`` verdict.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as e:
        raise InvalidToken("malformed token: expected three dot-separated segments") from e

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as e:  # noqa: BLE001 - any decode failure is an invalid token
        raise InvalidToken("malformed token header") from e
    if header.get("alg") != "HS256":
        raise InvalidToken(f"unexpected alg {header.get('alg')!r}; only HS256 accepted")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig, _b64url_decode(sig_b64)):
        raise InvalidToken("signature does not verify")

    try:
        return json.loads(_b64url_decode(payload_b64))
    except Exception as e:  # noqa: BLE001
        raise InvalidToken("malformed token payload") from e


class AuthorizationScreenPlugin:
    """Token / budget screen over an x402 payment, on a LemonCake Pay Token.

    Outcomes map onto the common verdict envelope. The authorization plane never
    rewrites the payload, so it never populates ``mutations`` — same envelope as
    every other plugin, ``mutations`` simply omitted:

    * valid token, spend within remaining budget -> bare ``admit``
    * expired / revoked / bad signature / over budget -> ``deny`` + ``reason``
      + an ``entities`` finding ``token_state:<state>`` so the precise cause
      (the field LemonCake's gateway returns as ``token_state``) survives into
      the common envelope.
    """

    name = "authorization"
    # Input fields this plugin reads. effective_budget_remaining and now arrive
    # via ctx (runner-threaded), so they are not declared input fields.
    declares = ["amount_usd", "payToken"]
    # Token verification keys off the token claims, not mutable payload fields,
    # so no upstream plugin's mutation can change what this screen authorizes.
    keys_off_raw: list[str] = []

    def __init__(self, secret: str, revoked: list[str] | None = None) -> None:
        if not secret:
            raise ValueError("secret is required to verify Pay Token signatures")
        self.secret = secret
        self.revoked = set(revoked or [])

    @staticmethod
    def _deny(state: str, reason: str) -> dict[str, Any]:
        return {"verdict": "deny", "reason": reason, "entities": [f"token_state:{state}"]}

    def screen(self, input: dict[str, Any], ctx: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = ctx or {}
        token = input.get("payToken", "") or ""
        amount = float(input.get("amount_usd", 0) or 0)
        now = int(ctx.get("now", 0) or 0)
        remaining = float(ctx.get("effective_budget_remaining", 0) or 0)

        if not token:
            return self._deny("missing", "no pay token presented")

        try:
            claims = _decode_hs256(token, self.secret)
        except InvalidToken as e:
            return self._deny("invalid_signature", f"pay token rejected: {e}")

        jti = claims.get("jti")
        if jti is not None and jti in self.revoked:
            return self._deny("revoked", "pay token has been revoked")

        exp = claims.get("exp")
        if exp is not None and now >= int(exp):
            return self._deny("expired", "pay token expired")

        if amount > remaining:
            return self._deny(
                "budget_exceeded",
                f"spend {amount:.2f} exceeds remaining budget {remaining:.2f}",
            )

        return {"verdict": "admit"}
