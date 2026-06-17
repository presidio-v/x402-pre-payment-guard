#!/usr/bin/env python3
"""Generate the authorization-plugin conformance vectors by running the
reference plugin on a fixed set of inputs. Re-run after a plugin change:

    PYTHONPATH=plugins/authorization python conformance/authorization/generate.py

Each vector carries the input, its canonical JCS bytes (RFC 8785 safe band:
json.dumps with sorted keys), the per-call ctx (runner-threaded budget + time),
and the expected verdict envelope the plugin returns. `conformance/verify.py`
re-runs the plugin and asserts byte-equality, so a pass is an independent
offline reproduction of every verdict — no network, no JWT library, no wall
clock (verification time is the fixed `now` in ctx).

The Pay Tokens below are minted here with a throwaway secret using the same
stdlib HS256 the plugin verifies with, so the vectors are fully self-contained.
"""

import base64
import hashlib
import hmac
import json
from pathlib import Path

from authorization_plugin import AuthorizationScreenPlugin

# Throwaway secret — conformance only, never a real signing key.
SECRET = "pre-payment-guard-conformance-secret"
# Fixed reference instant so expiry checks are deterministic (2023-11-14T22:13:20Z).
NOW = 1_700_000_000
HOUR = 3600


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint(claims: dict, secret: str = SECRET) -> str:
    """Mint an HS256 Pay Token with the same construction the plugin verifies."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def jcs(obj) -> str:
    # RFC 8785 safe band for ASCII string/dict inputs (matches the payload set).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


TOKEN_VALID = mint({"jti": "pt_valid_001", "exp": NOW + HOUR, "budget_usd": 50.0})
TOKEN_EXPIRED = mint({"jti": "pt_expired_002", "exp": NOW - HOUR, "budget_usd": 50.0})
TOKEN_REVOKED = mint({"jti": "pt_revoked_003", "exp": NOW + HOUR, "budget_usd": 50.0})
# Same claims as the valid token, signed with the WRONG secret -> bad signature.
TOKEN_BADSIG = mint({"jti": "pt_valid_001", "exp": NOW + HOUR, "budget_usd": 50.0}, secret="not-the-secret")

CASES = [
    {
        "id": "valid-within-budget-admit",
        "description": "valid token, spend within remaining budget",
        "config": {"secret": SECRET, "revoked": []},
        "ctx": {"now": NOW, "effective_budget_remaining": 50.0},
        "input": {"amount_usd": 0.10, "payToken": TOKEN_VALID},
    },
    {
        "id": "expired-deny",
        "description": "token past its exp claim",
        "config": {"secret": SECRET, "revoked": []},
        "ctx": {"now": NOW, "effective_budget_remaining": 50.0},
        "input": {"amount_usd": 0.10, "payToken": TOKEN_EXPIRED},
    },
    {
        "id": "revoked-deny",
        "description": "token jti present in the revocation set",
        "config": {"secret": SECRET, "revoked": ["pt_revoked_003"]},
        "ctx": {"now": NOW, "effective_budget_remaining": 50.0},
        "input": {"amount_usd": 0.10, "payToken": TOKEN_REVOKED},
    },
    {
        "id": "bad-signature-deny",
        "description": "token signed with a different secret",
        "config": {"secret": SECRET, "revoked": []},
        "ctx": {"now": NOW, "effective_budget_remaining": 50.0},
        "input": {"amount_usd": 0.10, "payToken": TOKEN_BADSIG},
    },
    {
        "id": "budget-exceeded-deny",
        "description": "valid token but spend exceeds ledger remaining",
        "config": {"secret": SECRET, "revoked": []},
        "ctx": {"now": NOW, "effective_budget_remaining": 1.50},
        "input": {"amount_usd": 3.00, "payToken": TOKEN_VALID},
    },
]


def main() -> None:
    vectors = []
    for c in CASES:
        plugin = AuthorizationScreenPlugin(secret=c["config"]["secret"], revoked=c["config"].get("revoked"))
        verdict = plugin.screen(c["input"], c["ctx"])
        canonical = jcs(c["input"])
        vectors.append(
            {
                "id": c["id"],
                "description": c["description"],
                "config": c["config"],
                "ctx": c["ctx"],
                "declares": plugin.declares,
                "input": c["input"],
                "input_jcs": canonical,
                "input_jcs_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                "expected": verdict,
            }
        )

    suite = {
        "suite": "pre-payment-guard-authorization-v1",
        "plugin": "authorization (LemonCake Pay Token, HS256 JWT, stdlib verify)",
        "vectors": vectors,
    }
    out = Path(__file__).resolve().parent / "vectors.json"
    out.write_text(json.dumps(suite, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} vectors -> {out}")
    for v in vectors:
        print(f"  {v['id']:32} -> {v['expected']}")


if __name__ == "__main__":
    main()
