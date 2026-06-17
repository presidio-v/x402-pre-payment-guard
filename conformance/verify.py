#!/usr/bin/env python3
"""Conformance runner for PRE_PAYMENT_GUARD plugin vectors.

For each vector it re-runs the reference plugin on the vector's input + config
and asserts the verdict envelope is byte-identical to the recorded `expected`.
A pass is an independent offline reproduction of every verdict — no network, no
trust in the recorded values.

    # payload suite (needs the presidio plugin on the path):
    pip install presidio-hardened-x402
    PYTHONPATH=plugins/payload python conformance/verify.py conformance/payload/vectors.json

    # authorization suite (stdlib only, no install):
    PYTHONPATH=plugins/authorization python conformance/verify.py conformance/authorization/vectors.json

    # both (each plugin dir on the path):
    PYTHONPATH=plugins/payload:plugins/authorization python conformance/verify.py \
        conformance/payload/vectors.json conformance/authorization/vectors.json

With no path argument it runs every conformance/*/vectors.json it can find. Each
suite is dispatched to its plugin by the suite's own name, so a suite whose
plugin module is not importable (e.g. payload without presidio installed) is
reported as skipped rather than failing the run. Exit 0 on full pass, nonzero
with a per-vector diff otherwise.
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _run_payload(vec: dict) -> dict:
    from payload_plugin import PayloadScreenPlugin

    plugin = PayloadScreenPlugin(pii_action=vec["config"]["pii_action"])
    return plugin.screen(vec["input"])


def _run_authorization(vec: dict) -> dict:
    from authorization_plugin import AuthorizationScreenPlugin

    cfg = vec["config"]
    plugin = AuthorizationScreenPlugin(secret=cfg["secret"], revoked=cfg.get("revoked"))
    return plugin.screen(vec["input"], vec.get("ctx"))


# Dispatch a suite to its reference plugin by the suite's declared name. Adding a
# plugin = one line here + its vectors.json; the runner stays plugin-agnostic.
RUNNERS = {
    "pre-payment-guard-payload-v1": _run_payload,
    "pre-payment-guard-authorization-v1": _run_authorization,
}


def run_vector(suite_name: str, vec: dict) -> dict:
    return RUNNERS[suite_name](vec)


def main(paths: list[str]) -> int:
    suites = paths or sorted(str(p) for p in REPO.glob("conformance/*/vectors.json"))
    failures: list[str] = []
    total = 0

    skipped: list[str] = []
    for sp in suites:
        suite = json.loads(Path(sp).read_text(encoding="utf-8"))
        suite_name = suite["suite"]
        if suite_name not in RUNNERS:
            skipped.append(f"{sp}: no runner for suite {suite_name!r}")
            continue
        try:
            # Probe importability once so a missing optional dep skips the suite
            # instead of crashing the whole run.
            run_vector(suite_name, suite["vectors"][0])
        except ImportError as e:
            skipped.append(f"{suite_name}: plugin not importable ({e})")
            continue
        for vec in suite["vectors"]:
            total += 1
            got = run_vector(suite_name, vec)
            # Canonical-compare so key order never matters.
            got_c = json.dumps(got, sort_keys=True, ensure_ascii=False)
            exp_c = json.dumps(vec["expected"], sort_keys=True, ensure_ascii=False)
            if got_c != exp_c:
                failures.append(
                    f"{vec['id']}: verdict mismatch\n  expected: {exp_c}\n  computed: {got_c}"
                )

    for s in skipped:
        print(f"SKIP: {s}")
    if failures:
        print(f"FAIL: {len(failures)}/{total} vectors\n" + "\n".join(failures))
        return 1
    print(f"PASS: {total} vectors reproduced byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
