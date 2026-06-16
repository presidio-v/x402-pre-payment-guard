#!/usr/bin/env python3
"""Conformance runner for PRE_PAYMENT_GUARD plugin vectors.

For each vector it re-runs the reference plugin on the vector's input + config
and asserts the verdict envelope is byte-identical to the recorded `expected`.
A pass is an independent offline reproduction of every verdict — no network, no
trust in the recorded values.

    pip install presidio-hardened-x402
    PYTHONPATH=plugins/payload python conformance/verify.py [path/to/vectors.json ...]

Defaults to conformance/payload/vectors.json. Exit 0 on full pass, nonzero with
a per-vector diff otherwise.
"""

import json
import sys
from pathlib import Path

from payload_plugin import PayloadScreenPlugin

REPO = Path(__file__).resolve().parent.parent


def run_vector(vec: dict) -> dict:
    plugin = PayloadScreenPlugin(pii_action=vec["config"]["pii_action"])
    return plugin.screen(vec["input"])


def main(paths: list[str]) -> int:
    suites = paths or [str(REPO / "conformance/payload/vectors.json")]
    failures: list[str] = []
    total = 0

    for sp in suites:
        suite = json.loads(Path(sp).read_text(encoding="utf-8"))
        for vec in suite["vectors"]:
            total += 1
            got = run_vector(vec)
            # Canonical-compare so key order never matters.
            got_c = json.dumps(got, sort_keys=True, ensure_ascii=False)
            exp_c = json.dumps(vec["expected"], sort_keys=True, ensure_ascii=False)
            if got_c != exp_c:
                failures.append(
                    f"{vec['id']}: verdict mismatch\n  expected: {exp_c}\n  computed: {got_c}"
                )

    if failures:
        print(f"FAIL: {len(failures)}/{total} vectors\n" + "\n".join(failures))
        return 1
    print(f"PASS: {total} vectors reproduced byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
