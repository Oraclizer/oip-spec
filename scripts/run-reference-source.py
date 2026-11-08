"""Run the actual Rust source producers and preserve their raw streams."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from reference_execution_contract import ROOT, inputs, observations, sha
from wire_model_artifact import runtime_source_hash

TEST_ROOT = "authority::recovery::wire::ed25519::vector_tests::"
TESTS = [("replay", TEST_ROOT + "reference_execution_trace::reference_source_trace_replays_input_only_fifteen_rows"),
         ("same-cut", TEST_ROOT + "reference_execution_trace::reference_source_same_cut_refusal_then_normal_reserve"),
         ("signed-response", TEST_ROOT + "signed_response_fixture::reference_signed_response_positive_and_byte_precedence_semantic_negative")]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True, help="Fresh output directory")
    ap.add_argument("--cargo", default="cargo")
    args = ap.parse_args()
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    contract = json.loads((ROOT / "tests/reference-replay.contract.json").read_text(encoding="utf-8"))
    replay_raw, replay_rows = inputs(contract)
    same_raw, same_rows = inputs(contract, "same_cut_input")
    source_hash, _ = runtime_source_hash(ROOT)
    runs = []
    for kind, test in TESTS:
        argv = [args.cargo, "test", "--locked", test, "--", "--exact", "--nocapture"]
        env = dict(os.environ, OIP_REFERENCE_OUTPUT_DIR=str(out / "source"))
        start = time.monotonic()
        result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, timeout=300)
        (out / (kind + "-stdout.log")).write_bytes(result.stdout)
        (out / (kind + "-stderr.log")).write_bytes(result.stderr)
        row = {"scope": kind, "test": test, "argv": argv, "exit": result.returncode,
               "seconds": time.monotonic() - start, "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)}
        runs.append(row)
        (out / "execution-attempts.json").write_text(json.dumps(runs, indent=2) + "\n", encoding="utf-8")
        if result.returncode != 0:
            raise ValueError("Actual Rust source producer failed: " + kind + "; raw streams preserved")
        exact = b"test " + test.encode("ascii") + b" ... ok"
        if exact not in result.stdout or re.search(rb"test result: ok\. 1 passed; 0 failed;", result.stdout) is None:
            raise ValueError("Rust did not report the one exact required producer test")
    raw_replay, replay = observations(out / "source/replay/observations.jsonl", replay_rows)
    raw_same, same = observations(out / "source/same-cut/observations.jsonl", same_rows)
    signed_path = out / "source/signed-response/observations.jsonl"
    signed_raw = signed_path.read_bytes()
    signed = [json.loads(line) for line in signed_raw.splitlines()]
    fixture = json.loads((ROOT / "tests/vectors/signed-response-cases.json").read_text(encoding="utf-8"))
    if [row["id"] for row in signed] != [row["id"] for row in fixture["cases"]] or any(row["semantic_assertion_holds"] is not True for row in signed):
        raise ValueError("Signed response fixture did not produce every exact semantic observation")
    receipt = {"schema": "oip-reference-source-receipt-v1", "status": "source-only-pass", "runtime_source_hash": source_hash,
        "input_sha256": sha(replay_raw), "input_rows": 15, "genesis_rows": 2, "stimulus_rows": 13,
        "observations_sha256": sha(raw_replay), "observation_rows": len(replay),
        "same_cut_input_sha256": sha(same_raw), "same_cut_rows": 3, "same_cut_observations_sha256": sha(raw_same),
        "same_cut_observation_rows": len(same), "signed_response_sha256": sha(signed_raw), "signed_response_cases": len(signed),
        "model_executions": 0, "does_not_close": contract["non_claims"], "runs": runs}
    (out / "source-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "replay": "2 genesis + 13 stimuli", "same_cut": "1 genesis + 2 stimuli", "signed_response_cases": len(signed)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
