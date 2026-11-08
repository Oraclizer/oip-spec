"""Require actual pinned model/source agreement in each declared capability.

The default whole-replay gate remains closed until its real model and ABI
arrive. The finite financial slice is a separate executable capability.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from model_diagnostics import load_allowlist, split_exact
from reference_execution_contract import ROOT, compare_financial, financial_protocol, inputs, observations, sha
from reference_model_artifact import load_reference_files, read_reference_lock, require_bound
from wire_model_artifact import runtime_source_hash


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-output", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--scope", choices=["financial", "full", "same-cut", "all"], default="all")
    ap.add_argument("--polyml")
    ap.add_argument("--artifact-root", type=Path, help="Local content-checked files; no remote fallback")
    args = ap.parse_args()
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    source_hash, _ = runtime_source_hash(ROOT)
    contract = json.loads((ROOT / "tests/reference-replay.contract.json").read_text(encoding="utf-8"))
    lock = read_reference_lock(ROOT / "tests/reference-models.lock.json")
    source_receipt = json.loads((args.source_output / "source-receipt.json").read_text(encoding="utf-8"))
    if source_receipt["status"] != "source-only-pass" or source_receipt["runtime_source_hash"] != source_hash:
        raise ValueError("Fresh actual source execution with this source footprint is required")
    wanted = ["financial", "full", "same-cut"] if args.scope == "all" else [args.scope]
    # Validate every requested capability before downloading/executing any model.
    bindings = {name: require_bound(lock, name, source_hash) for name in wanted}
    if args.scope != "financial" and set(wanted) != {"financial"}:
        raise ValueError("Full replay/current-service executable model and consumer ABI have not been received")
    model, members, identity = bindings["financial"]
    input_raw, rows = inputs(contract)
    if source_receipt["input_sha256"] != sha(input_raw):
        raise ValueError("Source receipt names a different input-only corpus")
    observed_raw, observed = observations(args.source_output / "source/replay/observations.jsonl", rows)
    if source_receipt["observations_sha256"] != sha(observed_raw):
        raise ValueError("Source observations differ from actual source receipt")
    protocol, selected = financial_protocol(rows)
    (out / "input.tsv").write_bytes(protocol)
    bundle = sha(json.dumps({role: member["sha256"] for role, member in members.items()}, sort_keys=True, separators=(",", ":")).encode("ascii"))
    paths = load_reference_files(lock, model, members, identity, ROOT / "target/reference-model" / bundle, args.artifact_root)
    if paths["driver"].read_bytes() != (ROOT / "tests/reference-financial-driver.ML").read_bytes():
        raise ValueError("Pinned driver differs from the reviewed source-footprint consumer")
    poly = args.polyml or os.environ.get("POLYML") or shutil.which("poly")
    if not poly:
        raise ValueError("Pinned standalone Poly/ML is unavailable")
    env = dict(os.environ, OIP_FINITE_MODEL=paths["model"].as_posix())
    argv = [poly, "-q", "--error-exit", "--minheap", "16M", "--maxheap", "512M", "--gcthreads", "1", "--script", str(paths["driver"])]
    result = subprocess.run(argv, input=protocol, capture_output=True, env=env, cwd=ROOT, timeout=300)
    (out / "raw-stdout.log").write_bytes(result.stdout)
    (out / "raw-stderr.log").write_bytes(result.stderr)
    if result.returncode != 0:
        raise ValueError("Actual finite model execution failed; original byte streams are preserved")
    allowed = load_allowlist(paths["diagnostics"], members["model"]["sha256"], members["driver"]["sha256"])
    lines, split_receipt = split_exact(result.stdout, result.stderr, prefixes=["OIP-FINANCIAL-MODEL", "OIP-FINITE"],
        allowlist=allowed, model_path=env["OIP_FINITE_MODEL"], driver_path=str(paths["driver"]))
    (out / "stdout-separation.json").write_text(json.dumps(split_receipt, indent=2) + "\n", encoding="utf-8")
    comparisons = compare_financial(lines, identity, selected, observed)
    mismatch = sum(bool(row["differences"]) for row in comparisons)
    receipt = {"schema": "oip-finite-financial-comparison-v1", "status": "finite-financial-pass" if mismatch == 0 else "finite-financial-mismatch",
        "semantic_scope": identity[2], "conformance_scope": {"seed_rows": 2, "raw_step_rows": 6}, "runtime_source_hash": source_hash,
        "identity": identity, "model_sha256": members["model"]["sha256"], "driver_sha256": members["driver"]["sha256"],
        "input_sha256": sha(input_raw), "protocol_sha256": sha(protocol), "source_observations_sha256": sha(observed_raw),
        "raw_stdout_sha256": sha(result.stdout), "raw_stderr_sha256": sha(result.stderr), "mismatching_rows": mismatch,
        "source_afterstate_entered_model": False, "comparisons": comparisons, "does_not_close": contract["non_claims"]}
    (out / "comparison-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "seed_rows": 2, "raw_step_rows": 6, "mismatching_rows": mismatch}))
    return 0 if mismatch == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
