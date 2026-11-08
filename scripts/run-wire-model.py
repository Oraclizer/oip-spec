"""Run only the independently pinned model and driver with a bounded ML heap."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from wire_model_artifact import read_lock,runtime_source_hash,load_artifact

ROOT=Path(__file__).resolve().parent.parent


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lock",type=Path,default=ROOT/"tests/model-artifact.lock.json")
    ap.add_argument("--artifact-root",type=Path,help="Locally hash-checked export files; no download")
    ap.add_argument("--polyml",help="Explicit standalone Poly/ML executable")
    ap.add_argument("--heap-mb",type=int,default=1024)
    args=ap.parse_args()
    lock,members=read_lock(args.lock)
    observed,_=runtime_source_hash(ROOT)
    if observed!=lock["runtime_source_hash"]:raise ValueError("Runtime/interface source footprint changed; a new verified model pin is required")
    corpus=ROOT/lock["corpus"]["path"]
    raw=corpus.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=lock["corpus"]["sha256"] or len(raw.splitlines())!=lock["corpus"]["rows"]:
        raise ValueError("The full required corpus differs from its lock")
    for line in raw.splitlines():
        row=json.loads(line)
        for field in ("max_frame","max_nesting"):
            value=row["boundary"][field]
            if type(value) is not int or not 0<=value<=(1<<63)-1:
                raise ValueError("Bad adapter metadata in required corpus: "+field+" is outside the common nonnegative signed64 host-size domain")
    if not 64<=args.heap_mb<=2048:raise ValueError("ML heap cap must be between 64 and 2048 MiB")
    poly=args.polyml or os.environ.get("POLYML") or shutil.which("poly")
    if not poly:raise ValueError("Standalone Poly/ML is unavailable")
    bundle={role:member["sha256"] for role,member in members.items()}
    bundle_hash=hashlib.sha256(json.dumps(bundle,sort_keys=True,separators=(",",":")).encode("ascii")).hexdigest()
    cache=ROOT/"target/wire-model"/bundle_hash
    files=load_artifact(lock,members,cache,args.artifact_root)
    if files["driver"].read_bytes()!=(ROOT/"tests/wire-values-driver.ML").read_bytes():
        raise ValueError("Pinned typed driver differs from the reviewed source consumer")
    argv=[sys.executable,str(ROOT/"scripts/jsonl-mirror-adapter.py"),"--model-file",str(files["model"]),
          "--model-sha256",members["model"]["sha256"],"--expected-runtime-source-hash",observed,
          "--expected-schema",str(lock["wire_schema"]),"--expected-abi",lock["abi"],"--expected-scope",lock["scope"],
          "--expected-entrypoint",lock["entrypoint"],"--expected-natural-refinement",lock["natural_refinement"],
          "--driver-file",str(files["driver"]),"--driver-sha256",members["driver"]["sha256"],
          "--diagnostics-file",str(files["diagnostics"]),"--raw-output-dir",str(cache/"streams"/str(time.time_ns())),
          "--backend",poly,"-q","--error-exit","--minheap","16M","--maxheap",str(args.heap_mb)+"M",
          "--gcthreads","1","--script",str(files["driver"])]
    # stdin and stdout go straight through the data serializer. Classification
    # is performed only by the hash-checked exported ML function.
    return subprocess.run(argv,cwd=ROOT,timeout=330).returncode


if __name__=="__main__":
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError,json.JSONDecodeError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(2)
