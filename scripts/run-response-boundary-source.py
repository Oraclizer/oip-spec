"""Record actual source enum inputs and converter outputs as separate streams."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from wire_model_artifact import runtime_source_hash
ROOT=Path(__file__).resolve().parent.parent
TEST="authority::recovery::wire::response::vector_tests::boundary_values::actual_typed_response_result_boundary_values"

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--output",type=Path,required=True);ap.add_argument("--cargo",default="cargo");args=ap.parse_args()
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ,OIP_REFERENCE_OUTPUT_DIR=str(out/"source"))
    argv=[args.cargo,"test","--locked","--lib",TEST,"--","--exact","--nocapture"]
    start=time.monotonic();result=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,timeout=300)
    (out/"raw-stdout.log").write_bytes(result.stdout);(out/"raw-stderr.log").write_bytes(result.stderr)
    if result.returncode or b"test result: ok. 1 passed; 0 failed;" not in result.stdout:raise ValueError("Actual source converter fixture did not run successfully")
    path=out/"source/result-converter"
    source=json.loads((path/"scope.json").read_text(encoding="utf-8"))
    inputs=[json.loads(line) for line in (path/"inputs.jsonl").read_bytes().splitlines()]
    observed=[json.loads(line) for line in (path/"observations.jsonl").read_bytes().splitlines()]
    if len(inputs)!=207 or [row["id"] for row in inputs]!=[row["id"] for row in observed]:raise ValueError("Missing/duplicate/reordered converter observations")
    egress_inputs=[json.loads(line) for line in (path/"egress-inputs.jsonl").read_bytes().splitlines()]
    egress_observed=[json.loads(line) for line in (path/"egress-observations.jsonl").read_bytes().splitlines()]
    if [row["id"] for row in inputs]!=[row["id"] for row in egress_inputs] or [row["id"] for row in inputs]!=[row["id"] for row in egress_observed]:raise ValueError("Incomplete actual encoder boundary observations")
    footprint,_=runtime_source_hash(ROOT)
    sha=lambda raw:hashlib.sha256(raw).hexdigest()
    receipt={"status":"source-enum-converter-only-pass","runtime_source_hash":footprint,"argv":argv,"exit":result.returncode,
        "seconds":time.monotonic()-start,"rows":207,"production_dispatcher_provenance":False,"source_scope":source,"model_executions":0,
        "inputs_sha256":sha((path/"inputs.jsonl").read_bytes()),"observations_sha256":sha((path/"observations.jsonl").read_bytes()),
        "raw_stdout_sha256":sha(result.stdout),"raw_stderr_sha256":sha(result.stderr),
        "egress_inputs_sha256":sha((path/"egress-inputs.jsonl").read_bytes()),"egress_observations_sha256":sha((path/"egress-observations.jsonl").read_bytes()),
        "egress_scope":"Actual encode_response after typed enum boundary; dispatcher/original-preflight provenance separate",
        "raw_boundary_values_sha256":sha((path/"raw-boundary-values.jsonl").read_bytes())}
    (out/"source-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":receipt["status"],"rows":207,"model_executions":0}))

if __name__=="__main__":
    try:main()
    except (ValueError,OSError,KeyError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr);raise SystemExit(2)
