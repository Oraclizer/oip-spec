"""Record actual original-operation and current-client inputs before comparison."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from wire_model_artifact import runtime_source_hash
ROOT=Path(__file__).resolve().parent.parent
TESTS={"operations":"authority::recovery::wire::ed25519::dispatch::source_tests::actual_submit_and_mirrored_worker_original_operation_partition",
       "client":"authority::recovery::wire::ed25519::vector_tests::client_value_tests::actual_current_client_known_unknown_and_precedence_inputs"}
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--output",type=Path,required=True);ap.add_argument("--cargo",default="cargo");args=ap.parse_args()
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False);runs=[]
    for name,test in TESTS.items():
        argv=[args.cargo,"test","--offline","--locked","--lib",test,"--","--exact","--nocapture"]
        env=dict(os.environ,OIP_REFERENCE_OUTPUT_DIR=str(out/"source"));start=time.monotonic()
        result=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,timeout=600)
        (out/(name+"-stdout.log")).write_bytes(result.stdout);(out/(name+"-stderr.log")).write_bytes(result.stderr)
        runs.append({"name":name,"argv":argv,"exit":result.returncode,"seconds":time.monotonic()-start,"stdout_sha256":sha(out/(name+"-stdout.log")),"stderr_sha256":sha(out/(name+"-stderr.log"))})
        (out/"attempts.json").write_text(json.dumps(runs,indent=2)+"\n",encoding="utf-8")
        if result.returncode or ("test "+test+" ... ok").encode() not in result.stdout:raise ValueError("Actual source fixture did not run successfully: "+name)
    source=out/"source";ops=source/"original-operations";clients=source/"client-values"
    metadata=json.loads((ops/"scope.json").read_text(encoding="utf-8"))
    if [metadata[key] for key in ["caller","noncaller","configured_refusal"]]!=[15,10,6]:raise ValueError("Original operation partition changed")
    files={}
    for folder in [ops,clients]:
        for path in sorted(folder.iterdir()):
            if path.is_file():files[path.relative_to(out).as_posix()]={"sha256":sha(path),"bytes":path.stat().st_size}
    fp,_=runtime_source_hash(ROOT)
    receipt={"schema":"oip-full-wire-source-receipt-v1","status":"source-operation-and-client-fixtures-pass","runtime_source_hash":fp,
        "operation_partition":{"caller":15,"noncaller":10,"configured_refusal":6},"current_client_cases":21,"scope":metadata,"files":files,"runs":runs,
        "production_dispatcher_start_worker_executed":False,"actual_submit_wait_message_calls":True,"worker_body_text_identity_required":True,
        "independent_WitnessHead_Etcd_runtime":False,"model_executions":0,"full_message_correspondence":False}
    (out/"source-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":receipt["status"],"partition":[15,10,6],"clients":21,"model_executions":0}))
if __name__=="__main__":
    try:main()
    except (ValueError,OSError,KeyError,subprocess.TimeoutExpired) as error:print(str(error),file=sys.stderr);raise SystemExit(2)
