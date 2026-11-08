"""Default full response consumer with model-issued exact primitive execution."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from response_full import IDENTITY,MetadataError,sender_input,client_input,complete_sender,complete_client
from response_full_artifact import read_lock
from response_full_process import ModelSession,PrimitiveSession
from response_full_compare import compare_full_sender,compare_client
from wire_model_artifact import runtime_source_hash,load_artifact

ROOT=Path(__file__).resolve().parent.parent
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read_rows(path):return [json.loads(line) for line in Path(path).read_bytes().splitlines()]
def paired(inputs,observed):
    if [row["id"] for row in inputs]!=[row["id"] for row in observed] or len({row["id"] for row in inputs})!=len(inputs):raise MetadataError("Source input/output identities are missing/duplicated/reordered")
    return zip(inputs,observed,strict=True)
def checked_source_files(out,fp):
    receipt=json.loads((out/"source-receipt.json").read_text(encoding="utf-8"))
    if receipt["status"]!="source-operation-and-client-fixtures-pass" or receipt["runtime_source_hash"]!=fp:raise MetadataError("Fresh exact source operation/client receipt required")
    for name,pin in receipt["files"].items():
        path=out/name
        if path.stat().st_size!=pin["bytes"] or sha(path)!=pin["sha256"]:raise MetadataError("Source observation differs from its actual receipt")
    return receipt
def check_missing_record(model,result,kind):
    transcript=result["transcript"];tables=transcript.rows()
    chosen=next((index for index,rows in enumerate(tables) if rows),None)
    if chosen is None:raise MetadataError("Required negative control has no needed primitive record")
    altered=[list(rows) for rows in tables];del altered[chosen][-{0:2,1:3,2:4}[chosen]:]
    status,requests=model.sender("Q" if kind=="full" else "q",result["args"],tuple(altered))
    if status!=0 or not requests:raise MetadataError("Removing a used primitive record did not expose missing metadata")
    # The final value call must itself fail, not reinterpret absence as false.
    try:status,_=model.sender("S" if kind=="full" else "B",result["args"],tuple(altered))
    except MetadataError:
        code=model.pipe.close()
        raw=(model.pipe.out/"raw-stdout.log").read_bytes()+(model.pipe.out/"raw-stderr.log").read_bytes()
        if code==0 or not any(marker in raw for marker in [b"OIP_PRIMITIVE_MISSING_SHA256",b"OIP_PRIMITIVE_MISSING_ED25519_SIGN",b"OIP_PRIMITIVE_MISSING_ED25519_VERIFY"]):
            raise MetadataError("Negative backend failure was not the exact missing-primitive abort")
        return {"record_table":chosen,"final_backend_aborted":True,"actual_exit":code,"raw_error_preserved":True}
    if status not in {-1,-2}:raise MetadataError("Missing primitive record became a protocol verdict")
    return {"record_table":chosen,"final_status":status,"missing_is_not_a_protocol_result":True}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-output",type=Path,required=True,help="Actual207 converter/encoder source receipt root")
    ap.add_argument("--operations-output",type=Path,required=True,help="Actual31 original operations and21 current clients")
    ap.add_argument("--output",type=Path,required=True);ap.add_argument("--polyml");ap.add_argument("--artifact-root",type=Path)
    ap.add_argument("--primitive-executable",type=Path,help="Exact local test provider built from the current source")
    ap.add_argument("--cargo",default="cargo");args=ap.parse_args()
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    fp,_=runtime_source_hash(ROOT)
    lock,members=read_lock(ROOT/"tests/wire-response-artifact.lock.json")
    if lock["runtime_source_hash"]!=fp:raise MetadataError("Full current source fingerprint changed")
    identity=IDENTITY+[fp]
    source_receipt=checked_source_files(args.operations_output,fp)
    boundary_receipt=json.loads((args.source_output/"source-receipt.json").read_text(encoding="utf-8"))
    if boundary_receipt["status"]!="source-enum-converter-only-pass" or boundary_receipt["runtime_source_hash"]!=fp:raise MetadataError("Actual207 same-source receipt required")
    folder=args.source_output/"source/result-converter"
    if sha(folder/"egress-inputs.jsonl")!=boundary_receipt["egress_inputs_sha256"] or sha(folder/"egress-observations.jsonl")!=boundary_receipt["egress_observations_sha256"]:raise MetadataError("Actual encoder streams changed")
    boundary_inputs=read_rows(folder/"egress-inputs.jsonl");boundary_observed=read_rows(folder/"egress-observations.jsonl")
    original=args.operations_output/"source/original-operations"
    operation_inputs=read_rows(original/"inputs.jsonl");operation_observed=read_rows(original/"observations.jsonl")
    current_inputs=read_rows(args.operations_output/"source/client-values/inputs.jsonl");current_observed=read_rows(args.operations_output/"source/client-values/observations.jsonl")
    contexts={row["id"]:row for row in read_rows(original/"client-contexts.jsonl")}
    if len(boundary_inputs)!=207 or len(operation_inputs)!=31 or len(current_inputs)!=21:raise MetadataError("Declared original/lower/current case coverage changed")
    classes={name:sum(row["branch_class"]==name for row in operation_inputs) for name in ["caller","noncaller","configured-refusal"]}
    if list(classes.values())!=[15,10,6]:raise MetadataError("Original operation branch partition changed")
    for row in boundary_inputs:sender_input(row,"boundary")
    for row in operation_inputs:sender_input(row,"full")
    bundle=hashlib.sha256(json.dumps(members,sort_keys=True).encode("ascii")).hexdigest()
    files=load_artifact(lock,members,ROOT/"target/full-response-model"/bundle,args.artifact_root)
    if files["driver"].read_bytes()!=(ROOT/"tests/response-full-driver.ML").read_bytes():raise MetadataError("Pinned full driver differs from the reviewed current consumer")
    poly=args.polyml or os.environ.get("POLYML") or shutil.which("poly")
    if not poly:raise MetadataError("Standalone pinned Poly/ML required")
    primitive=args.primitive_executable
    if primitive is None:
        built=subprocess.run([args.cargo,"build","--offline","--locked","--example","wire_primitive_oracle"],cwd=ROOT,capture_output=True,timeout=300)
        (out/"primitive-build-stdout.log").write_bytes(built.stdout);(out/"primitive-build-stderr.log").write_bytes(built.stderr)
        if built.returncode:raise MetadataError("Independent current-source primitive provider did not compile")
        target=Path(os.environ.get("CARGO_TARGET_DIR",ROOT/"target"));primitive=target/"debug/examples"/("wire_primitive_oracle.exe" if os.name=="nt" else "wire_primitive_oracle")
    fixture_keys={bytes(row["config"]["response_key"]).hex():6 for row in boundary_inputs+operation_inputs}
    env=dict(os.environ,OIP_WIRE_RESPONSE_MODEL=files["model"].as_posix())
    provider=None;model=None;negative_model=None;cases=[];negative=None;full_success=None
    def start_model(name):
        return ModelSession([poly,"-q","--error-exit","--minheap","16M","--maxheap","512M","--gcthreads","1","--script",str(files["driver"])],ROOT,env,out/name,
            identity,files["diagnostics"],members["model"]["sha256"],members["driver"]["sha256"],env["OIP_WIRE_RESPONSE_MODEL"],str(files["driver"]))
    try:
        provider=PrimitiveSession([str(primitive)],ROOT,env,out/"primitives",fixture_keys)
        model=start_model("model")
        for kind,input_rows,source_rows in [("full",operation_inputs,operation_observed),("boundary",boundary_inputs,boundary_observed)]:
            for source_input,observed in paired(input_rows,source_rows):
                evaluated=complete_sender(model,source_input,kind,provider)
                differences=compare_full_sender(evaluated,source_input,observed,kind)
                entry={"id":source_input["id"],"scope":kind,"model_status":evaluated["status"],"differences":differences,
                    "model_rows":evaluated["rows"],"model_prefix":evaluated["prefix"],"model_primitive_transcript":evaluated["transcript"].requests}
                if kind=="full" and evaluated["status"]==0:
                    context=dict(contexts[source_input["id"]]);context["network_response_packet_hex"]=""
                    client_rows,expected,_=client_input(context)
                    # This network is exclusively the model's own sender output.
                    client=complete_client(model,client_rows,expected,evaluated["rows"][12],provider)
                    sstatus,srows,cstatus,cvalue=model.combined(evaluated["args"],evaluated["transcript"].rows(),client_rows,client["transcript"].rows()[2])
                    if (sstatus,srows,cstatus,cvalue)!=(evaluated["status"],evaluated["rows"],client["status"],client["result"]):raise MetadataError("Combined entry did not preserve its internal model packet")
                    if observed["client_result"] is None:raise MetadataError("Actual source packet has no current-client observation")
                    entry["differences"].extend(compare_client(client,observed["client_result"]));entry["combined_client"]={"status":cstatus,"value":cvalue}
                    if full_success is None:full_success=(source_input,evaluated)
                cases.append(entry)
        for source_input,observed in paired(current_inputs,current_observed):
            client_rows,expected,network=client_input(source_input)
            client=complete_client(model,client_rows,expected,network,provider)
            cases.append({"id":source_input["id"],"scope":"standalone-current-client","model_status":client["status"],"model_typed_result":client["result"],
                "differences":compare_client(client,observed["actual"]),"model_primitive_transcript":client["transcript"].requests})
        if full_success is None:raise MetadataError("Original caller coverage has no full successful model/source packet control")
        model.close();model=None
        # Separate process: a deliberate missing lookup may correctly abort it.
        negative_model=start_model("model-missing-record")
        negative=check_missing_record(negative_model,full_success[1],"full")
        if not negative.get("final_backend_aborted"):negative_model.close()
        negative_model=None
    finally:
        if model is not None:model.close()
        if negative_model is not None:negative_model.pipe.close()
        if provider is not None:provider.close()
    differences=sum(bool(case["differences"]) for case in cases)
    receipt={"schema":"oip-full-response-comparison-v1","status":"scoped-full-wire-comparison-pass" if not differences else "wire-response-model-mismatch",
        "runtime_source_hash":fp,"identity":identity,"source_receipt_sha256":sha(args.operations_output/"source-receipt.json"),
        "boundary_receipt_sha256":sha(args.source_output/"source-receipt.json"),"model_sha256":members["model"]["sha256"],"driver_sha256":members["driver"]["sha256"],
        "primitive_provider_sha256":sha(primitive),"missing_record_control":negative,"case_count":len(cases),"differences":differences,"cases":cases,
        "source_observed_sender_answers_used_as_model_input":False,"original_operation_partition":classes,"typed_boundary_cases":207,"current_client_cases":21,
        "actual_submit_wait":True,"production_worker_start_executed":False,"mirrored_worker_identity_source_scope":source_receipt["scope"],
        "independent_WitnessHead_Etcd_runtime":False,"product_internal_or_storage_refinement":False,"full_message_correspondence":False}
    (out/"comparison-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":receipt["status"],"cases":len(cases),"mismatches":differences,"full_message_correspondence":False}))
    return 0 if not differences else 1
if __name__=="__main__":
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError,TypeError,subprocess.TimeoutExpired) as error:print(str(error),file=sys.stderr);raise SystemExit(2)
