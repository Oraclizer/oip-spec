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
ORIGINAL = "source/original-operations"
CURRENT = "source/client-values"
SOURCE_FILES = {
    f"{ORIGINAL}/client-contexts.jsonl",
    f"{ORIGINAL}/client-inputs.jsonl",
    f"{ORIGINAL}/inputs.jsonl",
    f"{ORIGINAL}/observations.jsonl",
    f"{ORIGINAL}/scope.json",
    f"{CURRENT}/inputs.jsonl",
    f"{CURRENT}/observations.jsonl",
    f"{CURRENT}/scope.json",
}


def parse_rows(contents):
    return [json.loads(line) for line in contents.splitlines()]


def paired(inputs,observed):
    if [row["id"] for row in inputs]!=[row["id"] for row in observed] or len({row["id"] for row in inputs})!=len(inputs):raise MetadataError("Source input/output identities are missing/duplicated/reordered")
    return zip(inputs,observed,strict=True)
def checked_source_files(out, fp):
    receipt_bytes = (out / "source-receipt.json").read_bytes()
    receipt = json.loads(receipt_bytes)
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "oip-full-wire-source-receipt-v1"
            or receipt.get("status") != "source-operation-and-client-fixtures-pass"
            or receipt.get("runtime_source_hash") != fp):
        raise MetadataError("Fresh exact source operation/client receipt required")
    pins = receipt.get("files")
    if not isinstance(pins, dict) or set(pins) != SOURCE_FILES:
        raise MetadataError("Source receipt file set must match the complete fixture streams")
    streams = {}
    for name, pin in pins.items():
        if not isinstance(pin, dict) or set(pin) != {"bytes", "sha256"} or type(pin["bytes"]) is not int:
            raise MetadataError(f"Invalid source receipt pin for {name}")
        contents = (out / name).read_bytes()
        if len(contents) != pin["bytes"] or hashlib.sha256(contents).hexdigest() != pin["sha256"]:
            raise MetadataError(f"Source observation differs from its actual receipt: {name}")
        streams[name] = contents
    if json.loads(streams[f"{ORIGINAL}/scope.json"]) != receipt.get("scope"):
        raise MetadataError("Source receipt scope differs from the pinned fixture scope")
    return receipt, hashlib.sha256(receipt_bytes).hexdigest(), streams


def fixture_varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            break
        octet = data[offset]
        offset += 1
        if shift == 63 and octet > 1:
            break
        value |= (octet & 127) << shift
        if octet < 128:
            return value, offset
    raise MetadataError("Truncated or out-of-range operation fixture varint")


def fixture_field(data, expected_tag, expected_kind):
    """Read one fixture identity field. Protocol admission runs separately."""
    matching = []
    offset = 0
    while offset < len(data):
        key, offset = fixture_varint(data, offset)
        tag, kind = key >> 3, key & 7
        if kind == 0:
            value, offset = fixture_varint(data, offset)
        elif kind in (1, 2):
            size, offset = (8, offset) if kind == 1 else fixture_varint(data, offset)
            end = offset + size
            if end > len(data):
                raise MetadataError("Truncated operation fixture field")
            value = data[offset:end]
            offset = end
        else:
            raise MetadataError("Unexpected operation fixture wire type")
        if tag == expected_tag:
            if kind != expected_kind:
                raise MetadataError("Unexpected operation fixture identity field type")
            matching.append(value)
    if len(matching) != 1:
        raise MetadataError("Missing or ambiguous operation fixture identity field")
    return matching[0]


def check_operation_fixtures(rows, operations):
    expected = {}
    for operation in operations:
        family, opcode = operation["family"], operation["opcode"]
        if not operation["reference_accepts"]:
            branch = "configured-refusal"
        else:
            branch = "caller" if operation["call"] else "noncaller"
        expected[f"operation-{family}-{opcode}"] = family, opcode, branch
    if [row["id"] for row in rows] != list(expected):
        raise MetadataError("Original operation fixtures differ from the operation table")
    classes = dict.fromkeys(("caller", "noncaller", "configured-refusal"), 0)
    for row in rows:
        family, opcode, branch = expected[row["id"]]
        packet = bytes.fromhex(row["raw_original_packet_hex"])
        core = fixture_field(packet, 1, 2)
        actual_family = fixture_field(core, 12, 0)
        body = fixture_field(core, 15 + actual_family, 2)
        actual_opcode = fixture_field(body, 1, 0)
        if ((row["family"], row["opcode"], row["branch_class"]) != (family, opcode, branch)
                or (actual_family, actual_opcode) != (family, opcode)):
            raise MetadataError(f"Original operation fixture does not match its packet and table identity: {row['id']}")
        classes[branch] += 1
    return classes


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
    ap.add_argument("--operations-output",type=Path,required=True,help="Actual33 original operations and21 current clients")
    ap.add_argument("--output",type=Path,required=True);ap.add_argument("--polyml");ap.add_argument("--artifact-root",type=Path)
    ap.add_argument("--primitive-executable",type=Path,help="Exact local test provider built from the current source")
    ap.add_argument("--cargo",default="cargo");args=ap.parse_args()
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    fp,_=runtime_source_hash(ROOT)
    lock,members=read_lock(ROOT/"tests/wire-response-artifact.lock.json")
    if lock["runtime_source_hash"]!=fp:raise MetadataError("Full current source fingerprint changed")
    identity=IDENTITY+[fp]
    source_receipt, source_receipt_hash, source_streams = checked_source_files(args.operations_output, fp)
    boundary_receipt_bytes = (args.source_output / "source-receipt.json").read_bytes()
    boundary_receipt = json.loads(boundary_receipt_bytes)
    if boundary_receipt["status"]!="source-enum-converter-only-pass" or boundary_receipt["runtime_source_hash"]!=fp:raise MetadataError("Actual207 same-source receipt required")
    folder=args.source_output/"source/result-converter"
    boundary_streams = {}
    for name in ("inputs", "observations"):
        contents = (folder / f"egress-{name}.jsonl").read_bytes()
        if hashlib.sha256(contents).hexdigest() != boundary_receipt[f"egress_{name}_sha256"]:
            raise MetadataError(f"Actual encoder {name} stream changed")
        boundary_streams[name] = parse_rows(contents)
    boundary_inputs = boundary_streams["inputs"]
    boundary_observed = boundary_streams["observations"]
    operation_inputs = parse_rows(source_streams[f"{ORIGINAL}/inputs.jsonl"])
    operation_observed = parse_rows(source_streams[f"{ORIGINAL}/observations.jsonl"])
    current_inputs = parse_rows(source_streams[f"{CURRENT}/inputs.jsonl"])
    current_observed = parse_rows(source_streams[f"{CURRENT}/observations.jsonl"])
    contexts = {row["id"]: row for row in parse_rows(source_streams[f"{ORIGINAL}/client-contexts.jsonl"])}
    if len(boundary_inputs)!=207 or len(operation_inputs)!=33 or len(current_inputs)!=21:raise MetadataError("Declared original/lower/current case coverage changed")
    operations = json.loads((ROOT / "spec/operations.json").read_bytes())["operations"]
    classes = check_operation_fixtures(operation_inputs, operations)
    if list(classes.values())!=[17,11,5]:raise MetadataError("Original operation branch partition changed")
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
        "runtime_source_hash":fp,"identity":identity,"source_receipt_sha256":source_receipt_hash,
        "boundary_receipt_sha256":hashlib.sha256(boundary_receipt_bytes).hexdigest(),"model_sha256":members["model"]["sha256"],"driver_sha256":members["driver"]["sha256"],
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
