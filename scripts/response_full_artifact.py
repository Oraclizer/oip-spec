"""Independent full sender/client content pins; old result identity cannot bind."""
from pathlib import Path
import json
import re
from model_diagnostics import digest,require_keys
from response_full import IDENTITY
from wire_model_artifact import verify_blob,load_artifact,runtime_source_hash

NAMES={"model":"oip_wire_response_full.ML","driver":"response-full-driver.ML","origin":"response-full-origin.json","diagnostics":"response-full-diagnostics.json"}
ENTRIES={"queries":"code_response_egress_queries_flat","boundary_queries":"code_response_encode_boundary_queries_flat",
    "sender":"code_response_egress_flat_oracle","boundary_sender":"code_response_encode_boundary_flat_oracle",
    "prefix":"code_response_egress_prefix_flat","boundary_prefix":"code_response_encode_boundary_prefix_flat",
    "client_queries":"code_response_admit_queries_flat","client":"code_response_admit_flat_oracle","combined":"code_response_egress_and_admit_flat_oracle"}
IDENTITY_FUNCTION="OIP_Wire_Response_Boundary.code_response_full_model_identity"

def read_lock(path):
    lock=json.loads(Path(path).read_text(encoding="utf-8"))
    require_keys(lock,["lock_version","binding_status","artifact_transport","repository","wire_schema","abi","scope","entrypoint","natural_refinement",
        "runtime_source_hash","verified_export_sha256","public_namespace","identity_function","input_schema","egress_entries","files"],"full response lock")
    if lock["binding_status"]!="bound":raise ValueError("Full current-source/public-namespace co-export is unbound")
    if lock["lock_version"]!=1 or lock["repository"]!="Oraclizer/formal-verification" or lock["artifact_transport"]!="github-git-blob-v1":raise ValueError("Unsupported full artifact transport")
    if type(lock["wire_schema"]) is not int or [str(lock["wire_schema"]),lock["abi"],lock["scope"],lock["entrypoint"],lock["natural_refinement"]]!=IDENTITY:raise ValueError("Old/unsupported full model identity")
    if lock["identity_function"]!=IDENTITY_FUNCTION or lock["entrypoint"]!="OIP_Wire_Response_Boundary.code_response_egress_flat_oracle":raise ValueError("Full coidentity function/entrypoint mismatch")
    digest(lock["runtime_source_hash"],"full source fingerprint");digest(lock["verified_export_sha256"],"full official export")
    if type(lock["public_namespace"]) is not str or not re.fullmatch(r"Oracle_Interoperability_Protocol(?:/[A-Za-z0-9_.-]+)*",lock["public_namespace"]):raise ValueError("Checked public full namespace required")
    if lock["input_schema"]!="tests/response-full-abi.json" or lock["egress_entries"]!=ENTRIES:raise ValueError("Full original message entries are incomplete")
    members={}
    if type(lock["files"]) is not list or len(lock["files"])!=4:raise ValueError("Four full artifacts required")
    for member in lock["files"]:
        require_keys(member,["role","name","git_blob_sha1","sha256","bytes"],"full content pin")
        role=member["role"]
        if role in members or role not in NAMES or member["name"]!=NAMES[role]:raise ValueError("Unknown full artifact role/name")
        digest(member["sha256"],"full artifact")
        if type(member["git_blob_sha1"]) is not str or re.fullmatch(r"[0-9a-f]{40}",member["git_blob_sha1"]) is None:raise ValueError("Content-only full Git blob pin required")
        if type(member["bytes"]) is not int or not 0<member["bytes"]<=16*1024*1024:raise ValueError("Unbound/excessive full artifact size")
        members[role]=member
    if members["model"]["sha256"]!=lock["verified_export_sha256"]:raise ValueError("Full model is not the received official export")
    return lock,members
