"""Serialize schema-1 JSONL to the exported SML model; no wire rules here.

The backend must run mirror-driver.ML with OIP_WIRE_MODEL pointing at the
hash-checked export.  An unfinished model result is an error by default.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from model_diagnostics import load_allowlist,split_exact
from wire_values import schema,validate_result
import re


BOUNDARY_FIELDS = (
    "deployment", "source", "target", "principal", "key_id", "epoch", "route_scope", "now",
    "asset_ttl_floor", "future_skew", "max_frame", "version_floor", "max_nesting",
)
REFUSALS = {54, 70, 71, 72, 73, 74, 75, 76}


def integer(value):
    if type(value) is not int:
        raise ValueError("Schema integer required; floats and booleans are not integers")
    return "~" + str(-value) if value < 0 else str(value)


def integers(values):
    if not isinstance(values, list):
        raise ValueError("Schema integer array required")
    return ",".join(integer(value) for value in values)


def boolean(value):
    if type(value) is not bool:
        raise ValueError("Schema boolean required")
    return "1" if value else "0"


def octets(value):
    if not isinstance(value, str):
        raise ValueError("Hexadecimal byte string required")
    return integers(list(bytes.fromhex(value)))


def encode_row(row):
    if type(row.get("schema")) is not int or row.get("schema") != 1 or row.get("layer") != "transport":
        raise ValueError("Only schema 1 transport inputs are supported")
    if row.get("threshold_supported") is not False:
        raise ValueError("The source transport profile has threshold support disabled")
    identifier = row["id"]
    if not isinstance(identifier, str):
        raise ValueError("A string id is required")
    ident = base64.urlsafe_b64encode(identifier.encode("utf-8")).decode("ascii")
    scope = row["boundary"]
    for field in ("max_frame", "max_nesting"):
        value = scope[field]
        if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
            raise ValueError("Bad adapter metadata: " + field + " is outside the common nonnegative signed64 host-size domain")
    profile = row["profile"]
    prior = row["prior_binding"]
    # expected/family/opcode/reference_accepts/seed are deliberately never read.
    fields = [
        ident, octets(row["packet_hex"]), integers([scope[key] for key in BOUNDARY_FIELDS]),
        integer(profile["version"]), integers(profile["families"]), integers(profile["atomicities"]),
        integers(profile["schemes"]), boolean(scope["critical_allowed"]), boolean(row["signature_valid"]),
        boolean(row["attestation_valid"]), "0" if prior is None else "1", "" if prior is None else octets(prior),
    ]
    return ident, "\t".join(fields)


def decode_output(line, ids):
    fields=line.rstrip("\r\n").split("\t")
    if len(fields)!=10 or fields[0]!="OIP-MIRROR":raise ValueError("Wrong typed model output field count")
    _,ident,status_text,present,binding,summary_present,typed,core,preimage,key=fields
    if ident not in ids:raise ValueError("Unknown model output id")
    if present not in {"0","1"} or summary_present not in {"0","1"}:raise ValueError("Bad model output presence")
    def octet_hex(text):
        parts=[] if text=="" else text.split(",")
        if any(re.fullmatch(r"0|[1-9][0-9]*",value) is None for value in parts):raise ValueError("Noncanonical model octet integer")
        values=[int(value) for value in parts]
        if any(not 0<=value<=255 for value in values):raise ValueError("Non-octet model output")
        return bytes(values).hex()
    retained=octet_hex(binding) if present=="1" else None
    if present=="0" and binding:raise ValueError("Absent binding has bytes")
    status=int(status_text.replace("~","-",1))
    if status==0:verdict="accept:first"
    elif status==1:verdict="accept:identical"
    elif status in REFUSALS:verdict=status
    else:raise ValueError("Unknown/Unsupported/Pending typed model status")
    accepted=status in {0,1}
    if summary_present!=("1" if accepted else "0"):raise ValueError("Missing or fabricated typed value view")
    if not accepted and any([typed,core,preimage,key]):raise ValueError("Refused model row has accepted observations")
    row={"id":ids[ident],"verdict":verdict,"retained_binding":retained,
         "reencoded_core_hex":octet_hex(core) if accepted else None,
         "signing_preimage_hex":octet_hex(preimage) if accepted else None,
         "transport_key_ir":key.split(",") if accepted else None,
         "typed_operand_ir":typed.split(",") if accepted else None}
    validate_result(row,schema())
    return ident,row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-file", required=True)
    ap.add_argument("--model-sha256", required=True, help="SHA-256 from the verified kernel export receipt")
    ap.add_argument("--expected-runtime-source-hash", required=True)
    ap.add_argument("--expected-schema", type=int, required=True)
    ap.add_argument("--expected-abi", required=True)
    ap.add_argument("--expected-scope", required=True)
    ap.add_argument("--expected-entrypoint", required=True)
    ap.add_argument("--expected-natural-refinement", required=True)
    ap.add_argument("--driver-file", required=True)
    ap.add_argument("--driver-sha256", required=True)
    ap.add_argument("--diagnostics-file", required=True)
    ap.add_argument("--raw-output-dir", type=Path, required=True)
    ap.add_argument("--backend", nargs=argparse.REMAINDER, required=True)
    args = ap.parse_args()
    if not args.backend:
        ap.error("An explicit backend argv is required")
    model = Path(args.model_file)
    if not model.is_file():
        ap.error("The exported model file is missing")
    if hashlib.sha256(model.read_bytes()).hexdigest() != args.model_sha256.lower():
        ap.error("The exported model bytes do not match the verified receipt")
    if hashlib.sha256(Path(args.driver_file).read_bytes()).hexdigest()!=args.driver_sha256:
        raise ValueError("Pinned driver SHA-256 mismatch")
    allowed=load_allowlist(args.diagnostics_file,args.model_sha256,args.driver_sha256)
    args.raw_output_dir.mkdir(parents=True,exist_ok=False)
    rows = [json.loads(line) for line in sys.stdin if line.strip()]
    if not rows:
        raise ValueError("The mirror requires a nonempty input corpus")
    ids, lines = {}, []
    for row in rows:
        ident, line = encode_row(row)
        if ident in ids:
            raise ValueError("Duplicate input id")
        ids[ident] = row["id"]
        lines.append(line)
    env = dict(os.environ, OIP_WIRE_MODEL=model.resolve().as_posix())
    result = subprocess.run(args.backend, input=("\n".join(lines) + "\n").encode("ascii"), capture_output=True, env=env, timeout=300)
    (args.raw_output_dir/"raw-stdout.log").write_bytes(result.stdout)
    (args.raw_output_dir/"raw-stderr.log").write_bytes(result.stderr)
    if result.returncode:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.write(result.stdout[-4000:])
        return result.returncode
    outputs = {}
    metadata_seen = False
    expected_metadata = ["OIP-MODEL", str(args.expected_schema), args.expected_abi, args.expected_scope,
                         args.expected_entrypoint, args.expected_natural_refinement, args.expected_runtime_source_hash]
    protocol,diagnostic_receipt=split_exact(result.stdout,result.stderr,prefixes=["OIP-MODEL","OIP-MIRROR"],
        allowlist=allowed,model_path=env["OIP_WIRE_MODEL"],driver_path=args.driver_file)
    (args.raw_output_dir/"stdout-separation.json").write_text(json.dumps(diagnostic_receipt,indent=2)+"\n",encoding="utf-8")
    for line in protocol:
        if line.startswith("OIP-MODEL\t"):
            if metadata_seen or line.rstrip("\r\n").split("\t") != expected_metadata:
                raise ValueError("Duplicate or mismatched exported model identity")
            metadata_seen = True
            continue
        if line.startswith("OIP-MIRROR\t") and not metadata_seen:
            raise ValueError("The exported model identity must precede every result")
        decoded = decode_output(line, ids)
        if decoded is None:
            if line.startswith("OIP-"):
                raise ValueError("Unknown model protocol record")
            raise ValueError("Unknown model protocol line")
        ident, row = decoded
        if ident in outputs:
            raise ValueError("Duplicate output id")
        outputs[ident] = row
    if not metadata_seen:
        raise ValueError("The exported model did not report its source/schema/ABI identity")
    if set(outputs) != set(ids):
        raise ValueError("The model did not return exactly one output for every input")
    for ident in ids:
        print(json.dumps(outputs[ident], separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.stderr.write(str(error) + "\n")
        raise SystemExit(2)
