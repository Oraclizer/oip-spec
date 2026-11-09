"""Generate table-derived operation frames and check real Rust/Go receivers.

The fixed cases have independently specified expected outcomes. Random cases
are seeded, compared between implementations and retained as regression data.
The default comparison uses the independently pinned proof-model export.
Two-language and custom-command diagnostics do not satisfy the required CI gate.
No protocol decoder is generated from the operation table.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from wire_values import schema as value_schema,validate_results,require_equal

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests/vectors/wire-operations.jsonl"
HASHES = ROOT / "tests/vectors/wire-operations.sha256"
OUT = ROOT / "target/operation-conformance"
SEED = 0x6F69702D763036
RUST_TEST = "wire::admission::operation_tests::operation_vectors_follow_the_real_transport_receiver"
GO_TEST = "TestOperationVectorsFollowTheRealTransportReceiver"
SIGNING_VECTORS = ROOT / "tests/vectors/reference-signing-inputs.json"
COUNTS = [7, 3, 8, 9, 2, 2, 2]
ADDED_OPERATIONS = {(1, 7), (4, 9)}
PROFILE = {"version": 6, "families": list(range(1, 8)), "atomicities": [1, 2, 3], "schemes": [1, 2]}
BOUNDARY = {"deployment": 7, "source": 0, "target": 0, "principal": 7, "key_id": 9, "epoch": 9,
            "route_scope": 1, "now": 105, "asset_ttl_floor": 0, "future_skew": 0, "version_floor": 6,
            "max_frame": 1048576, "max_nesting": 4, "critical_allowed": False,
            "public_key": ""}
VALUES = {"message_reference": 33, "call_sequence": 33, "session": 2, "revision": 2, "origin_epoch": 9,
          "origin_domain": 0, "origin_event": 17, "asset": 17, "owner": 7, "destination": 2,
          "recipient": 3, "holder": 7, "generation": 0, "epoch": 9, "duration": 5, "elapsed": 5,
          "reference": 2, "evidence_reference": 2, "decision_kind": 1, "action": 1, "officer": 7,
          "jurisdiction": 1, "legal_basis": 1, "issuance_epoch": 9, "sender": 3, "spend_recipient": 4,
          "commit_position": 2, "target": 0, "caller_namespace": 7, "kind": 1, "code": 12,
          "position": 2, "challenge": 11, "expires": 200, "previous": 7, "successor": 8,
          "old_session": 2, "new_session": 3, "next_epoch": 10, "domain": 0, "event": 17,
          "source_position": 41}


def dump(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def varint(value):
    assert 0 <= value <= (1 << 64) - 1
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(tag, kind, value):
    prefix = varint(tag * 8 + kind)
    if kind == 0:
        return prefix + varint(value)
    if kind == 1:
        return prefix + value.to_bytes(8, "little")
    assert kind == 2
    return prefix + varint(len(value)) + value


def table():
    # Keep schema validation in the existing generator, whose Table wrapper
    # is an internal renderer detail rather than a decoder interface.
    subprocess.run([sys.executable, str(ROOT / "scripts/render-operations.py"), "--check"], check=True)
    data = json.loads((ROOT / "spec/operations.json").read_text(encoding="utf-8"))
    operations = data["operations"]
    counts = [sum(o["family"] == family for o in operations) for family in range(1, 8)]
    if counts != COUNTS:
        raise SystemExit(f"operation family counts changed: {counts}")
    if len(operations) != 33 or sum(o["reference_accepts"] for o in operations) != 28:
        raise SystemExit("operation or reference-profile count changed")
    return data, operations


def words(fields, data):
    result = []
    for item in fields:
        kind = item["kind"]
        if kind == "use":
            result += words(data["groups"][item["group"]]["fields"], data)
        elif kind == "word":
            value = VALUES.get(item["name"], 1)
            accepted = item.get("accepted")
            if isinstance(accepted, list):
                value = accepted[0]
            elif accepted == "all":
                value = data["enums"][item["enum"]]["values"][0]["code"]
            result.append(value)
        elif kind == "optional":
            present = item["name"] in {"credential", "commit"}
            result.append(int(present))
            if present:
                result += words(item["fields"], data)
        elif kind == "counted_set":
            value = {"versions": 6, "families": 4, "atomicities": 3, "schemes": 1}.get(item["name"], 17)
            result += [1, value]
        elif kind == "counted_pairs":
            result += [1, 17, 0]
        elif kind == "tagged":
            chosen = item["cases"][0]
            result += [chosen["code"], *words(chosen["fields"], data)]
        else:
            raise ValueError(kind)
    return result


def operation_bytes(case):
    out = field(1, 0, case["opcode"])
    if case.get("packed_words"):
        out += field(2, 2, b"".join(x.to_bytes(8, "little") for x in case["words"]))
    else:
        out += b"".join(field(2, 1, x) for x in case["words"])
    out += b"".join(field(3, 2, bytes.fromhex(x)) for x in case["blobs"])
    if case.get("deadline") == "indefinite":
        out += field(4, 0, 1)
    elif isinstance(case.get("deadline"), int):
        out += field(5, 1, case["deadline"])
    return out


def core_bytes(case):
    header = case["header"]
    out = field(1, 0, header["version"]) + field(2, 0, header["purpose"])
    for tag, name in enumerate(["deployment", "source", "target", "principal", "key_id", "epoch", "issued", "ttl"], 3):
        out += field(tag, 1, header[name])
    out += field(11, 2, bytes.fromhex(header["uuid"])) + field(12, 0, case["family"]) + field(13, 0, header["primary"])
    if header.get("secondary") is not None:
        out += field(14, 0, header["secondary"])
    out += field(15, 0, header["scheme"]) + field(15 + case["family"], 2, operation_bytes(case))
    out += field(23, 0, header["atomicity"]) + field(24, 0, header["priority"]) + field(25, 1, header["route_scope"])
    raw_mutation = case.get("raw_mutation")
    if raw_mutation == "unknown-field":
        out += field(26, 0, 1)
    elif raw_mutation == "out-of-order":
        out = out[2:4] + out[:2] + out[4:]
    elif raw_mutation == "wide-varint":
        out = b"\x08\x86\x00" + out[2:]
    elif raw_mutation == "unknown-wire-type":
        out += varint(26 * 8 + 3)
    return out


def bases(data, operations):
    result = []
    for operation in operations:
        target = 2 if operation.get("target_domain") == "destination" or operation["family"] in {4, 5, 6, 7} else 0
        if operation["name"] in {"ExactReceipt", "CorrelatedResponse"}:
            target = 0
        header = {"version": 6, "purpose": 1, "deployment": 7, "source": 0, "target": target,
                  "principal": 7, "key_id": 9, "epoch": 9, "issued": 100, "ttl": 5,
                  "uuid": "000102030405400780090a0b0c0d0e0f", "primary": 1, "secondary": 77,
                  "scheme": 1, "atomicity": 3, "priority": 3, "route_scope": 1}
        row = {"id": operation["name"] + "/valid", "family": operation["family"], "opcode": operation["opcode"],
               "reference_accepts": operation["reference_accepts"], "header": header,
               "words": words(operation["words"], data), "blobs": [], "signature_mode": "valid",
               "profile": copy.deepcopy(PROFILE), "boundary": {**BOUNDARY, "target": target},
               "attestation_valid": True, "prior_binding": None, "known_verdict": "accept:first"}
        for blob in operation["blobs"]:
            kind = blob["type"]
            if kind == "amount_u256":
                value = (5).to_bytes(32, "big")
            elif kind == "commitment":
                value = bytes([165]) * 32
            elif kind == "octets" and blob["name"] == "predecessor":
                value = b""
            elif kind == "octets" and blob["name"] == "source_attestation":
                value = b"transport-fixture"
            elif kind == "proof":
                value = b"test-authorization"
            elif kind == "canonical_core":
                value = core_bytes(result[0])
            elif kind == "endpoint_contexts_json":
                value = b'[{"endpoint":2,"epoch":10,"grants":[],"dependencies":[],"write_permissions":[]}]'
            elif kind == "session_bindings_json":
                value = b'[[2,{"principal":7,"authority_epoch":10}]]'
            else:
                raise ValueError(kind)
            row["blobs"].append(value.hex())
        result.append(row)
    return result


def cases(base_rows, random_count):
    result = list(base_rows)
    debit = base_rows[0]

    def add(label, verdict, edit, original=debit):
        row = copy.deepcopy(original)
        row["id"] = original["id"].split("/")[0] + "/" + label
        row["known_verdict"] = verdict
        edit(row)
        result.append(row)

    add("new-version-new-field", 71, lambda x: (x["header"].update(version=7), x.update(raw_mutation="unknown-field")))
    add("unknown-field", 70, lambda x: x.update(raw_mutation="unknown-field"))
    add("uuid-not-v4", 70, lambda x: x["header"].update(uuid="000102030405300780090a0b0c0d0e0f"))
    add("out-of-order", 70, lambda x: x.update(raw_mutation="out-of-order"))
    add("nonminimal-varint", 70, lambda x: x.update(raw_mutation="wide-varint"))
    add("unknown-wire-type", 70, lambda x: x.update(raw_mutation="unknown-wire-type"))
    add("packed-words", 70, lambda x: x.update(packed_words=True))
    add("short-signature", 70, lambda x: x.update(signature_mode="short"))
    add("bad-signature", 73, lambda x: x.update(signature_mode="invalid"))
    add("small-order-signature", 73, lambda x: x.update(signature_mode="small-order"))
    add("noncanonical-signature-point", 73, lambda x: x.update(signature_mode="noncanonical-point"))
    add("small-order-key", 73, lambda x: x["boundary"].update(public_key="01" + "00" * 31))
    add("bad-opcode", 70, lambda x: x.update(opcode=0))
    add("oversize", 70, lambda x: x["boundary"].update(max_frame=1))
    add("ttl-expired", 54, lambda x: x["boundary"].update(now=106))
    add("issued-in-future", 75, lambda x: x["header"].update(issued=106))
    add("ttl-overflow", 75, lambda x: x["header"].update(issued=(1 << 64) - 1))
    add("clock-skew-overflow", 75, lambda x: x["boundary"].update(now=(1 << 64) - 1, future_skew=1))
    add("ttl-floor-expired", 54, lambda x: (x["header"].update(ttl=0), x["boundary"].update(asset_ttl_floor=2, now=103)))
    add("signature-before-attestation", 73, lambda x: x.update(signature_mode="invalid", attestation_valid=False))
    add("source-before-signature", 72, lambda x: (x["header"].update(principal=8), x.update(signature_mode="invalid")))
    add("ttl-before-signature", 54, lambda x: (x["boundary"].update(now=106), x.update(signature_mode="invalid")))
    add("attestation-before-operands", 72, lambda x: (x["words"].pop(), x.update(attestation_valid=False)))
    add("identical-retry", "accept:identical", lambda x: x.update(prior_binding=core_bytes(x).hex()))
    add("changed-binding", 76, lambda x: (x.update(prior_binding=core_bytes(x).hex()), x["words"].__setitem__(0, 34)))
    add("invalid-retry-signature", 73, lambda x: x.update(prior_binding=core_bytes(x).hex(), signature_mode="invalid"))
    add("invalid-retry-attestation", 72, lambda x: x.update(prior_binding=core_bytes(x).hex(), attestation_valid=False))
    add("no-nesting", 70, lambda x: x["boundary"].update(max_nesting=0))
    add("profile-before-size", 71, lambda x: (x["profile"].update(version=5), x["boundary"].update(max_frame=1)))
    add("family-not-selected", 71, lambda x: x["profile"].update(families=[4]))
    add("scheme-not-selected", 73, lambda x: x["profile"].update(schemes=[]))
    add("threshold-not-supported", 74, lambda x: x["header"].update(scheme=2))
    add("critical-not-authorized", 72, lambda x: x["header"].update(priority=0))
    add("critical-authorized", "accept:first", lambda x: (x["header"].update(priority=0), x["boundary"].update(critical_allowed=True)))
    add("integer-above-double-range", "accept:first", lambda x: (x["header"].update(secondary=(1 << 53) + 1), x["words"].__setitem__(0, (1 << 53) + 1)))
    legal = next(row for row in base_rows if row["family"] == 2)
    add("indefinite-appeal", "accept:first", lambda x: x.update(deadline="indefinite"), legal)
    add("finite-appeal", "accept:first", lambda x: x.update(deadline=200), legal)
    for row in base_rows:
        add("trailing-word", 70, lambda x: x["words"].append(0), row)
        add("missing-word", 70, lambda x: x["words"].pop(), row)
        add("opcode-above-family", 70, lambda x: x.update(opcode=COUNTS[x["family"]-1]+1), row)
    by_operation = {(row["family"], row["opcode"]): row for row in base_rows}
    sync = by_operation[1, 7]
    add("empty-attestation", "accept:first", lambda x: x["blobs"].__setitem__(2, ""), sync)
    add("absent-attestation", 70, lambda x: x["blobs"].pop(), sync)
    add("short-commitment", 70, lambda x: x["blobs"].__setitem__(0, "00" * 31), sync)
    add("initial-with-predecessor", 70, lambda x: x["blobs"].__setitem__(1, "00" * 32), sync)
    add("incremental-without-predecessor", 70, lambda x: x["words"].__setitem__(9, 2), sync)
    add("incremental", "accept:first",
        lambda x: (x["words"].__setitem__(9, 2), x["blobs"].__setitem__(1, "00" * 32)), sync)
    add("full-resync", "accept:first", lambda x: x["words"].__setitem__(9, 3), sync)
    add("unknown-mode", 70, lambda x: x["words"].__setitem__(9, 4), sync)
    add("maximum-source-position", "accept:first", lambda x: x["words"].__setitem__(8, (1 << 64) - 1), sync)
    query = by_operation[4, 9]
    add("unexpected-blob", 70, lambda x: x["blobs"].append(""), query)
    add("unexpected-deadline", 70, lambda x: x.update(deadline=200), query)
    legacy_bases = [row for row in base_rows if (row["family"], row["opcode"]) not in ADDED_OPERATIONS]
    state = SEED

    def next_number(bound):
        nonlocal state
        state = (state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
        return (z ^ (z >> 31)) % bound

    for index in range(random_count):
        row = copy.deepcopy(legacy_bases[next_number(len(legacy_bases))])
        row["id"] = f"random-{index:04}"
        row["seed"] = SEED
        row.pop("known_verdict", None)
        for _ in range(1 + next_number(3)):
            mode = next_number(10)
            if mode == 0:
                row["header"]["principal"] = 8
            elif mode == 1:
                row["signature_mode"] = "invalid"
            elif mode == 2:
                row["attestation_valid"] = False
            elif mode == 3:
                row["boundary"]["now"] = [99, 100, 105, 106][next_number(4)]
            elif mode == 4:
                row["words"].append([0, 1, (1 << 64) - 1][next_number(3)])
            elif mode == 5 and row["words"]:
                row["words"][next_number(len(row["words"]))] = [0, 1, 2, 7, 17, (1 << 53) + 1, (1 << 64) - 1][next_number(7)]
            elif mode == 6:
                row["boundary"]["max_nesting"] = next_number(5)
            elif mode == 7:
                row["header"]["version"] = [5, 6, 7][next_number(3)]
            elif mode == 8:
                row["prior_binding"] = core_bytes(row).hex()
            else:
                row["header"]["ttl"] = [0, 1, 5, (1 << 64) - 1][next_number(4)]
        result.append(row)
    return result


def tool(explicit, variable, name):
    answer = explicit or os.environ.get(variable) or shutil.which(name)
    if not answer:
        raise SystemExit(f"{name} is unavailable; pass --{name} or set {variable}")
    return str(answer)


def run(argv, *, env=None, cwd=ROOT, data=None):
    return subprocess.run(list(map(str, argv)), input=data, cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600).stdout


def signed_rows(cases, cargo):
    request = "".join(dump({"id": row["id"], "core_hex": core_bytes(row).hex(), "signature_mode": row["signature_mode"]}) + "\n" for row in cases)
    signed = run([cargo, "run", "--offline", "--locked", "--quiet", "--example", "sign_wire_operations"], data=request.encode())
    signatures = {row["id"]: row for row in map(json.loads, signed.splitlines())}
    result, known = [], {}
    for case in cases:
        signed = signatures[case["id"]]
        boundary = case["boundary"].copy()
        if not boundary["public_key"]:
            boundary["public_key"] = signed["public_key"]
        row = {"schema": 1, "id": case["id"], "layer": "transport", "threshold_supported": False, "family": case["family"],
               "opcode": case["opcode"], "reference_accepts": case["reference_accepts"],
               "packet_hex": signed["packet_hex"], "profile": case["profile"], "boundary": boundary,
               "signature_valid": signed["signature_valid"] and boundary["public_key"] == signed["public_key"],
               "attestation_valid": case["attestation_valid"], "prior_binding": case["prior_binding"]}
        if "seed" in case:
            row["seed"] = case["seed"]
        if "known_verdict" in case:
            known[row["id"]] = case["known_verdict"]
        result.append(row)
    return result, known


def encode_rows(rows):
    return "".join(dump(row) + "\n" for row in rows).encode()


def evaluate(rows, cargo, go):
    input_path = OUT / "input.jsonl"
    input_path.write_bytes(encode_rows(rows))
    env = os.environ.copy()
    env["OIP_WIRE_OPERATIONS_INPUT"] = str(input_path)
    rust_path, go_path = OUT / "rust.jsonl", OUT / "go.jsonl"
    env["OIP_WIRE_OPERATIONS_OUTPUT"] = str(rust_path)
    run([cargo, "test", "--offline", "--locked", "--lib", RUST_TEST, "--", "--exact"], env=env)
    env["OIP_WIRE_OPERATIONS_OUTPUT"] = str(go_path)
    run([go, "test", "-count=1", "-mod=readonly", "./wire", "-run", "^" + GO_TEST + "$"], env=env, cwd=ROOT / "go")
    rust, other = [list(map(json.loads, path.read_bytes().splitlines())) for path in (rust_path, go_path)]
    ids=[row["id"] for row in rows]
    definition=value_schema()
    validate_results(rust,ids,definition);validate_results(other,ids,definition)
    require_equal(rust,other)
    return rust


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="deliberately regenerate committed test vectors")
    parser.add_argument("--cargo")
    parser.add_argument("--go")
    parser.add_argument("--random-count", type=int, default=512)
    parser.add_argument("--mirror-command", nargs="+", help="Diagnostic custom model command; not accepted by the required CI gate")
    parser.add_argument("--require-mirror", action="store_true", help="Require the independently pinned default model")
    parser.add_argument("--two-language-only", action="store_true", help="Diagnostic only; does not satisfy model conformance")
    parser.add_argument("--model-artifact-root", help="Local verified model/driver/origin directory")
    parser.add_argument("--polyml", help="Explicit standalone Poly/ML executable")
    parser.add_argument("--model-heap-mb", type=int, default=1024)
    args = parser.parse_args()
    if args.two_language_only and (args.require_mirror or args.mirror_command):
        raise SystemExit("Two-language diagnostics cannot satisfy or replace the required model gate")
    if args.require_mirror and args.mirror_command:
        raise SystemExit("The required gate uses only the independently pinned model loader")
    if not args.two_language_only and not args.mirror_command:
        args.require_mirror = True
        args.mirror_command = [sys.executable, str(ROOT / "scripts/run-wire-model.py")]
        if args.model_artifact_root:
            args.mirror_command += ["--artifact-root", args.model_artifact_root]
        if args.polyml:
            args.mirror_command += ["--polyml", args.polyml]
        args.mirror_command += ["--heap-mb", str(args.model_heap_mb)]
    if args.random_count < 256:
        raise SystemExit("at least 256 random transport cases are required")
    OUT.mkdir(parents=True, exist_ok=True)
    cargo, go = tool(args.cargo, "CARGO", "cargo"), tool(args.go, "GO", "go")
    data, operations = table()
    inputs, known = signed_rows(cases(bases(data, operations), args.random_count), cargo)
    if args.write:
        # The test modules compile in the newly generated corpus on their first build.
        CORPUS.write_bytes(encode_rows(inputs))
    else:
        saved = list(map(json.loads, CORPUS.read_bytes().splitlines()))
        if [{k: v for k, v in row.items() if k != "expected"} for row in saved] != inputs:
            raise SystemExit("operation vector inputs differ; regenerate deliberately with --write")
        inputs = saved
    results = evaluate(inputs, cargo, go)
    for row in results:
        if row["id"] in known and row["verdict"] != known[row["id"]]:
            raise SystemExit(dump({"id": row["id"], "expected_from_case": known[row["id"]], "actual": row}))
    if args.mirror_command:
        raw = run(args.mirror_command, data=encode_rows(inputs))
        mirror = list(map(json.loads, raw.splitlines()))
        validate_results(mirror,[row["id"] for row in inputs],value_schema())
        require_equal(mirror,results)
    if args.write:
        for source, output in zip(inputs, results, strict=True):
            source["expected"] = {k: output[k] for k in ("verdict", "retained_binding")}
        CORPUS.write_bytes(encode_rows(inputs))
        hashed = [CORPUS,SIGNING_VECTORS]
        HASHES.write_text("".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in hashed), encoding="ascii", newline="\n")
    else:
        for line in HASHES.read_text(encoding="ascii").splitlines():
            expected_hash, name = line.split("  ",1)
            if Path(name).name != name or name not in {CORPUS.name,SIGNING_VECTORS.name}:
                raise SystemExit("unknown operation vector digest entry")
            if hashlib.sha256((CORPUS.parent/name).read_bytes()).hexdigest() != expected_hash:
                raise SystemExit("operation or signing vector digest differs")
        if len(HASHES.read_text(encoding="ascii").splitlines()) != 2:
            raise SystemExit("operation vector digest list is incomplete")
    print(dump({"operations": len(operations), "reference_accepts": sum(o["reference_accepts"] for o in operations),
                "cases": len(inputs), "random_cases": args.random_count, "seed": SEED,
                "rust_go_differences": 0, "fixed_expectations": len(known),
                "proof_model_mirror": "pass:pinned" if args.require_mirror else "diagnostic:custom-or-default" if args.mirror_command else "diagnostic:two-language-only"}))


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.stdout.buffer.write(error.stdout or b"")
        sys.stderr.buffer.write(error.stderr or b"")
        raise SystemExit(error.returncode)
