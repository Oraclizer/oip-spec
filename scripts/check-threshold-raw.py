"""Compare the pinned THRESHOLD signature step and the paired native receives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from model_diagnostics import load_allowlist, split_exact
from wire_model_artifact import MAX_BLOB_BYTES, digest, exact_keys, load_artifact, runtime_source_hash


ROOT = Path(__file__).resolve().parent.parent
LOCK = "tests/threshold-raw-artifact.lock.json"
ROWS = 22
ABI = "intinf-threshold-raw-v1"
SCOPE = "wire-v6-threshold-raw-observed-primitives"
ENTRYPOINT = "OIP_Threshold_Raw_ABI.threshold_raw_packet"
IDENTITY_FUNCTION = "OIP_Threshold_Raw_ABI.threshold_raw_model_identity"
REFINEMENT = "HOL-Library.Code_Target_Nat"
ROLES = {
    "model": "oip_threshold_raw_abi.ML",
    "driver": "threshold-raw-driver.ML",
    "origin": "threshold-raw-origin.json",
    "diagnostics": "threshold-raw-diagnostics.json",
}
FIXTURES = {
    "packets": ("tests/vectors/threshold-raw/input.jsonl", ROWS),
    "signature_observations": ("tests/vectors/threshold-raw/primitive-observations.jsonl", ROWS),
    "key_observations": ("tests/vectors/threshold-raw/key-observations.json", 3),
}
SELECTOR = ("deployment", "source", "principal", "key_id", "epoch")
ROSTER = (*SELECTOR, "quorum")
RUST_TEST = "wire::admission::threshold_tests::threshold_configured_transport_replays_raw_packets"
GO_TEST = "TestThresholdTransportReplaysRawPackets"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_lock(path):
    lock = json.loads(path.read_bytes())
    constants = {
        "lock_version": 1,
        "binding_status": "bound",
        "artifact_transport": "github-git-blob-v1",
        "repository": "Oraclizer/formal-verification",
        "wire_schema": 1,
        "abi": ABI,
        "scope": SCOPE,
        "entrypoint": ENTRYPOINT,
        "identity_function": IDENTITY_FUNCTION,
        "natural_refinement": REFINEMENT,
    }
    exact_keys(lock, [*constants, "runtime_source_hash", "verified_export_sha256",
                      "public_namespace", "fixtures", "files"], "threshold raw lock")
    for field, value in constants.items():
        if type(lock[field]) is not type(value) or lock[field] != value:
            raise ValueError("Unsupported or unbound threshold raw lock field: " + field)
    digest(lock["runtime_source_hash"], 64, "threshold source fingerprint")
    digest(lock["verified_export_sha256"], 64, "verified threshold export")
    namespace = lock["public_namespace"]
    if not isinstance(namespace, str) or not re.fullmatch(r"Oracle_Interoperability_Protocol(?:/[A-Za-z0-9_.-]+)*", namespace):
        raise ValueError("Checked public threshold namespace required")
    exact_keys(lock["fixtures"], FIXTURES, "threshold fixtures")
    for role, (name, rows) in FIXTURES.items():
        pin = lock["fixtures"][role]
        exact_keys(pin, ["path", "rows", "sha256"], "threshold fixture pin")
        if pin["path"] != name or type(pin["rows"]) is not int or pin["rows"] != rows:
            raise ValueError("Unexpected threshold fixture path or row count: " + role)
        digest(pin["sha256"], 64, "threshold fixture")
    members = {}
    if type(lock["files"]) is not list or len(lock["files"]) != len(ROLES):
        raise ValueError("Threshold model, driver, independent origin and diagnostics required")
    for member in lock["files"]:
        exact_keys(member, ["role", "name", "git_blob_sha1", "sha256", "bytes"], "threshold blob pin")
        role = member["role"]
        if role not in ROLES or role in members or member["name"] != ROLES[role]:
            raise ValueError("Unexpected or duplicate threshold artifact role")
        digest(member["git_blob_sha1"], 40, "threshold Git blob")
        digest(member["sha256"], 64, "threshold artifact")
        if type(member["bytes"]) is not int or not 0 < member["bytes"] <= MAX_BLOB_BYTES:
            raise ValueError("Unbound or excessive threshold artifact size")
        members[role] = member
    if members["model"]["sha256"] != lock["verified_export_sha256"]:
        raise ValueError("Threshold model differs from the verified export")
    return lock, members


def json_lines(raw):
    return [json.loads(line) for line in raw.splitlines()]


def fixture_input(lock):
    data = {}
    for role, (name, _) in FIXTURES.items():
        raw = (ROOT / name).read_bytes()
        if sha256(raw) != lock["fixtures"][role]["sha256"]:
            raise ValueError("Threshold fixture differs from its lock: " + name)
        data[role] = raw
    packets = json_lines(data["packets"])
    signatures = json_lines(data["signature_observations"])
    keys = json.loads(data["key_observations"])["checks"]
    if (len(packets), len(signatures), len(keys)) != (ROWS, ROWS, 3):
        raise ValueError("Unexpected threshold fixture counts")
    for row in packets:
        exact_keys(row, ["id", "packet_hex", "profile", "boundary", "roster", "attestation_valid",
                         "prior_binding"], "threshold packet input")
        boolean(row["attestation_valid"])
    ids = [row["id"] for row in packets]
    if (len(set(ids)) != ROWS or any(not re.fullmatch(r"[a-z0-9-]+", identifier) for identifier in ids)
            or ids != [row["id"] for row in signatures]):
        raise ValueError("Threshold packet and primitive input identities differ")
    return packets, signatures, keys


def octets(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value):
        raise ValueError("Canonical fixture hex required")
    return bytes.fromhex(value)


def integer(value):
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise ValueError("Threshold input integers must fit u64")
    return str(value)


def numbers(values):
    return "[" + ",".join(map(integer, values)) + "]"


def boolean(value):
    if type(value) is not bool:
        raise ValueError("Boolean primitive observation required")
    return "true" if value else "false"


def preimage(core):
    return b"OIP\0ENVELOPE\0" + len(core).to_bytes(4, "big") + core


def packet_blob(tag, value):
    field = bytearray([tag])
    length = len(value)
    while length >= 128:
        field.append((length & 127) | 128)
        length >>= 7
    field.append(length)
    return bytes(field) + value


def model_input(packets, signatures, keys):
    # The finite primitive observations are model arguments. Native results
    # enter the comparator only after both the model and the native tests run.
    positive = {(row["id"], call["key_hex"]) for row in signatures
                for call in row["calls"] if call["verified"] is True}
    if any(key["verified"] is not True or (key["signature_case"], key["key_hex"]) not in positive for key in keys):
        raise ValueError("Fixture key lacks its independent positive observation")
    public_keys = [octets(key["key_hex"]) for key in keys]
    if len(set(public_keys)) != len(keys) or any(len(key) != 32 for key in public_keys):
        raise ValueError("Distinct 32-byte primitive fixture keys required")
    key_facts = [f"({numbers(raw)},{boolean(key['verified'])})"
                 for raw, key in zip(public_keys, keys, strict=True)]
    lines = []
    for row, observed in zip(packets, signatures, strict=True):
        boundary = row["boundary"]
        roster = row["roster"]
        members = [] if roster is None else [
            f"({integer(signer)},{numbers(octets(key))})" for signer, key in roster["members"]
        ]
        raw = octets(row["packet_hex"])
        core = octets(observed["core_hex"])
        payload = octets(observed["payload_hex"])
        if packet_blob(10, core) + packet_blob(18, payload) != raw:
            raise ValueError("Primitive observation is for a different Packet: " + row["id"])
        message = preimage(core)
        facts = []
        for call in observed["calls"]:
            if octets(call["message_hex"]) != message:
                raise ValueError("Primitive observation is for a different preimage: " + row["id"])
            key, sig = octets(call["key_hex"]), octets(call["signature_hex"])
            if len(key) != 32 or len(sig) != 64:
                raise ValueError("Malformed finite primitive query: " + row["id"])
            facts.append(f"({numbers(key)},({numbers(message)},({numbers(sig)},{boolean(call['verified'])})))")
        args = [
            integer(boundary["max_frame"]), numbers(row["profile"]["schemes"]),
            numbers(boundary[field] for field in SELECTOR),
            numbers([] if roster is None else (roster[field] for field in ROSTER)),
            "[" + ",".join(members) + "]", "[" + ",".join(key_facts) + "]",
            "[" + ",".join(facts) + "]", numbers(raw),
        ]
        lines.append(f"val _ = threshold_emit {json.dumps(row['id'])} ({ENTRYPOINT} {' '.join(args)});\n")
    return "".join(lines).encode("ascii")


def model_signature(model, packet, observed, rust, go):
    exact_keys(model, ["id", "words", "blobs_hex"], "threshold model result")
    if (type(model["words"]) is not list or not model["words"]
            or any(type(word) is not str or not re.fullmatch(r"0|[1-9][0-9]*", word) for word in model["words"])):
        raise ValueError("Invalid threshold model words: " + packet["id"])
    words = list(map(int, model["words"]))
    blobs = model["blobs_hex"]
    if words in ([0, 70], [0, 74]) and blobs == []:
        return words[1], None
    if words[0] != 1 or packet["roster"] is None or rust["selected_roster"] is None:
        raise ValueError("Invalid threshold model signature result: " + packet["id"])
    core = observed["core_hex"]
    payload = octets(observed["payload_hex"])
    signing = preimage(octets(core)).hex()
    count = int.from_bytes(payload[:8], "big")
    if len(payload) != 8 + 72 * count:
        raise ValueError("Accepted threshold payload has a different record count: " + packet["id"])
    signers = [int.from_bytes(payload[index:index + 8], "big") for index in range(8, len(payload), 72)]
    roster = [packet["roster"][field] for field in ROSTER]
    if ([rust["selected_roster"][field] for field in ROSTER] != roster
            or go["selected_group_deployment_source_principal_key_epoch"] != roster[:5]
            or words != [1, *roster, count, *signers]
            or blobs != [core, signing, payload.hex()]
            or any((source["core_hex"], source["signing_preimage_hex"]) != (core, signing)
                   for source in (rust, go))):
        raise ValueError("Selected roster, signer IDs, Core or preimage differ: " + packet["id"])
    return "accept", core


def check_cases(packets, signatures, models, rust, go):
    ids = [row["id"] for row in packets]
    for stream in (signatures, models, rust, go):
        if [row["id"] for row in stream] != ids:
            raise ValueError("Threshold observation order or case coverage differs")
    results = []
    for packet, observed, model, rs, other in zip(packets, signatures, models, rust, go, strict=True):
        identifier = packet["id"]
        raw = octets(packet["packet_hex"])
        if rs["packet_hex"] != raw.hex() or other["packet_hex"] != raw.hex() or other["packet_sha256"] != sha256(raw):
            raise ValueError("Exact native Packet differs: " + identifier)
        gate, core = model_signature(model, packet, observed, rs, other)
        go_gate = other["signature_step"]
        callbacks = ["configured-operation"]
        if go_gate == "not-reached":
            if (len(raw) <= packet["boundary"]["max_frame"]
                    or other["admission_stop"] != "frame/version" or gate != 70):
                raise ValueError("Unexpected earlier native stop outside the raw frame check: " + identifier)
            go_gate = other["verdict"]
            callbacks = []
        elif rs["scope_ttl_verdict"] != "accept":
            raise ValueError("Earlier Rust scope or TTL stop: " + identifier)
        if rs["gate_verdict"] != gate or go_gate != gate:
            raise ValueError("Checked signature step and native admission differ: " + identifier)
        prior = packet["prior_binding"]
        # The host attestation and exact binding expectations are the finite
        # transport replay rule for these inputs, separate from the SML result.
        attestation_reached = gate == "accept"
        if attestation_reached:
            callbacks.append("attestation")
        if not attestation_reached:
            verdict, retained = gate, prior
        elif not packet["attestation_valid"]:
            verdict, retained = 72, prior
        elif prior is None:
            verdict, retained = "accept:first", core
        elif prior == core:
            verdict, retained = "accept:identical", prior
        else:
            verdict, retained = 76, prior
        if (rs["prior_binding"] != prior or other["binding_before"] != prior
                or rs["attestation_called"] is not attestation_reached
                or other["actual_callbacks"] != callbacks
                or rs["binding_unchanged"] is not (prior == retained)
                or other["binding_count_before"] != int(prior is not None)
                or other["binding_count_after"] != int(retained is not None)
                or any((source["verdict"], source["retained_binding"]) != (verdict, retained)
                       for source in (rs, other))):
            raise ValueError("Native attestation or exact transport binding differs: " + identifier)
        results.append({"id": identifier, "checked_signature_step": gate,
                        "native_transport_verdict": verdict, "attestation_reached": attestation_reached})
    return results


def capture(argv, out, name, *, env, cwd):
    stdout_path, stderr_path = out / f"{name}.stdout.log", out / f"{name}.stderr.log"
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=600)
    except subprocess.TimeoutExpired as error:
        stdout_path.write_bytes(error.stdout or b"")
        stderr_path.write_bytes(error.stderr or b"")
        raise
    stdout_path.write_bytes(result.stdout)
    stderr_path.write_bytes(result.stderr)
    if result.returncode:
        raise ValueError(f"{name} exited {result.returncode}; see raw logs in {out}")
    return result.stdout, result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--polyml", required=True, type=Path)
    parser.add_argument("--artifact-root", type=Path, help="Local files verified against the same bound lock")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    lock, members = read_lock(ROOT / LOCK)
    fingerprint, _ = runtime_source_hash(ROOT)
    if fingerprint != lock["runtime_source_hash"]:
        raise ValueError("Threshold lock requires the current runtime source fingerprint")
    packets, signatures, keys = fixture_input(lock)
    fixtures_ml = out / "model-inputs.ML"
    fixtures_ml.write_bytes(model_input(packets, signatures, keys))
    bundle = sha256(json.dumps(members, sort_keys=True, separators=(",", ":")).encode("ascii"))
    files = load_artifact(lock, members, ROOT / "target/threshold-raw-model" / bundle, args.artifact_root)
    if files["driver"].read_bytes() != (ROOT / "tests" / ROLES["driver"]).read_bytes():
        raise ValueError("Pinned threshold driver differs from the reviewed consumer")
    allowed = load_allowlist(files["diagnostics"], members["model"]["sha256"], members["driver"]["sha256"])
    model_env = dict(os.environ, OIP_THRESHOLD_RAW_MODEL=files["model"].as_posix(),
                     OIP_THRESHOLD_RAW_INPUTS=fixtures_ml.as_posix())
    driver = files["driver"].as_posix()
    stdout, stderr = capture([str(args.polyml.resolve()), "-q", "--error-exit", "--minheap", "16M",
                              "--maxheap", "1024M", "--gcthreads", "1", "--script", driver],
                             out, "model", env=model_env, cwd=ROOT)
    protocol, diagnostic_receipt = split_exact(stdout, stderr, prefixes=("OIP-MODEL", "OIP-THRESHOLD"),
                                                allowlist=allowed, model_path=model_env["OIP_THRESHOLD_RAW_MODEL"],
                                                driver_path=driver)
    identity = ["1", ABI, SCOPE, ENTRYPOINT, REFINEMENT, fingerprint]
    if (not protocol or protocol[0].split("\t") != ["OIP-MODEL", *identity]
            or any(not line.startswith("OIP-THRESHOLD\t") for line in protocol[1:])):
        raise ValueError("Checked threshold model identity or stream framing differs")
    model_rows = [line.split("\t", 1)[1] for line in protocol[1:]]
    model_bytes = ("\n".join(model_rows) + "\n").encode("ascii")
    (out / "model.jsonl").write_bytes(model_bytes)
    (out / "diagnostics-receipt.json").write_text(json.dumps(diagnostic_receipt, indent=2) + "\n", encoding="utf-8")
    env = dict(os.environ, OIP_P19_INPUT=str(ROOT / FIXTURES["packets"][0]))
    rust_path, go_path = out / "rust.jsonl", out / "go.jsonl"
    capture(["cargo", "test", "--offline", "--locked", "--lib", RUST_TEST, "--", "--exact"],
            out, "rust-test", env=dict(env, OIP_P19_OUTPUT=str(rust_path)), cwd=ROOT)
    capture(["go", "test", "-count=1", "-mod=readonly", "./wire", "-run", "^" + GO_TEST + "$"],
            out, "go-test", env=dict(env, OIP_P19_OUTPUT=str(go_path)), cwd=ROOT / "go")
    rust, go = rust_path.read_bytes(), go_path.read_bytes()
    results = check_cases(packets, signatures, json_lines(model_bytes), json_lines(rust), json_lines(go))
    receipt = {
        "schema": "oip-threshold-raw-comparison-v1",
        "scope": SCOPE,
        "identity": identity,
        "runtime_source_hash": fingerprint,
        "cases": results,
        "fixture_pins": lock["fixtures"],
        "artifact_sha256": {role: member["sha256"] for role, member in members.items()},
        "stream_sha256": {"model_inputs": sha256(fixtures_ml.read_bytes()), "model": sha256(model_bytes),
                          "rust": sha256(rust), "go": sha256(go)},
        "primitive_source": "pinned finite independent observations supplied as model arguments",
        "native_scope": "configured transport, host attestation and exact binding on the same packets",
    }
    (out / "comparison.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"scope": SCOPE, "cases": len(results), "languages": ["Rust", "Go"], "differences": 0}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
