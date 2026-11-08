"""Input-only serialization and strict, limited observation projections."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from model_diagnostics import require_keys

ROOT = Path(__file__).resolve().parent.parent
GENESIS_KEYS = {"profile", "source_connected", "clock", "control", "security_config", "security_config_sha256",
                "authority_binding_hex", "credential", "genesis", "fixture_keys"}
STIMULUS_KEYS = {"clock", "close", "credential", "packet_hex", "signature_packet_hex"}
APIS = {"receive_wire", "receive_wire_response", "resolve_wire_debit", "resolve_wire_debit_response"}
PHASE = {None: 0, "Held": 1, "Dispatched": 2, "Pending": 3, "Confirmed": 4, "Returned": 5, "Cancelled": 6}
FINANCIAL_FIELDS = ["status", "code", "hasCommit", "commit", "revision", "pool", "payer", "pending", "phase", "journalLength", "bindingCount"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_jsonl(path):
    raw = Path(path).read_bytes()
    if not raw or not raw.endswith(b"\n") or any(not line for line in raw.splitlines()):
        raise ValueError("Nonempty newline-terminated JSONL is required")
    return raw, [json.loads(line) for line in raw.splitlines()]


def inputs(contract, name="input", root=ROOT):
    pin = contract[name]
    path = root / pin["path"]
    raw, rows = read_jsonl(path)
    if sha(raw) != pin["sha256"] or len(rows) != pin["rows"] or [row["id"] for row in rows] != pin["ids"]:
        raise ValueError("Reference input identity, row count or order changed")
    seeds = 0
    for row in rows:
        require_keys(row, ["schema", "id", "api", "input"], "reference row")
        if row["schema"] != "oip-reference-input-v1" or type(row["id"]) is not str:
            raise ValueError("Unsupported reference input schema")
        value = row["input"]
        if row["api"] == "initialize":
            seeds += 1
            require_keys(value, GENESIS_KEYS, "genesis input")
            if value["fixture_keys"] != {"response_seed": 6, "peer_seed": 7}:
                raise ValueError("Unexpected fixed fixture key roles")
        elif row["api"] in APIS:
            require_keys(value, STIMULUS_KEYS, "stimulus input")
            for field in ["packet_hex", "signature_packet_hex"]:
                if type(value[field]) is not str or re.fullmatch(r"(?:[0-9a-f]{2})+", value[field]) is None:
                    raise ValueError("Canonical lowercase packet octets required")
            if row["api"].startswith("resolve_"):
                if type(value["close"]) is not bool:
                    raise ValueError("Resolver close flag must be explicit")
            elif value["close"] is not None:
                raise ValueError("Receive input cannot carry a resolver close flag")
        else:
            raise ValueError("Unsupported replay API")
        if type(value["clock"]) is not int or not 0 <= value["clock"] < 2**64:
            raise ValueError("Clock must be a u64 input")
    if seeds != pin["genesis_rows"] or len(rows) - seeds != pin["stimulus_rows"]:
        raise ValueError("Reference seed/stimulus scope changed")
    return raw, rows


def financial_protocol(rows):
    """Read only genesis/configuration and raw input packets, never observations."""
    by_id = {row["id"]: row for row in rows}
    lines, bindings = [], []
    for prefix in ["a", "b"]:
        seed = by_id[prefix + ".0"]["input"]
        genesis = seed["genesis"]
        if len(genesis["balances"]) != 1:
            raise ValueError("Finite single-asset seed requires one balance")
        account, balance = genesis["balances"][0]
        asset, origin, owner = account["asset"], account["endpoint"], account["owner"]
        enrollment = [item for item in genesis["regulation"]["enrollments"] if item["asset"] == asset and item["source"] == origin]
        if len(enrollment) != 1:
            raise ValueError("Finite seed requires one declared enrollment")
        receiver = enrollment[0]["receiver"]
        contexts = {context["endpoint"]: context for context in genesis["contexts"]}
        if contexts[origin]["dependencies"] or contexts[receiver]["dependencies"]:
            raise ValueError("Finite ABI does not cover dependency contexts")
        if not contexts[origin]["epoch"] == contexts[receiver]["epoch"] == genesis["epoch"] == seed["security_config"]["authority_epoch"]:
            raise ValueError("Finite seed context epochs differ")
        if genesis["owners"] != {str(asset): owner} or genesis["supply"] != {str(asset): balance}:
            raise ValueError("Finite single-asset owner/supply shape differs")
        metadata = [origin, receiver, asset, owner, balance, genesis["epoch"], genesis["epoch"], 0, 0]
        actors = sorted({grant[0] for grant in contexts[origin]["grants"] if grant[1:] == ["Normal", "Reserve"]})
        if not actors:
            raise ValueError("No finite Reserve actors")
        csv = lambda values: ",".join(str(u64(value)) for value in values)
        ident = prefix + ".0"
        lines.append("\t".join([ident, "seed", csv(metadata), csv(actors)]))
        bindings.append({"id": ident, "kind": "SEED", "metadata": metadata, "actors": actors})
        for number in [1, 2, 3]:
            ident = prefix + "." + str(number)
            packet = bytes.fromhex(by_id[ident]["input"]["packet_hex"])
            lines.append("\t".join([ident, "step", csv(packet), ""]))
            bindings.append({"id": ident, "kind": "STEP", "packet_sha256": sha(packet)})
    return ("\n".join(lines) + "\n").encode("ascii"), bindings


def u64(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("Finite protocol field is outside u64")
    return value


def observations(path, rows):
    raw, observed = read_jsonl(path)
    wanted = [(row["id"], phase) for row in rows for phase in (["after"] if row["api"] == "initialize" else ["before", "after"])]
    keys = []
    result = {}
    for row in observed:
        require_keys(row, ["schema", "id", "phase", "observation"], "source observation")
        if row["schema"] != "oip-reference-observation-v2":
            raise ValueError("Unsupported source observation schema")
        key = row["id"], row["phase"]
        if key in result:
            raise ValueError("Duplicate source observation")
        result[key] = row["observation"]
        keys.append(key)
    if keys != wanted:
        raise ValueError("Missing, extra or reordered source observations")
    return raw, result


def units(value):
    require_keys(value["value"], ["Units"], "financial units")
    return u64(value["value"]["Units"])


def financial_projection(source, metadata, seed=False):
    product = source["after"]["product"]
    account = {"endpoint": metadata[0], "asset": metadata[2], "owner": metadata[3]}
    accounts = [item for item in product["accounts"] if item["account"] == account]
    if len(accounts) != 1:
        raise ValueError("Missing/ambiguous financial source account")
    phase = product["phase"]
    if phase not in PHASE:
        raise ValueError("Unknown source financial phase")
    view = [u64(product["cut"]["revision"]), units(product["source_pool"]), units(accounts[0]["account_balance"]),
            u64(product["pending"]), PHASE[phase], len(product["retained_image"]["authority"]["primary"]["journal"]),
            len(product["ledger"]["state"]["reservations"])]
    if seed:
        return view
    response = source["response"]["verified"]
    if response["category"] != "known" or response["code"] not in {1, 10, 11, 12}:
        raise ValueError("Unknown/unsupported response is not a financial match")
    commit = response["commit"]
    return [0, u64(response["code"]), int(commit is not None), 0 if commit is None else u64(commit["position"])] + view


def compare_financial(protocol_lines, identity, bindings, source):
    expected_header = "\t".join(["OIP-FINANCIAL-MODEL"] + identity)
    if not protocol_lines or protocol_lines[0] != expected_header:
        raise ValueError("Missing or mismatched same-source financial model identity")
    results = protocol_lines[1:]
    if len(results) != len(bindings):
        raise ValueError("Missing or extra financial model rows")
    comparisons, metadata = [], None
    for line, binding in zip(results, bindings):
        parts = line.split("\t")
        if len(parts) != 4 or parts[:3] != ["OIP-FINITE", binding["id"], binding["kind"]]:
            raise ValueError("Unknown, duplicate or reordered financial model row")
        raw = parts[3].split(",")
        if any(re.fullmatch(r"(?:0|~?[1-9][0-9]*)", value) is None for value in raw):
            raise ValueError("Malformed financial integer vector")
        vector = [int(value.replace("~", "-")) for value in raw]
        seed = binding["kind"] == "SEED"
        if len(vector) != (7 if seed else 11):
            raise ValueError("Wrong financial result shape")
        if seed:
            metadata = binding["metadata"]
        if metadata is None:
            raise ValueError("Financial step before seed")
        projected = financial_projection(source[(binding["id"], "after")], metadata, seed=seed)
        fields = FINANCIAL_FIELDS[4:] if seed else FINANCIAL_FIELDS
        differences = [{"field": field, "model": actual, "source": wanted} for field, actual, wanted in zip(fields, vector, projected) if actual != wanted]
        if not seed and vector[0] != 0:
            raise ValueError("Unsupported/Pending financial status cannot match a source result")
        comparisons.append({"id": binding["id"], "kind": binding["kind"], "model": vector, "source_projection": projected,
                            "differences": differences})
    return comparisons
