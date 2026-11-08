"""Separate only exact, artifact-bound compiler diagnostics from raw output.

Callers must save both original byte streams before calling this module.
An unknown line, including an unregistered warning, is an execution error.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


def require_keys(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(label + ": missing or unexpected fields")


def digest(value, label):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(label + ": bound SHA-256 required")
    return value


def load_allowlist(path, model_sha256, driver_sha256):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    require_keys(value, ["schema", "model_sha256", "driver_sha256", "allowed"], "diagnostics")
    if value["schema"] != "oip-compiler-diagnostics-v1":
        raise ValueError("Unsupported diagnostics schema")
    if value["model_sha256"] != digest(model_sha256, "model") or value["driver_sha256"] != digest(driver_sha256, "driver"):
        raise ValueError("Diagnostic allowlist belongs to different model or driver bytes")
    if type(value["allowed"]) is not list:
        raise ValueError("Diagnostic block array required")
    for block in value["allowed"]:
        require_keys(block, ["stream", "lines", "maximum"], "diagnostic block")
        if block["stream"] not in {"stdout", "stderr"} or type(block["maximum"]) is not int or not 1 <= block["maximum"] <= 4:
            raise ValueError("Unsupported diagnostic stream or occurrence limit")
        if type(block["lines"]) is not list or not block["lines"] or any(type(line) is not str or "\n" in line or "\r" in line for line in block["lines"]):
            raise ValueError("Exact diagnostic lines required")
        for line in block["lines"]:
            residue = line.replace("{model_path}", "").replace("{driver_path}", "")
            if "{" in residue or "}" in residue or line.startswith("OIP-"):
                raise ValueError("Diagnostic templates cannot consume protocol or accept arbitrary text")
    return value


def split_exact(raw_stdout, raw_stderr, *, prefixes, allowlist=None, model_path="", driver_path=""):
    blocks = [] if allowlist is None else allowlist["allowed"]
    counts = [0] * len(blocks)
    protocol, removed = [], []
    for stream, raw in [("stdout", raw_stdout), ("stderr", raw_stderr)]:
        lines = raw.decode("ascii", errors="strict").splitlines()
        index = 0
        while index < len(lines):
            line = lines[index]
            if stream == "stdout" and any(line.startswith(prefix + "\t") for prefix in prefixes):
                protocol.append(line)
                index += 1
                continue
            match = None
            for number, block in enumerate(blocks):
                exact = [text.replace("{model_path}", model_path).replace("{driver_path}", driver_path) for text in block["lines"]]
                if block["stream"] == stream and lines[index:index + len(exact)] == exact:
                    if match is not None:
                        raise ValueError("Ambiguous exact diagnostic blocks")
                    match = (number, exact)
            if match is None:
                raise ValueError("Unknown model output line in " + stream + ": " + repr(line))
            number, exact = match
            counts[number] += 1
            if counts[number] > blocks[number]["maximum"]:
                raise ValueError("Diagnostic occurrence limit exceeded")
            removed.append({"stream": stream, "block": number, "lines": exact})
            index += len(exact)
    receipt = {"raw_stdout_sha256": hashlib.sha256(raw_stdout).hexdigest(),
        "raw_stderr_sha256": hashlib.sha256(raw_stderr).hexdigest(), "raw_streams_preserved_by_caller": True,
        "protocol_lines": len(protocol), "diagnostic_blocks": removed, "unknown_lines_ignored": 0}
    return protocol, receipt
