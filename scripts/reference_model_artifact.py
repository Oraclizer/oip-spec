"""Content-only pins for source-bound reference execution model artifacts."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import urllib.request

from model_diagnostics import digest, require_keys
from wire_model_artifact import relative_path, verify_blob

ROLE_NAMES = {"model": "oip_finite_financial.ML", "driver": "finite-driver.ML",
              "origin": "finite-export-origin.json", "diagnostics": "finite-compiler-diagnostics.json"}
FINANCIAL_IDENTITY = ["1", "intinf-finite-financial-v1", "finite-financial-raw-slice-v1",
                      "OIP_Finite_Financial.code_finite_raw_integer_step", "HOL-Library.Code_Target_Nat"]
FINANCIAL_CAPABILITIES = ["finite-single-asset-seed", "finite-raw-reserve", "finite-raw-dispatch", "finite-raw-debit",
                          "financial-result-and-commit-vector"]
MAX_BYTES = 16 * 1024 * 1024


def read_reference_lock(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    require_keys(value, ["format", "repository", "artifact_transport", "models"], "reference model lock")
    if value["format"] != 1 or value["repository"] != "Oraclizer/formal-verification" or value["artifact_transport"] != "github-git-blob-v1":
        raise ValueError("Unsupported reference artifact transport")
    require_keys(value["models"], ["financial", "full", "same-cut"], "reference capabilities")
    return value


def require_bound(lock, name, source_hash):
    model = lock["models"][name]
    require_keys(model, ["binding_status", "schema", "abi", "scope", "entrypoint", "natural_refinement", "runtime_source_hash",
                        "verified_export_sha256", "kernel_inputs_sha256", "engine", "capabilities", "files"], name + " model")
    if model["binding_status"] != "bound":
        raise ValueError(name + " model capability is unbound; no Unsupported/Pending/skip result is a match")
    if digest(model["runtime_source_hash"], "reference source") != source_hash:
        raise ValueError("Reference source footprint changed; a same-source identity/co-export is required")
    digest(model["kernel_inputs_sha256"], "kernel input seal")
    digest(model["verified_export_sha256"], "verified export")
    if name != "financial" or model["engine"] != "finite-financial-v1":
        raise ValueError(name + " model and its input-only consumer ABI have not been received")
    identity = [str(model["schema"]), model["abi"], model["scope"], model["entrypoint"], model["natural_refinement"]]
    if type(model["schema"]) is not int or identity != FINANCIAL_IDENTITY or model["capabilities"] != FINANCIAL_CAPABILITIES:
        raise ValueError("Unsupported finite financial capability or semantic identity")
    found = {}
    if type(model["files"]) is not list or len(model["files"]) != len(ROLE_NAMES):
        raise ValueError("Model, driver, origin and exact diagnostic pins are required")
    for member in model["files"]:
        require_keys(member, ["role", "name", "git_blob_sha1", "sha256", "bytes"], "reference artifact")
        role = member["role"]
        if role in found or role not in ROLE_NAMES or member["name"] != ROLE_NAMES[role]:
            raise ValueError("Unexpected/duplicate reference artifact role")
        digest(member["sha256"], "reference artifact")
        if type(member["git_blob_sha1"]) is not str or len(member["git_blob_sha1"]) != 40 or any(c not in "0123456789abcdef" for c in member["git_blob_sha1"]):
            raise ValueError("Content-only Git blob pin required")
        if type(member["bytes"]) is not int or not 0 < member["bytes"] <= MAX_BYTES:
            raise ValueError("Unbound or excessive reference artifact size")
        found[role] = member
    if found["model"]["sha256"] != model["verified_export_sha256"]:
        raise ValueError("Model bytes differ from verified export")
    return model, found, identity + [source_hash]


def load_reference_files(lock, model, members, identity, cache, local=None):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    paths = {}
    for role, member in members.items():
        path = cache / member["name"]
        if local is not None:
            data = relative_path(Path(local), member["name"]).read_bytes()
        elif path.is_file():
            data = path.read_bytes()
        else:
            url = "https://api.github.com/repos/" + lock["repository"] + "/git/blobs/" + member["git_blob_sha1"]
            request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "OIP-reference-conformance"})
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(2 * MAX_BYTES + 1)
            if len(raw) > 2 * MAX_BYTES:
                raise ValueError("Reference artifact response is too large")
            value = json.loads(raw)
            if value.get("encoding") != "base64" or value.get("sha") != member["git_blob_sha1"]:
                raise ValueError("Unexpected reference artifact transport response")
            data = base64.b64decode("".join(value["content"].split()), validate=True)
        verify_blob(data, member)
        path.write_bytes(data)
        paths[role] = path.resolve()
    origin = json.loads(paths["origin"].read_text(encoding="utf-8"))
    require_keys(origin, ["origin_version", "kernel_inputs_sha256", "identity", "model_sha256", "driver_sha256", "diagnostics_sha256"], "reference origin")
    if type(origin["origin_version"]) is not int or origin["origin_version"] != 1 or origin["identity"] != identity or origin["kernel_inputs_sha256"] != model["kernel_inputs_sha256"]:
        raise ValueError("Independent origin disagrees with verified same-source identity")
    for role in ["model", "driver", "diagnostics"]:
        if origin[role + "_sha256"] != members[role]["sha256"]:
            raise ValueError("Independent origin disagrees with artifact bytes")
    return paths
