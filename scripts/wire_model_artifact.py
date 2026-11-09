"""Verify independent model blobs and the runtime/interface source footprint.

Artifact pins never contain a formal-verification whole-commit reference.
The generated model, artifact lock, export origin and downstream consumer
manifest are excluded from the source footprint to keep its binding acyclic.
"""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import urllib.request

SCOPE="wire-v6-general-33-values"
ABI="intinf-wire-values-v2"
ENTRY="OIP_Wire_Oracle_V061.sync_v061_nested_transport_flat"
NAT_REFINEMENT="HOL-Library.Code_Target_Nat"
IDENTITY_FUNCTION="OIP_Wire_Oracle_V061.sync_v061_typed_model_identity"
ROLES={"model":"oip_wire_oracle.ML","driver":"mirror-driver.ML","origin":"export-origin.json","diagnostics":"compiler-diagnostics.json"}
MAX_BLOB_BYTES=16*1024*1024


def exact_keys(value,expected,label):
    if not isinstance(value,dict) or set(value)!=set(expected):
        raise ValueError(f"{label}: unexpected or missing fields")


def digest(value,length,label):
    if not isinstance(value,str) or not re.fullmatch("[0-9a-f]{"+str(length)+"}",value):
        raise ValueError(f"{label}: a bound lowercase digest is required")
    return value


def relative_path(root,name):
    if not isinstance(name,str):raise ValueError("A relative path is required")
    path=PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        raise ValueError("Unsafe relative artifact/source path")
    resolved=(root/name).resolve()
    if not resolved.is_relative_to(root.resolve()):raise ValueError("Source path escapes repository")
    return resolved


def read_lock(path):
    lock=json.loads(path.read_text(encoding="utf-8"))
    exact_keys(lock,["lock_version","binding_status","artifact_transport","repository","wire_schema","abi","scope",
                     "entrypoint","natural_refinement","runtime_source_hash","verified_export_sha256","public_namespace","identity_function","corpus","files"],"model lock")
    if lock["binding_status"]!="bound":
        raise ValueError("Model artifact lock is unbound: the verified kernel export and public blob pins are required")
    if type(lock["lock_version"]) is not int or type(lock["wire_schema"]) is not int or lock["lock_version"]!=1 or lock["wire_schema"]!=1 or lock["artifact_transport"]!="github-git-blob-v1":
        raise ValueError("Unsupported model lock or wire schema")
    if lock["repository"]!="Oraclizer/formal-verification":raise ValueError("Unexpected artifact repository")
    for key,expected in [("abi",ABI),("scope",SCOPE),("entrypoint",ENTRY),("natural_refinement",NAT_REFINEMENT)]:
        if lock[key]!=expected:raise ValueError("Unsupported model "+key)
    namespace=lock["public_namespace"]
    if not isinstance(namespace,str) or not re.fullmatch(r"Oracle_Interoperability_Protocol(?:/[A-Za-z0-9_.-]+)*",namespace):
        raise ValueError("Final checked public namespace is required")
    if lock["identity_function"]!=IDENTITY_FUNCTION or lock["entrypoint"]!=ENTRY:raise ValueError("Typed coidentity function/entrypoint mismatch")
    digest(lock["runtime_source_hash"],64,"runtime source hash")
    digest(lock["verified_export_sha256"],64,"verified export SHA-256")
    exact_keys(lock["corpus"],["path","rows","sha256"],"corpus pin")
    if lock["corpus"]["path"]!="tests/vectors/wire-operations.jsonl" or lock["corpus"]["rows"]!=692:
        raise ValueError("Unexpected required corpus")
    digest(lock["corpus"]["sha256"],64,"corpus SHA-256")
    if not isinstance(lock["files"],list) or len(lock["files"])!=4:raise ValueError("Model, driver, independent origin and exact diagnostics are required")
    found={}
    for member in lock["files"]:
        exact_keys(member,["role","name","git_blob_sha1","sha256","bytes"],"artifact file")
        role=member["role"]
        if role in found or role not in ROLES or member["name"]!=ROLES[role]:raise ValueError("Unexpected or duplicate artifact role")
        digest(member["git_blob_sha1"],40,"content-only Git blob identity")
        digest(member["sha256"],64,"artifact SHA-256")
        if type(member["bytes"]) is not int or not 0<member["bytes"]<=MAX_BLOB_BYTES:raise ValueError("Artifact size is unbound or excessive")
        found[role]=member
    if found["model"]["sha256"]!=lock["verified_export_sha256"]:
        raise ValueError("Model bytes differ from the verified export pin")
    return lock,found


def inspect_source(path):
    """Inspect the lexical entry before following it or applying source filters."""
    try:
        info=path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("Cannot inspect runtime source: "+str(path)) from exc
    if stat.S_ISLNK(info.st_mode) or getattr(info,"st_file_attributes",0)&getattr(stat,"FILE_ATTRIBUTE_REPARSE_POINT",0x400):
        raise ValueError("Aliased runtime source is forbidden: "+str(path))
    if stat.S_ISREG(info.st_mode) and info.st_nlink>1:
        raise ValueError("Hard-linked runtime source is forbidden: "+str(path))
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise ValueError("Non-regular runtime source is forbidden: "+str(path))
    return info


def source_path(root,name,optional=False):
    """Check every repository-relative component without resolving aliases."""
    if not isinstance(name,str):raise ValueError("A relative source path is required")
    relative=PurePosixPath(name)
    if not relative.parts or relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
        raise ValueError("Unsafe relative artifact/source path")
    if relative.as_posix()!=name:
        raise ValueError("A canonical relative source path is required")
    path=root
    for index,part in enumerate(relative.parts):
        path=path/part
        info=inspect_source(path)
        if info is None:
            if optional:return root.joinpath(*relative.parts),None
            raise ValueError("Missing runtime/interface source: "+name)
        if index<len(relative.parts)-1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("Source path parent is not a directory: "+name)
    return path,info


def runtime_source_hash(root):
    root=Path(root).absolute()  # Do not resolve away a root symlink/junction.
    root_info=inspect_source(root)
    if root_info is None or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("Missing repository source root")
    policy_path,policy_info=source_path(root,"tests/runtime-source-files.json")
    if not stat.S_ISREG(policy_info.st_mode):raise ValueError("Footprint policy is not a regular file")
    policy=json.loads(policy_path.read_text(encoding="utf-8"))
    exact_keys(policy,["format","scope","hash_algorithm","files","optional_files","source_directories","excludes","change_policy"],"runtime footprint policy")
    if policy["format"]!="oip-runtime-source-v1" or policy["scope"]!=SCOPE or policy["hash_algorithm"]!="sha256-canonical-path-digest-list":
        raise ValueError("Unsupported runtime footprint policy")
    if not all(isinstance(policy[key],list) and all(isinstance(name,str) for name in policy[key]) for key in ("files","optional_files")):
        raise ValueError("Source file inventories must be lists of relative paths")
    names=policy["files"]+policy["optional_files"]
    if len(names)!=len(set(names)) or "tests/runtime-source-files.json" not in policy["files"]:
        raise ValueError("Duplicate source paths or missing self-bound footprint policy")
    if set(names)&{"tests/model-artifact.lock.json","tests/reference-models.lock.json","tests/wire-response-artifact.lock.json"}:
        raise ValueError("Artifact lock cannot be part of its own runtime footprint")
    directories=policy["source_directories"]
    if not isinstance(directories,list) or directories!=["src","examples","go","scripts"]:
        raise ValueError("The Rust, example, Go and Python source directories must all be bound")
    source_names=set(names)

    def walk(directory,path):
        # Inspect every child first, including directories and non-.py entries.
        # Path.rglob/is_file can otherwise skip or traverse an alias silently.
        children=[]
        for candidate in sorted(path.iterdir(),key=lambda value:value.name):
            info=inspect_source(candidate)
            if info is None:raise ValueError("Source entry disappeared: "+str(candidate))
            if candidate.name==".git":raise ValueError("Nested Git metadata is not a source input")
            children.append((candidate,info))
        for candidate,info in children:
            if stat.S_ISDIR(info.st_mode):
                walk(directory,candidate)
            elif directory!="scripts" or candidate.suffix==".py":
                source_names.add(candidate.relative_to(root).as_posix())

    for directory in directories:
        path,info=source_path(root,directory)
        if not stat.S_ISDIR(info.st_mode):raise ValueError("Missing source directory: "+directory)
        walk(directory,path)
    if source_names&{"tests/model-artifact.lock.json","tests/reference-models.lock.json","tests/wire-response-artifact.lock.json"}:
        raise ValueError("The model lock cannot be part of its source footprint")
    rows=[]
    for name in sorted(source_names):
        path,info=source_path(root,name,optional=name in policy["optional_files"])
        if info is None:
            value=None
        elif stat.S_ISREG(info.st_mode):
            value=hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            raise ValueError("Runtime/interface source is not a regular file: "+name)
        rows.append({"path":name,"sha256":value})
    payload={"format":policy["format"],"scope":policy["scope"],"files":rows}
    data=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
    return hashlib.sha256(data).hexdigest(),payload


def verify_blob(data,member):
    if len(data)!=member["bytes"] or hashlib.sha256(data).hexdigest()!=member["sha256"]:
        raise ValueError("Artifact bytes or SHA-256 mismatch: "+member["role"])
    identity=hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\0"+data).hexdigest()
    if identity!=member["git_blob_sha1"]:raise ValueError("Git content identity mismatch")


def load_artifact(lock,members,cache,local=None):
    cache.mkdir(parents=True,exist_ok=True)
    paths={}
    for role,member in members.items():
        path=cache/member["name"]
        if local is not None:
            data=relative_path(local,member["name"]).read_bytes()
        elif path.is_file():
            data=path.read_bytes()
        else:
            url="https://api.github.com/repos/"+lock["repository"]+"/git/blobs/"+member["git_blob_sha1"]
            request=urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2026-03-10",
                                                       "User-Agent":"OIP-wire-model-conformance"})
            with urllib.request.urlopen(request,timeout=30) as response:
                raw=response.read(2*MAX_BLOB_BYTES+1)
            if len(raw)>2*MAX_BLOB_BYTES:raise ValueError("Artifact response exceeds bound")
            value=json.loads(raw)
            if value.get("encoding")!="base64" or value.get("sha")!=member["git_blob_sha1"]:
                raise ValueError("Unexpected Git blob response")
            data=base64.b64decode("".join(value["content"].split()),validate=True)
        verify_blob(data,member)
        path.write_bytes(data)
        paths[role]=path.resolve()
    origin=json.loads(paths["origin"].read_text(encoding="utf-8"))
    exact_keys(origin,["origin_version","kernel_inputs_sha256","wire_schema","abi","scope","entrypoint","natural_refinement",
                       "runtime_source_hash","model_sha256","driver_sha256","diagnostics_sha256","public_namespace","identity_function"],"independent export origin")
    if type(origin["origin_version"]) is not int or origin["origin_version"]!=1 or type(origin["wire_schema"]) is not int:
        raise ValueError("Unsupported export origin")
    digest(origin["kernel_inputs_sha256"],64,"kernel input seal")
    for key in ["wire_schema","abi","scope","entrypoint","natural_refinement","runtime_source_hash","public_namespace","identity_function"]:
        if origin[key]!=lock[key]:raise ValueError("Export origin disagrees with lock: "+key)
    if (origin["model_sha256"]!=members["model"]["sha256"] or origin["driver_sha256"]!=members["driver"]["sha256"]
        or origin["diagnostics_sha256"]!=members["diagnostics"]["sha256"]):
        raise ValueError("Export origin file hashes disagree")
    return paths
