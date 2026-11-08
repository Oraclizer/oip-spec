"""Structural validation of wire-value observations; no operand classifier."""
from pathlib import Path
import json
import re

ROOT=Path(__file__).resolve().parent.parent
FIELDS={"id","verdict","retained_binding","reencoded_core_hex","signing_preimage_hex","transport_key_ir","typed_operand_ir"}
VALUE_FIELDS={"reencoded_core_hex","signing_preimage_hex","transport_key_ir","typed_operand_ir"}
REFUSALS={54,70,71,72,73,74,75,76}

def exact_keys(value,keys,label):
    if type(value) is not dict or set(value)!=set(keys):raise ValueError(label+": missing or unexpected fields")

def octets(value,*,nonempty=False):
    if type(value) is not str or re.fullmatch(r"(?:[0-9a-f]{2})*",value) is None or nonempty and not value:
        raise ValueError("Canonical lowercase octets required")
    return value

def typed_tree(tokens,schema,*,root_tags=None):
    if type(tokens) is not list or not tokens or len(tokens)>262144:
        raise ValueError("Nonempty bounded typed IR token list required")
    if any(type(token) is not str or re.fullmatch(r"0|[1-9][0-9]*",token) is None for token in tokens):
        raise ValueError("Typed IR tokens must be canonical nonnegative decimal strings")
    values=list(map(int,tokens));index=0
    def take():
        nonlocal index
        if index>=len(values):raise ValueError("Truncated typed IR")
        value=values[index];index+=1;return value
    def parse(depth):
        if depth>64:raise ValueError("Typed IR is too deep")
        tag=take()
        if tag==0:
            value=take()
            if value>=2**64:raise ValueError("Typed wire scalar exceeds u64")
            return (tag,value)
        if tag==1:
            count=take()
            if count>len(values)-index:raise ValueError("Truncated typed bytes")
            data=[take() for _ in range(count)]
            if any(value>255 for value in data):raise ValueError("Non-octet typed bytes")
            return (tag,data)
        if tag==3:return (tag,)
        if tag==4:return (tag,parse(depth+1))
        if tag!=2 and str(tag) not in schema["domain_nodes"]:raise ValueError("Unknown typed domain node")
        count=take()
        if tag!=2 and count!=schema["domain_nodes"][str(tag)]["arity"]:raise ValueError("Wrong typed domain arity")
        if count>len(values)-index:raise ValueError("Truncated typed child list")
        return (tag,[parse(depth+1) for _ in range(count)])
    tree=parse(0)
    if index!=len(values):raise ValueError("Trailing typed IR tokens")
    if root_tags is not None and tree[0] not in root_tags:raise ValueError("Wrong typed IR root")
    return tree

def validate_result(row,schema):
    exact_keys(row,FIELDS,"wire result")
    if type(row["id"]) is not str or not row["id"]:raise ValueError("Result id required")
    verdict=row["verdict"]
    accepted=type(verdict) is str and verdict in {"accept:first","accept:identical"}
    if not accepted and (type(verdict) is not int or verdict not in REFUSALS):raise ValueError("Unknown/Pending wire verdict is not a match")
    if row["retained_binding"] is not None:octets(row["retained_binding"])
    if accepted:
        if row["retained_binding"] is None:raise ValueError("Accepted wire input has no retained binding")
        octets(row["reencoded_core_hex"],nonempty=True);octets(row["signing_preimage_hex"],nonempty=True)
        typed_tree(row["transport_key_ir"],schema,root_tags={200})
        typed_tree(row["typed_operand_ir"],schema,root_tags=set(range(10,22)))
    elif any(row[field] is not None for field in VALUE_FIELDS):raise ValueError("Refusal cannot carry a fabricated accepted value view")
    return row

def validate_results(rows,input_ids,schema):
    if [row.get("id") for row in rows]!=input_ids or len(set(input_ids))!=len(input_ids):raise ValueError("Missing/duplicate/reordered wire observations")
    return [validate_result(row,schema) for row in rows]

def require_equal(left,right):
    if len(left)!=len(right):raise ValueError("Wire implementation output count differs")
    for actual,expected in zip(left,right,strict=True):
        if actual!=expected:
            raise ValueError("Wire decision or exact typed value differs: "+json.dumps({"left":actual,"right":expected},sort_keys=True))

def schema():
    return json.loads((ROOT/"tests/typed-operands-ir.json").read_text(encoding="utf-8"))
