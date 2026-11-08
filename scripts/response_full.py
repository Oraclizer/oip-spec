"""Full response ABI serialization and strict model-issued primitive broker.

Only source inputs/getters and typed boundary enums enter the sender. Source
observations are accepted by separate comparison functions after evaluation.
"""
from __future__ import annotations
import json
import re

IDENTITY=["1","intinf-response-full-v1","wire-response-sender-client-v1",
          "OIP_Wire_Response_Boundary.code_response_egress_flat_oracle","HOL-Library.Code_Target_Nat"]
COMMON_KEYS={"id","mode","reply_values","retained_present","retained_values","raw_original_packet_hex","config",
             "policy_binding_hex","parameters_clock","signing_clock","frame_limit","channel"}
OPTIONAL_KEYS={"site","execution_kind","provenance","primitive_fixture_keys","family","opcode","branch_class"}

class MetadataError(ValueError):pass

def u64(value):
    if type(value) is not int or not 0<=value<2**64:raise MetadataError("Expected exact nonnegative u64 metadata")
    return value
def integers(values):
    if type(values) is not list:raise MetadataError("Expected integer metadata list")
    result=[]
    for value in values:
        if type(value) is str:
            if re.fullmatch(r"0|[1-9][0-9]*",value) is None:raise MetadataError("Noncanonical decimal metadata")
            value=int(value)
        result.append(u64(value))
    return result
def octets(value,length=None):
    if type(value) is not str or re.fullmatch(r"(?:[0-9a-f]{2})*",value) is None:raise MetadataError("Canonical hex octets required")
    result=list(bytes.fromhex(value))
    if length is not None and len(result)!=length:raise MetadataError("Wrong primitive/getter byte length")
    return result
def byte_list(values,length=None):
    result=integers(values)
    if any(value>255 for value in result) or length is not None and len(result)!=length:raise MetadataError("Invalid byte list")
    return result
def clock(value):return [0,0] if value is None else [1,u64(value)]
def matrix_encode(rows):
    flat=[len(rows)]
    for row in rows:flat.extend([len(row),*row])
    return ",".join(str(value) if value>=0 else "~"+str(-value) for value in flat)
def scalar_encode(values):return ",".join(map(str,values))
def parse_signed(text):
    if re.fullmatch(r"0|~?[1-9][0-9]*",text) is None:raise MetadataError("Noncanonical model integer")
    return int(text.replace("~","-"))
def matrix_decode(text):
    values=[] if text=="" else [parse_signed(value) for value in text.split(",")]
    if not values or values[0]<0:raise MetadataError("Malformed model row matrix")
    count=values[0];index=1;rows=[]
    for _ in range(count):
        if index>=len(values) or values[index]<0:raise MetadataError("Truncated model row matrix")
        size=values[index];index+=1
        if size>len(values)-index:raise MetadataError("Truncated model row payload")
        rows.append(values[index:index+size]);index+=size
    if index!=len(values):raise MetadataError("Trailing model row tokens")
    return rows

def sender_input(row,kind):
    if kind not in {"full","boundary"}:raise MetadataError("Unknown sender evidence scope")
    if type(row) is not dict or not COMMON_KEYS<=set(row) or set(row)-COMMON_KEYS-OPTIONAL_KEYS:raise MetadataError("Unexpected/missing sender input; observed answers are forbidden")
    mode=u64(row["mode"]);reply=integers(row["reply_values"]);retained=integers(row["retained_values"])
    if type(row["retained_present"]) is not bool:raise MetadataError("Retained presence must be explicit")
    present=row["retained_present"]
    if mode not in {0,1,2,3} or mode!=0 and present or not present and retained:raise MetadataError("Malformed typed boundary input")
    if mode==3 and (kind!="full" or reply or present or retained):raise MetadataError("Absent result is full-preflight-only; no dummy Outcome")
    config=row["config"];channel=row["channel"]
    peers=config["peers"]
    if type(peers) is not dict:raise MetadataError("Source peers must remain principal-keyed")
    peer_values=[peers[key] for key in sorted(peers,key=lambda value:int(value))]
    domains=[u64(peer["identity"]["domain"]) for peer in peer_values]
    peer_keys=[byte_list(peer["public_key"],32) for peer in peer_values]
    endpoints=sorted({u64(config["endpoint"]),*[u64(value) for value in config.get("other_endpoints",[])]})
    site=row.get("site")
    if kind=="full":
        if type(site) is not dict or set(site)!={"profile","ordered_control_present","security_ordered_profile"}:raise MetadataError("Full sender needs its actual site getters")
        profile=site["profile"];security=site["security_ordered_profile"]
        if type(site["ordered_control_present"]) is not bool:raise MetadataError("Bad ordered-control getter")
        site_row=[u64(profile["deployment"]),u64(profile["format"]),u64(profile["authority_profile"]),int(site["ordered_control_present"]),int(security is not None)]
        site_row.extend([u64(security[key]) for key in ["deployment","format","authority_profile"]] if security is not None else [0,0,0])
    else:
        if site is not None:raise MetadataError("Lower encoder fixture has no authority site; do not upgrade its provenance")
        # Explicitly unused lower-entry metadata, never used for full preflight.
        site_row=[0]*8
    context=[
        [u64(channel[key]) for key in ["version","deployment","local","remote","expires"]],
        integers(channel["families"]),integers(channel["atomicities"]),integers(channel["schemes"]),
        octets(channel["local_public_key_hex"],32),octets(channel["remote_public_key_hex"],32),
        [u64(config["profile"]["deployment"]),u64(config["local_principal"]),u64(config["local_key_id"]),u64(config["authority_epoch"]),u64(config["route_scope"]),u64(config["response_ttl_seconds"]),u64(config["max_nesting"])],
        endpoints,domains,byte_list(config["response_key"],32),octets(row["policy_binding_hex"],32),site_row,
        clock(row["parameters_clock"])+clock(row["signing_clock"]),[u64(row["frame_limit"])],*peer_keys]
    return {"context":context,"mode":mode,"reply":reply,"retained_present":present,"retained":retained,
            "original":octets(row["raw_original_packet_hex"])}

def client_input(row):
    expected={"id","channel","boundary","canonical_expected_packet_hex","network_response_packet_hex"}
    if type(row) is not dict or not expected<=set(row) or set(row)-expected-{"provenance"}:raise MetadataError("Client network inputs/getters required")
    c=row["channel"];b=row["boundary"]
    rows=[[u64(c[key]) for key in ["version","deployment","local","remote","expires"]],
          integers(c["families"]),integers(c["atomicities"]),integers(c["schemes"]),octets(c["local_public_key_hex"],32),octets(c["remote_public_key_hex"],32),
          [u64(b[key]) for key in ["deployment","source","target","principal","key_id","epoch","route_scope","now","asset_ttl_floor","future_skew","max_frame","version_floor","max_nesting"]],
          [int(b["critical_allowed"])],octets(b["public_key_hex"],32)]
    if type(b["critical_allowed"]) is not bool:raise MetadataError("Actual client critical flag required")
    return rows,octets(row["canonical_expected_packet_hex"]),octets(row["network_response_packet_hex"])

def decode_request(row):
    row=integers(row)
    if not row or row[0] not in {0,1,2}:raise MetadataError("Unknown named primitive request")
    kind=row[0];index=1;fields=[]
    for _ in range({0:1,1:2,2:3}[kind]):
        if index>=len(row):raise MetadataError("Truncated primitive request")
        size=row[index];index+=1
        if size>len(row)-index:raise MetadataError("Truncated primitive field")
        fields.append(byte_list(row[index:index+size]));index+=size
    if index!=len(row) or kind in {1,2} and len(fields[0])!=32:raise MetadataError("Invalid primitive request fields")
    return kind,tuple(tuple(value) for value in fields)

class Transcript:
    def __init__(self):self.hashes={};self.signatures={};self.verifications={};self.requests=[]
    def rows(self):
        hashes=[list(value) for pair in self.hashes.items() for value in pair]
        signs=[list(value) for key,result in self.signatures.items() for value in [key[0],key[1],result]]
        verifies=[list(value) for key,result in self.verifications.items() for value in [key[0],key[1],key[2],(int(result),)]]
        return hashes,signs,verifies
    def fill(self,request_row,provider):
        kind,fields=decode_request(request_row)
        table=[self.hashes,self.signatures,self.verifications][kind]
        key=fields[0] if kind==0 else fields
        if key in table:raise MetadataError("Model planner repeated an already filled query; no progress")
        answer=provider(kind,fields)
        if kind==0:answer=tuple(byte_list(list(answer),32))
        elif kind==1:answer=tuple(byte_list(list(answer),64))
        elif type(answer) is not bool:raise MetadataError("Missing verifier answer is not false verification")
        table[key]=answer;self.requests.append({"kind":kind,"fields":[list(v) for v in fields],"answer":list(answer) if kind!=2 else answer})

def complete_sender(model,source_input,kind,provider):
    args=sender_input(source_input,kind);transcript=Transcript();planner="Q" if kind=="full" else "q"
    for _ in range(32):
        status,requests=model.sender(planner,args,transcript.rows())
        if status<0:raise MetadataError("Sender planner metadata/missing primitive status: "+str(status))
        if status!=0:raise MetadataError("Planner returned a protocol verdict instead of request metadata")
        if not requests:break
        for request in requests:transcript.fill(request,provider)
    else:raise MetadataError("Primitive planner failed to converge")
    prefix_status,prefix=model.sender("P" if kind=="full" else "p",args,transcript.rows())
    status,output=model.sender("S" if kind=="full" else "B",args,transcript.rows())
    if prefix_status<0 or status<0:raise MetadataError("Missing transcript/typed result aborts actual model execution")
    if prefix_status!=0:raise MetadataError("Invalid model prefix metadata")
    if status==0 and len(output)!=15:raise MetadataError("Successful sender is missing actual output rows")
    if status==0:
        if len(output[0])!=6 or len(output[1])!=6 or len(output[13])!=6 or len(output[14])!=4:raise MetadataError("Malformed successful sender tuples")
        for index in [3,4,5,6,7,8,9,10,11,12]:byte_list(output[index])
        for index,length in [(5,32),(7,32),(8,16),(11,64)]:byte_list(output[index],length)
        if any(not output[index] for index in [3,4,6,9,10,12]):raise MetadataError("Sender success dropped exact bytes")
    if prefix and len(prefix)!=14:raise MetadataError("Malformed signer-prefix observation")
    if status!=0 and output:raise MetadataError("Refused sender invented a returned packet")
    return {"status":status,"rows":output,"prefix":prefix,"transcript":transcript,"args":args}

def complete_client(model,context,expected,network,provider):
    transcript=Transcript()
    for _ in range(16):
        status,requests=model.client("V",context,expected,network,transcript.rows()[2])
        if status!=0:raise MetadataError("Client request planner is incomplete")
        if not requests:break
        for request in requests:transcript.fill(request,provider)
    else:raise MetadataError("Client primitive planner failed to converge")
    status,result=model.client("C",context,expected,network,transcript.rows()[2])
    if status<0:raise MetadataError("Missing current-client transcript aborts execution")
    if status==0 and (len(result)!=9 or result[6] not in {0,1}):raise MetadataError("Client must preserve typed Known/Unknown result")
    if status!=0 and result:raise MetadataError("Refused client invented a typed result")
    return {"status":status,"result":result,"transcript":transcript}

def source_error_status(debug):
    # Observation normalization only. This never enters a model input.
    values={"InvalidFormat":70,"UnsupportedVersion":71,"InvalidSource":72,"InvalidSignature":73,"InvalidThresholdSignature":74,
            "TtlInvalid":75,"ReplayConflict":76,"ProductRejected":77,"TtlExpired":54,"Cancelled":53,"DeadlineExpired":52,
            "ResponseLost":51,"RequestUnresolved":50}
    if debug not in values:raise MetadataError("Unprojected actual source error must remain incomplete: "+str(debug))
    return values[debug]

def compare_sender(evaluated,observed,kind):
    status=evaluated["status"];rows=evaluated["rows"];prefix=evaluated["prefix"]
    actual_packet=observed.get("response_packet_hex")
    error=observed.get("encoder_error_debug") if kind=="boundary" else observed.get("error_debug")
    expected_status=0 if actual_packet is not None else source_error_status(error)
    differences=[]
    if status!=expected_status:differences.append({"field":"sender_status","model":status,"source":expected_status})
    if status==0 and actual_packet is not None:
        if byte_list(rows[12])!=octets(actual_packet):differences.append({"field":"response_packet","model":bytes(rows[12]).hex(),"source":actual_packet})
    if kind=="boundary":
        wanted=[observed["source_result_number"],int(observed["source_result_commit"] is not None),observed["source_result_commit"] or 0]
        if not prefix:raise MetadataError("Boundary model dropped its actual constructor prefix")
        if prefix[0]!=wanted:differences.append({"field":"converted_result","model":prefix[0],"source":wanted})
        fields={1:(observed["words"] or []),2:[observed["atomicity"]] if observed["words"] is not None else [],
                3:octets(observed["canonical_original_core_hex"]),4:octets(observed["binding_preimage_hex"] or ""),
                5:octets(observed["binding_digests_hex"][0]) if observed["binding_digests_hex"] else [],
                6:octets(observed["uuid_preimage_hex"] or "")}
        params=observed["actual_parameters"]
        if params:
            p=params[0];fields[8]=octets(p["uuid_hex"]);fields[9]=[p[key] for key in ["principal","key_id","authority_epoch","issued_seconds","ttl_seconds","route_scope"]]
        else:fields[8]=[];fields[9]=[]
        attempts=observed["actual_sign_queries"]
        fields[11]=octets(attempts[0]["preimage_hex"]) if attempts else []
        fields[12]=[int(attempts[0]["signature_hex"] is not None)] if attempts else []
        fields[13]=octets(attempts[0]["signature_hex"]) if attempts and attempts[0]["signature_hex"] is not None else []
        for index,value in fields.items():
            if prefix[index]!=value:differences.append({"field":"prefix-"+str(index),"model":prefix[index],"source":value})
    return differences
