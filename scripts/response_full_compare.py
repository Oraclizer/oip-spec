"""Post-execution comparisons. None of these source outputs feed the sender."""
from response_full import MetadataError,octets,byte_list,source_error_status

def frame_core(preimage_hex):
    data=bytes.fromhex(preimage_hex);prefix=b"OIP\0ENVELOPE\0"
    if not data.startswith(prefix) or len(data)<len(prefix)+4:raise MetadataError("Unprojected actual signer preimage")
    count=int.from_bytes(data[len(prefix):len(prefix)+4],"big");core=data[len(prefix)+4:]
    if count!=len(core):raise MetadataError("Actual signer frame length differs")
    return list(core)

def actual_prefix(source_input,observed,kind):
    trace=observed.get("trace",{})
    if "converted" not in trace:
        if kind=="full":return []
        raise MetadataError("Actual lower encoder is missing its boundary observations")
    rows=[[] for _ in range(14)]
    rows[0]=trace["converted"];rows[3]=octets(trace["canonical_original_core_hex"])
    if "words" not in trace:return rows
    rows[1]=trace["words"]
    if "atomicity" not in trace:return rows
    rows[2]=[trace["atomicity"]]
    message=b"oip/reference-response-binding/v1\0"+len(rows[3]).to_bytes(8,"big")+bytes(rows[3])+rows[2][0].to_bytes(8,"big")+len(rows[1]).to_bytes(8,"big")+b"".join(value.to_bytes(8,"big") for value in rows[1])
    rows[4]=list(message)
    if "binding_digest_hex" in trace:rows[5]=octets(trace["binding_digest_hex"],32)
    if "parameters_clock" in trace and rows[5]:
        rows[6]=list(b"oip/reference-response-uuid/v1\0"+bytes.fromhex(source_input["policy_binding_hex"])+bytes(rows[5])+trace["parameters_clock"].to_bytes(8,"big"))
    if "uuid_digest_hex" in trace:rows[7]=octets(trace["uuid_digest_hex"],32)
    if "parameters" in trace:
        value=trace["parameters"];rows[8]=octets(value["uuid_hex"],16)
        rows[9]=[value[key] for key in ["principal","key_id","authority_epoch","issued_seconds","ttl_seconds","route_scope"]]
    if "canonical_response_core_hex" in trace:rows[10]=octets(trace["canonical_response_core_hex"])
    if "signer_attempt_preimage_hex" in trace:
        rows[11]=octets(trace["signer_attempt_preimage_hex"]);rows[12]=[int(trace["signer_guard_permitted"])]
    if "curve_signature_hex" in trace:rows[13]=octets(trace["curve_signature_hex"],64)
    return rows

def compare_full_sender(evaluated,source_input,observed,kind):
    status=evaluated["status"];output=evaluated["rows"]
    packet=observed.get("response_packet_hex")
    error=observed.get("encoder_error_debug") if kind=="boundary" else observed.get("error_debug")
    expected_status=0 if packet is not None else source_error_status(error)
    differences=[]
    if status!=expected_status:differences.append({"field":"status","model":status,"source":expected_status})
    source_prefix=actual_prefix(source_input,observed,kind)
    if evaluated["prefix"]!=source_prefix:
        if len(evaluated["prefix"])!=len(source_prefix):differences.append({"field":"prefix-row-count","model":len(evaluated["prefix"]),"source":len(source_prefix)})
        else:
            for index,(model,actual) in enumerate(zip(evaluated["prefix"],source_prefix,strict=True)):
                if model!=actual:differences.append({"field":"prefix-"+str(index),"model":model,"source":actual})
    if status==0 and packet is not None:
        trace=observed["trace"];caller=trace["actual_call_id"];converted=trace["converted"]
        # The actual final descriptor is observed by validate_response; its
        # returned tuple is distinct from the caller's later current boundary.
        postcheck=trace.get("actual_postcheck")
        if postcheck is None:raise MetadataError("Actual encoder success has no checked typed tuple")
        wanted=[postcheck[:6],postcheck[:6],source_prefix[1],source_prefix[3],source_prefix[4],source_prefix[5],
                source_prefix[6],source_prefix[7],source_prefix[8],source_prefix[10],source_prefix[11],source_prefix[13],octets(packet),source_prefix[9],
                [0,0] if source_input["parameters_clock"] is None else [1,source_input["parameters_clock"]]]
        wanted[14]+=[0,0] if source_input["signing_clock"] is None else [1,source_input["signing_clock"]]
        if wanted[0][:2]!=caller or wanted[0][3:]!=converted:raise MetadataError("Source conversion/postcheck duplicate fields diverged")
        for index,(model,actual) in enumerate(zip(output,wanted,strict=True)):
            if model!=actual:differences.append({"field":"sender-success-"+str(index),"model":model,"source":actual})
    return differences

def compare_client(evaluated,observed):
    if "error_debug" in observed:expected_status=source_error_status(observed["error_debug"]);wanted=[]
    else:expected_status=observed["status"];wanted=observed["value"]
    if evaluated["status"]!=expected_status or evaluated["result"]!=wanted:
        return [{"field":"current-client","model":{"status":evaluated["status"],"value":evaluated["result"]},"source":{"status":expected_status,"value":wanted}}]
    return []
