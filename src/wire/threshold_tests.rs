//! Test-only raw input adapter. No model output or expected verdict is read.
use super::*;
use serde_json::{Value, json};
use std::cell::Cell;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn n(row: &Value, name: &str) -> u64 { row[name].as_u64().unwrap() }
fn verdict(result: Result<()>) -> Value {
    match result {
        Ok(()) => json!("accept"),
        Err(WireError::InvalidFormat) => json!(70),
        Err(WireError::UnsupportedVersion) => json!(71),
        Err(WireError::InvalidSource) => json!(72),
        Err(WireError::InvalidSignature) => json!(73),
        Err(WireError::InvalidThresholdSignature) => json!(74),
        Err(WireError::TtlExpired) => json!(54),
        Err(WireError::TtlInvalid) => json!(75),
        Err(WireError::ReplayConflict) => json!(76),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn threshold_configured_transport_replays_raw_packets() {
    let Some(path) = std::env::var_os("OIP_P19_INPUT") else { return };
    let input = std::fs::read_to_string(path).unwrap();
    let mut output = String::new();
    for line in input.lines().filter(|s| !s.is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let p = &row["profile"];
        let set = |name: &str| p[name].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        let profile = Profile { version:n(p,"version"), families:set("families"), atomicities:set("atomicities"), schemes:set("schemes") };
        let b = &row["boundary"];
        let boundary = Boundary {
            deployment:n(b,"deployment"), source:n(b,"source"), target:n(b,"target"),
            principal:n(b,"principal"), key_id:n(b,"key_id"), epoch:n(b,"epoch"), route_scope:n(b,"route_scope"),
            now:n(b,"now"), asset_ttl_floor:n(b,"asset_ttl_floor"), future_skew:n(b,"future_skew"),
            max_frame:usize::try_from(n(b,"max_frame")).unwrap(), max_nesting:usize::try_from(n(b,"max_nesting")).unwrap(),
            version_floor:n(b,"version_floor"), critical_allowed:b["critical_allowed"].as_bool().unwrap(),
            public_key:unhex(b["public_key"].as_str().unwrap()).try_into().unwrap(),
        };
        let r = &row["roster"];
        let rosters:Vec<_> = (!r.is_null()).then(|| ThresholdRoster {
            deployment:n(r,"deployment"), source:n(r,"source"), principal:n(r,"principal"), key_id:n(r,"key_id"),
            epoch:n(r,"epoch"), quorum:n(r,"quorum"),
            members:r["members"].as_array().unwrap().iter().map(|m| (m[0].as_u64().unwrap(), unhex(m[1].as_str().unwrap()).try_into().unwrap())).collect(),
        }).into_iter().collect();
        let bytes = unhex(row["packet_hex"].as_str().unwrap());
        let decoded = decode_packet(&bytes, boundary.max_frame);
        let gate = check_declared_version(&bytes,boundary.max_frame).and_then(|_| decoded.as_ref().map_err(|e| *e))
            .and_then(|packet| admit_packet_configured(packet,&profile,&boundary,&rosters));
        let key = decode_packet(&bytes, usize::MAX).ok().and_then(|p| TransportKey::for_core(p.core()).ok());
        let mut bindings = TransportBindings::default();
        if let (Some(key), Some(prior)) = (key,row["prior_binding"].as_str()) { bindings.0.insert(key,unhex(prior)); }
        let before = bindings.0.clone();
        let attested = Cell::new(false);
        let actual = bindings.receive_configured(&bytes,&profile,&boundary,&rosters, |_| {
            attested.set(true); row["attestation_valid"].as_bool().unwrap()
        });
        let result = match actual {
            Ok((Arrival::First,_)) => json!("accept:first"),
            Ok((Arrival::Identical,_)) => json!("accept:identical"),
            Err(error) => { assert_eq!(bindings.0,before,"refusal changes binding: {}",row["id"]); verdict(Err(error)) },
        };
        let observation = json!({
            "id":row["id"], "packet_hex":row["packet_hex"], "gate_verdict":verdict(gate), "verdict":result,
            "signing_preimage_hex":decoded.as_ref().ok().and_then(|p| p.signing_bytes().ok()).map(|b| hex(&b)),
            "core_hex":decoded.as_ref().ok().map(|p| hex(p.core_bytes())),
            "selected_roster":decoded.as_ref().ok().and_then(|p| crate::wire::threshold::select(&rosters,p.core())),
            "scope_ttl_verdict":decoded.as_ref().ok().map(|p| verdict(check_scope(p.core(),&profile,&boundary))),
            "attestation_called":attested.get(),"prior_binding":row["prior_binding"],
            "retained_binding":key.and_then(|k| bindings.0.get(&k)).map(|b| hex(b)),
            "binding_unchanged":bindings.0 == before,
        });
        output.push_str(&serde_json::to_string(&observation).unwrap()); output.push('\n');
    }
    std::fs::write(std::env::var_os("OIP_P19_OUTPUT").unwrap(),output).unwrap();
}

#[test]
fn threshold_admission_preserves_scope_and_size_precedence() {
    use ed25519_dalek::{Signer, SigningKey};
    use crate::wire::codec::{encode_core, encode_packet, signing_bytes};
    use crate::wire::generated::Packet;
    use prost::Message;
    let Some(path)=std::env::var_os("OIP_P19_INPUT") else{return};
    let input=std::fs::read_to_string(path).unwrap();
    let row:Value=serde_json::from_str(input.lines().next().unwrap()).unwrap();
    let bytes=unhex(row["packet_hex"].as_str().unwrap());let packet=decode_packet(&bytes,bytes.len()).unwrap();
    let profile=Profile{version:6,families:(1..=7).collect(),atomicities:(1..=3).collect(),schemes:[1,2].into()};
    let mut boundary=Boundary{deployment:7,source:0,target:0,principal:7,key_id:40,epoch:9,route_scope:1,now:105,
        asset_ttl_floor:0,future_skew:0,max_frame:1048576,max_nesting:4,version_floor:6,critical_allowed:false,
        public_key:SigningKey::from_bytes(&[7;32]).verifying_key().to_bytes()};
    boundary.source=1;assert_eq!(admit_packet_configured(&packet,&profile,&boundary,&[]),Err(WireError::InvalidSource));
    boundary.source=0;boundary.now=106;assert_eq!(admit_packet_configured(&packet,&profile,&boundary,&[]),Err(WireError::TtlExpired));
    boundary.now=99;assert_eq!(admit_packet_configured(&packet,&profile,&boundary,&[]),Err(WireError::TtlInvalid));
    boundary.now=105;boundary.max_frame=1;
    assert_eq!(admit_packet(&packet,&profile,&boundary),Err(WireError::InvalidThresholdSignature));
    assert_eq!(admit_packet_configured(&packet,&profile,&boundary,&[]),Err(WireError::InvalidFormat));
    let mut core=packet.core().clone();core.signature_scheme=Some(1);core.key_id=Some(9);
    let signed=Packet{signature:Some(SigningKey::from_bytes(&[7;32]).sign(&signing_bytes(&encode_core(&core).unwrap()).unwrap()).to_bytes().to_vec()),core:Some(core.clone())};
    let single=encode_packet(&signed).unwrap();let single=decode_packet(&single,single.len()).unwrap();boundary.key_id=9;
    assert_eq!(admit_packet(&single,&profile,&boundary),Ok(()));
    assert_eq!(admit_packet_configured(&single,&profile,&boundary,&[]),Err(WireError::InvalidFormat));
    core.signature_scheme=Some(3);
    assert_eq!(decode_packet(&Packet{core:Some(core),signature:Some(vec![1;64])}.encode_to_vec(),1048576).err(),Some(WireError::InvalidFormat));
    assert_eq!(decode_packet(&Packet{core:Some(packet.core().clone()),signature:Some(vec![])}.encode_to_vec(),1048576).err(),Some(WireError::InvalidFormat));
}

#[test]
fn threshold_roster_validates_quorum_members_and_keys() {
    use ed25519_dalek::SigningKey;
    let roster=ThresholdRoster{deployment:7,source:0,principal:7,key_id:40,epoch:9,quorum:2,
        members:vec![(0,SigningKey::from_bytes(&[61;32]).verifying_key().to_bytes()),
            (u64::MAX,SigningKey::from_bytes(&[62;32]).verifying_key().to_bytes())]};
    assert!(roster.valid());
    let mut invalid=roster.clone();invalid.quorum=0;assert!(!invalid.valid());
    invalid=roster.clone();invalid.quorum=3;assert!(!invalid.valid());
    invalid=roster.clone();invalid.members[1].0=0;assert!(!invalid.valid());
    invalid=roster.clone();invalid.members[1].1=invalid.members[0].1;assert!(!invalid.valid());
    invalid=roster.clone();invalid.members[0].1=[0;32];assert!(!invalid.valid());
    invalid=roster;invalid.members[0].1=[255;32];assert!(!invalid.valid());
}
