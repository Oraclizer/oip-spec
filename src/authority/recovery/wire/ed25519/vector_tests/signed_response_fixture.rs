//! Actual Ed25519 signer and public response admission, with fixed semantic cases.
use super::*;
use crate::authority::recovery::wire::response::{ResponseSigner,ResponseStatus,admit_response};
use crate::authority::recovery::wire::vector_tests::core_with;
use crate::wire::admission::Boundary;
use crate::wire::codec::{CanonicalPacket,encode_core,encode_packet,signing_bytes};
use crate::wire::generated::{Core,Operation,Packet,core::Body};
use serde_json::{Value,json};
use std::collections::VecDeque;
use std::fs::{self,OpenOptions};
use std::io::Write;
use std::sync::{Arc,Mutex};

fn hex(bytes:&[u8])->String { bytes.iter().map(|b|format!("{b:02x}")).collect() }
fn sha(bytes:&[u8])->String { hex(&Sha256::digest(bytes)) }

#[derive(Clone)]
struct ObservedClock { script:Arc<Mutex<VecDeque<u64>>>, reads:Arc<Mutex<Vec<u64>>> }
impl AuthorityClock for ObservedClock {
    fn unix_seconds(&self)->Option<u64> {
        let now=self.script.lock().ok()?.pop_front()?;
        self.reads.lock().ok()?.push(now);
        Some(now)
    }
}

pub(super) fn actual_signed_response(embedded:&CanonicalPacket,words:Vec<u64>)->(Vec<u8>,Value) {
    let mut config=config();
    // Principal registrations are not keyed by domain. Retain both keys in
    // the response projection when two registered principals share domain 0.
    let mut second=config.peers[&7].clone();
    second.identity.principal=8;
    second.identity.ocid=108;
    second.identity.rai=208;
    second.public_key=key(10).verifying_key().to_bytes();
    config.peers.insert(8,second);
    let clock=ObservedClock {script:Arc::new(Mutex::new(VecDeque::from([105,106]))),reads:Arc::new(Mutex::new(Vec::new()))};
    let security=Ed25519Security::new(config.clone(),key(6),clock.clone()).unwrap();
    let channel=super::reference_execution_trace::channel_for(6,7);
    assert!(security.channel_current(&channel));
    let atomicity=*channel.profile().atomicities.first().unwrap();
    let mut binding=Sha256::new();
    binding.update(b"oip/reference-response-binding/v1\0");
    binding.update(u64::try_from(embedded.core_bytes().len()).unwrap().to_be_bytes());
    binding.update(embedded.core_bytes());binding.update(atomicity.to_be_bytes());
    binding.update(u64::try_from(words.len()).unwrap().to_be_bytes());
    for word in &words {binding.update(word.to_be_bytes());}
    let response_binding:[u8;32]=binding.finalize().into();
    let params=security.parameters(&channel,response_binding).expect("actual source parameters");
    let after_parameters=clock.reads.lock().unwrap().clone();
    let core=Core {
        version:Some(6),purpose:Some(1),deployment:Some(channel.deployment()),
        source_domain:Some(channel.local()),target_domain:Some(channel.remote()),
        principal:Some(params.principal),key_id:Some(params.key_id),authority_epoch:Some(params.authority_epoch),
        issued_seconds:Some(params.issued_seconds),ttl_seconds:Some(params.ttl_seconds),uuid:Some(params.uuid.to_vec()),
        family:Some(5),primary:Some(1),secondary:None,signature_scheme:Some(1),atomicity:Some(atomicity),
        priority:Some(3),route_scope:Some(params.route_scope),
        body:Some(Body::Ack(Operation {opcode:Some(2),words,blobs:vec![embedded.core_bytes().to_vec()],appeal_deadline:None})),
    };
    let core_bytes=encode_core(&core).unwrap();
    let preimage=signing_bytes(&core_bytes).unwrap();
    let signature=security.sign(&preimage).expect("actual source sign");
    let all_reads=clock.reads.lock().unwrap().clone();
    assert_eq!(after_parameters,[105]);
    assert_eq!(all_reads,[105,106],"parameters and sign have separate clock observations");
    assert!(clock.script.lock().unwrap().is_empty());
    let packet=encode_packet(&Packet {core:Some(core),signature:Some(signature.to_vec())}).unwrap();
    let peers:Vec<_>=config.peers.iter().map(|(principal,peer)|json!({"principal":principal,
        "domain":peer.identity.domain,"public_key_hex":hex(&peer.public_key)})).collect();
    let response_peers:BTreeSet<_>=config.peers.values().map(|peer|(peer.identity.domain,hex(&peer.public_key))).collect();
    let observation=json!({"config":config,"policy_binding_hex":hex(&security.binding),
        "source_signing_peers":peers,"response_config_peers":response_peers,
        "local_principal":params.principal,"local_key_id":params.key_id,"response_public_key_hex":hex(&key(6).verifying_key().to_bytes()),
        "response_binding_hex":hex(&response_binding),"uuid_hex":hex(&params.uuid),
        "parameters_clock_reads":after_parameters,"sign_clock_reads":&all_reads[1..],
        "preimage_hex":hex(&preimage),"signature_hex":hex(&signature),"response_packet_hex":hex(&packet),
        "response_packet_sha256":sha(&packet),"embedded_original_core_hex":hex(embedded.core_bytes())});
    (packet,observation)
}

pub(super) fn expected_packet(case:&Value,debit:&[u8])->Vec<u8> {
    if case["expected_kind"]=="debit" {return debit.to_vec();}
    let opcode=case["query_opcode"].as_u64().unwrap();
    let words=case["query_words"].as_array().unwrap().iter().map(|v|v.as_u64().unwrap()).collect();
    let blobs=if opcode==8 {vec![decode_packet(debit,debit.len()).unwrap().core_bytes().to_vec()]} else {Vec::new()};
    signed(core_with(4,opcode,0,120+u8::try_from(opcode).unwrap(),words,blobs))
}

#[test]
fn reference_signed_response_positive_and_byte_precedence_semantic_negative() {
    let fixture:Value=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/signed-response-cases.json"))).unwrap();
    assert_eq!(fixture["schema"],"oip-signed-response-cases-v1");
    let out=super::reference_execution_trace::output_dir("signed-response");
    let mut output=OpenOptions::new().create_new(true).write(true).open(out.join("observations.jsonl")).unwrap();
    let debit=signed(debit_core(2));
    let mut judgments=Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let expected=expected_packet(case,&debit);
        let expected=decode_packet(&expected,expected.len()).unwrap();
        assert!(key(7).verifying_key().verify_strict(&expected.signing_bytes().unwrap(),
            &Signature::from_bytes(expected.signature().try_into().unwrap())).is_ok(),"actual signed original");
        let embedded=if case["embedded"]=="same" {expected.core().clone()} else {debit_core(2)};
        let embedded=signed(embedded);
        let embedded=decode_packet(&embedded,embedded.len()).unwrap();
        let words=case["response_words"].as_array().unwrap().iter().map(|v|v.as_u64().unwrap()).collect();
        let (response,mut observation)=actual_signed_response(&embedded,words);
        let boundary=Boundary {deployment:7,source:0,target:0,principal:42,key_id:3,epoch:9,route_scope:1,now:106,
            asset_ttl_floor:2,future_skew:0,max_frame:1024*1024,max_nesting:4,version_floor:6,critical_allowed:false,
            public_key:key(6).verifying_key().to_bytes()};
        let channel=super::reference_execution_trace::channel_for(7,6);
        let actual=admit_response(&channel,&boundary,&expected,&response);
        let (admission,known_code,error_code)=match &actual {
            Ok(result)=>match result.code {ResponseStatus::Known(code)=>("accepted",Some(code as u64),None),
                ResponseStatus::Unknown {..}=>panic!("Unknown response status is outside the fixed capability")},
            Err(WireError::InvalidFormat)=>("rejected",None,Some(70)),
            Err(WireError::ReplayConflict)=>("rejected",None,Some(76)),
            Err(other)=>panic!("unexpected actual response API error: {other:?}"),
        };
        let wanted=case["expect_error"].as_u64();
        let good=if wanted.is_some() {error_code==wanted} else {admission=="accepted" && known_code==Some(12)};
        observation["id"]=case["id"].clone();
        observation["expected_original_core_hex"]=json!(hex(expected.core_bytes()));
        observation["expected_original_signature_hex"]=json!(hex(expected.signature()));
        observation["actual_api_result"]=json!({"admission":admission,"known_code":known_code,"error_code":error_code,"debug":format!("{actual:?}")});
        observation["semantic_assertion_holds"]=json!(good);
        serde_json::to_writer(&mut output,&observation).unwrap();output.write_all(b"\n").unwrap();output.flush().unwrap();output.sync_all().unwrap();
        judgments.push((case["id"].as_str().unwrap().to_owned(),good));
    }
    fs::write(out.join("fixture-pin.json"),serde_json::to_vec(&json!({"cases":judgments.len(),"uses_actual_ed25519":true,
        "parameters_and_sign_clock_reads_are_distinct":true,"guard_variant_identified_by_source_pins":true})).unwrap()).unwrap();
    assert!(judgments.iter().all(|(_,ok)|*ok),"actual signed API semantic assertion failed: {judgments:?}");
}
