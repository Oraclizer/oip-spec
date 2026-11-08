//! Current caller inputs are recorded before actual client admission.
use super::*;
use crate::authority::recovery::wire::response::{admit_response,source_trace};
use crate::wire::admission::Boundary;
use crate::wire::codec::decode_packet;
use serde_json::{Value,json};
use std::fs::{self,OpenOptions};
use std::io::Write;
fn hex(bytes:&[u8])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn row(file:&mut std::fs::File,value:Value){serde_json::to_writer(&mut *file,&value).unwrap();file.write_all(b"\n").unwrap();file.flush().unwrap();file.sync_all().unwrap();}
#[test]
fn actual_current_client_known_unknown_and_precedence_inputs() {
    let fixture:Value=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/client-response-cases.json"))).unwrap();
    let out=super::reference_execution_trace::output_dir("client-values");
    let mut input=OpenOptions::new().create_new(true).write(true).open(out.join("inputs.jsonl")).unwrap();
    let mut observed=OpenOptions::new().create_new(true).write(true).open(out.join("observations.jsonl")).unwrap();
    let debit=signed(debit_core(2));let mut count=0;
    for case in fixture["cases"].as_array().unwrap(){
        let expected=super::signed_response_fixture::expected_packet(case,&debit);
        let expected=decode_packet(&expected,expected.len()).unwrap();
        let embedded=if case["embedded"]=="same"{expected.core().clone()}else{debit_core(2)};
        let embedded=signed(embedded);let embedded=decode_packet(&embedded,embedded.len()).unwrap();
        let words=case["response_words"].as_array().unwrap().iter().map(|v|v.as_u64().unwrap()).collect();
        let (packet,_sender_observation)=super::signed_response_fixture::actual_signed_response(&embedded,words);
        let channel=super::reference_execution_trace::channel_for(7,6);
        let boundary=Boundary{deployment:7,source:0,target:0,principal:42,key_id:3,epoch:9,route_scope:1,now:106,asset_ttl_floor:2,future_skew:0,
            max_frame:1024*1024,max_nesting:4,version_floor:6,critical_allowed:false,public_key:key(6).verifying_key().to_bytes()};
        row(&mut input,json!({"id":case["id"],"channel":{"version":channel.profile().version,"deployment":channel.deployment(),"local":channel.local(),"remote":channel.remote(),"expires":channel.expires(),
            "families":channel.profile().families,"atomicities":channel.profile().atomicities,"schemes":channel.profile().schemes,"local_public_key_hex":hex(&channel.peer_keys()[0]),"remote_public_key_hex":hex(&channel.peer_keys()[1])},
            "boundary":{"deployment":boundary.deployment,"source":boundary.source,"target":boundary.target,"principal":boundary.principal,"key_id":boundary.key_id,"epoch":boundary.epoch,
                "route_scope":boundary.route_scope,"now":boundary.now,"asset_ttl_floor":boundary.asset_ttl_floor,"future_skew":boundary.future_skew,"max_frame":boundary.max_frame,"max_nesting":boundary.max_nesting,
                "version_floor":boundary.version_floor,"critical_allowed":boundary.critical_allowed,"public_key_hex":hex(&boundary.public_key)},
            "canonical_expected_packet_hex":hex(&expected.encode().unwrap()),"network_response_packet_hex":hex(&packet),"provenance":"explicit protocol input before current caller API; never sender answer"}));
        let actual=admit_response(&channel,&boundary,&expected,&packet);
        let value=match &actual {Ok(v)=>json!({"status":0,"value":source_trace::client_result(v)}),Err(e)=>json!({"error_debug":format!("{e:?}")})};
        row(&mut observed,json!({"id":case["id"],"actual":value}));
        if let Some(error)=case["expect_error"].as_u64(){let expected_error=if error==70{WireError::InvalidFormat}else{assert_eq!(error,76);WireError::ReplayConflict};assert_eq!(actual,Err(expected_error));}
        else if !case["expect_unknown"].is_null(){let typed=source_trace::client_result(&actual.unwrap());assert_eq!(typed[6],0);assert_eq!(typed[7],case["expect_unknown"]["kind"].as_u64().unwrap());assert_eq!(typed[8],case["expect_unknown"]["number"].as_u64().unwrap());}
        else {assert_eq!(source_trace::client_result(&actual.unwrap())[3],12);}
        count+=1;
    }
    assert_eq!(count,21);fs::write(out.join("scope.json"),serde_json::to_vec(&json!({"cases":21,"includes_known":true,"includes_unknown":true,"actual_current_client":true,"sender_output_used_as_model_answer":false})).unwrap()).unwrap();
}
