//! Actual submit/wait and message methods with an explicitly mirrored worker.
//! The production WitnessHead/Etcd start path is not executed by this fixture.
use super::*;
use crate::authority::identity::Security;
use crate::authority::recovery::{AuthenticatedHead,Attachment,PersistentAuthority};
use crate::authority::recovery::ordered::OrderedHead;
use crate::authority::recovery::wire::ed25519::{Ed25519Profile,SessionIssuer};
use crate::authority::recovery::wire::response::{self,source_trace};
use crate::authority::recovery::wire::WireSecurity;
use crate::authority::recovery::wire::ed25519::vector_tests::reference_execution_trace::{Service,dispatcher_probe_setup,snapshot};
use crate::wire::codec::{decode_packet,encode_packet,signing_bytes,encode_core};
use crate::wire::generated::{Core,Packet,core::Body};
use crate::wire::negotiation::{Offer,Negotiation,SignedOffers,select_profile,negotiate,offer_bytes,confirmation_bytes};
use crate::wire::operands::{self,Operands};
use ed25519_dalek::{Signer,SigningKey};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::collections::BTreeSet;
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::PathBuf;
fn hex(bytes:&[u8])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn key(seed:u8)->SigningKey {SigningKey::from_bytes(&[seed;32])}
fn output(file:&mut File,value:Value){serde_json::to_writer(&mut *file,&value).unwrap();file.write_all(b"\n").unwrap();file.flush().unwrap();file.sync_all().unwrap();}
fn channel(local:u64,remote:u64,local_seed:u8,remote_seed:u8)->Channel {
    let offer=|sender,receiver|Offer{deployment:7,sender,receiver,challenge:3,expires:200,versions:BTreeSet::from([6]),
        families:(1..=7).collect(),atomicities:(1..=3).collect(),schemes:BTreeSet::from([1])};
    let first=offer(local,remote);let second=offer(remote,local);let profile=select_profile(&first,&second,6,false).unwrap();
    negotiate(&Negotiation{deployment:7,local,remote,challenge:3,now:105,floor:6,legacy_allowed:false,
        local_key:key(local_seed).verifying_key().to_bytes(),remote_key:key(remote_seed).verifying_key().to_bytes()},
        SignedOffers{local:&first,remote:&second,local_signature:&key(local_seed).sign(&offer_bytes(&first)).to_bytes(),
            remote_signature:&key(remote_seed).sign(&offer_bytes(&second)).to_bytes(),
            confirmation:&key(remote_seed).sign(&confirmation_bytes(&first,&second,&profile)).to_bytes()}).unwrap()
}
fn channel_json(value:&Channel)->Value {json!({"version":value.profile().version,"deployment":value.deployment(),"local":value.local(),"remote":value.remote(),
    "expires":value.expires(),"families":value.profile().families,"atomicities":value.profile().atomicities,"schemes":value.profile().schemes,
    "local_public_key_hex":hex(&value.peer_keys()[0]),"remote_public_key_hex":hex(&value.peer_keys()[1])})}
fn start_fixture(mut authority:Service,capacity:NonZeroUsize,max_wait:Duration)->std::io::Result<OrderedDispatcher> {
    if max_wait.is_zero() || Instant::now().checked_add(max_wait).is_none(){return Err(std::io::ErrorKind::InvalidInput.into())}
    let frame_limit=authority.security.config.max_frame;
    let (requests,queued)=sync_channel::<Work>(capacity.get());
    let worker=thread::Builder::new().name("oip-test-mirrored-dispatch-worker".into()).spawn(move||{
// BEGIN EXACT PRODUCTION WORKER BODY
                while let Ok(work) = queued.recv() {
                    let credentials = WireCredentials {
                        token: &work.token,
                        signature: &work.packet,
                        maintenance: None,
                        endorsement: None,
                        previous: None,
                        successor: None,
                    };
                    let result = match work.operation {
                        Operation::Receive => authority.receive_wire_response(
                            &work.channel,
                            Entry::Normal,
                            &work.packet,
                            &credentials,
                            DeliveryWindow::default(),
                        ),
                        Operation::ResolveDebit => authority.resolve_wire_debit_response(
                            &work.channel,
                            &work.packet,
                            &credentials,
                            false,
                        ),
                    };
                    // A dropped waiter never cancels completed authority work.
                    let _ = work.reply.try_send(result);
                }
// END EXACT PRODUCTION WORKER BODY
    })?;
    Ok(OrderedDispatcher{requests,worker,frame_limit,max_wait})
}
fn worker_identity()->String {
    let original=include_str!("dispatch.rs");let marker="                while let Ok(work) = queued.recv() {";
    let begin=original.find(marker).unwrap();let end=original[begin..].find("\n            })?;").unwrap()+begin;
    let actual=&original[begin..end];
    let fixture=include_str!("dispatch_source_tests.rs");
    let copied=fixture.split("// BEGIN EXACT PRODUCTION WORKER BODY\n").nth(1).unwrap().split("\n// END EXACT PRODUCTION WORKER BODY").next().unwrap();
    assert_eq!(actual,copied,"The mirrored worker may not drift from production");hex(&Sha256::digest(actual.as_bytes()))
}
fn body(core:&mut Core)->&mut crate::wire::generated::Operation {match core.body.as_mut().unwrap(){
    Body::StateSync(v)|Body::RegulatoryAction(v)|Body::LockManagement(v)|Body::Query(v)|Body::Ack(v)|Body::Heartbeat(v)|Body::Governance(v)=>v}}
#[test]
fn actual_submit_and_mirrored_worker_original_operation_partition() {
    let fragment=worker_identity();
    let out=if let Some(path)=std::env::var_os("OIP_REFERENCE_OUTPUT_DIR"){PathBuf::from(path).join("original-operations")}
        else{PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/original-operations").join(format!("{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))};
    fs::create_dir_all(&out).unwrap();let open=|name:&str|OpenOptions::new().create_new(true).write(true).open(out.join(name)).unwrap();
    let mut inputs=open("inputs.jsonl");let mut observed=open("observations.jsonl");let mut clients=open("client-inputs.jsonl");let mut client_contexts=open("client-contexts.jsonl");
    let corpus=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/wire-operations.jsonl"));
    let first=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/reference-replay-inputs.jsonl")).lines().next().unwrap();
    let seed:Value=serde_json::from_str(first).unwrap();let base:Ed25519Profile=serde_json::from_value(seed["input"]["security_config"].clone()).unwrap();
    let mut counts=[0usize;3];let mut seen=BTreeSet::new();
    for line in corpus.lines(){let row:Value=serde_json::from_str(line).unwrap();if !row["id"].as_str().unwrap().ends_with("/valid"){continue}
        let family=row["family"].as_u64().unwrap();let opcode=row["opcode"].as_u64().unwrap();if !seen.insert((family,opcode)){continue}
        let raw=row["packet_hex"].as_str().unwrap();let packet:Vec<u8>=raw.as_bytes().chunks_exact(2).map(|v|u8::from_str_radix(std::str::from_utf8(v).unwrap(),16).unwrap()).collect();
        let mut core=decode_packet(&packet,packet.len()).unwrap().core().clone();
        let decoded=operands::decode(&core,4).unwrap();let caller=matches!(decoded,Operands::Ordinary{..}|Operands::Legal{..}|Operands::Spend{..});
        if caller {body(&mut core).words[3]=0;}
        let uuid=core.uuid.as_mut().unwrap();uuid[0]=213;uuid[1]=family as u8;uuid[2]=opcode as u8;
        let core_bytes=encode_core(&core).unwrap();let signature=key(7).sign(&signing_bytes(&core_bytes).unwrap()).to_bytes();
        let packet=encode_packet(&Packet{core:Some(core.clone()),signature:Some(signature.to_vec())}).unwrap();
        let mut config=base.clone();config.other_endpoints.insert(2);
        for peer in config.peers.values_mut(){for grants in peer.sessions.values_mut(){let grant=grants[&0].clone();grants.insert(2,grant);}}
        let (_path,mut service,control,_clock,token)=dispatcher_probe_setup(config.clone());
        let before=snapshot(&mut service,&control);
        let site=json!({"profile":service.profile,"ordered_control_present":service.anchor.ordered_wire_control().is_some(),"security_ordered_profile":service.security.ordered_revocation_profile()});
        let policy=service.security.authority_binding(config.authority_epoch).unwrap();
        let link=channel(core.target_domain.unwrap(),core.source_domain.unwrap(),6,7);let saved_channel=channel_json(&link);
        let sink=source_trace::register(&packet);
        let dispatcher=start_fixture(service,NonZeroUsize::new(1).unwrap(),Duration::from_secs(30)).unwrap();
        let result=dispatcher.receive(link,token,packet.clone(),Instant::now()+Duration::from_secs(30));dispatcher.shutdown().unwrap();source_trace::unregister(&packet);
        let trace=sink.lock().unwrap().clone();
        let ready=trace.get("typed_observation").cloned().unwrap_or_else(||json!({"mode":3,"reply_values":[],"retained_present":false,"retained_values":[]}));
        if caller && row["reference_accepts"].as_bool().unwrap(){assert_ne!(ready["mode"],3,"A ready caller needs its actual before-converter value");}
        let category=if !row["reference_accepts"].as_bool().unwrap(){counts[2]+=1;"configured-refusal"}else if caller {counts[0]+=1;"caller"}else{counts[1]+=1;"noncaller"};
        let id=format!("operation-{family}-{opcode}");let mut input=ready.as_object().unwrap().clone();
        input.insert("id".into(),json!(id));input.insert("execution_kind".into(),json!("full"));input.insert("family".into(),json!(family));input.insert("opcode".into(),json!(opcode));input.insert("branch_class".into(),json!(category));
        input.insert("raw_original_packet_hex".into(),json!(hex(&packet)));input.insert("config".into(),json!(&config));input.insert("policy_binding_hex".into(),json!(hex(&policy)));
        input.insert("parameters_clock".into(),json!(105));input.insert("signing_clock".into(),json!(105));input.insert("frame_limit".into(),json!(config.max_frame));input.insert("channel".into(),saved_channel);input.insert("site".into(),site);
        input.insert("provenance".into(),json!({"actual_submit_wait":true,"actual_message_methods":true,"production_start_worker_executed":false,"mirrored_worker_body_sha256":fragment,"backend":"MemoryCAS+OrderedHead","WitnessHead_Etcd_runtime":false}));
        output(&mut inputs,Value::Object(input));
        let client_channel=channel(core.source_domain.unwrap(),core.target_domain.unwrap(),7,6);
        let boundary=crate::wire::admission::Boundary{deployment:7,source:core.target_domain.unwrap(),target:core.source_domain.unwrap(),principal:config.local_principal,
            key_id:config.local_key_id,epoch:config.authority_epoch,route_scope:config.route_scope,now:105,asset_ttl_floor:2,future_skew:0,max_frame:config.max_frame,max_nesting:config.max_nesting,version_floor:6,critical_allowed:false,public_key:config.response_key};
        let mut client_result=Value::Null;
        output(&mut client_contexts,json!({"id":id,"channel":channel_json(&client_channel),"boundary":{"deployment":boundary.deployment,"source":boundary.source,"target":boundary.target,"principal":boundary.principal,
            "key_id":boundary.key_id,"epoch":boundary.epoch,"route_scope":boundary.route_scope,"now":boundary.now,"asset_ttl_floor":boundary.asset_ttl_floor,"future_skew":boundary.future_skew,
            "max_frame":boundary.max_frame,"max_nesting":boundary.max_nesting,"version_floor":boundary.version_floor,"critical_allowed":boundary.critical_allowed,"public_key_hex":hex(&boundary.public_key)},
            "canonical_expected_packet_hex":hex(&packet),"provenance":"independent current-client configuration; contains no response packet"}));
        if let Ok(response_bytes)=&result {
            output(&mut clients,json!({"id":id,"channel":channel_json(&client_channel),"boundary":{"deployment":boundary.deployment,"source":boundary.source,"target":boundary.target,"principal":boundary.principal,
                "key_id":boundary.key_id,"epoch":boundary.epoch,"route_scope":boundary.route_scope,"now":boundary.now,"asset_ttl_floor":boundary.asset_ttl_floor,"future_skew":boundary.future_skew,
                "max_frame":boundary.max_frame,"max_nesting":boundary.max_nesting,"version_floor":boundary.version_floor,"critical_allowed":boundary.critical_allowed,"public_key_hex":hex(&boundary.public_key)},
                "canonical_expected_packet_hex":hex(&packet),"network_response_packet_hex":hex(response_bytes),"provenance":"source packet as explicit client network input; never sender answer"}));
            client_result=match response::admit_response(&client_channel,&boundary,&decode_packet(&packet,packet.len()).unwrap(),response_bytes){Ok(value)=>json!({"status":0,"value":source_trace::client_result(&value)}),Err(error)=>json!({"error_debug":format!("{error:?}")})};
        }
        let restored=Ed25519Security::new(config.clone(),key(6),_clock.clone()).unwrap();
        let mut after_service=PersistentAuthority::open(_path.file(),OrderedHead::new(control.clone(),config.profile,1),Attachment{profile:config.profile,proof:(config.profile,true),source_connected:true,security:restored}).unwrap();
        let after=snapshot(&mut after_service,&control);
        output(&mut observed,json!({"id":id,"response_packet_hex":result.as_ref().ok().map(|v|hex(v)),"error_debug":result.err().map(|e|format!("{e:?}")),
            "trace":trace,"before":before,"after":after,"client_result":client_result,"scope":"actual submit/wait + exact-source mirrored worker + actual message runtime; production Witness/Etcd start unreceived"}));
    }
    assert_eq!(counts,[15,10,6]);assert_eq!(seen.len(),31);
    fs::write(out.join("scope.json"),serde_json::to_vec(&json!({"operation_branches":31,"caller":15,"noncaller":10,"configured_refusal":6,
        "actual_submit_wait":true,"production_worker_start_executed":false,"production_worker_fragment_sha256":fragment,"independent_witness_runtime":false})).unwrap()).unwrap();
}
