//! Threshold envelope observations from the persistent authority APIs.
use super::*;
use crate::authority::identity::Entry;
use crate::authority::recovery::ordered::OrderedHead;
use crate::authority::recovery::vector_tests::{JournalPath, genesis};
use crate::authority::recovery::wire::vector_tests::{core_with, uint256, ordered_tests::MemoryControl};
use crate::authority::recovery::wire::{DebitResult, DeliveryWindow, WireCredentials};
use crate::authority::recovery::wire::response::{admit_response, admit_response_configured, ResponseCode, ResponseStatus};
use crate::authority::recovery::{Attachment, AuthenticatedHead, PersistentAuthority, RecoveryError, exact_image};
use crate::wire::codec::{encode_packet, signing_bytes};
use crate::wire::generated::Packet;
use crate::wire::negotiation::{Offer, Negotiation, SignedOffers, negotiate, offer_bytes, select_profile, confirmation_bytes};
use crate::wire::threshold::{ThresholdRoster, trace};
use serde_json::{Value, json};

type Service = PersistentAuthority<Ed25519Security<FixedClock>, OrderedHead<MemoryControl>>;
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn input() -> Option<Vec<Value>> {
    let path = std::env::var_os("OIP_P19_INPUT")?;
    Some(std::fs::read_to_string(path).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect())
}
fn roster(row: &Value) -> Vec<ThresholdRoster> {
    let r = &row["roster"];
    (!r.is_null()).then(|| ThresholdRoster {
        deployment:r["deployment"].as_u64().unwrap(), source:r["source"].as_u64().unwrap(), principal:r["principal"].as_u64().unwrap(),
        key_id:r["key_id"].as_u64().unwrap(), epoch:r["epoch"].as_u64().unwrap(), quorum:r["quorum"].as_u64().unwrap(),
        members:r["members"].as_array().unwrap().iter().map(|m|(m[0].as_u64().unwrap(),unhex(m[1].as_str().unwrap()).try_into().unwrap())).collect(),
    }).into_iter().collect()
}
fn channel(local: u8, remote: u8, schemes: BTreeSet<u64>) -> Channel {
    let offer = Offer { deployment:7,sender:0,receiver:0,challenge:3,expires:1000,versions:BTreeSet::from([6]),
        families:(1..=7).collect(),atomicities:(1..=3).collect(),schemes };
    let selected = select_profile(&offer,&offer,6,false).unwrap();
    negotiate(&Negotiation {deployment:7,local:0,remote:0,challenge:3,now:105,floor:6,legacy_allowed:false,
        local_key:key(local).verifying_key().to_bytes(),remote_key:key(remote).verifying_key().to_bytes()},
        SignedOffers {local:&offer,remote:&offer,local_signature:&key(local).sign(&offer_bytes(&offer)).to_bytes(),
            remote_signature:&key(remote).sign(&offer_bytes(&offer)).to_bytes(),
            confirmation:&key(remote).sign(&confirmation_bytes(&offer,&offer,&selected)).to_bytes()}).unwrap()
}
fn credentials<'a>(token: &'a SessionToken, packet: &'a Vec<u8>) -> WireCredentials<'a,Ed25519Security<FixedClock>> {
    WireCredentials {token,signature:packet,maintenance:None,endorsement:None,previous:None,successor:None}
}
fn attachment(config: ConfiguredEd25519Profile, now: u64) -> Attachment<Ed25519Security<FixedClock>, (RecoveryProfile,bool)> {
    Attachment {profile:config.single.profile,proof:(config.single.profile,true),source_connected:true,
        security:Ed25519Security::new_configured(config,key(6),FixedClock(now)).unwrap()}
}
fn image(service: &mut Service) -> Value {
    let head=service.anchor.current().unwrap().unwrap();
    let record=exact_image(&mut service.file,head).unwrap();
    json!({"head":head,"image":record.image})
}
struct Fixture { path:JournalPath, control:MemoryControl, service:Service, token:SessionToken, config:ConfiguredEd25519Profile }
impl Fixture {
    fn new(config: ConfiguredEd25519Profile) -> Self {
        let path=JournalPath::create();let control=MemoryControl::with_head(None);
        let mut service=PersistentAuthority::initialize(path.file(),OrderedHead::new(control.clone(),DEFAULT_PROFILE,1),
            attachment(config.clone(),105),genesis(10,1)).unwrap();
        let token=SessionIssuer::new(key(8)).issue(&service.security,7,2,300).unwrap();
        // Reach cut 2 through the existing authenticated SINGLE API. The raw
        // threshold Debit itself, its UUID and its preimage are never edited.
        let reserve=signed(core_with(3,1,0,5,vec![10,10,2,0,9,0,17,17,7,2,3,0,1,17,0,20],vec![uint256(5)]));
        let mut core=debit_core(1);let mut words=std::mem::take(&mut operation(&mut core).words);words[0]=11;words[1]=11;
        let dispatch=signed(core_with(3,2,0,6,words,vec![uint256(5)]));
        for packet in [&reserve,&dispatch] {
            let result=service.receive_wire(&channel(6,7,BTreeSet::from([1,2])),Entry::Normal,packet,&credentials(&token,packet),DeliveryWindow::default());
            assert!(result.is_ok(),"preparation: {result:?}");
        }
        Self {path,control,service,token,config}
    }
    fn reopen(&mut self, now:u64) {
        self.service=PersistentAuthority::open(self.path.file(),OrderedHead::new(self.control.clone(),DEFAULT_PROFILE,1),attachment(self.config.clone(),now)).unwrap();
        self.token=SessionIssuer::new(key(8)).issue(&self.service.security,7,2,300).unwrap();
    }
}
fn response_boundary(key_id:u64, now:u64) -> Boundary {
    Boundary {deployment:7,source:0,target:0,principal:42,key_id,epoch:9,route_scope:1,now,asset_ttl_floor:2,future_skew:0,
        max_frame:1024*1024,max_nesting:4,version_floor:6,critical_allowed:false,public_key:key(6).verifying_key().to_bytes()}
}
fn write_output(name:&str, rows: &[Value]) {
    let dir=std::env::var_os("OIP_P19_EVIDENCE").unwrap();
    std::fs::write(std::path::PathBuf::from(dir).join(name),rows.iter().map(|r|serde_json::to_string(r).unwrap()+"\n").collect::<String>()).unwrap();
}

#[test]
fn threshold_authority_receives_raw_packets() {
    let Some(rows)=input() else {return};
    let mut observations=Vec::new();
    for row in rows {
        let mut configured=ConfiguredEd25519Profile {single:config(),threshold_rosters:roster(&row)};
        configured.single.max_frame=usize::try_from(row["boundary"]["max_frame"].as_u64().unwrap()).unwrap();
        if let Err(error)=Ed25519Security::new_configured(configured.clone(),key(6),FixedClock(105)) {
            observations.push(json!({"id":row["id"],"configuration_refused":format!("{error:?}"),"config":configured}));continue;
        }
        let packet=unhex(row["packet_hex"].as_str().unwrap());
        let schemes=row["profile"]["schemes"].as_array().unwrap().iter().map(|v|v.as_u64().unwrap()).collect();
        let link=channel(6,7,schemes);
        let mut f=Fixture::new(configured.clone());
        let before=image(&mut f.service);
        trace::begin();
        let actual=f.service.receive_wire(&link,Entry::Normal,&packet,&credentials(&f.token,&packet),DeliveryWindow::default());
        let receive_trace=trace::take();let after=image(&mut f.service);
        if actual.is_err() {assert_eq!(before,after,"{} changed state on refusal",row["id"]);}
        trace::begin();
        let response=f.service.receive_wire_response(&link,Entry::Normal,&packet,&credentials(&f.token,&packet),DeliveryWindow::default());
        let response_trace=trace::take();
        let client=response.as_ref().ok().map(|bytes| {
            let expected=decode_packet(&packet,packet.len()).unwrap();
            format!("{:?}",admit_response(&channel(7,6,BTreeSet::from([1,2])),&response_boundary(3,105),&expected,bytes))
        });
        trace::begin();
        let resolution=f.service.resolve_wire_debit(&link,&packet,&credentials(&f.token,&packet),false);
        let resolution_trace=trace::take();
        observations.push(json!({"id":row["id"],"packet_hex":hex(&packet),"configured":configured,
            "receive_debug":format!("{actual:?}"),"response_error":response.as_ref().err().map(|e|format!("{e:?}")),
            "response_packet_hex":response.as_ref().ok().map(|b|hex(b)),"response_client":client,
            "resolution_debug":format!("{resolution:?}"),"receive_trace":receive_trace,"response_trace":response_trace,"resolution_trace":resolution_trace,
            "before":before,"after_receive":after,"after_resolution":image(&mut f.service),
            "scope":"Actual configured persistent APIs; MemoryControl exact CAS, no live Witness/Etcd; fixture attestation boolean/prior binding belong to the generic transport adapter only"}));
    }
    write_output("product-raw.jsonl",&observations);
}

#[test]
fn threshold_exact_retry_reopen_and_signed_responses() {
    let Some(rows)=input() else {return};let row=&rows[0];
    let configured=ConfiguredEd25519Profile{single:config(),threshold_rosters:roster(row)};
    let packet=unhex(row["packet_hex"].as_str().unwrap());
    let mut f=Fixture::new(configured.clone());let link=channel(6,7,BTreeSet::from([1,2]));
    let before=image(&mut f.service);
    trace::begin();
    let response=f.service.receive_wire_response(&link,Entry::Normal,&packet,&credentials(&f.token,&packet),DeliveryWindow::default()).unwrap();
    let original=decode_packet(&packet,packet.len()).unwrap();
    let verified=admit_response(&channel(7,6,BTreeSet::from([1,2])),&response_boundary(3,105),&original,&response).unwrap();
    assert_eq!(verified.code,ResponseStatus::Known(ResponseCode::Debited));
    let first_trace=trace::take();
    for stage in ["response-original","admission","authority-envelope","publication-reauthorization"] {
        assert!(first_trace.iter().any(|v|v["stage"]==stage),"missing actual consumer {stage}: {first_trace:?}");
        for event in first_trace.iter().filter(|v|v["stage"]==stage) {
            assert_eq!(event["packet_hex"],hex(&packet));
            assert_eq!(event["preimage_hex"],hex(&original.signing_bytes().unwrap()));
            assert_eq!(event["selected_roster"],serde_json::to_value(&configured.threshold_rosters[0]).unwrap());
            assert_eq!(event["result_debug"],"Ok(())");
        }
    }
    let after=image(&mut f.service);assert_ne!(before,after);
    let retry=f.service.receive_wire_response(&link,Entry::Normal,&packet,&credentials(&f.token,&packet),DeliveryWindow::default()).unwrap();
    assert_eq!(response,retry);assert_eq!(after,image(&mut f.service));
    f.reopen(106);
    trace::begin();
    let resolved=f.service.resolve_wire_debit(&link,&packet,&credentials(&f.token,&packet),false).unwrap();
    assert!(matches!(resolved,DebitResult::Published(_)),"{resolved:?}");
    let resolve_trace=trace::take();assert!(resolve_trace.iter().any(|v|v["stage"]=="exact-resolution"));
    for event in &resolve_trace {
        assert_eq!(event["packet_hex"],hex(&packet));
        assert_eq!(event["preimage_hex"],hex(&original.signing_bytes().unwrap()));
        assert_eq!(event["selected_roster"],serde_json::to_value(&configured.threshold_rosters[0]).unwrap());
    }
    let resolved_response=f.service.resolve_wire_debit_response(&link,&packet,&credentials(&f.token,&packet),false).unwrap();
    let resolved_verified=admit_response(&channel(7,6,BTreeSet::from([1,2])),&response_boundary(3,106),&original,&resolved_response).unwrap();
    assert_eq!(resolved_verified.code,ResponseStatus::Known(ResponseCode::Debited));
    assert_eq!(after,image(&mut f.service));
    let mut replacement=configured.clone();replacement.threshold_rosters[0].members[0].1=key(71).verifying_key().to_bytes();
    let rejected=PersistentAuthority::open(f.path.file(),OrderedHead::new(f.control.clone(),DEFAULT_PROFILE,1),attachment(replacement.clone(),106));
    assert!(matches!(rejected,Err(RecoveryError::AttachmentRejected)),"current retained policy must bind roster");
    let changed=Fixture::new(replacement.clone());
    let wrong=changed.service.security.verify_original_signature(&link,&original);
    assert_eq!(wrong,Err(WireError::InvalidThresholdSignature));
    write_output("product-reopen.jsonl",&[json!({"original_packet_hex":hex(&packet),"response_packet_hex":hex(&response),
        "resolved_response_packet_hex":hex(&resolved_response),"before":before,"after":after,"first_trace":first_trace,"resolve_trace":resolve_trace,
        "exact_retry_same_response":retry==response,"current_roster_binding":hex(&f.service.security.binding),
        "replacement_roster_binding":hex(&changed.service.security.binding),"replacement_attachment_refused":true,
        "old_signature_on_replacement_policy":format!("{wrong:?}")})]);
}

fn threshold_packet(mut core:Core, members:&[(u64,u8)], group:u64) -> Vec<u8> {
    core.signature_scheme=Some(2);core.key_id=Some(group);
    let message=signing_bytes(&encode_core(&core).unwrap()).unwrap();
    let mut signature=u64::try_from(members.len()).unwrap().to_be_bytes().to_vec();
    for (id,seed) in members {signature.extend(id.to_be_bytes());signature.extend(key(*seed).sign(&message).to_bytes());}
    encode_packet(&Packet{core:Some(core),signature:Some(signature)}).unwrap()
}

#[test]
fn threshold_inbound_responses_and_empty_roster_policy() {
    let Some(rows)=input() else{return};let row=&rows[0];
    let configured=ConfiguredEd25519Profile{single:config(),threshold_rosters:roster(row)};
    let packet=unhex(row["packet_hex"].as_str().unwrap());let original=decode_packet(&packet,packet.len()).unwrap();
    let mut f=Fixture::new(configured);let link=channel(6,7,BTreeSet::from([1,2]));
    let single=f.service.receive_wire_response(&link,Entry::Normal,&packet,&credentials(&f.token,&packet),DeliveryWindow::default()).unwrap();
    let response=threshold_packet(decode_packet(&single,single.len()).unwrap().core().clone(),&[(2,61),(7,62)],50);
    let response_roster=ThresholdRoster{deployment:7,source:0,principal:42,key_id:50,epoch:9,quorum:2,
        members:vec![(2,key(61).verifying_key().to_bytes()),(7,key(62).verifying_key().to_bytes())]};
    trace::begin();
    let accepted=admit_response_configured(&channel(7,6,BTreeSet::from([1,2])),&response_boundary(50,105),&[response_roster.clone()],&original,&response).unwrap();
    assert_eq!(accepted.code,ResponseStatus::Known(ResponseCode::Debited));
    let observed=trace::take();
    let mut wrong=response_roster.clone();wrong.epoch=8;
    assert_eq!(admit_response_configured(&channel(7,6,BTreeSet::from([1,2])),&response_boundary(50,105),&[wrong],&original,&response),Err(WireError::InvalidThresholdSignature));
    let old=config();let empty:ConfiguredEd25519Profile=old.clone().into();
    assert_eq!(serde_json::to_vec(&old).unwrap(),serde_json::to_vec(&empty).unwrap());
    let restored:ConfiguredEd25519Profile=serde_json::from_slice(&serde_json::to_vec(&old).unwrap()).unwrap();assert!(restored.threshold_rosters.is_empty());
    assert_eq!(authority_policy_binding(&old),configured_policy_binding(&empty));
    write_output("inbound-response-and-compatibility.jsonl",&[json!({"response_packet_hex":hex(&response),"roster":response_roster,"trace":observed,
        "empty_config_bytes_preserved":true,"empty_policy_digest_preserved":true,"old_config_digest":hex(&authority_policy_binding(&old).unwrap())})]);
}

fn synthetic_roster(epoch:u64, first:u8, second:u8) -> ThresholdRoster {
    ThresholdRoster {deployment:7,source:0,principal:7,key_id:40,epoch,quorum:2,
        members:vec![(2,key(first).verifying_key().to_bytes()),(7,key(second).verifying_key().to_bytes())]}
}

#[test]
fn threshold_handover_selects_successor_roster() {
    if input().is_none() {return}
    use crate::authority::identity::Consent;
    use crate::authority::recovery::vector_tests::{SUCCESSOR,contexts};
    use crate::authority::recovery::wire::WireReply;
    let mut old=config();
    old.handover_maintainers.insert(7);
    old.peers.get_mut(&7).unwrap().sessions.get_mut(&1).unwrap().get_mut(&0).unwrap().transfer_owner.insert(17);
    old.peers.insert(8,PeerRegistration{identity:SUCCESSOR,key_id:12,public_key:key(10).verifying_key().to_bytes(),
        sessions:BTreeMap::from([(1,BTreeMap::from([(0,EndpointGrant::default())]))])});
    let old=ConfiguredEd25519Profile{single:old,threshold_rosters:vec![synthetic_roster(9,61,62)]};
    let mut next=old.clone();next.single.authority_epoch=10;
    next.single.peers.get_mut(&7).unwrap().sessions.remove(&1);
    next.single.peers.get_mut(&8).unwrap().sessions=BTreeMap::from([(3,BTreeMap::from([(0,EndpointGrant::default())]))]);
    next.threshold_rosters=vec![synthetic_roster(10,71,72)];
    let security=Ed25519Security::new_configured(old.clone(),key(6),FixedClock(105)).unwrap();
    let ready=security.successor_readiness_configured_signing_bytes(&next,&contexts(10)).unwrap();
    let mut altered=next.clone();altered.threshold_rosters[0].quorum=1;
    assert_ne!(ready,security.successor_readiness_configured_signing_bytes(&altered,&contexts(10)).unwrap());
    let security=security.with_successor_configured(next.clone(),contexts(10),&key(6).sign(&ready).to_bytes()).unwrap();
    let proposal=Handover{asset:17,previous:7,successor:8,old_session:1,new_session:3,
        expected:CommitCut{authority_epoch:9,revision:0},epoch:10,contexts:contexts(10)};
    let left=key(7).sign(&security.handover_consent_signing_bytes(FORMER,&proposal).unwrap()).to_bytes().to_vec();
    let right=key(10).sign(&security.handover_consent_signing_bytes(SUCCESSOR,&proposal).unwrap()).to_bytes().to_vec();
    let issuer=SessionIssuer::new(key(8));
    let former=issuer.issue(&security,7,1,300).unwrap();let successor=issuer.issue(&security,8,1,300).unwrap();
    let maintenance=MaintenanceIssuer::new(key(9)).issue(&security,7,300).unwrap();
    let packet=threshold_packet(core_with(7,1,0,181,vec![1,0,17,7,8,1,3,10],
        vec![serde_json::to_vec(&proposal.contexts).unwrap(),left.clone(),right.clone()]),&[(2,61),(7,62)],40);
    let path=JournalPath::create();let control=MemoryControl::with_head(None);
    let mut service=PersistentAuthority::initialize(path.file(),OrderedHead::new(control.clone(),DEFAULT_PROFILE,1),
        Attachment{profile:DEFAULT_PROFILE,proof:(DEFAULT_PROFILE,true),source_connected:true,security},genesis(10,1)).unwrap();
    let before=image(&mut service);
    trace::begin();
    let result=service.receive_wire(&channel(6,7,BTreeSet::from([1,2])),Entry::Normal,&packet,
        &WireCredentials{token:&former,signature:&packet,maintenance:Some(&maintenance),
            previous:Some(&Consent{token:&former,signature:&left}),successor:Some(&Consent{token:&successor,signature:&right}),endorsement:None},
        DeliveryWindow::default()).unwrap();
    assert_eq!(result.reply,WireReply::Changed(true));
    let handover_trace=trace::take();let after=image(&mut service);assert_ne!(before,after);
    assert!(matches!(PersistentAuthority::open(path.file(),OrderedHead::new(control.clone(),DEFAULT_PROFILE,1),attachment(old.clone(),105)),Err(RecoveryError::AttachmentRejected)));
    let mut reopened=PersistentAuthority::open(path.file(),OrderedHead::new(control.clone(),DEFAULT_PROFILE,1),attachment(next.clone(),105)).unwrap();
    let current_token=issuer.issue(&reopened.security,7,2,300).unwrap();
    let current_cut=reopened.transact(|product|product.reads.current_cut()).unwrap();
    let mut query=core_with(4,1,0,182,vec![2,u64::try_from(current_cut.revision).unwrap(),2,0,17],vec![]);query.authority_epoch=Some(10);
    let old_roster=threshold_packet(query.clone(),&[(2,61),(7,62)],40);
    let before_old=image(&mut reopened);
    trace::begin();
    let old_result=reopened.receive_wire(&channel(6,7,BTreeSet::from([1,2])),Entry::Normal,&old_roster,&credentials(&current_token,&old_roster),DeliveryWindow::default());
    assert_eq!(old_result,Err(WireError::InvalidThresholdSignature));assert_eq!(before_old,image(&mut reopened));
    let current=threshold_packet(query,&[(2,71),(7,72)],40);
    let new_result=reopened.receive_wire(&channel(6,7,BTreeSet::from([1,2])),Entry::Normal,&current,&credentials(&current_token,&current),DeliveryWindow::default());
    assert!(new_result.is_ok(),"{new_result:?}");
    let current_trace=trace::take();
    write_output("handover.jsonl",&[json!({"old":old,"next":next,"handover_packet_hex":hex(&packet),"ready_preimage_hex":hex(&ready),
        "before":before,"after":after,"handover_trace":handover_trace,"current_trace":current_trace,
        "new_epoch_old_roster_packet_hex":hex(&old_roster),"new_epoch_current_roster_packet_hex":hex(&current),
        "old_roster_result":format!("{old_result:?}"),"current_roster_result":format!("{new_result:?}"),"old_policy_reopen_refused":true})]);
}

#[test]
fn threshold_ack_canonical_envelope_uses_current_roster() {
    if input().is_none(){return}
    let corpus=include_str!("../../../../../../tests/vectors/wire-operations.jsonl");
    let raw:Value=corpus.lines().map(|l|serde_json::from_str::<Value>(l).unwrap()).find(|r|r["id"]=="SettlementAcknowledgement/valid").unwrap();
    let bytes=unhex(raw["packet_hex"].as_str().unwrap());let canonical=decode_packet(&bytes,bytes.len()).unwrap();
    let Operands::Ack(ack)=decode(canonical.core(),4).unwrap() else{panic!("ack")};
    let mut config=config();config.acknowledgers.insert(ack.target,7);
    let peer=config.peers.get_mut(&7).unwrap();peer.identity.domain=ack.target;
    for grants in peer.sessions.values_mut(){for grant in grants.values_mut(){*grant=EndpointGrant::default();}}
    let mut group=synthetic_roster(9,61,62);group.source=ack.target;
    let configured=ConfiguredEd25519Profile{single:config,threshold_rosters:vec![group.clone()]};
    let security=Ed25519Security::new_configured(configured,key(6),FixedClock(105)).unwrap();
    let packet=threshold_packet(canonical.core().clone(),&[(2,61),(7,62)],40);
    trace::begin();assert!(security.verify_ack(&ack,&packet));
    let mut bad=packet.clone();*bad.last_mut().unwrap()^=1;assert!(!security.verify_ack(&ack,&bad));
    let observed=trace::take();
    write_output("canonical-ack.jsonl",&[json!({"packet_hex":hex(&packet),"bad_packet_hex":hex(&bad),"ack_debug":format!("{ack:?}"),"roster":group,"trace":observed})]);
}
