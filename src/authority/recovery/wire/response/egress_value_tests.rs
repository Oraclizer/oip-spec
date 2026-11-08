//! Observe the production encoder after an explicitly typed result boundary.
//! This does not replace the dispatcher/original-preflight provenance duty.
use super::*;
use crate::authority::identity::Security;
use crate::authority::recovery::wire::ed25519::{AuthorityClock,Ed25519Profile,Ed25519Security};
use crate::wire::negotiation::{Channel,Offer,Negotiation,SignedOffers,select_profile,negotiate,offer_bytes,confirmation_bytes};
use ed25519_dalek::{Signer,SigningKey};
use sha2::{Digest,Sha256};
use std::collections::{BTreeSet,VecDeque};
use std::sync::{Arc,Mutex};
fn hex(bytes:&[u8])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn key(seed:u8)->SigningKey {SigningKey::from_bytes(&[seed;32])}
#[derive(Clone)]
struct Clock {script:Arc<Mutex<VecDeque<u64>>>,reads:Arc<Mutex<Vec<u64>>>}
impl AuthorityClock for Clock {fn unix_seconds(&self)->Option<u64> {
    let value=self.script.lock().ok()?.pop_front()?;self.reads.lock().ok()?.push(value);Some(value)
}}
struct Trace {inner:Ed25519Security<Clock>,bindings:Mutex<Vec<[u8;32]>>,parameters:Mutex<Vec<Value>>,signatures:Mutex<Vec<Value>>}
impl ResponseSigner for Trace {
    fn parameters(&self,channel:&Channel,binding:[u8;32])->Option<ResponseParameters> {
        self.bindings.lock().ok()?.push(binding);
        let value=self.inner.parameters(channel,binding)?;
        self.parameters.lock().ok()?.push(json!({"principal":value.principal,"key_id":value.key_id,"authority_epoch":value.authority_epoch,
            "issued_seconds":value.issued_seconds,"ttl_seconds":value.ttl_seconds,"uuid_hex":hex(&value.uuid),"route_scope":value.route_scope}));
        Some(value)
    }
    fn sign(&self,preimage:&[u8])->Option<[u8;64]> {
        let signature=self.inner.sign(preimage);
        self.signatures.lock().ok()?.push(json!({"preimage_hex":hex(preimage),"signature_hex":signature.map(|s|hex(&s))}));
        signature
    }
}
fn channel()->Channel {
    let offer=||Offer{deployment:7,sender:0,receiver:0,challenge:3,expires:200,versions:BTreeSet::from([6]),
        families:(1..=7).collect(),atomicities:(1..=3).collect(),schemes:BTreeSet::from([1])};
    let local=offer();let remote=offer();let profile=select_profile(&local,&remote,6,false).unwrap();
    negotiate(&Negotiation{deployment:7,local:0,remote:0,challenge:3,now:105,floor:6,legacy_allowed:false,
        local_key:key(6).verifying_key().to_bytes(),remote_key:key(7).verifying_key().to_bytes()},
        SignedOffers{local:&local,remote:&remote,local_signature:&key(6).sign(&offer_bytes(&local)).to_bytes(),
            remote_signature:&key(7).sign(&offer_bytes(&remote)).to_bytes(),
            confirmation:&key(7).sign(&confirmation_bytes(&local,&remote,&profile)).to_bytes()}).unwrap()
}
pub(super) struct EgressRecorder {inputs:File,observed:File,config:Ed25519Profile,original:CanonicalPacket,packet:Vec<u8>,channel:Channel,policy:[u8;32]}
impl EgressRecorder {
    pub(super) fn new(out:&std::path::Path)->Self {
        let first=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/reference-replay-inputs.jsonl")).lines().next().unwrap();
        let fixture:Value=serde_json::from_str(first).unwrap();
        let config:Ed25519Profile=serde_json::from_value(fixture["input"]["security_config"].clone()).unwrap();
        let clock=Clock{script:Arc::new(Mutex::new(VecDeque::new())),reads:Arc::new(Mutex::new(Vec::new()))};
        let security=Ed25519Security::new(config.clone(),key(6),clock).unwrap();
        let policy=security.authority_binding(config.authority_epoch).unwrap();
        let packet=crate::authority::recovery::wire::vector_tests::signed(crate::authority::recovery::wire::vector_tests::debit_core(2));
        let original=decode_packet(&packet,packet.len()).unwrap();
        let open=|name:&str|OpenOptions::new().create_new(true).write(true).open(out.join(name)).unwrap();
        Self{inputs:open("egress-inputs.jsonl"),observed:open("egress-observations.jsonl"),config,original,packet,channel:channel(),policy}
    }
    pub(super) fn record(&mut self,input:Value,result:ResponseResult) {
        let id=input["id"].as_str().unwrap().to_owned();
        let mut source_input=input.as_object().unwrap().clone();
        source_input.insert("raw_original_packet_hex".to_owned(),json!(hex(&self.packet)));
        source_input.insert("config".to_owned(),json!(&self.config));
        source_input.insert("policy_binding_hex".to_owned(),json!(hex(&self.policy)));
        source_input.insert("parameters_clock".to_owned(),json!(105));source_input.insert("signing_clock".to_owned(),json!(106));
        source_input.insert("frame_limit".to_owned(),json!(self.config.max_frame));
        source_input.insert("channel".to_owned(),json!({"deployment":self.channel.deployment(),"local":self.channel.local(),"remote":self.channel.remote(),
            "expires":self.channel.expires(),"version":self.channel.profile().version,"families":self.channel.profile().families,
            "atomicities":self.channel.profile().atomicities,"schemes":self.channel.profile().schemes,
            "local_public_key_hex":hex(&self.channel.peer_keys()[0]),"remote_public_key_hex":hex(&self.channel.peer_keys()[1])}));
        Recorder::write(&mut self.inputs,Value::Object(source_input));
        let (_source_scope,source_sink)=super::super::super::source_trace::local();
        let clock=Clock{script:Arc::new(Mutex::new(VecDeque::from([105,106]))),reads:Arc::new(Mutex::new(Vec::new()))};
        let trace=Trace{inner:Ed25519Security::new(self.config.clone(),key(6),clock.clone()).unwrap(),bindings:Mutex::new(Vec::new()),parameters:Mutex::new(Vec::new()),signatures:Mutex::new(Vec::new())};
        let caller=caller_id(&decode(self.original.core(),1).unwrap()).unwrap();
        let words=response_words(caller,result);
        let atomicity=response_atomicity(&self.channel).unwrap();
        let binding_preimage=words.as_ref().ok().map(|words| {
            let mut out=b"oip/reference-response-binding/v1\0".to_vec();
            out.extend((self.original.core_bytes().len() as u64).to_be_bytes());out.extend(self.original.core_bytes());
            out.extend(atomicity.to_be_bytes());out.extend((words.len() as u64).to_be_bytes());
            for word in words {out.extend(word.to_be_bytes());}out
        });
        let encoded=encode_response(&self.channel,&trace,&self.original,caller,result,self.config.max_frame);
        let bindings=trace.bindings.lock().unwrap().clone();
        if let Some(bytes)=&binding_preimage {assert_eq!(bindings,vec![<[u8;32]>::from(Sha256::digest(bytes))],"source encoder binding arguments diverged");}
        let uuid_preimage=bindings.first().map(|binding| {let mut out=b"oip/reference-response-uuid/v1\0".to_vec();out.extend(self.policy);out.extend(binding);out.extend(105u64.to_be_bytes());out});
        Recorder::write(&mut self.observed,json!({"id":id,"source_result_number":result.code as u64,"source_result_commit":result.commit.map(|c|c.position),
            "words":words.as_ref().ok(),"atomicity":atomicity,"canonical_original_core_hex":hex(self.original.core_bytes()),
            "binding_preimage_hex":binding_preimage.as_deref().map(hex),"binding_digests_hex":bindings.iter().map(|b|hex(b)).collect::<Vec<_>>(),
            "uuid_preimage_hex":uuid_preimage.as_deref().map(hex),"actual_parameters":trace.parameters.lock().unwrap().clone(),
            "actual_sign_queries":trace.signatures.lock().unwrap().clone(),"actual_clock_reads":clock.reads.lock().unwrap().clone(),
            "response_packet_hex":encoded.as_ref().ok().map(|bytes|hex(bytes)),"encoder_error_debug":encoded.err().map(|e|format!("{e:?}")),
            "trace":source_sink.lock().unwrap().clone(),
            "scope":"encode_response after typed enum boundary; dispatcher/original-preflight provenance separate"}));
    }
}
