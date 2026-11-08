//! Test-only observation of actual message call arguments and returned values.
//! It supplies no answer to the production runtime or to the model.
use super::*;
use serde_json::{Value,json};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc,Mutex,OnceLock};

type Sink=Arc<Mutex<Value>>;
static EXPECTED:OnceLock<Mutex<BTreeMap<Vec<u8>,Sink>>>=OnceLock::new();
thread_local! {static CURRENT:RefCell<Option<Sink>>=const {RefCell::new(None)};}
pub(in crate::authority::recovery::wire) struct Scope(Option<Sink>);
impl Drop for Scope {fn drop(&mut self){CURRENT.with(|slot|*slot.borrow_mut()=self.0.take());}}
pub(in crate::authority::recovery::wire) fn local()->(Scope,Sink) {
    let sink=Arc::new(Mutex::new(json!({"events":[]})));
    let prior=CURRENT.with(|slot|slot.borrow_mut().replace(sink.clone()));(Scope(prior),sink)
}
pub(in crate::authority::recovery::wire) fn register(packet:&[u8])->Sink {
    let sink=Arc::new(Mutex::new(json!({"events":[]})));
    assert!(EXPECTED.get_or_init(||Mutex::new(BTreeMap::new())).lock().unwrap().insert(packet.to_vec(),sink.clone()).is_none());sink
}
pub(in crate::authority::recovery::wire) fn unregister(packet:&[u8]) {EXPECTED.get_or_init(||Mutex::new(BTreeMap::new())).lock().unwrap().remove(packet);}
pub(in crate::authority::recovery::wire) fn begin(packet:&[u8])->Scope {
    let selected=EXPECTED.get_or_init(||Mutex::new(BTreeMap::new())).lock().unwrap().get(packet).cloned();
    let prior=CURRENT.with(|slot|{let prior=slot.borrow().clone();if let Some(sink)=selected {*slot.borrow_mut()=Some(sink)}prior});Scope(prior)
}
fn update(f:impl FnOnce(&mut Value)) {CURRENT.with(|slot|{if let Some(sink)=slot.borrow().as_ref(){f(&mut sink.lock().unwrap());}});}
fn hex(bytes:&[u8])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn event(kind:&str){update(|value|value["events"].as_array_mut().unwrap().push(json!(kind)));}
pub(in crate::authority::recovery::wire) fn received(value:&Received,retained:Option<Receipt>) {
    let reply=match &value.reply {WireReply::Executed(reply)=>super::vector_tests::boundary_values::action(*reply),_=>vec![3]};
    let retained_values=retained.map(super::vector_tests::boundary_values::receipt).unwrap_or_default();
    update(|out|{out["typed_observation"]=json!({"mode":0,"reply_values":reply.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "retained_present":retained.is_some(),"retained_values":retained_values.iter().map(ToString::to_string).collect::<Vec<_>>()});
        out["raw_typed_return_debug"]=json!(format!("received={value:?}; retained={retained:?}"));});event("before-from-received");
}
pub(in crate::authority::recovery::wire) fn wire_error(value:&WireError) {
    let reply=super::vector_tests::boundary_values::error(value);
    update(|out|{out["typed_observation"]=json!({"mode":2,"reply_values":reply.iter().map(ToString::to_string).collect::<Vec<_>>(),"retained_present":false,"retained_values":[]});
        out["raw_typed_return_debug"]=json!(format!("wire_error={value:?}"));});event("before-error-converter");
}
pub(in crate::authority::recovery::wire) fn resolved(value:DebitResult) {
    let reply=match value {DebitResult::Rejected=>vec![0],DebitResult::Unresolved=>vec![2],DebitResult::Published(r)=>{
        let mut out=vec![1];out.extend(super::vector_tests::boundary_values::receipt(r));out}};
    update(|out|{out["typed_observation"]=json!({"mode":1,"reply_values":reply.iter().map(ToString::to_string).collect::<Vec<_>>(),"retained_present":false,"retained_values":[]});
        out["raw_typed_return_debug"]=json!(format!("resolution={value:?}"));});event("before-resolution-converter");
}
pub(in crate::authority::recovery::wire) fn product_enter(core:&Core,operands:&Operands,entry:crate::authority::identity::Entry) {
    update(|out|{out["run_operand_enter"]=json!({"canonical_core_hex":hex(&encode_core(core).unwrap()),"typed_operand_debug":format!("{operands:?}"),"entry_debug":format!("{entry:?}")});});event("actual-run-operand-enter");
}
pub(in crate::authority::recovery::wire) fn product_return(value:&WireReply){update(|out|out["run_operand_return_debug"]=json!(format!("{value:?}")));event("actual-run-operand-return");}
pub(in crate::authority::recovery::wire) fn execute_enter(value:&crate::authority::identity::Request<'_>){update(|out|out["execute_durable_arguments_debug"]=json!(format!("{value:?}")));event("actual-execute-durable-enter");}
pub(in crate::authority::recovery::wire) fn execute_return(value:&Result<crate::authority::identity::ActionReply,crate::authority::identity::EndpointError>){update(|out|out["execute_durable_return_debug"]=json!(format!("{value:?}")));event("actual-execute-durable-return");}
pub(super) fn encoder(original:&CanonicalPacket,id:CallId,result:ResponseResult) {
    update(|out|{out["canonical_original_core_hex"]=json!(hex(original.core_bytes()));out["actual_call_id"]=json!([id.namespace,id.sequence]);
        out["converted"]=json!([result.code as u64,u64::from(result.commit.is_some()),result.commit.map(|c|c.position as u64).unwrap_or(0)]);});event("actual-encode-response");
}
pub(super) fn postcheck(value:&VerifiedResponse){update(|out|out["actual_postcheck"]=json!(client_result(value)));}
pub(in crate::authority::recovery::wire) fn words(value:&[u64]){update(|out|out["words"]=json!(value));}
pub(in crate::authority::recovery::wire) fn atomicity(value:u64){update(|out|out["atomicity"]=json!(value));}
pub(in crate::authority::recovery::wire) fn core(value:&[u8]){update(|out|out["canonical_response_core_hex"]=json!(hex(value)));}
pub(in crate::authority::recovery::wire) fn parameters(binding:[u8;32],value:&ResponseParameters){update(|out|{
    out["binding_digest_hex"]=json!(hex(&binding));out["parameters"]=json!({"principal":value.principal,"key_id":value.key_id,"authority_epoch":value.authority_epoch,
        "issued_seconds":value.issued_seconds,"ttl_seconds":value.ttl_seconds,"uuid_hex":hex(&value.uuid),"route_scope":value.route_scope});});}
pub(in crate::authority::recovery::wire) fn uuid_digest(bytes:&[u8]){update(|out|out["uuid_digest_hex"]=json!(hex(bytes)));}
pub(in crate::authority::recovery::wire) fn clock(kind:&str,value:u64){update(|out|out[kind]=json!(value));}
pub(in crate::authority::recovery::wire) fn signer_attempt(bytes:&[u8]){update(|out|{out["signer_attempt_preimage_hex"]=json!(hex(bytes));out["signer_guard_permitted"]=json!(false);});event("actual-signer-method-attempt");}
pub(in crate::authority::recovery::wire) fn curve_signature(bytes:&[u8]){update(|out|{out["signer_guard_permitted"]=json!(true);out["curve_signature_hex"]=json!(hex(bytes));});event("actual-curve-signature");}
pub(in crate::authority::recovery::wire) fn client_result(value:&VerifiedResponse)->Vec<u64>{
    let (kind,number,known)=match value.code {ResponseStatus::Known(code)=>(code.descriptor().0,code as u64,1),ResponseStatus::Unknown{kind,code}=>(kind as u64,code,0)};
    vec![value.id.namespace,value.id.sequence,kind,number,u64::from(value.commit.is_some()),value.commit.map(|c|c.position as u64).unwrap_or(0),known,kind,number]
}
