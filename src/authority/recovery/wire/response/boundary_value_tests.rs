//! Actual source converter inputs/outputs at the declared product-result boundary.
use super::super::*;
use crate::wire::admission::Arrival;
use crate::authority::recovery::{RecoveryError};
use crate::authority::identity::EndpointError;
use serde_json::{Value,json};
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::PathBuf;
#[path = "egress_value_tests.rs"]
mod egress_values;

fn cat(head:&[u64],tail:Vec<u64>)->Vec<u64> {let mut out=head.to_vec();out.extend(tail);out}
fn commit(value:Option<CommitRef>)->Vec<u64> {match value {None=>vec![0,0],Some(c)=>vec![1,c.position as u64]}}
fn accepted(value:Reply)->u64 {match value {Reply::Rejected=>0,Reply::Busy=>1,Reply::Reserved=>2,Reply::SourceDispatched=>3,
    Reply::Debited=>4,Reply::Closed=>5,Reply::Preempted=>6,Reply::TimeObserved=>7,Reply::Recorded=>8,Reply::Credited=>9,
    Reply::Reconciled=>10,Reply::Refunded=>11,Reply::DataUpdated=>12,Reply::EvidenceRefreshed=>13,Reply::Published=>14}}
fn outcome(value:Outcome)->Vec<u64> {cat(&match value.reply {
    OutcomeReply::Accepted(reply)=>vec![0,accepted(reply)],OutcomeReply::DuplicateDecision=>vec![1],
    OutcomeReply::DuplicateSettlement(TerminalKind::Confirmed)=>vec![2,1],OutcomeReply::DuplicateSettlement(TerminalKind::Reversed)=>vec![2,2],
    OutcomeReply::Rejected=>vec![3],OutcomeReply::Busy=>vec![4],OutcomeReply::Unavailable=>vec![5]},commit(value.commit))}
fn collection(value:Collection)->Vec<u64> {match value {Collection::Collected(value)=>cat(&[0],outcome(value)),Collection::Waiting=>vec![1],Collection::Rejected=>vec![2]}}
fn refusal(value:Refusal)->u64 {match value {Refusal::InvalidAuthority=>0,Refusal::InvalidState=>1,Refusal::InvalidBinding=>2,
    Refusal::MissingPriorFreeze=>3,Refusal::MissingPriorSeizure=>4,Refusal::AppealStillOpen=>5,Refusal::AppealDeadlineMismatch=>6,
    Refusal::MissingDestination=>7,Refusal::ConflictingOrder=>8,Refusal::Busy=>9,Refusal::Unavailable=>10}}
fn legal(value:LegalReply)->Vec<u64> {match value {LegalReply::Emitted(c)=>vec![0,c.position as u64],LegalReply::Applied(c)=>vec![1,c.position as u64],LegalReply::Refused(r)=>vec![2,refusal(r)]}}
fn spend(value:SpendReply)->Vec<u64> {match value {SpendReply::Executed{root,commit}=>vec![0,root.domain,root.event,commit.position as u64],
    SpendReply::Rejected=>vec![1],SpendReply::Busy=>vec![2],SpendReply::Unavailable=>vec![3]}}
pub(in crate::authority::recovery::wire::response) fn receipt(value:Receipt)->Vec<u64> {match value {Receipt::Ordinary(value)=>cat(&[0],collection(value)),Receipt::Legal(value)=>cat(&[1],legal(value)),Receipt::Spend(value)=>cat(&[2],spend(value))}}
pub(in crate::authority::recovery::wire::response) fn action(value:ActionReply)->Vec<u64> {match value {
    ActionReply::Ordinary(CheckedExecution::Forwarded(value))=>cat(&[0,0],collection(value)),
    ActionReply::Ordinary(CheckedExecution::Busy)=>vec![0,1],ActionReply::Ordinary(CheckedExecution::Unavailable)=>vec![0,2],
    ActionReply::Ordinary(CheckedExecution::Rejected)=>vec![0,3],ActionReply::Legal(value)=>cat(&[1],legal(value)),ActionReply::Spend(value)=>cat(&[2],spend(value))}}
pub(in crate::authority::recovery::wire::response) fn error(value:&WireError)->Vec<u64> {vec![match value {
    WireError::InvalidFormat=>0,WireError::UnsupportedVersion=>1,WireError::InvalidSource=>2,WireError::InvalidSignature=>3,
    WireError::InvalidThresholdSignature=>4,WireError::TtlExpired=>5,WireError::TtlInvalid=>6,WireError::ReplayConflict=>7,
    WireError::ProductRejected=>8,WireError::Cancelled=>9,WireError::DeadlineExpired=>10,WireError::ResponseLost=>11,
    WireError::RequestUnresolved=>12,WireError::Recovery(RecoveryError::Endpoint(EndpointError::Rejected))=>13,
    WireError::Recovery(RecoveryError::Endpoint(EndpointError::Unavailable))=>14,WireError::Recovery(_)=>15}]}
fn decimal(values:Vec<u64>)->Vec<String> {values.into_iter().map(|v|v.to_string()).collect()}
struct Recorder {input:File,observed:File,raw:File,count:usize,pending:Option<Value>,egress:egress_values::EgressRecorder}
impl Recorder {
    fn write(file:&mut File,value:Value) {serde_json::to_writer(&mut *file,&value).unwrap();file.write_all(b"\n").unwrap();file.flush().unwrap();file.sync_all().unwrap();}
    fn input(&mut self,mode:u64,reply:Vec<u64>,retained:Option<Receipt>)->String {
        let id=format!("result-{}",self.count);self.count+=1;
        let row=json!({"id":id,"mode":mode,"reply_values":decimal(reply),"retained_present":retained.is_some(),
            "retained_values":decimal(retained.map(receipt).unwrap_or_default())});
        Self::write(&mut self.input,row.clone());self.pending=Some(row);id
    }
    fn output(&mut self,id:&str,value:ResponseResult) {
        Self::write(&mut self.observed,json!({"id":id,"number":value.code as u64,"commit":value.commit.map(|c|c.position as u64)}));
        let input=self.pending.take().expect("typed input precedes conversion");assert_eq!(input["id"],id);
        self.egress.record(input,value);
    }
    fn raw(&mut self,id:&str,value:String) {Self::write(&mut self.raw,json!({"id":id,"actual_source_enum_debug":value}));}
    fn received(&mut self,value:ActionReply,retained:Option<Receipt>) {
        let id=self.input(0,action(value),retained);
        self.raw(&id,format!("received={value:?}; retained={retained:?}"));
        let result=ResponseResult::from_received(Received{arrival:Arrival::First,reply:WireReply::Executed(value)},retained);
        self.output(&id,result);
    }
    fn resolved(&mut self,value:DebitResult) {
        let encoded=match value {DebitResult::Rejected=>vec![0],DebitResult::Unresolved=>vec![2],DebitResult::Published(r)=>cat(&[1],receipt(r))};
        let id=self.input(1,encoded,None);self.raw(&id,format!("resolution={value:?}"));self.output(&id,ResponseResult::from_resolution(value));
    }
}

#[test]
fn actual_typed_response_result_boundary_values() {
    let out=if let Some(value)=std::env::var_os("OIP_REFERENCE_OUTPUT_DIR") {PathBuf::from(value).join("result-converter")}
        else {PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/response-boundary").join(format!("{}-{}",std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))};
    fs::create_dir_all(&out).unwrap();
    let open=|name:&str|OpenOptions::new().create_new(true).write(true).open(out.join(name)).unwrap();
    let mut r=Recorder{input:open("inputs.jsonl"),observed:open("observations.jsonl"),raw:open("raw-boundary-values.jsonl"),count:0,pending:None,egress:egress_values::EgressRecorder::new(&out)};
    let replies=[Reply::Rejected,Reply::Busy,Reply::Reserved,Reply::SourceDispatched,Reply::Debited,Reply::Closed,Reply::Preempted,
        Reply::TimeObserved,Reply::Recorded,Reply::Credited,Reply::Reconciled,Reply::Refunded,Reply::DataUpdated,Reply::EvidenceRefreshed,Reply::Published];
    let mut outcomes=Vec::new();
    for reply in replies {outcomes.push(OutcomeReply::Accepted(reply));}
    outcomes.extend([OutcomeReply::DuplicateDecision,OutcomeReply::DuplicateSettlement(TerminalKind::Confirmed),
        OutcomeReply::DuplicateSettlement(TerminalKind::Reversed),OutcomeReply::Rejected,OutcomeReply::Busy,OutcomeReply::Unavailable]);
    for reply in outcomes {for commit in [None,Some(CommitRef{position:2})] {
        let value=Outcome{reply,commit};let stored=Receipt::Ordinary(Collection::Collected(value));
        r.received(ActionReply::Ordinary(CheckedExecution::Forwarded(Collection::Collected(value))),Some(stored));
        r.received(ActionReply::Ordinary(CheckedExecution::Forwarded(Collection::Collected(value))),None);
        r.resolved(DebitResult::Published(stored));
    }}
    for value in [CheckedExecution::Busy,CheckedExecution::Unavailable,CheckedExecution::Rejected,
        CheckedExecution::Forwarded(Collection::Waiting),CheckedExecution::Forwarded(Collection::Rejected)] {r.received(ActionReply::Ordinary(value),None);}
    let refusals=[Refusal::InvalidAuthority,Refusal::InvalidState,Refusal::InvalidBinding,Refusal::MissingPriorFreeze,
        Refusal::MissingPriorSeizure,Refusal::AppealStillOpen,Refusal::AppealDeadlineMismatch,Refusal::MissingDestination,
        Refusal::ConflictingOrder,Refusal::Busy,Refusal::Unavailable];
    let mut legal_values=vec![LegalReply::Emitted(CommitRef{position:7}),LegalReply::Applied(CommitRef{position:7})];
    legal_values.extend(refusals.map(LegalReply::Refused));
    for value in legal_values {r.received(ActionReply::Legal(value),Some(Receipt::Legal(value)));r.received(ActionReply::Legal(value),None);r.resolved(DebitResult::Published(Receipt::Legal(value)));}
    let root=crate::OriginKey{domain:0,event:17};let other=crate::OriginKey{domain:0,event:18};let commit=CommitRef{position:7};
    let paid=SpendReply::Executed{root,commit};
    for stored in [Some(Receipt::Spend(paid)),Some(Receipt::Spend(SpendReply::Executed{root:other,commit})),
        Some(Receipt::Spend(SpendReply::Executed{root,commit:CommitRef{position:8}})),None] {r.received(ActionReply::Spend(paid),stored);}
    for value in [paid,SpendReply::Rejected,SpendReply::Busy,SpendReply::Unavailable] {
        r.received(ActionReply::Spend(value),Some(Receipt::Spend(value)));r.received(ActionReply::Spend(value),None);r.resolved(DebitResult::Published(Receipt::Spend(value)));
    }
    for value in [DebitResult::Rejected,DebitResult::Unresolved,DebitResult::Published(Receipt::Ordinary(Collection::Waiting)),DebitResult::Published(Receipt::Ordinary(Collection::Rejected))] {r.resolved(value);}
    let id=r.input(0,vec![3],None);r.raw(&id,"WireReply::Changed(true); retained=None".to_owned());r.output(&id,ResponseResult::from_received(Received{arrival:Arrival::First,reply:WireReply::Changed(true)},None));
    for value in [WireError::InvalidFormat,WireError::UnsupportedVersion,WireError::InvalidSource,WireError::InvalidSignature,
        WireError::InvalidThresholdSignature,WireError::TtlExpired,WireError::TtlInvalid,WireError::ReplayConflict,
        WireError::ProductRejected,WireError::Cancelled,WireError::DeadlineExpired,WireError::ResponseLost,WireError::RequestUnresolved,
        WireError::Recovery(RecoveryError::Endpoint(EndpointError::Rejected)),WireError::Recovery(RecoveryError::Endpoint(EndpointError::Unavailable)),
        WireError::Recovery(RecoveryError::Hold)] {let id=r.input(2,error(&value),None);r.raw(&id,format!("wire_error={value:?}"));r.output(&id,ResponseResult::error(value));}
    fs::write(out.join("scope.json"),serde_json::to_vec(&json!({"scope":"actual typed enum converter fixtures","cases":r.count,
        "dispatcher_producer_provenance":false,"source_verdict_as_model_input":false})).unwrap()).unwrap();
    assert_eq!(r.count,207,"The declared converter fixture set changed");
}
