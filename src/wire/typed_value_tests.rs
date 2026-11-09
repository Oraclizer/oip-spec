//! Project actual decoded Rust values into the shared typed-value IR.
use crate::authority::regulation::{Action, LegalStage, SpendKind};
use crate::lock_finality::{Binding, Command, EndpointContext, Permission, Route, TerminalKind};
use crate::wire::codec::{decode_core, encode_core};
use crate::wire::generated::Core;
use crate::wire::operands::{Operands, QueryOperand, ReadOperand, decode};
use crate::{CallId, CommitCut};

type Ir = Vec<u64>;
fn scalar(value:u64)->Ir {vec![0,value]}
fn node(tag:u64,fields:Vec<Ir>)->Ir {let mut out=vec![tag,fields.len() as u64];for field in fields {out.extend(field)}out}
fn bytes(value:&[u8])->Ir {let mut out=vec![1,value.len() as u64];out.extend(value.iter().map(|v|u64::from(*v)));out}
fn list(values:impl IntoIterator<Item=Ir>)->Ir {node(2,values.into_iter().collect())}
fn option<T>(value:Option<T>, project:impl FnOnce(T)->Ir)->Ir {match value {None=>vec![3],Some(value)=>{let mut out=vec![4];out.extend(project(value));out}}}
fn pair(first:u64,second:u64)->Ir {node(90,vec![scalar(first),scalar(second)])}
fn triple(first:u64,second:u64,third:u64)->Ir {node(91,vec![scalar(first),scalar(second),scalar(third)])}
fn cut(value:CommitCut)->Ir {pair(value.authority_epoch,value.revision as u64)}
fn native(id:CallId,reference:u64,session:u64,expected:CommitCut,origin_epoch:u64,binding:Binding,endpoint:u64,caller:u64)->Ir {
    node(100,vec![scalar(reference),pair(id.namespace,id.sequence),scalar(session),cut(expected),scalar(origin_epoch),
        pair(binding.origin.domain,binding.origin.event),scalar(binding.asset),scalar(binding.owner),scalar(binding.destination),
        scalar(binding.recipient),scalar(binding.amount),scalar(endpoint),scalar(caller)])
}
fn terminal(value:TerminalKind)->u64 {match value {TerminalKind::Confirmed=>1,TerminalKind::Reversed=>2}}
fn command(value:Command)->Ir {match value {
    Command::Reserve{duration}=>node(110,vec![scalar(duration)]),
    Command::Dispatch{generation}=>node(111,vec![scalar(generation)]),
    Command::Debit{generation}=>node(112,vec![scalar(generation)]),
    Command::Cancel{generation}=>node(113,vec![scalar(generation)]),
    Command::Fence{generation}=>node(114,vec![scalar(generation)]),
    Command::Preempt{duration}=>node(115,vec![scalar(duration)]),
    Command::Timeout{elapsed}=>node(116,vec![scalar(elapsed)]),
    Command::RecordTerminal(value)=>node(117,vec![scalar(terminal(value.kind)),scalar(value.reference)]),
    Command::Credit{reference}=>node(118,vec![scalar(reference)]),
    Command::Refund{generation,reference}=>node(119,vec![scalar(generation),scalar(reference)]),
    Command::Reconcile{generation,reference}=>node(120,vec![scalar(generation),scalar(reference)]),
    Command::Write{generation,value}=>node(121,vec![scalar(generation),scalar(value)]),
    Command::PublishPrimary=>node(122,vec![]),
}}
fn query(value:QueryOperand)->Ir {match value {
    QueryOperand::Application(asset)=>node(160,vec![scalar(asset)]),
    QueryOperand::Source{domain,asset}=>node(161,vec![pair(domain,asset)]),
    QueryOperand::Destination{domain,asset,holder}=>node(162,vec![triple(domain,asset,holder)]),
    QueryOperand::Root{origin,destination,asset,holder}=>node(163,vec![pair(origin.domain,origin.event),triple(destination,asset,holder)]),
    QueryOperand::Regulatory{domain,asset}=>node(164,vec![scalar(domain),scalar(asset)]),
    QueryOperand::Terminal(origin)=>node(165,vec![pair(origin.domain,origin.event)]),
}}
fn read(value:ReadOperand,epoch:u64)->Ir {
    let proof=node(104,vec![scalar(value.session()),scalar(epoch)]);
    match value {
        ReadOperand::Current{revision,query:value,..}=>node(13,vec![proof,node(150,vec![query(value),pair(epoch,revision as u64)])]),
        ReadOperand::Historical{revision,query:value,..}=>node(13,vec![proof,node(151,vec![query(value),scalar(revision as u64)])]),
        ReadOperand::Raw{query:value,..}=>node(13,vec![proof,node(152,vec![query(value)])]),
        ReadOperand::Status{origin,..}=>node(13,vec![proof,node(153,vec![pair(origin.domain,origin.event)])]),
        ReadOperand::Journal{..}=>node(13,vec![proof,node(154,vec![])]),
        ReadOperand::Capture{query:value,..}=>node(14,vec![proof,query(value)]),
        ReadOperand::Owner{asset,..}=>node(13,vec![proof,node(155,vec![scalar(asset)])]),
    }
}
fn route(value:Route)->u64 {match value {Route::Normal=>0,Route::Administrative=>1,Route::Adapter=>2}}
fn permission(value:Permission)->u64 {match value {
    Permission::Reserve=>0,Permission::Dispatch=>1,Permission::Debit=>2,Permission::Cancel=>3,Permission::Fence=>4,
    Permission::Preempt=>5,Permission::ObserveTime=>6,Permission::Attest=>7,Permission::Credit=>8,Permission::Refund=>9,
    Permission::Reconcile=>10,Permission::Write=>11,Permission::PublishPrimary=>12,
}}
fn context(value:&EndpointContext)->Ir {
    node(106,vec![scalar(value.endpoint),scalar(value.epoch),
        list(value.grants.iter().map(|(principal,r,p)|triple(*principal,route(*r),permission(*p)))),
        list(value.dependencies.iter().map(|(asset,deps)|node(109,vec![scalar(*asset),list(deps.iter().copied().map(scalar))]))),
        list(value.write_permissions.iter().map(|(principal,asset,epoch)|triple(*principal,*asset,*epoch)))])
}
fn action(value:Action)->u64 {match value {Action::Freeze=>1,Action::Restrict=>2,Action::Seize=>3,Action::Confiscate=>4,
    Action::Unfreeze=>5,Action::Unrestrict=>6,Action::Release=>7}}
fn spend_kind(value:SpendKind)->u64 {match value {SpendKind::Ordinary=>0,SpendKind::Recover=>1,SpendKind::Seize=>2,
    SpendKind::Confiscate=>3,SpendKind::Liquidate=>4}}

pub(super) fn operand_ir(core:&Core,value:&Operands,depth:usize)->Ir {
    match value {
        Operands::Ordinary{id,payload,proofs}=>{
            if let Command::RecordTerminal(evidence)=payload.command {assert_eq!(evidence.binding,payload.binding,"typed terminal binding copy diverged");}
            node(10,vec![
            native(*id,payload.message_id,payload.session,payload.cut,payload.origin_epoch,payload.binding,payload.endpoint,payload.caller),
            option(payload.credential,|c|node(101,vec![scalar(c.asset),scalar(c.holder),scalar(c.generation),scalar(c.epoch),pair(c.origin.domain,c.origin.event)])),
            list(payload.versions.iter().map(|(asset,version)|pair(*asset,*version))),command(payload.command),list(proofs.iter().map(|p|bytes(p)))])},
        Operands::SyncCommitment {
            id, message_reference, session, cut: expected, origin_epoch, origin_domain,
            origin_event, asset, source_position, mode, commitment, predecessor, source_attestation,
        } => node(22, vec![
            scalar(*message_reference),
            pair(id.namespace, id.sequence),
            scalar(*session),
            cut(*expected),
            scalar(*origin_epoch),
            pair(*origin_domain, *origin_event),
            scalar(*asset),
            scalar(*source_position),
            scalar(*mode as u64),
            bytes(commitment),
            option(predecessor.as_ref(), |predecessor| bytes(predecessor)),
            bytes(source_attestation),
        ]),
        Operands::Legal{id,stage,payload,order,proof}=>{
            assert_eq!(order.binding,payload.binding,"typed legal binding copy diverged");
            assert_eq!(order.action,payload.action,"typed legal action copy diverged");
            node(11,vec![
            native(*id,payload.message_id,payload.session,payload.cut,payload.origin_epoch,payload.binding,core.target_domain.expect("typed target"),payload.caller),
            scalar(match stage {LegalStage::SourceEmission=>0,LegalStage::ReceivingCommit=>1}),
            node(102,vec![scalar(action(order.action)),scalar(order.officer),scalar(order.jurisdiction),scalar(order.legal_basis),scalar(order.issuance_epoch),
                list(order.scope.iter().copied().map(scalar)),option(order.predecessor,|o|pair(o.domain,o.event)),
                option(order.destination,scalar),option(order.appeal_deadline,scalar)]),bytes(proof)])},
        Operands::Spend{id,payload,authorization,proof}=>{
            if let Some(order)=authorization {assert_eq!(order.scope,payload.scope,"typed spend scope copy diverged");}
            node(12,vec![
            native(*id,payload.message_id,payload.session,payload.cut,payload.origin_epoch,payload.scope.root,core.target_domain.expect("typed target"),payload.caller),
            node(103,vec![scalar(payload.reference.position as u64),scalar(payload.scope.sender),scalar(payload.scope.recipient),
                scalar(spend_kind(payload.scope.kind)),scalar(payload.scope.amount),
                option(authorization.as_ref(),|a|node(108,vec![scalar(a.officer),scalar(a.jurisdiction),scalar(a.legal_basis),
                    list(a.assets.iter().copied().map(scalar)),option(a.prior_seizure,|o|pair(o.domain,o.event)),option(a.appeal_deadline,scalar)])),
                option(proof.as_deref(),bytes)])])},
        Operands::Read(value)=>read(*value,core.authority_epoch.expect("typed epoch")),
        Operands::CurrentCommitment { session, revision, asset, origin_domain } => {
            let epoch = core.authority_epoch.expect("typed epoch");
            let proof = node(104, vec![scalar(*session), scalar(epoch)]);
            let request = node(156, vec![pair(epoch, *revision as u64), scalar(*asset), scalar(*origin_domain)]);
            node(13, vec![proof, request])
        },
        Operands::Receipt{session,original}=>{
            let decoded=decode(original,depth.checked_sub(1).expect("typed receipt depth")).expect("actual nested operand");
            node(15,vec![scalar(*session),bytes(&encode_core(original).expect("decoded original reencoding")),operand_ir(original,&decoded,depth-1)])
        },
        Operands::Response{id,kind,code,commit,original}=>{
            let original=decode_core(original).expect("actual decoded original");
            let decoded=decode(&original,depth.checked_sub(1).expect("typed response depth")).expect("actual nested operand");
            node(16,vec![pair(id.namespace,id.sequence),scalar(*kind),scalar(*code),option(*commit,|c|scalar(c.position as u64)),
                bytes(&encode_core(&original).expect("decoded original reencoding")),operand_ir(&original,&decoded,depth-1)])
        },
        Operands::Ack(value)=>{let d=value.commitment.decision;let b=d.binding;
            assert_eq!(value.key.origin,value.commitment.origin,"typed ACK publication origin diverged");
            assert_eq!(value.key.origin,b.origin,"typed ACK binding origin diverged");
            assert_eq!(value.key.commit,d.commit,"typed ACK commit copy diverged");
            node(17,vec![node(105,vec![pair(value.key.origin.domain,value.key.origin.event),scalar(value.key.commit.position as u64),
                scalar(value.target),scalar(b.asset),scalar(b.owner),scalar(b.destination),scalar(b.recipient),scalar(b.amount),
                scalar(d.origin_epoch),scalar(terminal(d.kind))])])},
        Operands::Capabilities(value)=>node(18,vec![scalar(value.deployment),scalar(value.sender),scalar(value.receiver),scalar(value.challenge),scalar(value.expires),
            list(value.versions.iter().copied().map(scalar)),list(value.families.iter().copied().map(scalar)),
            list(value.atomicities.iter().copied().map(scalar)),list(value.schemes.iter().copied().map(scalar))]),
        Operands::Liveness{challenge,expires}=>node(19,vec![scalar(*challenge),scalar(*expires)]),
        Operands::Handover{session,proposal,proofs}=>node(20,vec![scalar(*session),cut(proposal.expected),scalar(proposal.asset),
            scalar(proposal.previous),scalar(proposal.successor),scalar(proposal.old_session),scalar(proposal.new_session),scalar(proposal.epoch),
            list(proposal.contexts.iter().map(context)),bytes(&proofs[0]),bytes(&proofs[1])]),
        Operands::Install{session,cut:expected,epoch,contexts,sessions,proof}=>node(21,vec![scalar(*session),cut(*expected),scalar(*epoch),
            list(contexts.iter().map(context)),list(sessions.iter().map(|(id,value)|node(107,vec![scalar(*id),scalar(value.principal),scalar(value.authority_epoch)]))),bytes(proof)]),
    }
}

pub(super) fn key_ir(key:crate::wire::admission::TransportKey)->Ir {
    node(200,vec![scalar(key.deployment),scalar(key.source),scalar(key.principal),bytes(&key.uuid)])
}
pub(super) fn decimal(value:Ir)->Vec<String> {value.into_iter().map(|v|v.to_string()).collect()}
