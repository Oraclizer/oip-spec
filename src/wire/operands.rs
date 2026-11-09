//! Positional operands whose meaning the family and opcode fix, decoded from the
//! canonical operation and never from a second request.

use super::codec::{Result, Unsigned256, WireError, body, decode_core};
use super::generated::{Core, Operation, operation::AppealDeadline};
use super::negotiation::Offer;
use crate::authority::identity::Handover;
use crate::authority::recovery::wire::response::{ResponseCode, ResponseStatus};
use crate::authority::regulation::{
    Action as LegalAction, EnforcementOrder, LegalStage, Order, SpendKind, SpendScope,
};
use crate::authority::{
    Acknowledgement, CallPayload, CommitRef, OriginDecision, Publication, SettlementKey,
};
use crate::lock_finality::{
    Binding, Command, Credential, EndpointContext, TerminalEvidence, TerminalKind,
};
use crate::{CallId, CommitCut, OriginKey, SessionBinding};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

const BAD: WireError = WireError::InvalidFormat;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryOperand {
    Application(u64),
    Source {
        domain: u64,
        asset: u64,
    },
    Destination {
        domain: u64,
        asset: u64,
        holder: u64,
    },
    Root {
        origin: OriginKey,
        destination: u64,
        asset: u64,
        holder: u64,
    },
    Regulatory {
        domain: u64,
        asset: u64,
    },
    Terminal(OriginKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOperand {
    Current {
        session: u64,
        revision: usize,
        query: QueryOperand,
    },
    Historical {
        session: u64,
        revision: usize,
        query: QueryOperand,
    },
    Raw {
        session: u64,
        query: QueryOperand,
    },
    Status {
        session: u64,
        origin: OriginKey,
    },
    Journal {
        session: u64,
    },
    Capture {
        session: u64,
        query: QueryOperand,
    },
    Owner {
        session: u64,
        asset: u64,
    },
}

impl ReadOperand {
    pub fn session(self) -> u64 {
        match self {
            Self::Current { session, .. }
            | Self::Historical { session, .. }
            | Self::Raw { session, .. }
            | Self::Status { session, .. }
            | Self::Journal { session }
            | Self::Capture { session, .. }
            | Self::Owner { session, .. } => session,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum SyncMode {
    Initial = 1,
    Incremental = 2,
    FullResync = 3,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operands {
    Ordinary {
        id: CallId,
        payload: CallPayload,
        proofs: Vec<Vec<u8>>,
    },
    SyncCommitment {
        id: CallId,
        message_reference: u64,
        session: u64,
        cut: CommitCut,
        origin_epoch: u64,
        origin_domain: u64,
        origin_event: u64,
        asset: u64,
        source_position: u64,
        mode: SyncMode,
        commitment: [u8; 32],
        predecessor: Option<[u8; 32]>,
        source_attestation: Vec<u8>,
    },
    Read(ReadOperand),
    CurrentCommitment {
        session: u64,
        revision: usize,
        asset: u64,
        origin_domain: u64,
    },
    Receipt {
        session: u64,
        original: Box<Core>,
    },
    Legal {
        id: CallId,
        stage: LegalStage,
        payload: crate::authority::regulation::LegalPayload,
        order: Order,
        proof: Vec<u8>,
    },
    Spend {
        id: CallId,
        payload: crate::authority::regulation::SpendPayload,
        authorization: Option<EnforcementOrder>,
        proof: Option<Vec<u8>>,
    },
    Ack(Acknowledgement),
    Response {
        id: CallId,
        kind: u64,
        code: u64,
        commit: Option<CommitRef>,
        original: Vec<u8>,
    },
    Capabilities(Offer),
    Liveness {
        challenge: u64,
        expires: u64,
    },
    Handover {
        session: u64,
        proposal: Handover,
        proofs: [Vec<u8>; 2],
    },
    Install {
        session: u64,
        cut: CommitCut,
        epoch: u64,
        contexts: Vec<EndpointContext>,
        sessions: BTreeMap<u64, SessionBinding>,
        proof: Vec<u8>,
    },
}

struct Words<'a>(&'a [u64]);

impl Words<'_> {
    fn word(&mut self) -> Result<u64> {
        let (word, remaining) = self.0.split_first().ok_or(BAD)?;
        self.0 = remaining;
        Ok(*word)
    }
    fn size(&mut self) -> Result<usize> {
        usize::try_from(self.word()?).map_err(|_| BAD)
    }
    fn origin(&mut self) -> Result<OriginKey> {
        Ok(OriginKey {
            domain: self.word()?,
            event: self.word()?,
        })
    }
    fn present(&mut self) -> Result<bool> {
        match self.word()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(BAD),
        }
    }
    fn optional_origin(&mut self) -> Result<Option<OriginKey>> {
        if self.present()? {
            Ok(Some(self.origin()?))
        } else {
            Ok(None)
        }
    }
    fn optional_word(&mut self) -> Result<Option<u64>> {
        if self.present()? {
            Ok(Some(self.word()?))
        } else {
            Ok(None)
        }
    }
    fn take(&mut self, count: usize) -> Result<&[u64]> {
        let (items, remaining) = self.0.split_at_checked(count).ok_or(BAD)?;
        self.0 = remaining;
        Ok(items)
    }
    fn set(&mut self) -> Result<BTreeSet<u64>> {
        let count = self.size()?;
        let items = self.take(count)?;
        if items.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BAD);
        }
        Ok(items.iter().copied().collect())
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() { Ok(()) } else { Err(BAD) }
    }
}

fn query(words: &[u64]) -> Result<QueryOperand> {
    Ok(match words {
        [1, asset] => QueryOperand::Application(*asset),
        [2, domain, asset] => QueryOperand::Source {
            domain: *domain,
            asset: *asset,
        },
        [3, domain, asset, holder] => QueryOperand::Destination {
            domain: *domain,
            asset: *asset,
            holder: *holder,
        },
        [4, source, event, destination, asset, holder] => QueryOperand::Root {
            origin: OriginKey {
                domain: *source,
                event: *event,
            },
            destination: *destination,
            asset: *asset,
            holder: *holder,
        },
        [5, domain, asset] => QueryOperand::Regulatory {
            domain: *domain,
            asset: *asset,
        },
        [6, domain, event] => QueryOperand::Terminal(OriginKey {
            domain: *domain,
            event: *event,
        }),
        _ => return Err(BAD),
    })
}

fn read(op: &Operation, depth: usize) -> Result<Operands> {
    let mut words = Words(&op.words);
    let session = words.word()?;
    if op.appeal_deadline.is_some() {
        return Err(BAD);
    }
    if op.opcode == Some(8) {
        words.end()?;
        let [original] = op.blobs.as_slice() else {
            return Err(BAD);
        };
        if depth <= 1 {
            return Err(BAD);
        }
        let core = decode_core(original)?;
        if !matches!(
            decode(&core, depth - 1)?,
            Operands::Ordinary { .. }
                | Operands::Legal { .. }
                | Operands::Spend { .. }
                | Operands::SyncCommitment { .. }
        ) {
            return Err(BAD);
        }
        return Ok(Operands::Receipt {
            session,
            original: Box::new(core),
        });
    }
    if !op.blobs.is_empty() {
        return Err(BAD);
    }
    if op.opcode == Some(9) {
        let revision = words.size()?;
        let asset = words.word()?;
        let origin_domain = words.word()?;
        words.end()?;
        return Ok(Operands::CurrentCommitment {
            session,
            revision,
            asset,
            origin_domain,
        });
    }
    Ok(Operands::Read(match op.opcode {
        Some(1) => ReadOperand::Current {
            session,
            revision: words.size()?,
            query: query(words.0)?,
        },
        Some(2) => ReadOperand::Historical {
            session,
            revision: words.size()?,
            query: query(words.0)?,
        },
        Some(3) => ReadOperand::Raw {
            session,
            query: query(words.0)?,
        },
        Some(4) => {
            let origin = words.origin()?;
            words.end()?;
            ReadOperand::Status { session, origin }
        }
        Some(5) => {
            words.end()?;
            ReadOperand::Journal { session }
        }
        Some(6) => ReadOperand::Capture {
            session,
            query: query(words.0)?,
        },
        Some(7) => {
            let asset = words.word()?;
            words.end()?;
            ReadOperand::Owner { session, asset }
        }
        _ => return Err(BAD),
    }))
}

fn amount(bytes: &[u8]) -> Result<u64> {
    Unsigned256::from_bytes(bytes)?.product_amount()
}

fn sync_commitment(core: &Core, op: &Operation) -> Result<Operands> {
    let [message_reference, sequence, session, revision, origin_epoch, origin_domain, origin_event, asset, source_position, mode] =
        op.words.as_slice()
    else {
        return Err(BAD);
    };
    let [commitment, predecessor, source_attestation] = op.blobs.as_slice() else {
        return Err(BAD);
    };
    if op.appeal_deadline.is_some() {
        return Err(BAD);
    }
    let mode = match mode {
        1 => SyncMode::Initial,
        2 => SyncMode::Incremental,
        3 => SyncMode::FullResync,
        _ => return Err(BAD),
    };
    let predecessor = match mode {
        SyncMode::Incremental => Some(predecessor.as_slice().try_into().map_err(|_| BAD)?),
        _ if predecessor.is_empty() => None,
        _ => return Err(BAD),
    };
    Ok(Operands::SyncCommitment {
        id: CallId {
            namespace: core.principal.ok_or(BAD)?,
            sequence: *sequence,
        },
        message_reference: *message_reference,
        session: *session,
        cut: CommitCut {
            authority_epoch: core.authority_epoch.ok_or(BAD)?,
            revision: usize::try_from(*revision).map_err(|_| BAD)?,
        },
        origin_epoch: *origin_epoch,
        origin_domain: *origin_domain,
        origin_event: *origin_event,
        asset: *asset,
        source_position: *source_position,
        mode,
        commitment: commitment.as_slice().try_into().map_err(|_| BAD)?,
        predecessor,
        // The authority evaluates the proof after admitting the request and checking its cut.
        source_attestation: source_attestation.clone(),
    })
}

fn kind(word: u64) -> Result<TerminalKind> {
    match word {
        1 => Ok(TerminalKind::Confirmed),
        2 => Ok(TerminalKind::Reversed),
        _ => Err(BAD),
    }
}

fn deadline(op: &Operation) -> Option<u64> {
    match op.appeal_deadline {
        Some(AppealDeadline::AppealDeadlineUtcSeconds(value)) => Some(value),
        _ => None,
    }
}

fn native<'a>(core: &Core, op: &'a Operation) -> Result<(CallId, CallPayload, Words<'a>)> {
    let mut words = Words(&op.words);
    let message_id = words.word()?;
    let caller = core.principal.ok_or(BAD)?;
    let id = CallId {
        namespace: caller,
        sequence: words.word()?,
    };
    let session = words.word()?;
    let cut = CommitCut {
        authority_epoch: core.authority_epoch.ok_or(BAD)?,
        revision: words.size()?,
    };
    let origin_epoch = words.word()?;
    let binding = Binding {
        origin: words.origin()?,
        asset: words.word()?,
        owner: words.word()?,
        destination: words.word()?,
        recipient: words.word()?,
        amount: amount(op.blobs.first().ok_or(BAD)?)?,
    };
    Ok((
        id,
        CallPayload {
            message_id,
            origin_epoch,
            endpoint: core.target_domain.ok_or(BAD)?,
            caller,
            session,
            cut,
            binding,
            credential: None,
            versions: Vec::new(),
            command: Command::PublishPrimary,
        },
        words,
    ))
}

fn ordinary(core: &Core, family: u64, op: &Operation) -> Result<Operands> {
    if op.appeal_deadline.is_some() {
        return Err(BAD);
    }
    let (id, mut payload, mut words) = native(core, op)?;
    if words.present()? {
        payload.credential = Some(Credential {
            asset: words.word()?,
            origin: words.origin()?,
            holder: words.word()?,
            generation: words.word()?,
            epoch: words.word()?,
        });
    }
    let count = words.size()?;
    let versions = words.take(count.checked_mul(2).ok_or(BAD)?)?;
    payload.versions = versions
        .chunks_exact(2)
        .map(|pair| (pair[0], pair[1]))
        .collect();
    if payload
        .versions
        .windows(2)
        .any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(BAD);
    }
    payload.command = match (family, op.opcode.ok_or(BAD)?, words.0) {
        (1, 1, [g]) => Command::Debit { generation: *g },
        (1, 2, [decision, reference]) => Command::RecordTerminal(TerminalEvidence {
            binding: payload.binding,
            kind: kind(*decision)?,
            reference: *reference,
        }),
        (1, 3, [reference]) => Command::Credit {
            reference: *reference,
        },
        (1, 4, [g, reference]) => Command::Refund {
            generation: *g,
            reference: *reference,
        },
        (1, 5, []) => Command::PublishPrimary,
        (3, 1, [duration]) => Command::Reserve {
            duration: *duration,
        },
        (3, 2, [g]) => Command::Dispatch { generation: *g },
        (3, 3, [g]) => Command::Cancel { generation: *g },
        (3, 4, [g]) => Command::Fence { generation: *g },
        (3, 5, [duration]) => Command::Preempt {
            duration: *duration,
        },
        (3, 6, [g, reference]) => Command::Reconcile {
            generation: *g,
            reference: *reference,
        },
        (3, 7, [g, value]) => Command::Write {
            generation: *g,
            value: *value,
        },
        (3, 8, [elapsed]) => Command::Timeout { elapsed: *elapsed },
        _ => return Err(BAD),
    };
    let endpoint = if matches!(payload.command, Command::Credit { .. }) {
        payload.binding.destination
    } else {
        payload.binding.origin.domain
    };
    if payload.endpoint != endpoint {
        return Err(WireError::InvalidSource);
    }
    let proof_count = usize::from(matches!(
        payload.command,
        Command::RecordTerminal(_)
            | Command::Refund { .. }
            | Command::Cancel { .. }
            | Command::Fence { .. }
            | Command::Reconcile { .. }
            | Command::Preempt { .. }
    ));
    let proofs = &op.blobs[1..];
    if proofs.len() != proof_count || proofs.iter().any(Vec::is_empty) {
        return Err(BAD);
    }
    Ok(Operands::Ordinary {
        id,
        payload,
        proofs: proofs.to_vec(),
    })
}

fn legal(core: &Core, op: &Operation) -> Result<Operands> {
    let (id, p, mut words) = native(core, op)?;
    let [_, proof] = op.blobs.as_slice() else {
        return Err(BAD);
    };
    if proof.is_empty() {
        return Err(BAD);
    }
    let stage = match op.opcode {
        Some(1) => LegalStage::SourceEmission,
        Some(2) => LegalStage::ReceivingCommit,
        _ => return Err(BAD),
    };
    let action = match words.word()? {
        1 => LegalAction::Freeze,
        2 => LegalAction::Restrict,
        3 => LegalAction::Seize,
        4 => LegalAction::Confiscate,
        5 => LegalAction::Unfreeze,
        6 => LegalAction::Unrestrict,
        7 => LegalAction::Release,
        _ => return Err(BAD),
    };
    let order = Order {
        binding: p.binding,
        action,
        officer: words.word()?,
        jurisdiction: words.word()?,
        legal_basis: words.word()?,
        issuance_epoch: words.word()?,
        scope: words.set()?,
        predecessor: words.optional_origin()?,
        destination: words.optional_word()?,
        appeal_deadline: deadline(op),
    };
    words.end()?;
    let target = match stage {
        LegalStage::SourceEmission => p.binding.origin.domain,
        LegalStage::ReceivingCommit => p.binding.destination,
    };
    if p.endpoint != target || order.issuance_epoch != p.origin_epoch {
        return Err(WireError::InvalidSource);
    }
    Ok(Operands::Legal {
        id,
        stage,
        order,
        proof: proof.clone(),
        payload: crate::authority::regulation::LegalPayload {
            message_id: p.message_id,
            caller: p.caller,
            session: p.session,
            cut: p.cut,
            binding: p.binding,
            action,
            origin_epoch: p.origin_epoch,
        },
    })
}

fn spend(core: &Core, family: u64, op: &Operation) -> Result<Operands> {
    let (id, p, mut words) = native(core, op)?;
    let reference = CommitRef {
        position: words.size()?,
    };
    let sender = words.word()?;
    let recipient = words.word()?;
    let kind = match (family, words.word()?) {
        (1, 0) => SpendKind::Ordinary,
        (2, 1) => SpendKind::Recover,
        (2, 2) => SpendKind::Seize,
        (2, 3) => SpendKind::Confiscate,
        (2, 4) => SpendKind::Liquidate,
        _ => return Err(BAD),
    };
    let scope = SpendScope {
        root: p.binding,
        sender,
        recipient,
        kind,
        amount: amount(op.blobs.get(1).ok_or(BAD)?)?,
    };
    let (authorization, proof) = if family == 2 {
        let [_, _, proof] = op.blobs.as_slice() else {
            return Err(BAD);
        };
        if proof.is_empty() {
            return Err(BAD);
        }
        (
            Some(EnforcementOrder {
                scope,
                officer: words.word()?,
                jurisdiction: words.word()?,
                legal_basis: words.word()?,
                assets: words.set()?,
                prior_seizure: words.optional_origin()?,
                appeal_deadline: deadline(op),
            }),
            Some(proof.clone()),
        )
    } else {
        if op.blobs.len() != 2 || op.appeal_deadline.is_some() {
            return Err(BAD);
        }
        (None, None)
    };
    words.end()?;
    if p.endpoint != p.binding.destination {
        return Err(WireError::InvalidSource);
    }
    Ok(Operands::Spend {
        id,
        authorization,
        proof,
        payload: crate::authority::regulation::SpendPayload {
            message_id: p.message_id,
            caller: p.caller,
            session: p.session,
            cut: p.cut,
            origin_epoch: p.origin_epoch,
            reference,
            scope,
        },
    })
}

pub(crate) fn same_original(core: &Core, original: &Core) -> bool {
    core.deployment == original.deployment
        && core.source_domain == original.source_domain
        && core.target_domain == original.target_domain
        && core.principal == original.principal
        && core.authority_epoch == original.authority_epoch
        && original.version == Some(6)
}

fn ack(
    core: &Core,
    op: &Operation,
    depth: usize,
    check_sync_response_codes: bool,
) -> Result<Operands> {
    if op.appeal_deadline.is_some() {
        return Err(BAD);
    }
    let mut words = Words(&op.words);
    if op.opcode == Some(2) {
        let [original] = op.blobs.as_slice() else {
            return Err(BAD);
        };
        let nested = decode_core(original)?;
        let decoded = decode(&nested, depth.checked_sub(1).ok_or(BAD)?)?;
        let id = CallId {
            namespace: words.word()?,
            sequence: words.word()?,
        };
        let kind = words.word()?;
        let code = words.word()?;
        let commit = if words.present()? {
            Some(CommitRef {
                position: words.size()?,
            })
        } else {
            None
        };
        words.end()?;
        let sync_descriptor = if check_sync_response_codes {
            ResponseCode::sync_only_descriptor(code)
        } else {
            None
        };
        let committed = commit.is_some();
        if !(1..=3).contains(&kind)
            || (kind != 1 && committed)
            || sync_descriptor.is_some_and(|descriptor| descriptor != (kind, committed))
        {
            return Err(BAD);
        }
        if nested.version != core.version
            || nested.deployment != core.deployment
            || nested.principal != Some(id.namespace)
            || nested.source_domain != core.target_domain
            || nested.target_domain != core.source_domain
        {
            return Err(WireError::InvalidSource);
        }
        let decoded = match decoded {
            Operands::Receipt { original, .. } => {
                if !same_original(&nested, &original) {
                    return Err(WireError::InvalidSource);
                }
                decode(&original, depth.checked_sub(2).ok_or(BAD)?)?
            }
            decoded => decoded,
        };
        let sync_call = match decoded {
            Operands::Ordinary { id: nested, payload, .. } => {
                if nested != id || (matches!(payload.command, Command::Debit { .. })
                    && commit.is_some_and(|reference| reference.position != payload.cut.revision))
                {
                    return Err(BAD);
                }
                false
            }
            Operands::Legal { id: nested, .. }
            | Operands::Spend { id: nested, .. }
                if nested != id =>
            {
                return Err(BAD);
            }
            Operands::SyncCommitment { id: nested, .. } => {
                if nested != id {
                    return Err(BAD);
                }
                true
            }
            Operands::CurrentCommitment { .. } | Operands::Response { .. } => return Err(BAD),
            _ => false,
        };
        if (sync_descriptor.is_some() && !sync_call)
            || (check_sync_response_codes && sync_call
                && !ResponseStatus::compatible_with_sync(kind, code, committed))
        {
            return Err(BAD);
        }
        return Ok(Operands::Response {
            id,
            kind,
            code,
            commit,
            original: original.clone(),
        });
    }
    let [encoded] = op.blobs.as_slice() else {
        return Err(BAD);
    };
    let origin = words.origin()?;
    let commit = CommitRef {
        position: words.size()?,
    };
    let target = words.word()?;
    let binding = Binding {
        origin,
        asset: words.word()?,
        owner: words.word()?,
        destination: words.word()?,
        recipient: words.word()?,
        amount: amount(encoded)?,
    };
    let origin_epoch = words.word()?;
    let kind = kind(words.word()?)?;
    words.end()?;
    Ok(Operands::Ack(Acknowledgement {
        key: SettlementKey { origin, commit },
        target,
        commitment: Publication {
            origin,
            decision: OriginDecision {
                binding,
                kind,
                origin_epoch,
                commit,
            },
        },
    }))
}

fn heartbeat(core: &Core, op: &Operation) -> Result<Operands> {
    if !op.blobs.is_empty() || op.appeal_deadline.is_some() {
        return Err(BAD);
    }
    let mut words = Words(&op.words);
    let challenge = words.word()?;
    let expires = words.word()?;
    let result = if op.opcode == Some(1) {
        Operands::Capabilities(Offer {
            deployment: core.deployment.ok_or(BAD)?,
            sender: core.source_domain.ok_or(BAD)?,
            receiver: core.target_domain.ok_or(BAD)?,
            challenge,
            expires,
            versions: words.set()?,
            families: words.set()?,
            atomicities: words.set()?,
            schemes: words.set()?,
        })
    } else {
        Operands::Liveness { challenge, expires }
    };
    words.end()?;
    Ok(result)
}

fn canonical_record<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = serde_json::from_slice(bytes).map_err(|_| BAD)?;
    if serde_json::to_vec(&value).map_err(|_| BAD)? != bytes {
        return Err(BAD);
    }
    Ok(value)
}

fn contexts(bytes: &[u8]) -> Result<Vec<EndpointContext>> {
    let values: Vec<EndpointContext> = canonical_record(bytes)?;
    if values.is_empty()
        || values
            .windows(2)
            .any(|pair| pair[0].endpoint >= pair[1].endpoint)
    {
        return Err(BAD);
    }
    Ok(values)
}

fn governance(core: &Core, op: &Operation) -> Result<Operands> {
    if op.appeal_deadline.is_some() {
        return Err(BAD);
    }
    let mut words = Words(&op.words);
    let session = words.word()?;
    let cut = CommitCut {
        authority_epoch: core.authority_epoch.ok_or(BAD)?,
        revision: words.size()?,
    };
    let [batch, first, second] = op.blobs.as_slice() else {
        return Err(BAD);
    };
    if first.is_empty() || second.is_empty() {
        return Err(BAD);
    }
    let contexts = contexts(batch)?;
    let result = if op.opcode == Some(1) {
        Operands::Handover {
            session,
            proposal: Handover {
                asset: words.word()?,
                previous: words.word()?,
                successor: words.word()?,
                expected: cut,
                old_session: words.word()?,
                new_session: words.word()?,
                epoch: words.word()?,
                contexts,
            },
            proofs: [first.clone(), second.clone()],
        }
    } else {
        let entries: Vec<(u64, SessionBinding)> = canonical_record(first)?;
        if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(BAD);
        }
        Operands::Install {
            session,
            cut,
            epoch: words.word()?,
            contexts,
            sessions: entries.into_iter().collect(),
            proof: second.clone(),
        }
    };
    words.end()?;
    Ok(result)
}

pub fn decode(core: &Core, max_nesting: usize) -> Result<Operands> {
    decode_with_response_checks(core, max_nesting, true)
}

/// Decode the response structure and correlation fields before the signed
/// verifier compares the retained original and checks the response status.
pub(crate) fn decode_before_response_status(core: &Core, max_nesting: usize) -> Result<Operands> {
    decode_with_response_checks(core, max_nesting, false)
}

fn decode_with_response_checks(
    core: &Core,
    max_nesting: usize,
    check_sync_response_codes: bool,
) -> Result<Operands> {
    if max_nesting == 0 {
        return Err(BAD);
    }
    let (family, op) = body(core)?;
    match (family, op.opcode) {
        (1, Some(7)) => sync_commitment(core, op),
        (1, Some(6)) | (2, Some(3)) => spend(core, family, op),
        (1 | 3, _) => ordinary(core, family, op),
        (2, _) => legal(core, op),
        (4, _) => read(op, max_nesting),
        (5, _) => ack(core, op, max_nesting, check_sync_response_codes),
        (6, _) => heartbeat(core, op),
        (7, _) => governance(core, op),
        _ => Err(BAD),
    }
}
