//! Wire admission at the actual locked, authenticated persistent authority.

use super::ordered::{DebitPublication, DebitRequest, DebitWork, Disposition, OrderedCut, OrderedPublication, WireControl};
use super::{AnchorHead, AuthenticatedHead, CheckpointState, PersistentAuthority, PublicationGuard, PublicationRefusal, RecoveryError, WirePublication, exact_image};
use crate::authority::reads::{CheckedExecution, Query};
use crate::authority::{Collection, CommitRef, OutcomeReply};
use crate::authority::identity::{
    Action, ActionReply, Consent, Credentials, Entry, Identity, Observation, Operation,
    ProductAuthority, ReadRequest, Receipt, Request, Scope, Security, SessionProof,
};
use crate::authority::sync::{self, Stream};
use crate::lock_finality::{Account, Command, Reply};
use crate::wire::admission::{Arrival, Boundary, TransportKey, admit_packet_configured, compare_binding, wire_expiry};
use crate::wire::codec::{CanonicalPacket, WireError, check_declared_version, decode_packet, encode_core};
use crate::wire::generated::Core;
use crate::wire::legacy::{self, ValidatedLegacy};
use crate::wire::negotiation::{Channel, Offer};
use crate::wire::operands::{Operands, QueryOperand, ReadOperand, decode, same_original};
use crate::{AuthenticatedCaller, CallId, CommitCut};
use sha2::{Digest, Sha256};
use std::{cell::Cell, ops::ControlFlow, sync::mpsc::Receiver, time::Instant};

pub mod ed25519;
pub mod response;
pub mod schedule;

/// Installed by the trusted authority host. Peer keys, the active handshake
/// challenge, source identity and proof adapters are independent inputs.
pub trait WireSecurity: Security {
    fn threshold_rosters(&self) -> &[crate::wire::threshold::ThresholdRoster] {
        &[]
    }
    fn verify_original_signature(&self, channel: &Channel, packet: &CanonicalPacket) -> Result<(), WireError> {
        crate::wire::admission::check_signature(
            packet, &channel.profile().schemes, &channel.peer_keys()[1], self.threshold_rosters(),
        )
    }
    fn channel_current(&self, channel: &Channel) -> bool;
    fn delivery_cancelled(&self, _core: &Core) -> bool {
        false
    }
    fn frame_limit(&self, channel: &Channel) -> usize;
    /// Whether this configuration accepts the operation that a decoded frame
    /// carries. The selected version profile is the negotiated version
    /// together with the operations the configuration accepts, so a frame
    /// whose operation is outside that set receives UnsupportedVersion before
    /// its source, signature or authority is checked.
    fn accepts_operation(&self, _channel: &Channel, _core: &Core) -> bool {
        true
    }
    /// The largest signed delivery TTL in seconds that this configuration
    /// admits. None sets no limit. A larger signed TTL receives TtlInvalid
    /// after the admission gate and before any transport binding or effect.
    /// The trusted asset-class floor still applies to an admitted TTL.
    fn max_delivery_ttl(&self, _channel: &Channel) -> Option<u64> {
        None
    }
    fn wire_boundary(&self, channel: &Channel, core: &Core, live: CommitCut) -> Option<Boundary>;
    fn legacy_configured(&self, channel: &Channel) -> bool;
    fn verify_operand_proof(&self, core: &Core, operands: &Operands) -> bool;
    /// Bind the product signature credential to the exact admitted packet.
    fn matches_signed_packet(&self, _bytes: &[u8], _signature: &Self::Signature) -> bool {
        true
    }
    fn ack_maintenance_principal(&self, token: &Self::MaintenanceToken) -> Option<crate::Principal> {
        self.authenticate_maintenance(token)
    }
    fn handover_maintenance_principal(&self, token: &Self::MaintenanceToken) -> Option<crate::Principal> {
        self.authenticate_maintenance(token)
    }
    fn matches_handover_consents(
        &self, _operands: &Operands, _previous: &Self::Signature, _successor: &Self::Signature,
    ) -> bool {
        true
    }
    fn matches_recovery_endorsement(&self, _operands: &Operands, _signature: Option<&Self::Signature>) -> bool {
        true
    }
    fn requires_clock_observation(&self) -> bool {
        false
    }
    fn ordered_schedule_limits(&self) -> Option<schedule::WireScheduleLimits> {
        None
    }
    fn response_signer(&self) -> Option<&dyn response::ResponseSigner> {
        None
    }
}

pub struct WireCredentials<'a, S: Security> {
    pub token: &'a S::Token,
    pub signature: &'a S::Signature,
    pub maintenance: Option<&'a S::MaintenanceToken>,
    pub endorsement: Option<&'a Credentials<'a, S>>,
    pub previous: Option<&'a Consent<'a, S>>,
    pub successor: Option<&'a Consent<'a, S>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeliveryWindow {
    pub cancelled: bool,
    /// The strict compatibility path checks this value at publication.
    /// For ordered calls, the caller waits with [wait_for_ordered_wire_reply].
    pub deadline: Option<u64>,
    pub response_lost: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum WireReply {
    Executed(ActionReply),
    Observation(Observation),
    Receipt(Option<Receipt>),
    Acknowledged(bool),
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
    Changed(bool),
}

#[derive(Debug, Eq, PartialEq)]
pub struct Received {
    pub arrival: Arrival,
    pub reply: WireReply,
}

/// Wait for an ordered worker's reply until the caller's monotonic deadline.
/// The worker keeps its authority to finish. A timed-out or disconnected
/// waiter must resolve the original signed request before reissuing the work.
pub fn wait_for_ordered_wire_reply<T>(
    reply: &Receiver<Result<T, WireError>>,
    deadline: Instant,
) -> Result<T, WireError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(WireError::RequestUnresolved);
    }
    let result = reply.recv_timeout(deadline - now)
        .map_err(|_| WireError::RequestUnresolved)?;
    if Instant::now() >= deadline {
        return Err(WireError::RequestUnresolved);
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebitResult {
    Unresolved,
    Rejected,
    Published(Receipt),
}

pub(super) fn hold() -> WireError {
    WireError::Recovery(RecoveryError::Hold)
}

enum Input<'a> {
    Modern(Box<CanonicalPacket>),
    Legacy { bytes: &'a [u8], core: Box<Core> },
}

impl Input<'_> {
    fn core(&self) -> &Core {
        match self {
            Self::Modern(packet) => packet.core(),
            Self::Legacy { core, .. } => core,
        }
    }

    fn verify(
        &self,
        channel: &Channel,
        boundary: &Boundary,
        rosters: &[crate::wire::threshold::ThresholdRoster],
    ) -> Result<Option<ValidatedLegacy>, WireError> {
        match self {
            Self::Modern(packet) => {
                if packet.core_bytes().len() > boundary.max_frame {
                    return Err(WireError::InvalidFormat);
                }
                let admitted = admit_packet_configured(packet, channel.profile(), boundary, rosters);
                #[cfg(test)] crate::wire::threshold::trace::record("admission", packet, rosters, &admitted);
                admitted?;
                Ok(None)
            }
            Self::Legacy { bytes, .. } => {
                legacy::receive(bytes, channel.profile(), boundary).map(Some)
            }
        }
    }
}

fn required(value: Option<u64>) -> Result<u64, WireError> {
    value.ok_or(WireError::InvalidFormat)
}

/// Refuse an operation outside the selected version profile of this
/// configuration. The check reads only the decoded frame.
fn check_operation<S: WireSecurity>(
    security: &S,
    channel: &Channel,
    core: &Core,
) -> Result<(), WireError> {
    if !security.accepts_operation(channel, core) {
        return Err(WireError::UnsupportedVersion);
    }
    Ok(())
}

/// Refuse a signed delivery TTL above the configured limit.
fn check_delivery_ttl<S: WireSecurity>(
    security: &S,
    channel: &Channel,
    core: &Core,
) -> Result<(), WireError> {
    let ttl = required(core.ttl_seconds)?;
    if security.max_delivery_ttl(channel).is_some_and(|limit| ttl > limit) {
        return Err(WireError::TtlInvalid);
    }
    Ok(())
}

fn source_session(operands: &Operands) -> Option<u64> {
    match operands {
        Operands::Ordinary { payload, .. } => Some(payload.session),
        Operands::Legal { payload, .. } => Some(payload.session),
        Operands::Spend { payload, .. } => Some(payload.session),
        Operands::Read(read) => Some(read.session()),
        Operands::Receipt { session, .. }
        | Operands::SyncCommitment { session, .. }
        | Operands::CurrentCommitment { session, .. }
        | Operands::Handover { session, .. }
        | Operands::Install { session, .. } => Some(*session),
        _ => None,
    }
}

fn has_proof(operands: &Operands) -> bool {
    match operands {
        Operands::Ordinary { proofs, .. } => !proofs.is_empty(),
        Operands::Legal { .. } | Operands::Handover { .. } | Operands::Install { .. } => true,
        Operands::Spend { proof, .. } => proof.is_some(),
        _ => false,
    }
}

fn query_at(operand: QueryOperand) -> Query {
    match operand {
        QueryOperand::Application(asset) => Query::ApplicationValue(asset),
        QueryOperand::Source { domain, asset } => Query::SourcePool(domain, asset),
        QueryOperand::Destination {
            domain,
            asset,
            holder,
        } => Query::DestinationBalance(Account {
            endpoint: domain,
            asset,
            owner: holder,
        }),
        QueryOperand::Root {
            origin,
            destination,
            asset,
            holder,
        } => Query::RootBalance(
            origin,
            Account {
                endpoint: destination,
                asset,
                owner: holder,
            },
        ),
        QueryOperand::Regulatory { domain, asset } => Query::RegulatoryState(domain, asset),
        QueryOperand::Terminal(origin) => Query::TerminalReceipt(origin),
    }
}

fn read_at(read: ReadOperand, epoch: u64) -> ReadRequest {
    match read {
        ReadOperand::Current {
            revision, query, ..
        } => ReadRequest::Current {
            query: query_at(query),
            expected: CommitCut {
                authority_epoch: epoch,
                revision,
            },
        },
        ReadOperand::Historical {
            revision, query, ..
        } => ReadRequest::Historical {
            query: query_at(query),
            revision,
        },
        ReadOperand::Raw { query, .. } => ReadRequest::Raw(query_at(query)),
        ReadOperand::Status { origin, .. } => ReadRequest::Status(origin),
        ReadOperand::Journal { .. } => ReadRequest::Journal,
        ReadOperand::Capture { query, .. } => ReadRequest::CaptureCache(query_at(query)),
        ReadOperand::Owner { asset, .. } => ReadRequest::Owner(asset),
    }
}

fn commitment_read_at(operands: &Operands, authority_epoch: u64) -> Option<ReadRequest> {
    let Operands::CurrentCommitment { revision, asset, origin_domain, .. } = *operands else {
        return None;
    };
    Some(ReadRequest::Current {
        query: Query::Commitment(Stream { asset, origin_domain }),
        expected: CommitCut { authority_epoch, revision },
    })
}

fn request_at(target: u64, operands: &Operands) -> Option<Request<'_>> {
    match operands {
        Operands::Ordinary { id, payload, .. } => Some(Request {
            target,
            id: *id,
            expected: payload.cut,
            action: Action::Ordinary(payload),
        }),
        Operands::Legal {
            id,
            stage,
            payload,
            order,
            ..
        } => Some(Request {
            target,
            id: *id,
            expected: payload.cut,
            action: Action::Legal {
                stage: *stage,
                payload: *payload,
                order,
            },
        }),
        Operands::Spend {
            id,
            payload,
            authorization,
            ..
        } => Some(Request {
            target,
            id: *id,
            expected: payload.cut,
            action: Action::Spend {
                payload: *payload,
                enforcement: authorization.as_ref(),
            },
        }),
        _ => None,
    }
}

fn signed_request_at<'a>(core: &Core, operands: &'a Operands, exact: &'a [u8]) -> Option<Request<'a>> {
    if let Some(call) = sync::Call::from_operand(core, operands, exact) {
        return Some(Request {
            target: call.target,
            id: call.id,
            expected: call.cut,
            action: Action::SyncCommitment(call),
        });
    }
    request_at(core.target_domain?, operands)
}

fn run_operand<S: WireSecurity>(
    product: &mut ProductAuthority<S>,
    core: &Core,
    operands: &Operands,
    request: Option<Request<'_>>,
    entry: Entry,
    credentials: &WireCredentials<'_, S>,
    max_nesting: usize,
    ordered: bool,
) -> Result<WireReply, WireError> {
    #[cfg(test)] response::source_trace::product_enter(core,operands,entry);
    let target = required(core.target_domain)?;
    let epoch = required(core.authority_epoch)?;
    let auth = |session| Credentials {
        token: credentials.token,
        signature: credentials.signature,
        proof: SessionProof { session, epoch },
    };
    if let Some(request) = request {
        let auth = auth(source_session(operands).expect("typed call carries a session"));
        // The caller cannot substitute a Request: this is the sole
        // materialization of the independently decoded canonical operand.
        let _ = entry; // all identity routes use the same final consumer
        if !product.security.matches_recovery_endorsement(
            operands, credentials.endorsement.map(|endorsement| endorsement.signature),
        ) {
            return Err(WireError::ProductRejected);
        }
        #[cfg(test)] response::source_trace::execute_enter(&request);
        let executed=product.execute_durable(&auth, request, credentials.endorsement);
        #[cfg(test)] response::source_trace::execute_return(&executed);
        return executed
            .map(WireReply::Executed)
            .map_err(|_| WireError::ProductRejected);
    }
    match operands {
        Operands::CurrentCommitment { session, .. } => {
            let request = commitment_read_at(operands, epoch).ok_or(WireError::InvalidFormat)?;
            product
                .read(entry, &auth(*session), target, request, None)
                .map(WireReply::Observation)
                .map_err(|_| WireError::ProductRejected)
        }
        Operands::Read(read) => {
            let request = read_at(*read, epoch);
            product
                .read(entry, &auth(read.session()), target, request, None)
                .map(WireReply::Observation)
                .map_err(|_| WireError::ProductRejected)
        }
        Operands::Receipt { session, original } => {
            if !same_original(core, original) {
                return Err(WireError::InvalidSource);
            }
            let decoded = decode(
                original,
                max_nesting.checked_sub(1).ok_or(WireError::InvalidFormat)?,
            )?;
            let exact = encode_core(original)?;
            let request = signed_request_at(original, &decoded, &exact)
                .ok_or(WireError::InvalidFormat)?;
            if ordered && matches!(
                request.action,
                Action::Ordinary(payload) if matches!(payload.command, Command::Debit { .. })
            ) {
                // A nested Core lacks the original packet signature. Use
                // resolve_wire_debit for the exact ordered Debit receipt.
                return Err(WireError::ProductRejected);
            }
            if ordered || matches!(request.action,
                Action::Ordinary(payload) if matches!(payload.command, Command::Write { .. }))
            {
                let key = TransportKey::for_core(original)?;
                if compare_binding(product.reads.authority.state.wire_bindings.get(&key), &exact)?
                    != Arrival::Identical
                {
                    return Err(WireError::RequestUnresolved);
                }
            }
            product
                .receipt_durable(&auth(*session), request)
                .map(WireReply::Receipt)
                .map_err(|_| WireError::ProductRejected)
        }
        Operands::Ack(ack) => {
            if Some(ack.target) != core.source_domain {
                return Err(WireError::InvalidSource);
            }
            let token = credentials.maintenance.ok_or(WireError::ProductRejected)?;
            product.security.ack_maintenance_principal(token).ok_or(WireError::ProductRejected)?;
            let mut host = product.maintenance(token).ok_or(WireError::ProductRejected)?;
            Ok(WireReply::Acknowledged(
                host.acknowledge_secondary(*ack, credentials.signature),
            ))
        }
        // Ordered clients must correlate the response with their retained
        // original through response::admit_response.
        Operands::Response { .. } if ordered => Err(WireError::ProductRejected),
        Operands::Response {
            id,
            kind,
            code,
            commit,
            original,
        } => Ok(WireReply::Response {
            id: *id,
            kind: *kind,
            code: *code,
            commit: *commit,
            original: original.clone(),
        }),
        Operands::Capabilities(offer) => Ok(WireReply::Capabilities(offer.clone())),
        Operands::Liveness { challenge, expires } => Ok(WireReply::Liveness {
            challenge: *challenge,
            expires: *expires,
        }),
        Operands::Handover { proposal, .. } => {
            let previous = credentials.previous.ok_or(WireError::ProductRejected)?;
            let successor = credentials.successor.ok_or(WireError::ProductRejected)?;
            if core.principal != Some(proposal.previous) {
                return Err(WireError::InvalidSource);
            }
            let token = credentials.maintenance.ok_or(WireError::ProductRejected)?;
            if !product.security.matches_handover_consents(operands, previous.signature, successor.signature)
                || product.security.handover_maintenance_principal(token).is_none()
            {
                return Err(WireError::ProductRejected);
            }
            let bound_reference = ordered && product.security.requires_authority_binding();
            let mut host = product.maintenance(token).ok_or(WireError::ProductRejected)?;
            let changed = host.handover(
                proposal,
                Consent {
                    token: previous.token,
                    signature: previous.signature,
                },
                Consent {
                    token: successor.token,
                    signature: successor.signature,
                },
            );
            if bound_reference && !changed {
                return Err(WireError::ProductRejected);
            }
            Ok(WireReply::Changed(changed))
        }
        Operands::Install {
            cut,
            epoch,
            contexts,
            sessions,
            ..
        } => {
            if *cut != product.reads.current_cut() {
                return Err(WireError::ProductRejected);
            }
            let mut host = product
                .maintenance(credentials.maintenance.ok_or(WireError::ProductRejected)?)
                .ok_or(WireError::ProductRejected)?;
            Ok(WireReply::Changed(host.install_epoch(
                *epoch,
                contexts.clone(),
                sessions.clone(),
            )))
        }
        _ => Err(WireError::InvalidFormat),
    }
}

fn boundary_for<S: WireSecurity>(
    security: &S,
    channel: &Channel,
    core: &Core,
    deployment: u64,
    cut: CommitCut,
) -> Result<Boundary, WireError> {
    boundary_at(security, channel, core, deployment, cut, None)
}

fn boundary_at<S: WireSecurity>(
    security: &S,
    channel: &Channel,
    core: &Core,
    deployment: u64,
    cut: CommitCut,
    admitted_at: Option<u64>,
) -> Result<Boundary, WireError> {
    let boundary = security
        .wire_boundary(channel, core, cut)
        .ok_or(WireError::InvalidSource)?;
    // Retain the channel's authenticated peer identity even when the envelope
    // uses a separately registered threshold roster for that principal.
    if !security.channel_current(channel)
        || boundary.public_key != channel.peer_keys()[1]
        || channel.deployment() != deployment
        || boundary.deployment != deployment
        || admitted_at.unwrap_or(boundary.now) > channel.expires()
        || boundary.source != channel.remote()
        || boundary.target != channel.local()
        || boundary.epoch != cut.authority_epoch
    {
        return Err(WireError::InvalidSource);
    }
    if channel.profile().version == 5 && !security.legacy_configured(channel) {
        return Err(WireError::UnsupportedVersion);
    }
    Ok(boundary)
}

fn debit_request(request: &Request<'_>, bytes: &[u8]) -> Option<DebitRequest> {
    let Action::Ordinary(payload) = request.action else { return None };
    let Command::Debit { generation } = payload.command else { return None };
    Some(DebitRequest {
        id: request.id,
        work: DebitWork { origin: payload.binding.origin, generation },
        packet: bytes.to_vec(),
    })
}

#[derive(Clone, Copy)]
struct OrderedInput<'a> {
    authority: &'a dyn WireControl,
    head: AnchorHead,
    observed: Option<&'a OrderedCut>,
}

struct CheckedInput {
    core: Core,
    cut: CommitCut,
    transport: TransportKey,
    signed_core_sha256: [u8; 32],
    ordered: Option<OrderedPublication>,
    admitted_at: u64,
    identity: Identity,
    session: Option<SessionProof>,
    ack_maintainer: Option<crate::Principal>,
    handover_maintainer: Option<crate::Principal>,
    recovery_endorser: Option<(Identity, SessionProof)>,
    debit_scope: Option<(Scope, Operation, bool)>,
    commitment_scope: Option<(Scope, Operation, bool)>,
}
fn gate_delivery(delivery: DeliveryWindow, now: u64, strict: bool) -> Result<(), WireError> {
    if delivery.cancelled {
        return Err(WireError::Cancelled);
    }
    if strict && delivery.deadline.is_some_and(|deadline| now > deadline) {
        return Err(WireError::DeadlineExpired);
    }
    Ok(())
}

fn consume<S: WireSecurity>(
    product: &mut ProductAuthority<S>,
    channel: &Channel,
    entry: Entry,
    bytes: &[u8],
    credentials: &WireCredentials<'_, S>,
    delivery: DeliveryWindow,
    deployment: u64,
    ordered: Option<OrderedInput<'_>>,
    capture_receipt: bool,
) -> Result<(Received, CheckedInput, Option<Receipt>), WireError> {
    let cut = product.reads.current_cut();
    let observed = ordered.as_ref().map(|ordered| {
        let observed = match ordered.observed {
            Some(cut) => cut.clone(),
            None => ordered.authority.observe().map_err(|_| hold())?,
        };
        if observed.head() != Some(ordered.head) {
            return Err(hold());
        }
        Ok(observed)
    }).transpose()?;
    let frame_limit = product.security.frame_limit(channel);
    if bytes.len() > frame_limit {
        return Err(WireError::InvalidFormat);
    }
    let input = match channel.profile().version {
        6 => {
            check_declared_version(bytes, frame_limit)?;
            Input::Modern(Box::new(decode_packet(bytes, frame_limit)?))
        }
        5 if product.security.legacy_configured(channel) => Input::Legacy {
            bytes,
            core: Box::new(legacy::decode_shape(bytes, frame_limit)?),
        },
        _ => return Err(WireError::UnsupportedVersion),
    };
    check_operation(product.security.as_ref(), channel, input.core())?;
    if !product.security.matches_signed_packet(bytes, credentials.signature) {
        return Err(WireError::InvalidSignature);
    }
    let core = input.core();
    let boundary = boundary_for(product.security.as_ref(), channel, core, deployment, cut)?;
    if bytes.len() > boundary.max_frame {
        return Err(WireError::InvalidFormat);
    }
    gate_delivery(delivery, boundary.now, ordered.is_none())?;
    if ordered.is_none() && product.security.delivery_cancelled(core) {
        return Err(WireError::Cancelled);
    }
    let legacy = input.verify(channel, &boundary, product.security.threshold_rosters())?;
    check_delivery_ttl(product.security.as_ref(), channel, core)?;
    let operands = decode(core, boundary.max_nesting)?;
    let session = source_session(&operands).map(|session| SessionProof { session, epoch: boundary.epoch });
    let identity = if let Some(proof) = session {
        product.active_identity(credentials.token, proof)
    } else {
        product.authenticate(credentials.token)
    }
    .map_err(|_| WireError::InvalidSource)?;
    if Some(identity.principal) != core.principal || Some(identity.domain) != core.source_domain {
        return Err(WireError::InvalidSource);
    }
    let key = TransportKey::for_core(core)?;
    let mut ack_maintainer = None;
    let mut handover_maintainer = None;
    let mut recovery_endorser = None;
    if let Some(observed) = &observed {
        observed.authorize(identity.principal, key, false)?;
        if matches!(operands, Operands::Ack(_)) {
            let token = credentials.maintenance.ok_or(WireError::ProductRejected)?;
            let maintainer = product.security.ack_maintenance_principal(token).ok_or(WireError::ProductRejected)?;
            observed.authorize_principal(maintainer)?;
            ack_maintainer = Some(maintainer);
        }
        if let Operands::Handover { proposal, .. } = &operands {
            let token = credentials.maintenance.ok_or(WireError::ProductRejected)?;
            let maintainer = product.security.handover_maintenance_principal(token).ok_or(WireError::ProductRejected)?;
            observed.authorize_principal(maintainer)?;
            observed.authorize_principal(proposal.previous)?;
            observed.authorize_principal(proposal.successor)?;
            handover_maintainer = Some(maintainer);
        }
        if let Some(endorsement) = credentials.endorsement.filter(|_| matches!(
            &operands,
            Operands::Ordinary { payload, .. } if matches!(payload.command,
                Command::Cancel { .. } | Command::Fence { .. } | Command::Preempt { .. } |
                Command::Refund { .. } | Command::Reconcile { .. })
        )) {
            let owner = product.active_identity(endorsement.token, endorsement.proof)
                .map_err(|_| WireError::ProductRejected)?;
            observed.authorize_principal(owner.principal)?;
            recovery_endorser = Some((owner, endorsement.proof));
        }
        observed.check_pending_transport(key, bytes)?;
    }
    let exact = match (&input, &legacy) {
        (Input::Modern(packet), _) => packet.core_bytes(),
        (_, Some(legacy)) => legacy.exact_bytes(),
        _ => return Err(WireError::InvalidFormat),
    };
    let arrival = compare_binding(product.reads.authority.state.wire_bindings.get(&key), exact)?;
    // A retained exact native call is still subject to the current identity
    // and receipt policy. Fresh evidence is consumed only for a new result.
    let primary = &product.reads.authority.state.primary;
    let request = signed_request_at(core, &operands, exact);
    if arrival == Arrival::First
        && request.is_some_and(|request| {
            matches!(request.action,
                Action::Ordinary(payload) if matches!(payload.command, Command::Write { .. }))
                && primary.claimed(request.id)
        })
    {
        return Err(WireError::ReplayConflict);
    }
    if request.is_some() && product.security.requires_clock_observation()
        && primary.ledger.clock() == 0
    {
        return Err(WireError::ProductRejected);
    }
    let retained = arrival == Arrival::Identical
        && request.as_ref().is_some_and(|request| {
            primary.claimed(request.id)
        });
    if has_proof(&operands) && !retained && !product.security.verify_operand_proof(core, &operands)
    {
        return Err(WireError::InvalidSource);
    }
    // Re-evaluate current trusted scope and time immediately before the
    // actual product consumer. The locked retained state cannot change here.
    let current = boundary_for(product.security.as_ref(), channel, core, deployment, cut)?;
    gate_delivery(delivery, current.now, ordered.is_none())?;
    if bytes.len() > current.max_frame || current.max_nesting < boundary.max_nesting {
        decode(core, current.max_nesting)?;
        if bytes.len() > current.max_frame {
            return Err(WireError::InvalidFormat);
        }
    }
    input.verify(channel, &current, product.security.threshold_rosters())?;
    let mut debit_scope = None;
    let mut debit_attempt = None;
    if let (Some(observed), Some(request)) = (&observed, &request) {
        if let Some(original) = debit_request(request, bytes) {
            let Action::Ordinary(payload) = request.action else { unreachable!() };
            let auth = Credentials {
                token: credentials.token,
                signature: credentials.signature,
                proof: SessionProof { session: payload.session, epoch: current.epoch },
            };
            product.authorize_call(&auth, request, Operation::Execute)
                .map_err(|_| WireError::ProductRejected)?;
            let disposition = observed.check_debit(&original)?;
            debit_scope = Some((Scope::Asset(payload.binding.asset), Operation::Execute, retained));
            if !retained {
                if primary.claimed(request.id) {
                    return Err(WireError::ReplayConflict);
                }
                debit_attempt = Some((original, disposition));
            }
        } else if observed.has_debit(request.id) {
            return Err(WireError::ReplayConflict);
        }
    }
    let reply = run_operand(
        product,
        core,
        &operands,
        request,
        entry,
        credentials,
        current.max_nesting,
        ordered.is_some(),
    )?;
    #[cfg(test)] response::source_trace::product_return(&reply);
    let commitment_scope = match &operands {
        Operands::SyncCommitment { asset, .. } => {
            Some((Scope::Asset(*asset), Operation::Execute, retained))
        }
        Operands::CurrentCommitment { .. } => {
            let read = commitment_read_at(&operands, current.epoch).ok_or(WireError::InvalidFormat)?;
            Some((Scope::Read(read), Operation::Current, false))
        }
        Operands::Receipt { original, .. }
            if matches!(&original.body,
                Some(crate::wire::generated::core::Body::StateSync(op)) if op.opcode == Some(7)) =>
        {
            let Operands::SyncCommitment { asset, .. } = decode(original, 1)? else {
                return Err(WireError::InvalidFormat);
            };
            Some((Scope::Asset(asset), Operation::Receipt, false))
        }
        _ => None,
    };
    let ordered = match (ordered, observed) {
        (Some(ordered), Some(mut observed)) => {
            let debit = if let Some((original, disposition)) = debit_attempt {
                let WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
                    Collection::Collected(outcome),
                ))) = &reply else {
                    return Err(WireError::ProductRejected);
                };
                if matches!(disposition, Some(Disposition::Published | Disposition::Refused)) {
                    return Err(hold());
                }
                if outcome.reply == OutcomeReply::Accepted(Reply::Debited) {
                    let id = original.id;
                    observed = ordered.authority.reserve_debit(observed, original)?;
                    Some(DebitPublication::Applied(id))
                } else {
                    // Preserve the exact receipt without taking over another
                    // caller's work slot on a fresh refusal.
                    Some(DebitPublication::Refused(original))
                }
            } else {
                None
            };
            Some(OrderedPublication { cut: observed, debit })
        }
        (None, None) => None,
        _ => unreachable!(),
    };
    if arrival == Arrival::First {
        product
            .reads
            .authority
            .state
            .wire_bindings
            .insert(key, exact.to_vec());
    }
    let receipt = if capture_receipt {
        request.and_then(|request| product.observe_receipt(request).ok().flatten())
    } else {
        None
    };
    Ok((
        Received { arrival, reply },
        CheckedInput {
            core: core.clone(), cut, transport: key,
            signed_core_sha256: Sha256::digest(exact).into(),
            ordered, admitted_at: current.now, identity, session, ack_maintainer,
            handover_maintainer, recovery_endorser, debit_scope, commitment_scope,
        },
        receipt,
    ))
}

fn publication_guard<S: WireSecurity>(
    security: &S,
    channel: &Channel,
    bytes: &[u8],
    credentials: &WireCredentials<'_, S>,
    delivery: DeliveryWindow,
    deployment: u64,
    check: CheckedInput,
) -> Result<PublicationGuard, WireError> {
    let CheckedInput { core, cut, transport, signed_core_sha256, ordered,
        admitted_at, identity, session, ack_maintainer, handover_maintainer,
        recovery_endorser, debit_scope, commitment_scope } = check;
    let mut boundary = boundary_at(
        security, channel, &core, deployment, cut,
        ordered.as_ref().map(|_| admitted_at),
    )?;
    if ordered.is_some() || commitment_scope.is_some() {
        let current_identity = match session {
            Some(proof) => security.authenticate_session(credentials.token, proof),
            None => security.authenticate(credentials.token),
        };
        if current_identity != Some(identity) || !security.matches_signed_packet(bytes, credentials.signature) {
            return Err(WireError::InvalidSource);
        }
    }
    if let Some((scope, operation, receipt)) = commitment_scope {
        let proof = session.ok_or(WireError::InvalidSource)?;
        let permitted = |operation| security.permit_session(identity, proof, boundary.target, operation, scope);
        if !permitted(operation) || (receipt && !permitted(Operation::Receipt)) {
            return Err(WireError::ProductRejected);
        }
    }
    if ordered.is_some() {
        if let Some((scope, operation, receipt)) = debit_scope {
            let permitted = |operation| security.permit(
                identity, boundary.target, operation, scope, cut.authority_epoch,
            );
            if !permitted(operation) || (receipt && !permitted(Operation::Receipt)) {
                return Err(WireError::ProductRejected);
            }
        }
        if let Some(maintainer) = ack_maintainer {
            if credentials.maintenance.and_then(|token| security.ack_maintenance_principal(token))
                != Some(maintainer)
            {
                return Err(WireError::ProductRejected);
            }
        }
        if let Some((owner, proof)) = recovery_endorser {
            if credentials.endorsement.and_then(|endorsement| {
                security.authenticate_session(endorsement.token, proof)
            }) != Some(owner) {
                return Err(WireError::ProductRejected);
            }
        }
        if let Some(maintainer) = handover_maintainer {
            if credentials.maintenance.and_then(|token| security.handover_maintenance_principal(token))
                != Some(maintainer)
            {
                return Err(WireError::ProductRejected);
            }
            let operands = decode(&core, boundary.max_nesting)?;
            let Operands::Handover { ref proposal, .. } = operands else {
                return Err(WireError::InvalidFormat);
            };
            let previous = credentials.previous.ok_or(WireError::ProductRejected)?;
            let successor = credentials.successor.ok_or(WireError::ProductRejected)?;
            let old_proof = SessionProof { session: proposal.old_session, epoch: cut.authority_epoch };
            if security.authenticate_session(previous.token, old_proof).map(|id| id.principal) != Some(proposal.previous)
                || security.authenticate(successor.token).map(|id| id.principal) != Some(proposal.successor)
                || !security.verify_operand_proof(&core, &operands)
            {
                return Err(WireError::ProductRejected);
            }
        }
        boundary.now = admitted_at;
    } else {
        gate_delivery(delivery, boundary.now, true)?;
    }
    if ordered.is_none() && security.delivery_cancelled(&core) {
        return Err(WireError::Cancelled);
    }
    if bytes.len() > boundary.max_frame {
        return Err(WireError::InvalidFormat);
    }
    match channel.profile().version {
        6 => {
            let packet = decode_packet(bytes, boundary.max_frame)?;
            let admitted = admit_packet_configured(&packet, channel.profile(), &boundary, security.threshold_rosters());
            #[cfg(test)] crate::wire::threshold::trace::record("publication-reauthorization", &packet, security.threshold_rosters(), &admitted);
            admitted?;
        }
        5 => {
            legacy::receive(bytes, channel.profile(), &boundary)?;
        }
        _ => return Err(WireError::UnsupportedVersion),
    }
    decode(&core, boundary.max_nesting)?;
    if let Some(ordered) = ordered {
        return Ok(PublicationGuard::Ordered(ordered));
    }
    Ok(PublicationGuard::Strict(WirePublication {
        wire_expiry: wire_expiry(&core, &boundary)?,
        core,
        packet_sha256: Sha256::digest(bytes).into(),
        transport,
        signed_core_sha256,
        service_deadline: delivery.deadline,
    }))
}

impl<S: WireSecurity, H: AuthenticatedHead> PersistentAuthority<S, H> {
    /// Resolve an exact signed Debit using current authorization. The original
    /// packet is receipt data, so its delivery TTL is not consumed again.
    /// If requested, close an unresolved original by an authority CAS. A lost
    /// CAS result must be retried with the same original bytes.
    pub fn resolve_wire_debit(
        &mut self,
        channel: &Channel,
        original: &[u8],
        credentials: &WireCredentials<'_, S>,
        close: bool,
    ) -> Result<DebitResult, WireError> {
        Self::check_attachment(&self.anchor, self.profile, self.source_connected, &self.proof)
            .map_err(WireError::Recovery)?;
        let control = self.anchor.ordered_wire_control().ok_or_else(hold)?;
        if self.security.ordered_revocation_profile() != Some(self.profile) {
            return Err(WireError::InvalidSource);
        }
        let observed = control.observe().map_err(|_| hold())?;
        let checkpoint = Self::read_configured_checkpoint(
            &self.anchor, self.profile, self.source_connected, &self.proof,
            self.independent_checkpoint,
        ).map_err(WireError::Recovery)?;
        let head = observed.head().ok_or_else(hold)?;
        // A published prefix is immutable. Read it even while another handle
        // is preparing a later record, then fence the exact observation below.
        let record = exact_image(&mut self.file, head).map_err(WireError::Recovery)?;
        if let CheckpointState::Independent(witness) = checkpoint {
            if witness.protected_head != Some(head) {
                return Err(hold());
            }
            let floor = witness.head.ok_or_else(hold)?;
            super::validate_lineage(&mut self.file, head, &record, floor)
                .map_err(WireError::Recovery)?;
            self.anchor.verify_independent_journal(&mut self.file, head).map_err(|_| hold())?;
        }
        if !record.image.accepts_security(self.security.as_ref()) {
            return Err(WireError::Recovery(RecoveryError::AttachmentRejected));
        }
        let frame_limit = self.security.frame_limit(channel);
        check_declared_version(original, frame_limit)?;
        let packet = decode_packet(original, frame_limit)?;
        let core = packet.core();
        // An operation outside the selected profile is refused before any
        // signature check, as on every other entry.
        check_operation(self.security.as_ref(), channel, core)?;
        if !self.security.matches_signed_packet(original, credentials.signature) {
            return Err(WireError::InvalidSignature);
        }
        let product = record.image.open(self.profile, self.security.clone(), self.source_connected);
        let cut = product.reads.current_cut();
        let mut boundary = boundary_for(self.security.as_ref(), channel, core, self.profile.deployment, cut)?;
        if original.len() > boundary.max_frame {
            return Err(WireError::InvalidFormat);
        }
        boundary.now = required(core.issued_seconds)?;
        let admitted = admit_packet_configured(&packet, channel.profile(), &boundary, self.security.threshold_rosters());
        #[cfg(test)] crate::wire::threshold::trace::record("exact-resolution", &packet, self.security.threshold_rosters(), &admitted);
        admitted?;
        let transport = TransportKey::for_core(core)?;
        let operands = decode(core, boundary.max_nesting)?;
        let request = request_at(boundary.target, &operands).ok_or(WireError::InvalidFormat)?;
        let exact = debit_request(&request, original).ok_or(WireError::InvalidFormat)?;
        let auth = Credentials {
            token: credentials.token,
            signature: credentials.signature,
            proof: SessionProof {
                session: source_session(&operands).ok_or(WireError::InvalidFormat)?,
                epoch: cut.authority_epoch,
            },
        };
        let identity = product.authorize_call(&auth, &request, Operation::Receipt)
            .map_err(|_| WireError::ProductRejected)?;
        if identity.principal != boundary.principal || identity.domain != boundary.source {
            return Err(WireError::InvalidSource);
        }
        observed.authorize(identity.principal, transport, true)?;
        let disposition = observed.disposition(&exact)?;
        observed.check_pending_transport(transport, original)?;
        let Action::Ordinary(payload) = request.action else { unreachable!() };
        let arrival = compare_binding(
            product.reads.authority.state.wire_bindings.get(&transport),
            packet.core_bytes(),
        )?;
        let receipt = product.receipt_durable(&auth, request).map_err(|_| WireError::ProductRejected)?;
        let reply = match receipt {
            Some(receipt @ Receipt::Ordinary(Collection::Collected(_))) => {
                if disposition == Some(Disposition::Rejected) || arrival != Arrival::Identical {
                    return Err(WireError::ReplayConflict);
                }
                DebitResult::Published(receipt)
            }
            Some(Receipt::Ordinary(Collection::Waiting)) => {
                match disposition {
                    Some(Disposition::Published | Disposition::Refused) => return Err(hold()),
                    Some(Disposition::Rejected) => DebitResult::Rejected,
                    _ if close => {
                        product.authorize_call(&auth, &request, Operation::Execute)
                            .map_err(|_| WireError::ProductRejected)?;
                        if disposition.is_none() && !product.reads.authority.state.primary.ledger
                            .receipt_credential_matches(AuthenticatedCaller(identity.principal), payload.request())
                        {
                            return Err(WireError::ProductRejected);
                        }
                        control.reject_debit(observed, exact)?;
                        return Ok(DebitResult::Rejected);
                    }
                    _ => DebitResult::Unresolved,
                }
            }
            _ => return Err(WireError::ReplayConflict),
        };
        if !control.unchanged(&observed).map_err(|_| hold())? {
            return Err(hold());
        }
        Ok(reply)
    }

    pub fn receive_wire(
        &mut self,
        channel: &Channel,
        entry: Entry,
        bytes: &[u8],
        credentials: &WireCredentials<'_, S>,
        delivery: DeliveryWindow,
    ) -> Result<Received, WireError> {
        self.receive_wire_result(channel, entry, bytes, credentials, delivery, false)
            .map(|(received, _)| received)
    }

    fn receive_wire_result(
        &mut self,
        channel: &Channel,
        entry: Entry,
        bytes: &[u8],
        credentials: &WireCredentials<'_, S>,
        delivery: DeliveryWindow,
        capture_receipt: bool,
    ) -> Result<(Received, Option<Receipt>), WireError> {
        let deployment = self.profile.deployment;
        let security = self.security.clone();
        if self.anchor.ordered_wire_control().is_some() {
            if channel.profile().version != 6 {
                return Err(WireError::UnsupportedVersion);
            }
            if security.ordered_revocation_profile() != Some(self.profile) {
                return Err(WireError::InvalidSource);
            }
        } else if security.ordered_revocation_profile().is_some() {
            return Err(WireError::InvalidSource);
        }
        let checked = Cell::new(None);
        let refusal = Cell::new(None);
        let result = self
            .transact_guarded(
                |anchor, head, product| {
                    match consume(
                        product,
                        channel,
                        entry,
                        bytes,
                        credentials,
                        delivery,
                        deployment,
                        anchor.ordered_wire_control().map(|authority| OrderedInput { authority, head, observed: None }),
                        capture_receipt,
                    ) {
                        Ok((reply, check, receipt)) => {
                            checked.set(Some(check));
                            ControlFlow::Continue(Ok((reply, receipt)))
                        }
                        Err(error) => ControlFlow::Break(Err(error)),
                    }
                },
                true,
                || {
                    let Some(check) = checked.take() else {
                        return Ok(None);
                    };
                    let result = publication_guard(
                        security.as_ref(), channel, bytes, credentials, delivery, deployment, check,
                    ).map(Some);
                    result.map_err(|error| {
                        refusal.set(Some(error));
                        RecoveryError::Hold
                    })
                },
            )
            .map_err(|error| match error {
                RecoveryError::Publication(PublicationRefusal::Unsupported) => WireError::Recovery(RecoveryError::Hold),
                RecoveryError::Publication(PublicationRefusal::DeadlineExpired) => WireError::DeadlineExpired,
                RecoveryError::Publication(PublicationRefusal::TtlExpired) => WireError::TtlExpired,
                RecoveryError::Publication(PublicationRefusal::Cancelled) => WireError::Cancelled,
                _ => refusal.get().unwrap_or(WireError::Recovery(error)),
            })??;
        if delivery.response_lost {
            return Err(WireError::ResponseLost);
        }
        Ok(result)
    }
}

#[cfg(test)]
pub(in crate::authority::recovery) mod vector_tests;
