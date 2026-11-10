//! Signed, correlated v0.6 responses from the reference authority.

use super::{DebitResult, DeliveryWindow, Received, WireCredentials, WireReply, WireSecurity};
use crate::CallId;
use crate::authority::identity::{ActionReply, EndpointError, Entry, Receipt};
use crate::authority::reads::CheckedExecution;
use crate::authority::recovery::{AuthenticatedHead, PersistentAuthority, RecoveryError};
use crate::authority::regulation::{LegalReply, LegalStage, Refusal, SpendReply};
use crate::authority::sync;
use crate::authority::{Collection, CommitRef, Outcome, OutcomeReply};
use crate::lock_finality::{Command, Reply, TerminalKind};
use crate::wire::admission::{Boundary, admit_packet};
use crate::wire::codec::{
    CanonicalPacket, WireError, check_declared_version, decode_packet, encode_core,
    encode_packet, signing_bytes,
};
use crate::wire::generated::{Core, Operation, Packet, core::Body};
use crate::wire::negotiation::{Channel, verify};
use crate::wire::operands::{Operands, decode, decode_before_response_status};
use sha2::{Digest, Sha256};

const BAD: WireError = WireError::InvalidFormat;

macro_rules! response_codes {
    ($($code:ident => ($kind:literal, $number:literal, $commit:literal)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u64)]
        pub enum ResponseCode { $($code = $number),+ }

        impl ResponseCode {
            fn descriptor(self) -> (u64, bool) {
                match self { $(Self::$code => ($kind, $commit)),+ }
            }

            fn from_number(number: u64) -> Option<Self> {
                match number {
                    $($number => Some(Self::$code),)+
                    _ => None,
                }
            }
        }
    };
}

response_codes! {
    Rejected => (1, 1, false),
    Busy => (1, 2, false),
    Unavailable => (1, 3, false),
    OriginalRejected => (1, 4, false),
    Reserved => (1, 10, true),
    SourceDispatched => (1, 11, true),
    Debited => (1, 12, true),
    Closed => (1, 13, true),
    Preempted => (1, 14, true),
    TimeObserved => (1, 15, true),
    Recorded => (1, 16, true),
    Credited => (1, 17, true),
    Reconciled => (1, 18, true),
    Refunded => (1, 19, true),
    DataUpdated => (1, 20, true),
    EvidenceRefreshed => (1, 21, true),
    Published => (1, 22, true),
    DuplicateDecision => (1, 23, true),
    DuplicateConfirmed => (1, 24, true),
    DuplicateReversed => (1, 25, true),
    LegalEmitted => (1, 26, true),
    LegalApplied => (1, 27, true),
    SpendExecuted => (1, 28, true),
    StateCommitmentSynced => (1, 29, true),
    LegalInvalidAuthority => (1, 30, false),
    LegalInvalidState => (1, 31, false),
    LegalInvalidBinding => (1, 32, false),
    LegalMissingPriorFreeze => (1, 33, false),
    LegalMissingPriorSeizure => (1, 34, false),
    LegalAppealStillOpen => (1, 35, false),
    LegalAppealDeadlineMismatch => (1, 36, false),
    LegalMissingDestination => (1, 37, false),
    LegalConflictingOrder => (1, 38, false),
    StateCommitmentMismatch => (1, 39, false),
    StateCommitmentStale => (1, 40, false),
    SourceAttestationRejected => (1, 41, false),
    Unresolved => (2, 50, false),
    ResponseLost => (2, 51, false),
    DeadlineExpired => (2, 52, false),
    Cancelled => (2, 53, false),
    TtlExpired => (2, 54, false),
    DeliveryBusy => (2, 55, false),
    DeliveryUnavailable => (2, 56, false),
    InvalidFormat => (3, 70, false),
    UnsupportedVersion => (3, 71, false),
    InvalidSource => (3, 72, false),
    InvalidSignature => (3, 73, false),
    InvalidThresholdSignature => (3, 74, false),
    TtlInvalid => (3, 75, false),
    ReplayConflict => (3, 76, false),
    ProductRejected => (3, 77, false),
}

impl ResponseCode {
    fn matches_call(self, operands: &Operands) -> bool {
        use ResponseCode::*;
        match operands {
            Operands::SyncCommitment { .. } => self.matches_sync_commitment(),
            Operands::Ordinary { payload, .. } => match self {
                Reserved => matches!(payload.command, Command::Reserve { .. }),
                SourceDispatched => matches!(payload.command, Command::Dispatch { .. }),
                Debited | OriginalRejected => matches!(payload.command, Command::Debit { .. }),
                Closed => matches!(
                    payload.command,
                    Command::Cancel { .. } | Command::Fence { .. }
                ),
                Preempted => matches!(payload.command, Command::Preempt { .. }),
                TimeObserved => matches!(payload.command, Command::Timeout { .. }),
                Recorded | EvidenceRefreshed | DuplicateDecision => {
                    matches!(payload.command, Command::RecordTerminal(_))
                }
                Credited | DuplicateConfirmed => matches!(payload.command, Command::Credit { .. }),
                Reconciled => matches!(payload.command, Command::Reconcile { .. }),
                Refunded | DuplicateReversed => matches!(payload.command, Command::Refund { .. }),
                DataUpdated => matches!(payload.command, Command::Write { .. }),
                Published => matches!(payload.command, Command::PublishPrimary),
                _ => self.is_common(),
            },
            Operands::Legal { stage, .. } => match self {
                LegalEmitted => *stage == LegalStage::SourceEmission,
                LegalApplied => *stage == LegalStage::ReceivingCommit,
                LegalInvalidAuthority
                | LegalInvalidState
                | LegalInvalidBinding
                | LegalMissingPriorFreeze
                | LegalMissingPriorSeizure
                | LegalAppealStillOpen
                | LegalAppealDeadlineMismatch
                | LegalMissingDestination
                | LegalConflictingOrder => true,
                _ => self.is_common(),
            },
            Operands::Spend { .. } => self == SpendExecuted || self.is_common(),
            _ => false,
        }
    }

    pub(crate) fn sync_only_descriptor(number: u64) -> Option<(u64, bool)> {
        Self::from_number(number)
            .filter(|code| code.is_sync_only())
            .map(Self::descriptor)
    }

    fn is_sync_only(self) -> bool {
        matches!(
            self,
            Self::StateCommitmentSynced
                | Self::StateCommitmentMismatch
                | Self::StateCommitmentStale
                | Self::SourceAttestationRejected
        )
    }

    fn matches_sync_commitment(self) -> bool {
        self.is_common() || self.is_sync_only()
    }

    fn is_common(self) -> bool {
        self.descriptor().0 != 1 || matches!(self, Self::Rejected | Self::Busy | Self::Unavailable)
    }
}

/// The category that the kind word of a response names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
    /// The exact product outcome retained for the original call.
    Recorded = 1,
    /// A delivery status. It does not establish the outcome of the call.
    Delivery = 2,
    /// A refusal of the original frame.
    Refusal = 3,
}

impl ResponseKind {
    fn from_number(number: u64) -> Option<Self> {
        match number {
            1 => Some(Self::Recorded),
            2 => Some(Self::Delivery),
            3 => Some(Self::Refusal),
            _ => None,
        }
    }
}

/// The result code of a verified response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseStatus {
    /// A code of this version, checked against its kind, its commit presence
    /// and the original call.
    Known(ResponseCode),
    /// A code this version does not define for the original call, accepted
    /// as its category only.
    /// The verifier checks the category and commit presence but cannot check
    /// the code against the original call, so it never reports such a code
    /// as a result of this version.
    Unknown { kind: ResponseKind, code: u64 },
}

impl ResponseStatus {
    fn decode(kind: u64, number: u64, commit: bool, sync_call: bool) -> Result<Self, WireError> {
        match ResponseCode::from_number(number).filter(|code| sync_call || !code.is_sync_only()) {
            Some(code) if code.descriptor() == (kind, commit) => Ok(Self::Known(code)),
            Some(_) => Err(BAD),
            None => {
                let kind = ResponseKind::from_number(kind).ok_or(BAD)?;
                if kind != ResponseKind::Recorded && commit {
                    return Err(BAD);
                }
                Ok(Self::Unknown { kind, code: number })
            }
        }
    }

    pub(crate) fn compatible_with_sync(kind: u64, number: u64, commit: bool) -> bool {
        Self::decode(kind, number, commit, true)
            .is_ok_and(|status| status.known().is_none_or(ResponseCode::matches_sync_commitment))
    }

    /// The code when this version defines it.
    pub fn known(self) -> Option<ResponseCode> {
        match self {
            Self::Known(code) => Some(code),
            Self::Unknown { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedResponse {
    pub id: CallId,
    pub code: ResponseStatus,
    pub commit: Option<CommitRef>,
}

/// Supplies current envelope fields and signs with the local key authenticated
/// by the negotiated channel.
pub trait ResponseSigner {
    fn parameters(
        &self,
        channel: &Channel,
        response_binding: [u8; 32],
    ) -> Option<ResponseParameters>;
    fn sign(&self, preimage: &[u8]) -> Option<[u8; 64]>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseParameters {
    pub principal: u64,
    pub key_id: u64,
    pub authority_epoch: u64,
    pub issued_seconds: u64,
    pub ttl_seconds: u64,
    pub uuid: [u8; 16],
    pub route_scope: u64,
}

#[derive(Clone, Copy)]
struct ResponseResult {
    code: ResponseCode,
    commit: Option<CommitRef>,
}

impl ResponseResult {
    fn plain(code: ResponseCode) -> Self {
        Self { code, commit: None }
    }

    fn from_received(received: Received, retained: Option<Receipt>) -> Self {
        use ResponseCode::*;
        match (received.reply, retained) {
            (WireReply::Executed(ActionReply::SyncCommitment(reply)), Some(Receipt::SyncCommitment(stored)))
                if reply == stored => Self::sync_commitment(stored),
            (
                WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
                    Collection::Collected(reply),
                ))),
                Some(Receipt::Ordinary(Collection::Collected(stored))),
            ) if reply == stored => Self::ordinary(stored),
            (WireReply::Executed(ActionReply::Legal(reply)), Some(Receipt::Legal(stored)))
                if reply == stored =>
            {
                Self::legal(stored)
            }
            (WireReply::Executed(ActionReply::Spend(reply)), Some(Receipt::Spend(stored)))
                if reply == stored =>
            {
                Self::spend(stored)
            }
            (
                WireReply::Executed(
                    ActionReply::Ordinary(CheckedExecution::Busy)
                    | ActionReply::Legal(LegalReply::Refused(Refusal::Busy))
                    | ActionReply::Spend(SpendReply::Busy),
                ),
                _,
            ) => Self::plain(DeliveryBusy),
            (
                WireReply::Executed(
                    ActionReply::Ordinary(CheckedExecution::Unavailable)
                    | ActionReply::Legal(LegalReply::Refused(Refusal::Unavailable))
                    | ActionReply::Spend(SpendReply::Unavailable),
                ),
                _,
            ) => Self::plain(DeliveryUnavailable),
            (
                WireReply::Executed(
                    ActionReply::Legal(LegalReply::Emitted(_) | LegalReply::Applied(_))
                    | ActionReply::Spend(SpendReply::Executed { .. })
                    | ActionReply::SyncCommitment(_)
                    | ActionReply::Ordinary(CheckedExecution::Forwarded(
                        Collection::Waiting | Collection::Collected(_),
                    )),
                ),
                _,
            ) => Self::plain(Unresolved),
            _ => Self::plain(ProductRejected),
        }
    }

    fn sync_commitment(outcome: sync::Outcome) -> Self {
        use ResponseCode::*;
        match outcome {
            sync::Outcome::Synced(commit) => Self { code: StateCommitmentSynced, commit: Some(commit) },
            sync::Outcome::Busy => Self::plain(Busy),
            sync::Outcome::Unavailable => Self::plain(Unavailable),
            sync::Outcome::Mismatch => Self::plain(StateCommitmentMismatch),
            sync::Outcome::Stale => Self::plain(StateCommitmentStale),
            sync::Outcome::SourceAttestationRejected => Self::plain(SourceAttestationRejected),
        }
    }

    fn from_resolution(resolution: DebitResult) -> Self {
        use ResponseCode::*;
        match resolution {
            DebitResult::Rejected => Self::plain(OriginalRejected),
            DebitResult::Published(Receipt::Ordinary(Collection::Collected(outcome))) => {
                Self::ordinary(outcome)
            }
            _ => Self::plain(Unresolved),
        }
    }

    fn ordinary(outcome: Outcome) -> Self {
        use ResponseCode::*;
        let code = match outcome.reply {
            OutcomeReply::Accepted(reply) => match reply {
                Reply::Rejected => Rejected,
                Reply::Busy => Busy,
                Reply::Reserved => Reserved,
                Reply::SourceDispatched => SourceDispatched,
                Reply::Debited => Debited,
                Reply::Closed => Closed,
                Reply::Preempted => Preempted,
                Reply::TimeObserved => TimeObserved,
                Reply::Recorded => Recorded,
                Reply::Credited => Credited,
                Reply::Reconciled => Reconciled,
                Reply::Refunded => Refunded,
                Reply::DataUpdated => DataUpdated,
                Reply::EvidenceRefreshed => EvidenceRefreshed,
                Reply::Published => Published,
            },
            OutcomeReply::Rejected => Rejected,
            OutcomeReply::Busy => Busy,
            OutcomeReply::Unavailable => Unavailable,
            OutcomeReply::DuplicateDecision => DuplicateDecision,
            OutcomeReply::DuplicateSettlement(TerminalKind::Confirmed) => DuplicateConfirmed,
            OutcomeReply::DuplicateSettlement(TerminalKind::Reversed) => DuplicateReversed,
        };
        Self {
            code,
            commit: outcome.commit,
        }
    }

    fn legal(reply: LegalReply) -> Self {
        use ResponseCode::*;
        let (code, commit) = match reply {
            LegalReply::Emitted(commit) => (LegalEmitted, Some(commit)),
            LegalReply::Applied(commit) => (LegalApplied, Some(commit)),
            LegalReply::Refused(reason) => (
                match reason {
                    Refusal::InvalidAuthority => LegalInvalidAuthority,
                    Refusal::InvalidState => LegalInvalidState,
                    Refusal::InvalidBinding => LegalInvalidBinding,
                    Refusal::MissingPriorFreeze => LegalMissingPriorFreeze,
                    Refusal::MissingPriorSeizure => LegalMissingPriorSeizure,
                    Refusal::AppealStillOpen => LegalAppealStillOpen,
                    Refusal::AppealDeadlineMismatch => LegalAppealDeadlineMismatch,
                    Refusal::MissingDestination => LegalMissingDestination,
                    Refusal::ConflictingOrder => LegalConflictingOrder,
                    Refusal::Busy => Busy,
                    Refusal::Unavailable => Unavailable,
                },
                None,
            ),
        };
        Self { code, commit }
    }

    fn spend(reply: SpendReply) -> Self {
        use ResponseCode::*;
        match reply {
            SpendReply::Executed { commit, .. } => Self {
                code: SpendExecuted,
                commit: Some(commit),
            },
            SpendReply::Rejected => Self::plain(Rejected),
            SpendReply::Busy => Self::plain(Busy),
            SpendReply::Unavailable => Self::plain(Unavailable),
        }
    }

    fn error(error: WireError) -> Self {
        use ResponseCode::*;
        Self::plain(match error {
            WireError::InvalidFormat => InvalidFormat,
            WireError::UnsupportedVersion => UnsupportedVersion,
            WireError::InvalidSource => InvalidSource,
            WireError::InvalidSignature => InvalidSignature,
            WireError::InvalidThresholdSignature => InvalidThresholdSignature,
            WireError::TtlInvalid => TtlInvalid,
            WireError::ReplayConflict => ReplayConflict,
            WireError::ProductRejected
            | WireError::Recovery(RecoveryError::Endpoint(EndpointError::Rejected)) => {
                ProductRejected
            }
            WireError::TtlExpired => TtlExpired,
            WireError::Cancelled => Cancelled,
            WireError::DeadlineExpired => DeadlineExpired,
            WireError::ResponseLost => ResponseLost,
            WireError::RequestUnresolved => Unresolved,
            WireError::Recovery(RecoveryError::Endpoint(EndpointError::Unavailable)) => {
                DeliveryUnavailable
            }
            WireError::Recovery(_) => Unresolved,
        })
    }
}

fn caller_id(operands: &Operands) -> Result<CallId, WireError> {
    match operands {
        Operands::Ordinary { id, .. } | Operands::Legal { id, .. } | Operands::Spend { id, .. }
        | Operands::SyncCommitment { id, .. } => {
            Ok(*id)
        }
        _ => Err(BAD),
    }
}

fn validate_response(
    response: &CanonicalPacket,
    expected: &CanonicalPacket,
    max_nesting: usize,
) -> Result<VerifiedResponse, WireError> {
    let Operands::Response {
        id,
        kind,
        code,
        commit,
        original,
    } = decode_before_response_status(response.core(), max_nesting)?
    else {
        return Err(BAD);
    };
    let expected_operands = decode(expected.core(), 1)?;
    if original != expected.core_bytes() || id != caller_id(&expected_operands)? {
        return Err(WireError::ReplayConflict);
    }
    let sync_call = matches!(expected_operands, Operands::SyncCommitment { .. });
    let code = ResponseStatus::decode(kind, code, commit.is_some(), sync_call)?;
    if code
        .known()
        .is_some_and(|code| !code.matches_call(&expected_operands))
    {
        return Err(BAD);
    }
    Ok(VerifiedResponse { id, code, commit })
}

/// Verify the peer signature and correlate a reference response against the
/// canonical original retained by the caller. The configured boundary
/// supplies the current peer, key and envelope policy.
pub fn admit_response(
    channel: &Channel,
    boundary: &Boundary,
    expected: &CanonicalPacket,
    response: &[u8],
) -> Result<VerifiedResponse, WireError> {
    if channel.local() != boundary.target
        || channel.remote() != boundary.source
        || channel.deployment() != boundary.deployment
        || boundary.now > channel.expires()
        || boundary.public_key != channel.peer_keys()[1]
    {
        return Err(WireError::InvalidSource);
    }
    check_declared_version(response, boundary.max_frame)?;
    let response = decode_packet(response, boundary.max_frame)?;
    admit_packet(&response, channel.profile(), boundary)?;
    validate_response(&response, expected, boundary.max_nesting)
}

fn response_words(id: CallId, outcome: ResponseResult) -> Result<Vec<u64>, WireError> {
    let (kind, needs_commit) = outcome.code.descriptor();
    if needs_commit != outcome.commit.is_some() {
        return Err(BAD);
    }
    let mut words = vec![
        id.namespace,
        id.sequence,
        kind,
        outcome.code as u64,
        u64::from(needs_commit),
    ];
    if let Some(commit) = outcome.commit {
        words.push(u64::try_from(commit.position).map_err(|_| BAD)?);
    }
    Ok(words)
}

fn response_atomicity(channel: &Channel) -> Result<u64, WireError> {
    channel
        .profile()
        .atomicities
        .first()
        .copied()
        .ok_or(WireError::UnsupportedVersion)
}

fn response_core(
    channel: &Channel,
    params: &ResponseParameters,
    atomicity: u64,
    words: Vec<u64>,
    original: &[u8],
) -> Core {
    Core {
        version: Some(6),
        purpose: Some(1),
        deployment: Some(channel.deployment()),
        source_domain: Some(channel.local()),
        target_domain: Some(channel.remote()),
        principal: Some(params.principal),
        key_id: Some(params.key_id),
        authority_epoch: Some(params.authority_epoch),
        issued_seconds: Some(params.issued_seconds),
        ttl_seconds: Some(params.ttl_seconds),
        uuid: Some(params.uuid.to_vec()),
        family: Some(5),
        primary: Some(1),
        secondary: None,
        signature_scheme: Some(1),
        atomicity: Some(atomicity),
        priority: Some(3),
        route_scope: Some(params.route_scope),
        body: Some(Body::Ack(Operation {
            opcode: Some(2),
            words,
            blobs: vec![original.to_vec()],
            appeal_deadline: None,
        })),
    }
}

/// The length of the largest response that this authority can send for the
/// original, measured by encoding a response of the same shape. Every field
/// of that shape has a fixed width except the embedded original Core, and the
/// commit position is the only optional word, so the measured length bounds
/// every response for this original.
fn largest_response_len(channel: &Channel, original: &CanonicalPacket) -> Result<usize, WireError> {
    let words = response_words(
        CallId {
            namespace: 0,
            sequence: 0,
        },
        ResponseResult {
            code: ResponseCode::Debited,
            commit: Some(CommitRef { position: 0 }),
        },
    )?;
    let mut uuid = [0; 16];
    uuid[6] = 0x40;
    uuid[8] = 0x80;
    let params = ResponseParameters {
        principal: 0,
        key_id: 0,
        authority_epoch: 0,
        issued_seconds: 0,
        ttl_seconds: 0,
        uuid,
        route_scope: 0,
    };
    let core = response_core(
        channel,
        &params,
        response_atomicity(channel)?,
        words,
        original.core_bytes(),
    );
    Ok(encode_packet(&Packet {
        core: Some(core),
        signature: Some(vec![0; 64]),
    })?
    .len())
}

/// Verify the signature of a received original with the peer key that the
/// channel authenticated, before any answer about the frame is signed. A frame
/// that fails here receives only an unsigned error. The check reads the frame
/// and the channel key, and no registration of the principal, key or epoch
/// that the frame names, so the error cannot reveal that registration.
fn check_original_signature(channel: &Channel, original: &CanonicalPacket) -> Result<(), WireError> {
    let scheme = original.core().signature_scheme.ok_or(BAD)?;
    if scheme == 2 {
        return Err(WireError::InvalidThresholdSignature);
    }
    if !channel.profile().schemes.contains(&scheme)
        || !verify(
            &channel.peer_keys()[1],
            &original.signing_bytes()?,
            original.signature(),
        )
    {
        return Err(WireError::InvalidSignature);
    }
    Ok(())
}

fn encode_response(
    channel: &Channel,
    signer: &dyn ResponseSigner,
    original: &CanonicalPacket,
    id: CallId,
    outcome: ResponseResult,
    max_frame: usize,
) -> Result<Vec<u8>, WireError> {
    #[cfg(test)] let _source_encoder = source_trace::encoder(original,id,outcome);
    let words = response_words(id, outcome)?;
    #[cfg(test)] source_trace::words(&words);
    let atomicity = response_atomicity(channel)?;
    #[cfg(test)] source_trace::atomicity(atomicity);
    let mut binding = Sha256::new();
    binding.update(b"oip/reference-response-binding/v1\0");
    binding.update(
        u64::try_from(original.core_bytes().len())
            .map_err(|_| BAD)?
            .to_be_bytes(),
    );
    binding.update(original.core_bytes());
    binding.update(atomicity.to_be_bytes());
    binding.update(u64::try_from(words.len()).map_err(|_| BAD)?.to_be_bytes());
    for word in &words {
        binding.update(word.to_be_bytes());
    }
    let params = signer
        .parameters(channel, binding.finalize().into())
        .ok_or(WireError::InvalidSource)?;
    if params.issued_seconds > channel.expires() {
        return Err(WireError::InvalidSource);
    }
    let core = response_core(channel, &params, atomicity, words, original.core_bytes());
    let core_bytes = encode_core(&core)?;
    #[cfg(test)] source_trace::core(&core_bytes);
    let signature = signer
        .sign(&signing_bytes(&core_bytes)?)
        .ok_or(WireError::ResponseLost)?;
    let packet = encode_packet(&Packet {
        core: Some(core),
        signature: Some(signature.to_vec()),
    })?;
    let decoded = decode_packet(&packet, max_frame)?;
    let boundary = Boundary {
        deployment: channel.deployment(),
        source: channel.local(),
        target: channel.remote(),
        principal: params.principal,
        key_id: params.key_id,
        epoch: params.authority_epoch,
        route_scope: params.route_scope,
        now: params.issued_seconds,
        asset_ttl_floor: 0,
        future_skew: 0,
        max_frame,
        max_nesting: 2,
        version_floor: 6,
        critical_allowed: false,
        public_key: channel.peer_keys()[0],
    };
    admit_packet(&decoded, channel.profile(), &boundary)?;
    let verified = validate_response(&decoded, original, boundary.max_nesting)?;
    if verified.code != ResponseStatus::Known(outcome.code) {
        return Err(BAD);
    }
    #[cfg(test)] source_trace::postcheck(&verified);
    Ok(packet)
}

impl<S: WireSecurity, H: AuthenticatedHead> PersistentAuthority<S, H> {
    fn response_original(
        &self,
        channel: &Channel,
        bytes: &[u8],
    ) -> Result<(CanonicalPacket, CallId), WireError> {
        if channel.profile().version != 6 || !channel.profile().allows(5, 2) {
            return Err(WireError::UnsupportedVersion);
        }
        if self.anchor.ordered_wire_control().is_none()
            || self.security.ordered_revocation_profile() != Some(self.profile)
            || !self.security.channel_current(channel)
            || channel.deployment() != self.profile.deployment
        {
            return Err(WireError::InvalidSource);
        }
        let frame_limit = self.security.frame_limit(channel);
        check_declared_version(bytes, frame_limit)?;
        let original = decode_packet(bytes, frame_limit)?;
        let core = original.core();
        // The same operation check that runs in front of the admission gate.
        super::check_operation(self.security.as_ref(), channel, core)?;
        if core.version != Some(channel.profile().version)
            || core.deployment != Some(channel.deployment())
            || core.source_domain != Some(channel.remote())
            || core.target_domain != Some(channel.local())
        {
            return Err(WireError::InvalidSource);
        }
        let id = caller_id(&decode(core, 1)?)?;
        // The response embeds the original Core. A request whose response
        // could not fit the frame limit is refused here, before any effect.
        if largest_response_len(channel, &original)? > frame_limit {
            return Err(WireError::InvalidFormat);
        }
        // Every check above reads only the frame and the channel. Nothing is
        // signed for a frame whose own signature does not verify.
        check_original_signature(channel, &original)?;
        Ok((original, id))
    }

    /// Execute the signed call and return its correlated response after the
    /// existing authority transaction returns. Only call frames with a
    /// caller-qualified ID have a reference ACK Response.
    pub fn receive_wire_response(
        &mut self,
        channel: &Channel,
        entry: Entry,
        bytes: &[u8],
        credentials: &WireCredentials<'_, S>,
        delivery: DeliveryWindow,
    ) -> Result<Vec<u8>, WireError> {
        #[cfg(test)] let _source_scope=source_trace::begin(bytes);
        let (original, id) = self.response_original(channel, bytes)?;
        let security = self.security.clone();
        let signer = security.response_signer().ok_or(WireError::InvalidSource)?;
        let outcome =
            match self.receive_wire_result(channel, entry, bytes, credentials, delivery, true) {
                Ok((received, retained)) => {
                    #[cfg(test)] source_trace::received(&received,retained);
                    ResponseResult::from_received(received, retained)
                },
                Err(error) => {
                    #[cfg(test)] source_trace::wire_error(&error);
                    ResponseResult::error(error)
                },
            };
        encode_response(
            channel,
            signer,
            &original,
            id,
            outcome,
            security.frame_limit(channel),
        )
    }

    /// Produce the correlated response to an exact authorized resolution.
    pub fn resolve_wire_debit_response(
        &mut self,
        channel: &Channel,
        original: &[u8],
        credentials: &WireCredentials<'_, S>,
        close: bool,
    ) -> Result<Vec<u8>, WireError> {
        #[cfg(test)] let _source_scope=source_trace::begin(original);
        let (packet, id) = self.response_original(channel, original)?;
        let security = self.security.clone();
        let signer = security.response_signer().ok_or(WireError::InvalidSource)?;
        let outcome = match self.resolve_wire_debit(channel, original, credentials, close) {
            Ok(result) => {
                #[cfg(test)] source_trace::resolved(result);
                ResponseResult::from_resolution(result)
            },
            Err(error) => {
                    #[cfg(test)] source_trace::wire_error(&error);
                    ResponseResult::error(error)
                },
        };
        encode_response(
            channel,
            signer,
            &packet,
            id,
            outcome,
            security.frame_limit(channel),
        )
    }
}

#[cfg(test)]
pub(in crate::authority::recovery::wire) mod source_trace;
#[cfg(test)]
mod vector_tests;
#[cfg(test)]
mod extension_tests;
