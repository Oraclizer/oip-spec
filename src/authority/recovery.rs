//! Authenticated, append-only persistence for the product authority.

use super::identity::{
    ActionReply, Bootstrap, Consent, Credentials, EndpointError, Entry, Handover, Identity,
    Observation, ProductAuthority, ReadRequest, Receipt, Request, Security,
};
use super::reads::{CacheClaim, CacheEntry, ReadAuthority};
use super::{Acknowledgement, Authority, SecondaryJob, SettlementKey, Snapshot};
use crate::lock_finality::{Binding, EndpointContext, TerminalEvidence, TerminalKind};
use crate::{CommitCut, OriginKey, Principal, SessionBinding, SessionId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

pub mod archive;
pub mod ordered;
pub mod schedule;
pub mod wire;

/// BTreeMap keys are encoded as ordered tuples, including non-string keys.
pub(crate) mod ordered_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<K: Ord + Serialize, V: Serialize, S: Serializer>(
        map: &BTreeMap<K, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(map)
    }

    pub fn deserialize<
        'de,
        K: Ord + Deserialize<'de>,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    >(
        deserializer: D,
    ) -> Result<BTreeMap<K, V>, D::Error> {
        let entries = Vec::<(K, V)>::deserialize(deserializer)?;
        let count = entries.len();
        let map: BTreeMap<_, _> = entries.into_iter().collect();
        if map.len() != count {
            return Err(serde::de::Error::custom("duplicate map key"));
        }
        Ok(map)
    }
}

pub const RECOVERY_FORMAT: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryProfile {
    pub deployment: u64,
    pub format: u32,
    pub authority_profile: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnchorHead {
    pub profile: RecoveryProfile,
    pub sequence: u64,
    pub offset: u64,
    pub length: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadError;

/// Authenticated witness and writer identity bound to the attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointFence {
    /// Independently authenticated ancestor for lineage validation.
    pub head: Option<AnchorHead>,
    /// Exact latest head protected against restore, independent of the lineage floor.
    pub protected_head: Option<AnchorHead>,
    pub writer_generation: u64,
    pub writer_id: [u8; 32],
}

/// A single repair request, observed with its independent witness and nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtectedRepairCut {
    pub restored: Option<AnchorHead>,
    pub checkpoint: CheckpointFence,
    pub nonce: [u8; 32],
}

impl ProtectedRepairCut {
    /// Bind the authorization to this profile, connection and authenticated
    /// attachment. Fixed widths and presence tags give a unique preimage.
    pub fn authorization_message(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        attachment_binding: [u8; 32],
    ) -> Vec<u8> {
        let mut message = b"oip/protected-head-repair/v1\0".to_vec();
        Self::encode_profile(&mut message, profile);
        message.push(u8::from(connected));
        message.extend_from_slice(&attachment_binding);
        Self::encode_head(&mut message, self.restored);
        Self::encode_head(&mut message, self.checkpoint.head);
        Self::encode_head(&mut message, self.checkpoint.protected_head);
        message.extend_from_slice(&self.checkpoint.writer_generation.to_be_bytes());
        message.extend_from_slice(&self.checkpoint.writer_id);
        message.extend_from_slice(&self.nonce);
        message
    }

    fn encode_profile(message: &mut Vec<u8>, profile: RecoveryProfile) {
        message.extend_from_slice(&profile.deployment.to_be_bytes());
        message.extend_from_slice(&profile.format.to_be_bytes());
        message.extend_from_slice(&profile.authority_profile.to_be_bytes());
    }

    fn encode_head(message: &mut Vec<u8>, head: Option<AnchorHead>) {
        message.push(u8::from(head.is_some()));
        if let Some(head) = head {
            Self::encode_profile(message, head.profile);
            message.extend_from_slice(&head.sequence.to_be_bytes());
            message.extend_from_slice(&head.offset.to_be_bytes());
            message.extend_from_slice(&head.length.to_be_bytes());
            message.extend_from_slice(&head.digest);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointState {
    /// The authority itself supplies freshness and restoration fencing.
    Direct,
    /// An authenticated witness. None confirms absence of a published history.
    Independent(CheckpointFence),
}

/// The admitted request and the cutoffs which apply to its effect.
pub struct WirePublication {
    pub core: crate::wire::generated::Core,
    pub packet_sha256: [u8; 32],
    pub transport: crate::wire::admission::TransportKey,
    pub signed_core_sha256: [u8; 32],
    pub service_deadline: Option<u64>,
    pub wire_expiry: u64,
}

enum PublicationGuard {
    Strict(WirePublication),
    Ordered(ordered::OrderedPublication),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationRefusal {
    Unsupported,
    CheckpointChanged,
    DeadlineExpired,
    TtlExpired,
    Cancelled,
}

/// An independently authenticated and rollback-resistant adapter. The
/// adapter must bind its proof to the current profile and atomically CAS the
/// latest head. An error from CAS can mean that the write took effect.
pub trait AuthenticatedHead {
    type AttachmentProof;
    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &Self::AttachmentProof,
    ) -> bool;
    fn current(&self) -> Result<Option<AnchorHead>, HeadError>;

    /// Configured ordered-admission control. Legacy heads use the strict path.
    fn ordered_wire_control(&self) -> Option<&dyn ordered::WireControl> {
        None
    }

    /// Mode required by this authenticated attachment's configuration.
    /// Resolve it independently of witness availability or rollbackable
    /// journal data. A legacy direct authority uses the default.
    fn attachment_requires_independent_checkpoint(
        &self,
        _profile: RecoveryProfile,
        _connected: bool,
        _proof: &Self::AttachmentProof,
    ) -> Result<bool, HeadError> {
        Ok(false)
    }

    /// An unavailable or unverifiable required witness is an error. A known
    /// empty witness is distinct from a profile with direct freshness.
    fn checkpoint_state(&self) -> Result<CheckpointState, HeadError> {
        Ok(CheckpointState::Direct)
    }

    /// Fence the observed lineage, protected head, and writer at the same
    /// authority decision as the exact-head CAS. Successful publication
    /// requires independent protection of the candidate before it is visible.
    /// A wire guard must also be enforced at durable visibility.
    /// A definite refusal must leave the head unchanged. Outer errors can be
    /// ambiguous and are reconciled by the caller against the exact record.
    fn compare_and_set_with_checkpoint(
        &self,
        _expected: Option<AnchorHead>,
        _candidate: AnchorHead,
        _checkpoint: CheckpointFence,
        _wire: Option<&WirePublication>,
    ) -> Result<Result<(), PublicationRefusal>, HeadError> {
        Ok(Err(PublicationRefusal::Unsupported))
    }
    /// Observe the head and witness in a single authenticated authority read
    /// for this attachment. A provider without that cut must refuse readback.
    fn checkpoint_readback(&self) -> Result<(Option<AnchorHead>, CheckpointFence), HeadError> {
        Err(HeadError)
    }

    /// Check a live journal against any archive bound to the selected witness.
    /// Legacy independent providers supply their original checkpoint contract.
    fn verify_independent_journal(&self, _file: &mut File, _head: AnchorHead) -> Result<(), HeadError> {
        Ok(())
    }

    /// Read the repair cut and its nonce in one authenticated observation.
    fn protected_repair_cut(&self) -> Result<ProtectedRepairCut, HeadError> {
        Err(HeadError)
    }

    /// Restore an already published head only with authorization over this
    /// exact cut and attachment. Compare the restored pointer, witness, writer
    /// and independently retained nonce, then consume the nonce atomically
    /// with the repair. Restoring the local authority must not restore a nonce.
    /// This operation must not authorize or execute a new application effect.
    /// False is a definite refusal. An error can mean the pointer was repaired.
    fn recover_published_head(
        &self,
        _cut: ProtectedRepairCut,
        _attachment: &Self::AttachmentProof,
        _authorization: &[u8],
    ) -> Result<bool, HeadError> {
        Ok(false)
    }

    fn compare_and_set(
        &self,
        expected: Option<AnchorHead>,
        candidate: AnchorHead,
    ) -> Result<bool, HeadError>;

    /// True only for a configured strict provider. The guarded CAS must
    /// independently refuse publication if its guarantees are unavailable.
    fn supports_wire_publication(&self) -> bool {
        false
    }

    /// Compare against the exact head and apply both cutoffs at durable
    /// visibility. Evaluate cancellation in the same authority order. If
    /// these guarantees are unavailable, refuse without publication.
    /// Outer errors may mean the outcome is ambiguous.
    fn compare_and_set_at_publication(
        &self,
        _expected: Option<AnchorHead>,
        _candidate: AnchorHead,
        _guard: &WirePublication,
    ) -> Result<Result<(), PublicationRefusal>, HeadError> {
        Ok(Err(PublicationRefusal::Unsupported))
    }
}

/// Trusted operator configuration. The profile proof is issued for the
/// installed identity, signature, policy and source-connection adapters.
pub struct Attachment<S: Security, P> {
    pub profile: RecoveryProfile,
    pub proof: P,
    pub security: S,
    pub source_connected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    AttachmentRejected,
    MissingHead,
    InvalidImage,
    AlreadyInitialized,
    InvalidBootstrap,
    Io,
    Hold,
    Publication(PublicationRefusal),
    Endpoint(EndpointError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAction {
    None,
    Query(Binding),
    Hold(Binding),
    ConsiderConfirmed(Binding),
    ConsiderReversed(Binding),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RetainedImage {
    authority: Snapshot,
    #[serde(with = "ordered_map")]
    directory: BTreeMap<Principal, Identity>,
    provider: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    security_binding: Option<[u8; 32]>,
}

impl RetainedImage {
    fn capture<S: Security>(service: &ProductAuthority<S>) -> Self {
        Self {
            authority: service.reads.authority.snapshot(),
            directory: service.directory.clone(),
            provider: service.reads.provider,
            security_binding: service.security.prepared_authority_binding(service.reads.current_cut().authority_epoch),
        }
    }

    fn accepts_security(&self, security: &impl Security) -> bool {
        (!security.requires_authority_binding() || self.security_binding.is_some())
            && self.security_binding == security.authority_binding(self.authority.primary.ledger.current_cut().authority_epoch)
    }

    fn accepts_prepared_security(&self, security: &impl Security) -> bool {
        (!security.requires_authority_binding() || self.security_binding.is_some())
            && self.security_binding == security.prepared_authority_binding(self.authority.primary.ledger.current_cut().authority_epoch)
    }

    fn open<S: Security>(
        self,
        profile: RecoveryProfile,
        security: Arc<S>,
        connected: bool,
    ) -> ProductAuthority<S> {
        let authority = Authority {
            state: self.authority,
            up: true,
            connected,
        };
        let mut reads = ReadAuthority::new(authority, self.provider);
        reads.profile = Some(profile);
        ProductAuthority::from_records(reads, self.directory, security)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CommitRecord {
    profile: RecoveryProfile,
    sequence: u64,
    previous: Option<AnchorHead>,
    image: RetainedImage,
}

fn encode(record: &CommitRecord) -> Result<Vec<u8>, RecoveryError> {
    serde_json::to_vec(record).map_err(|_| RecoveryError::InvalidImage)
}

fn read_record(file: &mut File, head: AnchorHead) -> Result<CommitRecord, RecoveryError> {
    let end = recovery_bounds::checked_end(head.offset, head.length)
        .ok_or(RecoveryError::InvalidImage)?;
    if head.length == 0 || end > file.metadata().map_err(|_| RecoveryError::Io)?.len() {
        return Err(RecoveryError::InvalidImage);
    }
    let size = usize::try_from(head.length).map_err(|_| RecoveryError::InvalidImage)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| RecoveryError::InvalidImage)?;
    bytes.resize(size, 0);
    file.seek(SeekFrom::Start(head.offset))
        .map_err(|_| RecoveryError::Io)?;
    file.read_exact(&mut bytes).map_err(|_| RecoveryError::Io)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != head.digest {
        return Err(RecoveryError::InvalidImage);
    }
    let record: CommitRecord =
        serde_json::from_slice(&bytes).map_err(|_| RecoveryError::InvalidImage)?;
    if record.profile != head.profile
        || record.sequence != head.sequence
        || encode(&record)? != bytes
    {
        return Err(RecoveryError::InvalidImage);
    }
    match record.previous {
        None if head.sequence == 0 => (),
        Some(previous)
            if recovery_bounds::valid_predecessor(
                previous.profile == head.profile,
                previous.sequence,
                previous.offset,
                previous.length,
                head.sequence,
                head.offset,
            ) => {}
        _ => return Err(RecoveryError::InvalidImage),
    }
    Ok(record)
}

fn exact_image(file: &mut File, head: AnchorHead) -> Result<CommitRecord, RecoveryError> {
    let record = read_record(file, head)?;
    let previous = record.previous.map(|parent| read_record(file, parent)).transpose()?;
    validate_retained_transition(&record, previous.as_ref())?;
    Ok(record)
}

fn validate_retained_transition(record: &CommitRecord, previous: Option<&CommitRecord>) -> Result<(), RecoveryError> {
    let state = &record.image.authority;
    if !state.primary.ledger.has_consistent_endpoint_registry()
        || !state.primary.owners.keys().eq(state.primary.ledger.registered_assets())
        || !state.primary.has_consistent_settlement_receipts()
        || !super::sync::State::valid_image(state, record.profile.deployment)
        || !state.read_history.has_consistent_asset_registry(&state.primary.ledger)
        || !state.read_history.matches_current(&state.primary)
        || !state.secondary.is_bound_to_primary(&state.primary)
        || !state.primary.regulation.matches_applied_history(&state.primary.ledger)
        || !state.primary.regulation.has_disjoint_receipt_ids(|id| state.primary.calls.contains_key(id))
    {
        return Err(RecoveryError::InvalidImage);
    }
    if let Some(previous) = previous {
        let before = &previous.image.authority;
        if (before.primary.ledger.current_cut().authority_epoch == state.primary.ledger.current_cut().authority_epoch
                && previous.image.security_binding != record.image.security_binding)
            || !before.primary.ledger.has_consistent_endpoint_registry()
            || !state.primary.ledger.preserves_registered_endpoints(&before.primary.ledger)
            || !before.primary.has_consistent_settlement_receipts()
            || !state.primary.preserves_retained_outcomes(&before.primary)
            || !before.wire_bindings.iter().all(|(key, bytes)| {
                state.wire_bindings.get(key) == Some(bytes)
            })
            || !before.read_history.matches_current(&before.primary)
            || !state.read_history.preserves_preceding_history(&before.read_history)
            || !before.secondary.is_bound_to_primary(&before.primary)
            || !state.secondary.preserves_previous_jobs(&before.secondary)
            || !before.primary.regulation.matches_applied_history(&before.primary.ledger)
            || !state.primary.regulation.preserves_retained_regulation(&before.primary.regulation)
        {
            return Err(RecoveryError::InvalidImage);
        }
    } else if state.primary.ledger.current_cut().revision != 0 || !state.secondary.jobs.is_empty() {
        return Err(RecoveryError::InvalidImage);
    }
    Ok(())
}

fn validate_lineage(
    file: &mut File,
    head: AnchorHead,
    record: &CommitRecord,
    floor: AnchorHead,
) -> Result<(), RecoveryError> {
    if head.profile != floor.profile || head.sequence < floor.sequence {
        return Err(RecoveryError::Hold);
    }
    if head == floor {
        return Ok(());
    }
    let mut next = record.previous;
    while let Some(parent) = next {
        if parent.sequence == floor.sequence {
            if parent != floor {
                return Err(RecoveryError::Hold);
            }
            // The digest in the link does not establish that these bytes survived.
            read_record(file, floor)?;
            return Ok(());
        }
        if parent.sequence < floor.sequence {
            break;
        }
        next = read_record(file, parent)?.previous;
    }
    Err(RecoveryError::Hold)
}

fn append_record(
    file: &mut File,
    record: &CommitRecord,
    flush: impl FnOnce(&File) -> io::Result<()>,
) -> Result<AnchorHead, RecoveryError> {
    let bytes = encode(record)?;
    let offset = file.seek(SeekFrom::End(0)).map_err(|_| RecoveryError::Io)?;
    file.write_all(&bytes).map_err(|_| RecoveryError::Io)?;
    flush(file).map_err(|_| RecoveryError::Io)?;
    Ok(AnchorHead {
        profile: record.profile,
        sequence: record.sequence,
        offset,
        length: u64::try_from(bytes.len()).map_err(|_| RecoveryError::Io)?,
        digest: Sha256::digest(&bytes).into(),
    })
}

#[cfg(test)]
fn commit(
    file: &mut File,
    anchor: &impl AuthenticatedHead,
    record: &CommitRecord,
    flush: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), RecoveryError> {
    commit_guarded(file, anchor, record, flush, CheckpointState::Direct, || Ok(None))
}

fn commit_guarded(
    file: &mut File,
    anchor: &impl AuthenticatedHead,
    record: &CommitRecord,
    flush: impl FnOnce(&File) -> io::Result<()>,
    checkpoint: CheckpointState,
    before_publish: impl FnOnce() -> Result<Option<PublicationGuard>, RecoveryError>,
) -> Result<(), RecoveryError> {
    let candidate = append_record(file, record, flush)?;
    publish_prepared_record(file, anchor, record, candidate, checkpoint, before_publish)
}

fn publish_prepared_record(
    file: &mut File,
    anchor: &impl AuthenticatedHead,
    record: &CommitRecord,
    candidate: AnchorHead,
    checkpoint: CheckpointState,
    before_publish: impl FnOnce() -> Result<Option<PublicationGuard>, RecoveryError>,
) -> Result<(), RecoveryError> {
    let guard = before_publish()?;
    let publication = match (checkpoint, guard.as_ref()) {
        (CheckpointState::Independent(witness), Some(PublicationGuard::Strict(guard))) => {
            anchor.compare_and_set_with_checkpoint(record.previous, candidate, witness, Some(guard))
        }
        (CheckpointState::Independent(witness), None) => {
            anchor.compare_and_set_with_checkpoint(record.previous, candidate, witness, None)
        }
        (CheckpointState::Direct, Some(PublicationGuard::Strict(guard))) => {
            anchor.compare_and_set_at_publication(record.previous, candidate, guard)
        }
        (CheckpointState::Direct, Some(PublicationGuard::Ordered(admission))) => {
            let control = anchor.ordered_wire_control().ok_or(RecoveryError::Hold)?;
            if admission.cut.head() != record.previous {
                return Err(RecoveryError::Hold);
            }
            control.publish(candidate, admission).map(|changed| {
                if changed { Ok(()) } else { Err(PublicationRefusal::CheckpointChanged) }
            })
        }
        (CheckpointState::Independent(witness), Some(PublicationGuard::Ordered(admission))) => {
            let control = anchor.ordered_wire_control().ok_or(RecoveryError::Hold)?;
            if admission.cut.head() != record.previous || witness.protected_head != record.previous {
                return Err(RecoveryError::Hold);
            }
            control.publish_independent(file, candidate, admission, witness)
        }
        (CheckpointState::Direct, None) => {
            anchor.compare_and_set(record.previous, candidate).map(|_| Ok(()))
        }
    };
    if let Ok(Err(refusal)) = publication {
        return match refusal {
            PublicationRefusal::Unsupported | PublicationRefusal::CheckpointChanged => {
                Err(RecoveryError::Hold)
            }
            _ => Err(RecoveryError::Publication(refusal)),
        };
    }
    confirm_authority_record(file, anchor, candidate, record, checkpoint)
}

fn confirm_authority_record(
    file: &mut File,
    anchor: &impl AuthenticatedHead,
    expected: AnchorHead,
    record: &CommitRecord,
    checkpoint: CheckpointState,
) -> Result<(), RecoveryError> {
    let (head, floor) = match checkpoint {
        CheckpointState::Direct => (anchor.current().map_err(|_| RecoveryError::Hold)?, None),
        CheckpointState::Independent(observed) => {
            let (head, current) = anchor.checkpoint_readback().map_err(|_| RecoveryError::Hold)?;
            if current.writer_generation != observed.writer_generation
                || current.writer_id != observed.writer_id
                || current.protected_head != Some(expected)
            {
                return Err(RecoveryError::Hold);
            }
            (head, Some(current.head.ok_or(RecoveryError::Hold)?))
        }
    };
    if head != Some(expected) {
        return Err(RecoveryError::Hold);
    }
    let readback = exact_image(file, expected)?;
    if readback != *record {
        return Err(RecoveryError::InvalidImage);
    }
    if let Some(floor) = floor {
        validate_lineage(file, expected, &readback, floor)?;
        anchor.verify_independent_journal(file, expected).map_err(|_| RecoveryError::Hold)?;
    }
    Ok(())
}

struct LockedFile<'a>(&'a mut File);

impl<'a> LockedFile<'a> {
    fn acquire(file: &'a mut File) -> Result<Self, RecoveryError> {
        file.try_lock().map_err(|_| RecoveryError::Hold)?;
        Ok(Self(file))
    }
}

impl Drop for LockedFile<'_> {
    fn drop(&mut self) {
        // A failed unlock can only prevent later calls from acquiring the file.
        let _ = self.0.unlock();
    }
}

/// Public product service backed by one already established journal file.
///
/// The retained ledger cannot be deserialized as a public execution handle.
/// ```compile_fail
/// let _ = serde_json::from_str::<oip_spec::lock_finality::Ledger>("{}");
/// ```
/// A stored image cannot be decoded outside the authority boundary.
/// ```compile_fail
/// let _ = serde_json::from_str::<oip_spec::authority::Snapshot>("{}");
/// ```
/// The previous in-memory engine is internal.
/// ```compile_fail
/// use oip_spec::authority::identity::ProductAuthority;
/// ```
pub struct PersistentAuthority<S: Security, H: AuthenticatedHead> {
    file: File,
    anchor: H,
    profile: RecoveryProfile,
    proof: H::AttachmentProof,
    security: Arc<S>,
    source_connected: bool,
    independent_checkpoint: Option<bool>,
}

impl<S: Security, H: AuthenticatedHead> PersistentAuthority<S, H> {
    /// Explicit provisioning. Reopen never invokes this path.
    pub fn initialize(
        mut file: File,
        anchor: H,
        attachment: Attachment<S, H::AttachmentProof>,
        initial: Bootstrap,
    ) -> Result<Self, RecoveryError> {
        Self::check_attachment(
            &anchor,
            attachment.profile,
            attachment.source_connected,
            &attachment.proof,
        )?;
        let service = ProductAuthority::bootstrap(initial, attachment.security)
            .ok_or(RecoveryError::InvalidBootstrap)?;
        let checkpoint = {
            let locked = LockedFile::acquire(&mut file)?;
            if anchor.current().map_err(|_| RecoveryError::Hold)?.is_some()
                || locked.0.metadata().map_err(|_| RecoveryError::Io)?.len() != 0
            {
                return Err(RecoveryError::AlreadyInitialized);
            }
            let checkpoint = Self::read_configured_checkpoint(
                &anchor, attachment.profile, attachment.source_connected, &attachment.proof, None,
            )?;
            if let CheckpointState::Independent(witness) = checkpoint {
                if witness.head.is_some() || witness.protected_head.is_some() {
                    return Err(RecoveryError::AlreadyInitialized);
                }
            }
            let record = CommitRecord {
                profile: attachment.profile,
                sequence: 0,
                previous: None,
                image: RetainedImage::capture(&service),
            };
            if !record.image.accepts_security(service.security.as_ref()) {
                return Err(RecoveryError::InvalidBootstrap);
            }
            validate_retained_transition(&record, None)?;
            commit_guarded(
                locked.0,
                &anchor,
                &record,
                File::sync_all,
                checkpoint,
                || Ok(None),
            )?;
            checkpoint
        };
        Ok(Self {
            file,
            anchor,
            profile: attachment.profile,
            proof: attachment.proof,
            security: Arc::clone(&service.security),
            source_connected: attachment.source_connected,
            independent_checkpoint: Some(matches!(checkpoint, CheckpointState::Independent(_))),
        })
    }

    /// Explicit recovery operation. Do not invoke application code or append
    /// a record. The provider must authorize repair of a published pointer.
    pub fn repair_protected_head(
        mut file: File,
        anchor: &H,
        attachment: &Attachment<S, H::AttachmentProof>,
        authorization: &[u8],
    ) -> Result<(), RecoveryError> {
        Self::check_attachment(
            anchor,
            attachment.profile,
            attachment.source_connected,
            &attachment.proof,
        )?;
        let locked = LockedFile::acquire(&mut file)?;
        if !anchor.attachment_requires_independent_checkpoint(
            attachment.profile, attachment.source_connected, &attachment.proof,
        ).map_err(|_| RecoveryError::Hold)? {
            return Err(RecoveryError::Hold);
        }
        let cut = anchor.protected_repair_cut().map_err(|_| RecoveryError::Hold)?;
        let ProtectedRepairCut { restored, checkpoint, .. } = cut;
        let protected = checkpoint.protected_head.ok_or(RecoveryError::Hold)?;
        let floor = checkpoint.head.ok_or(RecoveryError::Hold)?;
        if protected.profile != attachment.profile {
            return Err(RecoveryError::AttachmentRejected);
        }
        let record = exact_image(locked.0, protected)?;
        validate_lineage(locked.0, protected, &record, floor)?;
        if restored != Some(protected) {
            if let Some(previous) = restored {
                validate_lineage(locked.0, protected, &record, previous)?;
            }
            locked.0.sync_all().map_err(|_| RecoveryError::Io)?;
            if let Ok(false) = anchor.recover_published_head(cut, &attachment.proof, authorization) {
                return Err(RecoveryError::Hold);
            }
        }
        confirm_authority_record(locked.0, anchor, protected, &record, CheckpointState::Independent(checkpoint))
    }

    /// Construct a fresh service without an earlier product or snapshot.
    pub fn open(
        file: File,
        anchor: H,
        attachment: Attachment<S, H::AttachmentProof>,
    ) -> Result<Self, RecoveryError> {
        let mut service = Self {
            file,
            anchor,
            profile: attachment.profile,
            proof: attachment.proof,
            security: Arc::new(attachment.security),
            source_connected: attachment.source_connected,
            independent_checkpoint: None,
        };
        service.transact(|_| ())?;
        Ok(service)
    }

    fn check_attachment(
        anchor: &H,
        profile: RecoveryProfile,
        connected: bool,
        proof: &H::AttachmentProof,
    ) -> Result<(), RecoveryError> {
        if profile.format != RECOVERY_FORMAT || !anchor.verify_attachment(profile, connected, proof)
        {
            return Err(RecoveryError::AttachmentRejected);
        }
        Ok(())
    }

    fn read_configured_checkpoint(
        anchor: &H,
        profile: RecoveryProfile,
        connected: bool,
        proof: &H::AttachmentProof,
        established: Option<bool>,
    ) -> Result<CheckpointState, RecoveryError> {
        let required = anchor.attachment_requires_independent_checkpoint(profile, connected, proof)
            .map_err(|_| RecoveryError::Hold)?;
        let observed = anchor.checkpoint_state().map_err(|_| RecoveryError::Hold)?;
        if required != matches!(observed, CheckpointState::Independent(_))
            || established.is_some_and(|previous| previous != required)
        {
            return Err(RecoveryError::Hold);
        }
        Ok(observed)
    }

    /// Replace the volatile source attachment only after current verification.
    pub fn reconnect(
        &mut self,
        proof: H::AttachmentProof,
        connected: bool,
    ) -> Result<(), RecoveryError> {
        Self::check_attachment(&self.anchor, self.profile, connected, &proof)?;
        self.proof = proof;
        self.source_connected = connected;
        Ok(())
    }

    fn transact<T>(
        &mut self,
        act: impl FnOnce(&mut ProductAuthority<S>) -> T,
    ) -> Result<T, RecoveryError> {
        self.transact_guarded(|_, _, product| std::ops::ControlFlow::Continue(act(product)), false, || Ok(None))
    }

    fn transact_guarded<T>(
        &mut self,
        act: impl FnOnce(&H, AnchorHead, &mut ProductAuthority<S>) -> std::ops::ControlFlow<T, T>,
        wire: bool,
        before_publish: impl FnOnce() -> Result<Option<PublicationGuard>, RecoveryError>,
    ) -> Result<T, RecoveryError> {
        Self::check_attachment(
            &self.anchor,
            self.profile,
            self.source_connected,
            &self.proof,
        )?;
        let locked = LockedFile::acquire(&mut self.file)?;
        let head = self
            .anchor
            .current()
            .map_err(|_| RecoveryError::Hold)?
            .ok_or(RecoveryError::MissingHead)?;
        if head.profile != self.profile {
            return Err(RecoveryError::AttachmentRejected);
        }
        let checkpoint = Self::read_configured_checkpoint(
            &self.anchor, self.profile, self.source_connected, &self.proof, self.independent_checkpoint,
        )?;
        let independent = matches!(checkpoint, CheckpointState::Independent(_));
        let before = exact_image(locked.0, head)?;
        if !before.image.accepts_security(self.security.as_ref()) {
            return Err(RecoveryError::AttachmentRejected);
        }
        match checkpoint {
            CheckpointState::Independent(witness) => {
                if witness.protected_head != Some(head) {
                    return Err(RecoveryError::Hold);
                }
                let floor = witness.head.ok_or(RecoveryError::Hold)?;
                validate_lineage(locked.0, head, &before, floor)?;
                self.anchor.verify_independent_journal(locked.0, head).map_err(|_| RecoveryError::Hold)?;
            }
            CheckpointState::Direct => {}
        }
        let mut product =
            before
                .image
                .clone()
                .open(self.profile, self.security.clone(), self.source_connected);
        let reply = match act(&self.anchor, head, &mut product) {
            std::ops::ControlFlow::Continue(reply) => reply,
            std::ops::ControlFlow::Break(reply) => return Ok(reply),
        };
        let image = RetainedImage::capture(&product);
        if !image.accepts_prepared_security(self.security.as_ref()) {
            return Err(RecoveryError::AttachmentRejected);
        }
        if image != before.image {
            if wire
                && self.anchor.ordered_wire_control().is_none()
                && !self.anchor.supports_wire_publication()
            {
                return Err(RecoveryError::Hold);
            }
            let record = CommitRecord {
                profile: self.profile,
                sequence: head.sequence.checked_add(1).ok_or(RecoveryError::Hold)?,
                previous: Some(head),
                image,
            };
            validate_retained_transition(&record, Some(&before))?;
            let validate_wire_guard = || {
                    let guard = before_publish()?;
                    if wire && guard.is_none() {
                        return Err(RecoveryError::Hold);
                    }
                    Ok(guard)
            };
            if wire && self.anchor.ordered_wire_control().is_some() {
                let candidate = append_record(locked.0, &record, File::sync_all)?;
                // Prepared bytes are immutable after sync. Release the file
                // lock so receipt resolution can race the exact-head CAS.
                drop(locked);
                publish_prepared_record(
                    &mut self.file, &self.anchor, &record, candidate, checkpoint, validate_wire_guard,
                )?;
            } else {
                commit_guarded(
                    locked.0, &self.anchor, &record, File::sync_all, checkpoint, validate_wire_guard,
                )?;
            }
        } else {
            if let Some(PublicationGuard::Ordered(admission)) = before_publish()? {
                let control = self.anchor.ordered_wire_control().ok_or(RecoveryError::Hold)?;
                if admission.cut.head() != Some(head)
                    || !control.unchanged(&admission.cut).map_err(|_| RecoveryError::Hold)?
                {
                    return Err(RecoveryError::Hold);
                }
            }
            confirm_authority_record(locked.0, &self.anchor, head, &before, checkpoint)?;
        }
        self.independent_checkpoint = Some(independent);
        Ok(reply)
    }

    pub fn execute(
        &mut self,
        _entry: Entry,
        auth: &Credentials<'_, S>,
        request: Request<'_>,
        endorsement: Option<&Credentials<'_, S>>,
    ) -> Result<ActionReply, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| product.execute_durable(auth, request, endorsement))?
            .map_err(RecoveryError::Endpoint)
    }

    pub fn receipt(
        &mut self,
        _entry: Entry,
        auth: &Credentials<'_, S>,
        request: Request<'_>,
    ) -> Result<Option<Receipt>, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| product.receipt_durable(auth, request))?
            .map_err(RecoveryError::Endpoint)
    }

    pub fn read(
        &mut self,
        entry: Entry,
        auth: &Credentials<'_, S>,
        target: u64,
        request: ReadRequest,
        cache: Option<&CacheClaim>,
    ) -> Result<Observation, RecoveryError> {
        self.require_native_client()?;
        let cache = cache.map(CacheEntry::from_claim);
        self.transact(|product| product.read(entry, auth, target, request, cache.as_ref()))?
            .map_err(RecoveryError::Endpoint)
    }

    // Native client operations and generic maintenance require an unordered profile.
    fn require_native_client(&self) -> Result<(), RecoveryError> {
        if self.anchor.ordered_wire_control().is_some()
            || self.security.ordered_revocation_profile().is_some()
        {
            return Err(RecoveryError::Endpoint(EndpointError::Rejected));
        }
        Ok(())
    }

    pub fn handover(
        &mut self,
        maintenance: &S::MaintenanceToken,
        proposal: &Handover,
        previous: Consent<'_, S>,
        successor: Consent<'_, S>,
    ) -> Result<bool, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| {
            product
                .maintenance(maintenance)
                .map(|mut host| host.handover(proposal, previous, successor))
                .ok_or(RecoveryError::Endpoint(EndpointError::Rejected))
        })?
    }

    pub fn install_epoch(
        &mut self,
        maintenance: &S::MaintenanceToken,
        epoch: u64,
        contexts: Vec<EndpointContext>,
        sessions: BTreeMap<SessionId, SessionBinding>,
    ) -> Result<bool, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| {
            product
                .maintenance(maintenance)
                .map(|mut host| host.install_epoch(epoch, contexts, sessions))
                .ok_or(RecoveryError::Endpoint(EndpointError::Rejected))
        })?
    }

    pub fn observe_time(
        &mut self,
        maintenance: &S::MaintenanceToken,
        session: SessionId,
        expected: CommitCut,
        now: u64,
        signature: &S::Signature,
    ) -> Result<bool, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| {
            product
                .maintenance(maintenance)
                .map(|mut host| host.observe_time(session, expected, now, signature))
                .ok_or(RecoveryError::Endpoint(EndpointError::Rejected))
        })?
    }

    pub fn enqueue_secondary(
        &mut self,
        maintenance: &S::MaintenanceToken,
        origin: OriginKey,
    ) -> Result<Option<SettlementKey>, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| {
            product
                .maintenance(maintenance)
                .map(|mut host| host.enqueue_secondary(origin))
                .ok_or(RecoveryError::Endpoint(EndpointError::Rejected))
        })?
    }

    pub fn dispatch_secondary(
        &mut self,
        maintenance: &S::MaintenanceToken,
        key: SettlementKey,
    ) -> Result<Option<SecondaryJob>, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| {
            product
                .maintenance(maintenance)
                .map(|mut host| host.dispatch_secondary(key))
                .ok_or(RecoveryError::Endpoint(EndpointError::Rejected))
        })?
    }

    pub fn fail_secondary(
        &mut self,
        maintenance: &S::MaintenanceToken,
        key: SettlementKey,
    ) -> Result<bool, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| {
            product
                .maintenance(maintenance)
                .map(|mut host| host.fail_secondary(key))
                .ok_or(RecoveryError::Endpoint(EndpointError::Rejected))
        })?
    }

    pub fn acknowledge_secondary(
        &mut self,
        maintenance: &S::MaintenanceToken,
        ack: Acknowledgement,
        signature: &S::Signature,
    ) -> Result<bool, RecoveryError> {
        self.require_native_client()?;
        self.transact(|product| {
            product
                .maintenance(maintenance)
                .map(|mut host| host.acknowledge_secondary(ack, signature))
                .ok_or(RecoveryError::Endpoint(EndpointError::Rejected))
        })?
    }

    pub fn source_probe(
        &mut self,
        maintenance: &S::MaintenanceToken,
        origin: OriginKey,
        evidence: Option<TerminalEvidence>,
    ) -> Result<SourceAction, RecoveryError> {
        self.transact(|product| source_probe_at(product, maintenance, origin, evidence))?
    }
}

fn source_probe_at<S: Security>(
    product: &mut ProductAuthority<S>,
    maintenance: &S::MaintenanceToken,
    origin: OriginKey,
    evidence: Option<TerminalEvidence>,
) -> Result<SourceAction, RecoveryError> {
    if product.maintenance(maintenance).is_none() {
        return Err(RecoveryError::Endpoint(EndpointError::Rejected));
    }
    let authority = &product.reads.authority;
    let Some(binding) = authority.state.primary.ledger.open_source_binding(origin) else {
        return Ok(SourceAction::None);
    };
    if !authority.connected {
        return Ok(SourceAction::Hold(binding));
    }
    match evidence {
        None => Ok(SourceAction::Query(binding)),
        Some(evidence)
            if evidence.binding == binding
                && product.security.verify_recovery_evidence(evidence) =>
        {
            match evidence.kind {
                TerminalKind::Confirmed => Ok(SourceAction::ConsiderConfirmed(binding)),
                TerminalKind::Reversed => Ok(SourceAction::ConsiderReversed(binding)),
            }
        }
        Some(_) => Ok(SourceAction::Hold(binding)),
    }
}

#[cfg(test)]
mod vector_tests;

#[allow(unexpected_cfgs)]
mod recovery_bounds;
