//! Ordered authority with an independently archived final selection.

use super::etcd::EtcdTransport;
use super::{
    AnchorHead, AuthenticatedHead, CheckpointFence, ControlStore, ControlValue, DebitRequest,
    HeadError, OrderedCut, OrderedHead, OrderedPublication, PublicationRefusal, RecoveryProfile,
    State, WireControl, proposed_publication,
};
use crate::Principal;
use crate::authority::recovery::archive::{ArchiveRef, JournalArchive};
use crate::authority::recovery::{CheckpointState, RecoveryError, exact_image, validate_lineage};
use crate::wire::{admission::TransportKey, codec::WireError};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::{Path, PathBuf};

mod bootstrap;
pub use bootstrap::WitnessGenesis;
mod ed25519;
pub use ed25519::{Ed25519WitnessAuthority, WitnessAttachmentContext, WitnessAttachmentIssuer};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessWriter {
    pub generation: u64,
    pub identity: [u8; 32],
}

impl WitnessWriter {
    fn valid(self) -> bool {
        self.generation > 0 && self.identity != [0; 32]
    }
}

/// The trusted host supplies independent attachment and repair verification.
/// The provider has no default acceptance policy.
pub trait WitnessAttachmentVerifier {
    type Proof;

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        authority: [u8; 32],
        witness: [u8; 32],
        writer: WitnessWriter,
        connected: bool,
        proof: &Self::Proof,
    ) -> bool;

    fn verify_genesis(&self, cut: &WitnessGenesis, proof: &Self::Proof, signature: &[u8]) -> bool;

    fn verify_repair(&self, cut: &WitnessRepair, proof: &Self::Proof, signature: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Mark {
    revision: u64,
    bytes_sha256: [u8; 32],
}

impl Mark {
    fn of(value: &ControlValue) -> Self {
        Self {
            revision: value.revision,
            bytes_sha256: Sha256::digest(&value.bytes).into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Selection {
    profile: RecoveryProfile,
    authority: [u8; 32],
    witness: [u8; 32],
    control: Vec<u8>,
    archive: ArchiveRef,
    floor: AnchorHead,
    writer: WitnessWriter,
    previous: Option<Mark>,
    repair_nonce: [u8; 32],
    authorization: Option<[u8; 32]>,
}

struct Selected {
    raw: ControlValue,
    envelope: Selection,
    state: State,
}

impl Selected {
    fn mark(&self) -> Mark {
        Mark::of(&self.raw)
    }

    fn control(&self) -> ControlValue {
        ControlValue {
            revision: self.raw.revision,
            bytes: self.envelope.control.clone(),
        }
    }

    fn checkpoint(&self) -> CheckpointFence {
        CheckpointFence {
            head: Some(self.envelope.floor),
            protected_head: Some(self.envelope.archive.head),
            writer_generation: self.envelope.writer.generation,
            writer_id: self.envelope.writer.identity,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AuthorityPrepare {
    profile: RecoveryProfile,
    base: Mark,
    /// Exact proposed witness envelopes. These are never public results.
    preparations: Vec<Vec<u8>>,
}

impl AuthorityPrepare {
    fn agrees(&self, selected: &Selected) -> bool {
        self.base == selected.mark()
            || (Some(self.base) == selected.envelope.previous
                && self.preparations.contains(&selected.raw.bytes))
    }
}

/// Exact repair authorization for one independent witness and one restored
/// authority. The destination path and prospective writer are signed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WitnessRepair {
    profile: RecoveryProfile,
    authority: [u8; 32],
    witness: [u8; 32],
    restored: Mark,
    selected: Mark,
    archive: ArchiveRef,
    writer: WitnessWriter,
    repair_nonce: [u8; 32],
    connected: bool,
    destination: PathBuf,
}

impl WitnessRepair {
    pub fn authorization_message(&self) -> Result<Vec<u8>, HeadError> {
        let mut bytes = b"oip/independent-archive-repair/v1\0".to_vec();
        bytes.extend(encode(self)?);
        Ok(bytes)
    }
}

pub struct WitnessHead<A> {
    ordered: OrderedHead<WitnessStore<A>>,
}

struct WitnessStore<A> {
    authority: EtcdTransport,
    witness: EtcdTransport,
    archive: JournalArchive,
    profile: RecoveryProfile,
    writer: WitnessWriter,
    max_preparations: usize,
    attachment: A,
}

impl<A: WitnessAttachmentVerifier> WitnessHead<A> {
    pub fn new(
        authority: EtcdTransport,
        witness: EtcdTransport,
        archive: JournalArchive,
        profile: RecoveryProfile,
        writer: WitnessWriter,
        max_preparations: usize,
        attachment: A,
    ) -> Result<Self, HeadError> {
        if !authority.independent_of(&witness) || !writer.valid() || max_preparations == 0 {
            return Err(HeadError);
        }
        let store = WitnessStore {
            authority,
            witness,
            archive,
            profile,
            writer,
            max_preparations,
            attachment,
        };
        Ok(Self {
            ordered: OrderedHead::new(store, profile, writer.generation),
        })
    }

    /// Return the exact public context that the configured attachment issuer
    /// must sign. It carries no storage credentials or control handle.
    pub fn attachment_context(&self, connected: bool) -> WitnessAttachmentContext {
        let store = &self.ordered.store;
        WitnessAttachmentContext {
            profile: store.profile,
            authority: store.authority.attachment_binding(),
            witness: store.witness.attachment_binding(),
            writer: store.writer,
            connected,
        }
    }

    pub fn revoke(&self, principal: Principal) -> Result<bool, HeadError> {
        self.ordered.revoke(principal)
    }

    pub fn cancel(&self, transport: TransportKey) -> Result<bool, HeadError> {
        self.ordered.cancel(transport)
    }

    pub fn rotate_writer(&self, successor: WitnessWriter) -> Result<bool, HeadError> {
        let store = &self.ordered.store;
        let previous = store.current_selection()?;
        if !successor.valid() || successor.generation <= store.writer.generation {
            return Err(HeadError);
        }
        let mut state = previous.state.clone();
        state.writer_generation = successor.generation;
        let candidate = store.propose(
            &previous,
            state.encode()?,
            previous.envelope.archive,
            successor,
        );
        store.select(&previous, &candidate)
    }

    /// Read a repair cut through the prospective new authority configuration.
    /// This operation does not activate either the endpoint or its writer.
    pub fn repair_cut(
        &self,
        destination: &Path,
        connected: bool,
        proof: &A::Proof,
    ) -> Result<WitnessRepair, RecoveryError> {
        let store = &self.ordered.store;
        if !store.verify_attachment(store.profile, connected, proof) {
            return Err(RecoveryError::AttachmentRejected);
        }
        let selected = store.read_witness().map_err(hold)?;
        if store.writer.generation <= selected.envelope.writer.generation {
            return Err(RecoveryError::Hold);
        }
        let restored = store.authority.current().map_err(hold)?;
        Ok(WitnessRepair {
            profile: store.profile,
            authority: store.authority.attachment_binding(),
            witness: store.witness.attachment_binding(),
            restored: Mark::of(&restored),
            selected: selected.mark(),
            archive: selected.envelope.archive,
            writer: store.writer,
            repair_nonce: selected.envelope.repair_nonce,
            connected,
            destination: destination.to_path_buf(),
        })
    }

    /// Consume one exact repair authorization and activate a fresh writer
    /// using the already selected archive. Restoration never replaces a path.
    pub fn repair_from_archive(
        &self,
        cut: &WitnessRepair,
        proof: &A::Proof,
        signature: &[u8],
    ) -> Result<(), RecoveryError> {
        let store = &self.ordered.store;
        if cut.profile != store.profile
            || cut.authority != store.authority.attachment_binding()
            || cut.witness != store.witness.attachment_binding()
            || cut.writer != store.writer
            || !store.verify_attachment(store.profile, cut.connected, proof)
            || !store.attachment.verify_repair(cut, proof, signature)
        {
            return Err(RecoveryError::AttachmentRejected);
        }
        let authorization = Sha256::digest(cut.authorization_message().map_err(hold)?).into();
        let selected = store.read_witness().map_err(hold)?;
        if selected.envelope.authorization == Some(authorization)
            && selected.envelope.previous == Some(cut.selected)
            && selected.envelope.writer == cut.writer
            && selected.envelope.archive == cut.archive
            && selected.envelope.authority == cut.authority
        {
            return store.archive.verify_restored(cut.archive, &cut.destination);
        }
        if selected.mark() != cut.selected
            || selected.envelope.repair_nonce != cut.repair_nonce
            || selected.envelope.archive != cut.archive
            || cut.writer.generation <= selected.envelope.writer.generation
        {
            return Err(RecoveryError::Hold);
        }
        let restored = store.authority.current().map_err(hold)?;
        let mut state = selected.state.clone();
        state.writer_generation = cut.writer.generation;
        let mut candidate = store.propose(
            &selected,
            state.encode().map_err(hold)?,
            cut.archive,
            cut.writer,
        );
        candidate.authorization = Some(authorization);
        let bytes = encode(&candidate).map_err(hold)?;
        let prepare = AuthorityPrepare {
            profile: store.profile,
            base: cut.selected,
            preparations: vec![bytes.clone()],
        };
        if Mark::of(&restored) != cut.restored
            && restored.bytes != encode(&prepare).map_err(hold)?
        {
            return Err(RecoveryError::Hold);
        }
        match store.archive.restore(cut.archive, &cut.destination) {
            Ok(()) => {}
            Err(RecoveryError::AlreadyInitialized) => {
                store
                    .archive
                    .verify_restored(cut.archive, &cut.destination)?;
            }
            Err(error) => return Err(error),
        }
        store
            .install_exact_prepare(&restored, cut.restored, &prepare)
            .map_err(hold)?;
        // A lost selection reply is reconciled by the exact witness,
        // never by issuing a second CAS with a fresh expected value.
        let _ = store.witness.replace(&selected.raw, &bytes);
        if store.read_witness().map_err(hold)?.raw.bytes != bytes {
            return Err(RecoveryError::Hold);
        }
        store.archive.verify_restored(cut.archive, &cut.destination)
    }
}

impl<A: WitnessAttachmentVerifier> WitnessStore<A> {
    fn read_witness(&self) -> Result<Selected, HeadError> {
        let raw = self.witness.current()?;
        let envelope: Selection = decode(&raw.bytes)?;
        let state: State = decode(&envelope.control)?;
        if envelope.profile != self.profile
            || state.profile != self.profile
            || envelope.witness != self.witness.attachment_binding()
            || !envelope.writer.valid()
            || state.writer_generation != envelope.writer.generation
            || state.head != Some(envelope.archive.head)
            || envelope.repair_nonce == [0; 32]
            || envelope
                .previous
                .is_some_and(|parent| parent.revision == 0 || parent.revision >= raw.revision)
        {
            return Err(HeadError);
        }
        let mut archive = self
            .archive
            .open_verified(envelope.archive)
            .map_err(|_| HeadError)?;
        let record = exact_image(&mut archive, envelope.archive.head).map_err(|_| HeadError)?;
        validate_lineage(&mut archive, envelope.archive.head, &record, envelope.floor)
            .map_err(|_| HeadError)?;
        Ok(Selected {
            raw,
            envelope,
            state,
        })
    }

    fn selected_for_writer(&self) -> Result<Selected, HeadError> {
        let selected = self.read_witness()?;
        if selected.envelope.writer != self.writer
            || selected.envelope.authority != self.authority.attachment_binding()
        {
            return Err(HeadError);
        }
        Ok(selected)
    }

    fn authority_for(
        &self,
        selected: &Selected,
    ) -> Result<(ControlValue, AuthorityPrepare), HeadError> {
        let raw = self.authority.current()?;
        let prepare: AuthorityPrepare = decode(&raw.bytes)?;
        if prepare.profile != self.profile
            || prepare.preparations.len() > self.max_preparations
            || !prepare.agrees(selected)
        {
            return Err(HeadError);
        }
        Ok((raw, prepare))
    }

    fn install_exact_prepare(
        &self,
        observed: &ControlValue,
        before: Mark,
        prepare: &AuthorityPrepare,
    ) -> Result<(), HeadError> {
        let bytes = encode(prepare)?;
        if observed.bytes == bytes {
            return Ok(());
        }
        if Mark::of(observed) != before {
            return Err(HeadError);
        }
        if self.authority.replace(observed, &bytes) == Ok(true)
            || self.authority.current()?.bytes == bytes
        {
            Ok(())
        } else {
            Err(HeadError)
        }
    }

    fn current_selection(&self) -> Result<Selected, HeadError> {
        let selected = self.selected_for_writer()?;
        self.authority_for(&selected)?;
        Ok(selected)
    }

    fn propose(
        &self,
        previous: &Selected,
        control: Vec<u8>,
        archive: ArchiveRef,
        writer: WitnessWriter,
    ) -> Selection {
        let mark = previous.mark();
        let authority = self.authority.attachment_binding();
        let witness = self.witness.attachment_binding();
        let mut hash = Sha256::new();
        hash.update(b"oip/witness-repair-nonce/v1\0");
        hash.update(mark.revision.to_be_bytes());
        hash.update(mark.bytes_sha256);
        hash.update(authority);
        hash.update(witness);
        hash.update(archive.prefix_sha256);
        hash.update(writer.identity);
        hash.update(writer.generation.to_be_bytes());
        hash.update(Sha256::digest(&control));
        Selection {
            profile: self.profile,
            authority,
            witness,
            control,
            archive,
            floor: previous.envelope.floor,
            writer,
            previous: Some(mark),
            repair_nonce: hash.finalize().into(),
            authorization: None,
        }
    }

    fn select(&self, previous: &Selected, candidate: &Selection) -> Result<bool, HeadError> {
        let bytes = self.prepare_selection(previous, candidate)?;
        self.witness.replace(&previous.raw, &bytes)
    }

    fn prepare_selection(
        &self,
        previous: &Selected,
        candidate: &Selection,
    ) -> Result<Vec<u8>, HeadError> {
        let (authority, mut prepare) = self.authority_for(previous)?;
        let base = previous.mark();
        if prepare.base != base {
            // Prior preparations are discarded only after their exact selected
            // successor has been authenticated above.
            prepare = AuthorityPrepare {
                profile: self.profile,
                base,
                preparations: Vec::new(),
            };
        }
        let bytes = encode(candidate)?;
        if !prepare.preparations.contains(&bytes) {
            if prepare.preparations.len() == self.max_preparations {
                return Err(HeadError);
            }
            prepare.preparations.push(bytes.clone());
            if self.authority.replace(&authority, &encode(&prepare)?) != Ok(true) {
                let (_, readback) = self.authority_for(previous)?;
                if readback.base != base || !readback.preparations.contains(&bytes) {
                    return Err(HeadError);
                }
            }
        }
        Ok(bytes)
    }
}

impl<A: WitnessAttachmentVerifier> ControlStore for WitnessStore<A> {
    type AttachmentProof = A::Proof;

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &A::Proof,
    ) -> bool {
        profile == self.profile
            && self.attachment.verify_attachment(
                profile,
                self.authority.attachment_binding(),
                self.witness.attachment_binding(),
                self.writer,
                connected,
                proof,
            )
    }

    fn current(&self) -> Result<ControlValue, HeadError> {
        Ok(self.current_selection()?.control())
    }

    fn replace(&self, expected: &ControlValue, candidate: &[u8]) -> Result<bool, HeadError> {
        let previous = self.current_selection()?;
        if previous.control() != *expected {
            return Ok(false);
        }
        let state: State = decode(candidate)?;
        if state.profile != self.profile
            || state.head != previous.state.head
            || state.writer_generation != self.writer.generation
        {
            return Err(HeadError);
        }
        let proposal = self.propose(
            &previous,
            candidate.to_vec(),
            previous.envelope.archive,
            self.writer,
        );
        self.select(&previous, &proposal)
    }
}

impl<A: WitnessAttachmentVerifier> AuthenticatedHead for WitnessHead<A> {
    type AttachmentProof = A::Proof;

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &A::Proof,
    ) -> bool {
        self.ordered.verify_attachment(profile, connected, proof)
    }

    fn current(&self) -> Result<Option<AnchorHead>, HeadError> {
        self.ordered.current()
    }

    fn ordered_wire_control(&self) -> Option<&dyn WireControl> {
        Some(self)
    }

    fn attachment_requires_independent_checkpoint(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &A::Proof,
    ) -> Result<bool, HeadError> {
        self.verify_attachment(profile, connected, proof)
            .then_some(true)
            .ok_or(HeadError)
    }

    fn checkpoint_state(&self) -> Result<CheckpointState, HeadError> {
        let selected = self.ordered.store.selected_for_writer()?;
        Ok(CheckpointState::Independent(selected.checkpoint()))
    }

    fn checkpoint_readback(&self) -> Result<(Option<AnchorHead>, CheckpointFence), HeadError> {
        // This path confirms only the selected witness and immutable archive.
        // A missing authority mirror still blocks fresh admissions.
        let selected = self.ordered.store.selected_for_writer()?;
        Ok((selected.state.head, selected.checkpoint()))
    }

    fn verify_independent_journal(
        &self,
        file: &mut File,
        head: AnchorHead,
    ) -> Result<(), HeadError> {
        let store = &self.ordered.store;
        let selected = store.selected_for_writer()?;
        if selected.envelope.archive.head != head {
            return Err(HeadError);
        }
        store
            .archive
            .verify_journal_prefix(file, selected.envelope.archive)
            .map_err(|_| HeadError)
    }

    fn compare_and_set(&self, _: Option<AnchorHead>, _: AnchorHead) -> Result<bool, HeadError> {
        Err(HeadError)
    }
}

impl<A: WitnessAttachmentVerifier> WireControl for WitnessHead<A> {
    fn observe(&self) -> Result<OrderedCut, HeadError> {
        self.ordered.observe()
    }

    fn unchanged(&self, cut: &OrderedCut) -> Result<bool, HeadError> {
        self.ordered.unchanged(cut)
    }

    fn selection_binding(&self, cut: &OrderedCut) -> Result<[u8; 32], HeadError> {
        let selected = self.ordered.store.current_selection()?;
        if selected.control() != cut.stored {
            return Err(HeadError);
        }
        let mark = selected.mark();
        let mut hash = Sha256::new();
        hash.update(b"oip/independent-selection-binding/v1\0");
        hash.update(mark.revision.to_be_bytes());
        hash.update(mark.bytes_sha256);
        Ok(hash.finalize().into())
    }

    fn reserve_debit(
        &self,
        cut: OrderedCut,
        request: DebitRequest,
    ) -> Result<OrderedCut, WireError> {
        self.ordered.reserve_debit(cut, request)
    }

    fn reject_debit(&self, cut: OrderedCut, request: DebitRequest) -> Result<(), WireError> {
        self.ordered.reject_debit(cut, request)
    }

    fn publish(&self, _: AnchorHead, _: &OrderedPublication) -> Result<bool, HeadError> {
        Err(HeadError)
    }

    fn publish_independent(
        &self,
        file: &mut File,
        candidate: AnchorHead,
        admission: &OrderedPublication,
        checkpoint: CheckpointFence,
    ) -> Result<Result<(), PublicationRefusal>, HeadError> {
        let store = &self.ordered.store;
        let previous = store.current_selection()?;
        if previous.control() != admission.cut.stored || previous.checkpoint() != checkpoint {
            return Ok(Err(PublicationRefusal::CheckpointChanged));
        }
        let Some(state) = proposed_publication::<WitnessStore<A>>(candidate, admission)? else {
            return Ok(Err(PublicationRefusal::CheckpointChanged));
        };
        let archive = store
            .archive
            .retain(file, candidate)
            .map_err(|_| HeadError)?;
        let mut staged = store
            .archive
            .open_verified(archive)
            .map_err(|_| HeadError)?;
        store
            .archive
            .verify_journal_prefix(&mut staged, previous.envelope.archive)
            .map_err(|_| HeadError)?;
        let proposal = store.propose(&previous, state.encode()?, archive, store.writer);
        store.select(&previous, &proposal).map(|selected| {
            if selected {
                Ok(())
            } else {
                Err(PublicationRefusal::CheckpointChanged)
            }
        })
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, HeadError> {
    serde_json::to_vec(value).map_err(|_| HeadError)
}

fn decode<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T, HeadError> {
    let value: T = serde_json::from_slice(raw).map_err(|_| HeadError)?;
    if encode(&value)? != raw {
        return Err(HeadError);
    }
    Ok(value)
}

fn hold(_: HeadError) -> RecoveryError {
    RecoveryError::Hold
}

#[cfg(all(test, target_os = "linux"))]
pub(in crate::authority::recovery) mod vector_tests;
