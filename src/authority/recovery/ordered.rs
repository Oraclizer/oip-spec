//! Ordered admission and publication on a single authenticated control value.

use super::{AnchorHead, AuthenticatedHead, CheckpointFence, HeadError, PublicationRefusal, RecoveryProfile, ordered_map};
use crate::wire::{admission::TransportKey, codec::{WireError, decode_packet}};
use crate::{CallId, OriginKey, Principal};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod etcd;
pub mod witness;

/// A linearizable read of the authority's exact control value.
#[derive(Clone, Eq, PartialEq)]
pub struct ControlValue {
    pub revision: u64,
    pub bytes: Vec<u8>,
}

/// The authority service exclusively owns write access to this store.
/// Compare both revision and exact bytes in the same durable transaction.
/// Errors can be ambiguous. A restored store must be fenced independently.
pub trait ControlStore {
    type AttachmentProof;
    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &Self::AttachmentProof,
    ) -> bool;
    fn current(&self) -> Result<ControlValue, HeadError>;
    fn replace(&self, expected: &ControlValue, candidate: &[u8]) -> Result<bool, HeadError>;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(super) struct DebitWork {
    pub origin: OriginKey,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DebitRequest {
    pub(super) id: CallId,
    pub(super) work: DebitWork,
    pub(super) packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum Disposition {
    Pending,
    Published,
    Rejected,
    Refused,
}

#[derive(Clone, Serialize, Deserialize)]
struct Decision {
    request: DebitRequest,
    disposition: Disposition,
}

#[derive(Clone, Serialize, Deserialize)]
struct State {
    profile: RecoveryProfile,
    head: Option<AnchorHead>,
    writer_generation: u64,
    revoked: BTreeSet<Principal>,
    cancelled: BTreeSet<TransportKey>,
    #[serde(with = "ordered_map")]
    decisions: BTreeMap<CallId, Decision>,
    #[serde(with = "ordered_map")]
    latest: BTreeMap<DebitWork, CallId>,
}

impl State {
    fn encode(&self) -> Result<Vec<u8>, HeadError> {
        serde_json::to_vec(self).map_err(|_| HeadError)
    }
}

/// Opaque observation used by the ordered wire consumer.
#[derive(Clone)]
pub struct OrderedCut {
    stored: ControlValue,
    state: State,
}

impl OrderedCut {
    pub(super) fn head(&self) -> Option<AnchorHead> {
        self.state.head
    }

    pub(super) fn has_debit(&self, id: CallId) -> bool {
        self.state.decisions.contains_key(&id)
    }

    pub(super) fn authorize(
        &self,
        principal: Principal,
        transport: TransportKey,
        resolve: bool,
    ) -> Result<(), WireError> {
        self.authorize_principal(principal)?;
        if !resolve && self.state.cancelled.contains(&transport) {
            return Err(WireError::Cancelled);
        }
        Ok(())
    }

    pub(super) fn authorize_principal(&self, principal: Principal) -> Result<(), WireError> {
        if self.state.revoked.contains(&principal) {
            return Err(WireError::InvalidSource);
        }
        Ok(())
    }

    pub(super) fn check_pending_transport(&self, key: TransportKey, packet: &[u8]) -> Result<(), WireError> {
        for decision in self.state.decisions.values() {
            let saved = &decision.request.packet;
            if decision.disposition != Disposition::Pending || saved == packet {
                continue;
            }
            let saved = decode_packet(saved, saved.len()).map_err(|_| super::wire::hold())?;
            let saved_key = TransportKey::for_core(saved.core()).map_err(|_| super::wire::hold())?;
            if saved_key == key {
                return Err(WireError::ReplayConflict);
            }
        }
        Ok(())
    }

    pub(super) fn disposition(&self, request: &DebitRequest) -> Result<Option<Disposition>, WireError> {
        match self.state.decisions.get(&request.id) {
            None => Ok(None),
            Some(saved) if saved.request == *request => Ok(Some(saved.disposition)),
            Some(_) => Err(WireError::ReplayConflict),
        }
    }

    pub(super) fn check_debit(&self, request: &DebitRequest) -> Result<Option<Disposition>, WireError> {
        let disposition = self.disposition(request)?;
        if disposition == Some(Disposition::Rejected) {
            return Err(WireError::ProductRejected);
        }
        if disposition.is_none() {
            if let Some(previous) = self.state.latest.get(&request.work) {
                let saved = self.state.decisions.get(previous).ok_or_else(super::wire::hold)?;
                if previous.namespace != request.id.namespace
                    || !matches!(saved.disposition, Disposition::Rejected | Disposition::Refused)
                {
                    return Err(WireError::RequestUnresolved);
                }
            }
        }
        Ok(disposition)
    }
}

pub(super) enum DebitPublication {
    Applied(CallId),
    Refused(DebitRequest),
}

pub struct OrderedPublication {
    pub(super) cut: OrderedCut,
    pub(super) debit: Option<DebitPublication>,
}

/// Authority-only operations. The application receives these through its
/// authenticated head, so an ordinary or strict CAS cannot publish a wire effect.
pub trait WireControl {
    fn observe(&self) -> Result<OrderedCut, HeadError>;
    fn unchanged(&self, cut: &OrderedCut) -> Result<bool, HeadError>;

    /// Bind authenticated maintenance to the exact independent selection.
    fn selection_binding(&self, _cut: &OrderedCut) -> Result<[u8; 32], HeadError> {
        Err(HeadError)
    }
    #[doc(hidden)]
    fn reserve_debit(
        &self,
        cut: OrderedCut,
        request: DebitRequest,
    ) -> Result<OrderedCut, WireError>;
    #[doc(hidden)]
    fn reject_debit(&self, cut: OrderedCut, request: DebitRequest) -> Result<(), WireError>;
    fn publish(&self, candidate: AnchorHead, admission: &OrderedPublication) -> Result<bool, HeadError>;

    /// Select an independently archived record. Existing direct providers
    /// never enter this path.
    fn publish_independent(
        &self,
        _file: &mut std::fs::File,
        _candidate: AnchorHead,
        _admission: &OrderedPublication,
        _checkpoint: CheckpointFence,
    ) -> Result<Result<(), PublicationRefusal>, HeadError> {
        Ok(Err(PublicationRefusal::Unsupported))
    }
}

/// The control service's authenticated head and wire policy share one store.
/// The host exposes revocation, cancellation and writer rotation only to its
/// authenticated control plane. Do not expose the store or its credentials.
pub struct OrderedHead<B> {
    store: B,
    profile: RecoveryProfile,
    writer_generation: u64,
}

impl<B: ControlStore> OrderedHead<B> {
    /// Bootstrap bytes for a previously authorized head. An operator must
    /// provision a new control key and supply that head's exact descriptor.
    pub fn initial_value(
        profile: RecoveryProfile,
        head: Option<AnchorHead>,
        writer_generation: u64,
    ) -> Result<Vec<u8>, HeadError> {
        if head.is_some_and(|head| head.profile != profile) {
            return Err(HeadError);
        }
        State {
            profile,
            head,
            writer_generation,
            revoked: BTreeSet::new(),
            cancelled: BTreeSet::new(),
            decisions: BTreeMap::new(),
            latest: BTreeMap::new(),
        }
        .encode()
    }

    pub fn new(store: B, profile: RecoveryProfile, writer_generation: u64) -> Self {
        Self { store, profile, writer_generation }
    }

    pub fn revoke(&self, principal: Principal) -> Result<bool, HeadError> {
        self.update(|state| { state.revoked.insert(principal); })
    }

    pub fn cancel(&self, transport: TransportKey) -> Result<bool, HeadError> {
        self.update(|state| { state.cancelled.insert(transport); })
    }

    pub fn rotate_writer(&self, next: u64) -> Result<bool, HeadError> {
        if next <= self.writer_generation {
            return Err(HeadError);
        }
        self.update(|state| state.writer_generation = next)
    }

    fn update(&self, change: impl FnOnce(&mut State)) -> Result<bool, HeadError> {
        let mut cut = self.observe()?;
        change(&mut cut.state);
        self.store.replace(&cut.stored, &cut.state.encode()?)
    }

    fn replace_head(state: &mut State, candidate: AnchorHead) -> bool {
        let next = state.head.map_or(Some(0), |head| head.sequence.checked_add(1));
        if candidate.profile != state.profile || Some(candidate.sequence) != next {
            return false;
        }
        state.head = Some(candidate);
        true
    }
}

impl<B: ControlStore> AuthenticatedHead for OrderedHead<B> {
    type AttachmentProof = B::AttachmentProof;

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &Self::AttachmentProof,
    ) -> bool {
        self.profile == profile && self.store.verify_attachment(profile, connected, proof)
    }

    fn current(&self) -> Result<Option<AnchorHead>, HeadError> {
        Ok(self.observe()?.state.head)
    }

    fn compare_and_set(
        &self,
        expected: Option<AnchorHead>,
        candidate: AnchorHead,
    ) -> Result<bool, HeadError> {
        let mut cut = self.observe()?;
        if cut.state.head != expected || !Self::replace_head(&mut cut.state, candidate) {
            return Ok(false);
        }
        self.store.replace(&cut.stored, &cut.state.encode()?)
    }

    fn ordered_wire_control(&self) -> Option<&dyn WireControl> {
        Some(self)
    }
}

impl<B: ControlStore> WireControl for OrderedHead<B> {
    fn observe(&self) -> Result<OrderedCut, HeadError> {
        let stored = self.store.current()?;
        let state: State = serde_json::from_slice(&stored.bytes).map_err(|_| HeadError)?;
        if state.profile != self.profile || state.writer_generation != self.writer_generation
            || state.encode()? != stored.bytes
        {
            return Err(HeadError);
        }
        Ok(OrderedCut { stored, state })
    }

    fn unchanged(&self, cut: &OrderedCut) -> Result<bool, HeadError> {
        Ok(self.store.current()? == cut.stored)
    }

    fn reserve_debit(&self, mut cut: OrderedCut, request: DebitRequest) -> Result<OrderedCut, WireError> {
        if cut.check_debit(&request)?.is_some() {
            return Ok(cut);
        }
        cut.state.latest.insert(request.work, request.id);
        cut.state.decisions.insert(request.id, Decision { request, disposition: Disposition::Pending });
        let bytes = cut.state.encode().map_err(|_| super::wire::hold())?;
        if !self.store.replace(&cut.stored, &bytes).map_err(|_| super::wire::hold())? {
            return Err(super::wire::hold());
        }
        let current = self.observe().map_err(|_| super::wire::hold())?;
        if current.stored.bytes != bytes {
            return Err(super::wire::hold());
        }
        Ok(current)
    }

    fn reject_debit(&self, mut cut: OrderedCut, request: DebitRequest) -> Result<(), WireError> {
        match cut.disposition(&request)? {
            Some(Disposition::Rejected) => return Ok(()),
            Some(Disposition::Pending) => {}
            None if !cut.state.latest.contains_key(&request.work) => {
                cut.state.latest.insert(request.work, request.id);
            }
            _ => return Err(WireError::RequestUnresolved),
        }
        cut.state.decisions.insert(request.id, Decision { request, disposition: Disposition::Rejected });
        let bytes = cut.state.encode().map_err(|_| super::wire::hold())?;
        if !self.store.replace(&cut.stored, &bytes).map_err(|_| super::wire::hold())? {
            return Err(super::wire::hold());
        }
        Ok(())
    }

    fn publish(&self, candidate: AnchorHead, admission: &OrderedPublication) -> Result<bool, HeadError> {
        let Some(state) = proposed_publication::<B>(candidate, admission)? else {
            return Ok(false);
        };
        self.store.replace(&admission.cut.stored, &state.encode()?)
    }
}

fn proposed_publication<B: ControlStore>(
    candidate: AnchorHead,
    admission: &OrderedPublication,
) -> Result<Option<State>, HeadError> {
    let mut state = admission.cut.state.clone();
    if !OrderedHead::<B>::replace_head(&mut state, candidate) {
        return Ok(None);
    }
    match &admission.debit {
        Some(DebitPublication::Applied(id)) => {
            let saved = state.decisions.get_mut(id).ok_or(HeadError)?;
            if saved.disposition != Disposition::Pending {
                return Ok(None);
            }
            saved.disposition = Disposition::Published;
        }
        Some(DebitPublication::Refused(request)) => {
            state.decisions.insert(request.id, Decision {
                request: request.clone(),
                disposition: Disposition::Refused,
            });
        }
        None => {}
    }
    Ok(Some(state))
}
