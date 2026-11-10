//! Exact synchronization calls and the receiver's committed stream state.

use super::identity::EndpointError;
use super::{Authority, CommitRef, Snapshot, recovery::ordered_map};
use crate::lock_finality::EndpointId;
use crate::wire::admission::TransportKey;
use crate::wire::codec::decode_core;
use crate::wire::generated::Core;
use crate::wire::operands::{Operands, SyncMode, decode};
use crate::{AssetId, CallId, CommitCut, OriginKey, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Stream {
    pub asset: AssetId,
    pub origin_domain: EndpointId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Commitment {
    pub commitment: [u8; 32],
    pub source_position: u64,
    pub origin_epoch: u64,
    pub origin_event: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    Synced(CommitRef),
    Busy,
    Unavailable,
    Mismatch,
    Stale,
    SourceAttestationRejected,
}

/// Bound to the canonical Core that passed wire admission.
#[derive(Clone, Copy, Debug)]
pub struct Call<'a> {
    pub(crate) id: CallId,
    pub(crate) deployment: u64,
    pub(crate) target: EndpointId,
    pub(crate) session: SessionId,
    pub(crate) cut: CommitCut,
    pub(crate) stream: Stream,
    pub(crate) entry: Commitment,
    pub(crate) mode: SyncMode,
    pub(crate) predecessor: Option<[u8; 32]>,
    pub(crate) source_attestation: &'a [u8],
    pub(crate) exact: &'a [u8],
}

impl<'a> Call<'a> {
    pub(super) fn from_operand(
        core: &Core,
        operands: &'a Operands,
        exact: &'a [u8],
    ) -> Option<Self> {
        let Operands::SyncCommitment {
            id,
            session,
            cut,
            origin_epoch,
            origin_domain,
            origin_event,
            asset,
            source_position,
            mode,
            commitment,
            predecessor,
            source_attestation,
            ..
        } = operands
        else {
            return None;
        };
        Some(Self {
            id: *id,
            deployment: core.deployment?,
            target: core.target_domain?,
            session: *session,
            cut: *cut,
            stream: Stream {
                asset: *asset,
                origin_domain: *origin_domain,
            },
            entry: Commitment {
                commitment: *commitment,
                source_position: *source_position,
                origin_epoch: *origin_epoch,
                origin_event: *origin_event,
            },
            mode: *mode,
            predecessor: *predecessor,
            source_attestation,
            exact,
        })
    }

    pub(super) fn origin(self) -> OriginKey {
        OriginKey {
            domain: self.stream.origin_domain,
            event: self.entry.origin_event,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Recorded {
    exact: Vec<u8>,
    outcome: Outcome,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct State {
    #[serde(with = "ordered_map")]
    calls: BTreeMap<CallId, Recorded>,
    #[serde(with = "ordered_map")]
    pub(super) entries: BTreeMap<Stream, Commitment>,
    events: BTreeSet<OriginKey>,
}

impl State {
    pub(super) fn is_empty(&self) -> bool {
        self.calls.is_empty() && self.entries.is_empty() && self.events.is_empty()
    }

    pub(super) fn claimed(&self, id: CallId) -> bool {
        self.calls.contains_key(&id)
    }

    pub(super) fn outcome_count(&self) -> usize {
        self.calls.len()
    }

    pub(super) fn receipt(&self, call: Call<'_>) -> Result<Option<Outcome>, EndpointError> {
        match self.calls.get(&call.id) {
            Some(record) if record.exact == call.exact => Ok(Some(record.outcome)),
            Some(_) => Err(EndpointError::Rejected),
            None => Ok(None),
        }
    }

    fn mode_matches(&self, call: Call<'_>, full_resync: impl FnOnce() -> bool) -> bool {
        match (call.mode, self.entries.get(&call.stream)) {
            (SyncMode::Initial, None) => call.predecessor.is_none(),
            (SyncMode::Incremental, Some(before)) => call.predecessor == Some(before.commitment),
            (SyncMode::FullResync, Some(_)) => call.predecessor.is_none() && full_resync(),
            _ => false,
        }
    }

    fn fresh(&self, call: Call<'_>) -> bool {
        !self.events.contains(&call.origin())
            && self
                .entries
                .get(&call.stream)
                .is_none_or(|before| call.entry.source_position > before.source_position)
    }

    fn insert_entry(&mut self, call: Call<'_>) {
        self.entries.insert(call.stream, call.entry);
        self.events.insert(call.origin());
    }

    pub(super) fn preserves_calls(&self, before: &Self) -> bool {
        before
            .calls
            .iter()
            .all(|(id, retained)| self.calls.get(id) == Some(retained))
    }

    /// The authenticated image contains both the projection and exact calls.
    /// Check their consistency without consulting today's origin roster.
    pub(super) fn valid_image(image: &Snapshot, deployment: u64) -> bool {
        let state = &image.primary.sync;
        let ledger = &image.primary.ledger;
        let current = ledger.current_cut();
        let mut successful = BTreeMap::new();
        for (&id, retained) in &state.calls {
            let decoded = (|| {
                let core = decode_core(&retained.exact).ok()?;
                let operands = decode(&core, 1).ok()?;
                let call = Call::from_operand(&core, &operands, &retained.exact)?;
                let transport = TransportKey::for_core(&core).ok()?;
                if call.id != id
                    || call.deployment != deployment
                    || !ledger.has_endpoint(call.target)
                    || !ledger.has_asset(call.stream.asset)
                    || call.cut.authority_epoch > current.authority_epoch
                    || image.wire_bindings.get(&transport) != Some(&retained.exact)
                    || image.primary.calls.contains_key(&id)
                    || image.primary.regulation.claimed(id)
                {
                    return None;
                }
                if let Outcome::Synced(commit) = retained.outcome {
                    if call.cut.revision != commit.position
                        || commit.position >= current.revision
                        || !image
                            .primary
                            .journal
                            .binary_search_by_key(&commit, |item| item.commit)
                            .is_ok_and(|index| {
                                let item = &image.primary.journal[index];
                                item.id == id && item.target == call.target
                            })
                    {
                        return None;
                    }
                }
                Some((core, operands))
            })();
            let Some(decoded) = decoded else { return false };
            if let Outcome::Synced(commit) = retained.outcome
                && successful
                    .insert(commit, (decoded, &retained.exact))
                    .is_some()
            {
                return false;
            }
        }
        let mut replay = Self::default();
        for (commit, ((core, operands), exact)) in successful {
            let Some(call) = Call::from_operand(&core, &operands, exact) else {
                return false;
            };
            if !replay.mode_matches(call, || true)
                || !replay.fresh(call)
                || image
                    .read_history
                    .commitment_at(commit.position + 1, call.stream)
                    != Some(call.entry)
            {
                return false;
            }
            replay.insert_entry(call);
        }
        state.entries == replay.entries && state.events == replay.events
    }
}

impl Authority {
    pub(super) fn submit_commitment(
        &mut self,
        call: Call<'_>,
        verify_attestation: impl FnOnce() -> bool,
        full_resync: impl FnOnce() -> bool,
    ) -> Result<Outcome, EndpointError> {
        let mut primary = self.state.primary.clone();
        if primary.claimed(call.id) || !primary.ledger.has_asset(call.stream.asset) {
            return Err(EndpointError::Rejected);
        }
        let before = primary.ledger.current_cut();
        let outcome = if !self.connected {
            Outcome::Unavailable
        } else if call.cut != before {
            Outcome::Busy
        } else if !verify_attestation() {
            Outcome::SourceAttestationRejected
        } else if !primary.sync.mode_matches(call, full_resync) {
            Outcome::Mismatch
        } else if !primary.sync.fresh(call) {
            Outcome::Stale
        } else {
            let position = primary
                .ledger
                .commit_external_step()
                .ok_or(EndpointError::Unavailable)?;
            primary.sync.insert_entry(call);
            primary.note_execution(call.id, call.target, before);
            Outcome::Synced(CommitRef { position })
        };
        primary.sync.calls.insert(
            call.id,
            Recorded {
                exact: call.exact.to_vec(),
                outcome,
            },
        );
        self.commit_primary(primary);
        Ok(outcome)
    }
}
