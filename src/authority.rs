//! Authoritative calls, original event decisions and secondary settlement.
//!
//! This reference commits the primary state by replacing one in-memory value.
//! Signed calls, terminal attestation and acknowledgements are adapter inputs.

#[cfg(test)]
use crate::lock_finality::{Account, DurableLedger};
use crate::lock_finality::{
    Binding, Command, Credential, EndpointContext, EndpointId, Ledger, Phase, Reply, Request, Route,
    TerminalEvidence, TerminalKind,
};
use crate::{
    AssetId, AuthenticatedCaller, CallId, CommitCut, OriginKey, Principal, SessionBinding,
    SessionId,
};
use std::collections::{BTreeMap, BTreeSet};

pub mod identity;
pub mod reads;
pub mod recovery;
pub mod regulation;
pub mod sync;
use reads::ReadHistory;
use regulation::RegulationState;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CallPayload {
    pub message_id: u64,
    pub origin_epoch: u64,
    pub endpoint: EndpointId,
    pub caller: Principal,
    pub session: SessionId,
    pub cut: CommitCut,
    pub binding: Binding,
    pub credential: Option<Credential>,
    pub versions: Vec<(AssetId, u64)>,
    pub command: Command,
}

impl CallPayload {
    fn request(&self) -> Request<'_> {
        Request {
            endpoint: self.endpoint,
            caller: self.caller,
            session: self.session,
            cut: self.cut,
            binding: self.binding,
            credential: self.credential,
            versions: &self.versions,
            command: self.command,
        }
    }
}

/// Position in the underlying authority's commit sequence.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct CommitRef {
    pub position: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum OutcomeReply {
    Accepted(Reply),
    DuplicateDecision,
    DuplicateSettlement(TerminalKind),
    Rejected,
    Busy,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    pub reply: OutcomeReply,
    pub commit: Option<CommitRef>,
}

impl Outcome {
    fn plain(reply: OutcomeReply) -> Self {
        Self {
            reply,
            commit: None,
        }
    }

    fn committed(reply: OutcomeReply, commit: CommitRef) -> Self {
        Self {
            reply,
            commit: Some(commit),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Collection {
    Collected(Outcome),
    Waiting,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct StoredCall {
    payload: CallPayload,
    outcome: Outcome,
}

impl StoredCall {
    fn settlement_receipt_kind(&self) -> Option<TerminalKind> {
        match self.outcome.reply {
            OutcomeReply::Accepted(Reply::Credited) => Some(TerminalKind::Confirmed),
            OutcomeReply::Accepted(Reply::Refunded) => Some(TerminalKind::Reversed),
            OutcomeReply::DuplicateSettlement(kind) => Some(kind),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OriginDecision {
    pub binding: Binding,
    pub kind: TerminalKind,
    pub origin_epoch: u64,
    pub commit: CommitRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct OriginSlot {
    binding: Binding,
    epoch: u64,
    debit: CommitRef,
    decision: Option<OriginDecision>,
    settled: Option<CommitRef>,
    published: Option<CommitRef>,
}

impl OriginSlot {
    fn matches(self, payload: &CallPayload) -> bool {
        self.binding == payload.binding && self.epoch == payload.origin_epoch
    }

    fn matches_decision(self, payload: &CallPayload, kind: TerminalKind) -> bool {
        self.matches(payload) && self.decision.is_some_and(|decision| decision.kind == kind)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Publication {
    pub origin: OriginKey,
    pub decision: OriginDecision,
}

impl Publication {
    pub fn key(self) -> SettlementKey {
        SettlementKey {
            origin: self.origin,
            commit: self.decision.commit,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct SettlementKey {
    pub origin: OriginKey,
    pub commit: CommitRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SettlementStatus {
    Waiting,
    InFlight,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SecondaryJob {
    pub commitment: Publication,
    pub target: EndpointId,
    pub attempts: u64,
    pub status: SettlementStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acknowledgement {
    pub key: SettlementKey,
    pub commitment: Publication,
    pub target: EndpointId,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct SecondaryQueue {
    target: EndpointId,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    jobs: BTreeMap<SettlementKey, SecondaryJob>,
}

impl SecondaryQueue {
    fn is_bound_to_primary(&self, primary: &PrimarySnapshot) -> bool {
        self.jobs.iter().all(|(key, job)| {
            *key == job.commitment.key()
                && job.target == self.target
                && primary.publication(key.origin) == Some(job.commitment)
                && (job.status == SettlementStatus::Waiting || job.attempts > 0)
        })
    }

    fn preserves_previous_jobs(&self, previous: &Self) -> bool {
        self.target == previous.target && previous.jobs.iter().all(|(key, old)| {
            self.jobs.get(key).is_some_and(|current| {
                current.commitment == old.commitment
                    && current.target == old.target
                    && current.attempts >= old.attempts
                    && (old.status != SettlementStatus::Completed || current == old)
            })
        })
    }

    fn enqueue(&mut self, commitment: Publication) -> SettlementKey {
        let key = commitment.key();
        self.jobs.entry(key).or_insert(SecondaryJob {
            commitment,
            target: self.target,
            attempts: 0,
            status: SettlementStatus::Waiting,
        });
        key
    }

    fn dispatch(&mut self, key: SettlementKey) -> Option<SecondaryJob> {
        let job = self.jobs.get_mut(&key)?;
        if job.status == SettlementStatus::Completed {
            return None;
        }
        job.attempts = job.attempts.checked_add(1)?;
        job.status = SettlementStatus::InFlight;
        Some(*job)
    }

    fn fail(&mut self, key: SettlementKey) -> bool {
        let Some(job) = self.jobs.get_mut(&key) else {
            return false;
        };
        if job.status != SettlementStatus::InFlight {
            return false;
        }
        job.status = SettlementStatus::Waiting;
        true
    }

    fn acknowledge(
        &mut self,
        ack: Acknowledgement,
        verify: impl FnOnce(&Acknowledgement) -> bool,
    ) -> bool {
        let Some(job) = self.jobs.get_mut(&ack.key) else {
            return false;
        };
        if ack.key != job.commitment.key()
            || ack.commitment != job.commitment
            || ack.target != job.target
            || ack.target != self.target
            || job.attempts == 0
            || !verify(&ack)
        {
            return false;
        }
        job.status = SettlementStatus::Completed;
        true
    }
}

/// Opaque primary image, comparable to a later authoritative image.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct JournalItem {
    id: CallId,
    target: EndpointId,
    commit: CommitRef,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PrimarySnapshot {
    ledger: Ledger,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    calls: BTreeMap<CallId, StoredCall>,
    completed: BTreeSet<CallId>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    origins: BTreeMap<OriginKey, OriginSlot>,
    regulation: RegulationState,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    owners: BTreeMap<AssetId, Principal>,
    journal: Vec<JournalItem>,
    #[serde(default, skip_serializing_if = "sync::State::is_empty")]
    sync: sync::State,
}

impl PrimarySnapshot {
    fn has_consistent_settlement_receipts(&self) -> bool {
        if self
            .journal
            .last()
            .is_some_and(|item| item.commit.position >= self.ledger.current_cut().revision)
            || !self.journal.windows(2).all(|items| items[0].commit < items[1].commit)
        {
            return false;
        }
        let mut effects = BTreeMap::new();
        for item in &self.journal {
            let Some(stored) = self.calls.get(&item.id) else {
                continue;
            };
            match stored.outcome.reply {
                OutcomeReply::Accepted(Reply::Credited | Reply::Refunded) => {
                    let payload = &stored.payload;
                    if stored.outcome.commit != Some(item.commit)
                        || payload.cut.revision != item.commit.position
                        || payload.endpoint != item.target
                        || effects.insert(payload.binding.origin, item).is_some()
                    {
                        return false;
                    }
                }
                OutcomeReply::DuplicateSettlement(_) => return false,
                _ => (),
            }
        }
        if self.ledger.settled_origins().any(|origin| !effects.contains_key(&origin)) {
            return false;
        }
        self.origins.iter().all(|(key, slot)| {
            slot.settled == effects.get(key).map(|item| item.commit)
        }) && self.calls.iter().all(|(id, stored)| {
            let Some(kind) = stored.settlement_receipt_kind() else {
                return true;
            };
            let payload = &stored.payload;
            let reference = match (payload.command, kind) {
                (Command::Credit { reference }, TerminalKind::Confirmed)
                | (Command::Refund { reference, .. }, TerminalKind::Reversed) => reference,
                _ => return false,
            };
            let origin = payload.binding.origin;
            let Some(item) = effects.get(&origin) else {
                return false;
            };
            let settled_in_ledger = matches!(
                (kind, self.ledger.phase(origin)),
                (TerminalKind::Confirmed, Some(Phase::Credited | Phase::Reconciled))
                    | (TerminalKind::Reversed, Some(Phase::Refunded))
            );
            settled_in_ledger
                && self
                    .origins
                    .get(&origin)
                    .is_some_and(|slot| slot.matches_decision(payload, kind))
                && stored.outcome.commit == Some(item.commit)
                && self.ledger.evidence(reference)
                    == Some(TerminalEvidence { binding: payload.binding, kind, reference })
                && (matches!(stored.outcome.reply, OutcomeReply::DuplicateSettlement(_)) || item.id == *id)
        })
    }

    fn preserves_retained_outcomes(&self, previous: &Self) -> bool {
        self.journal.starts_with(&previous.journal)
            && previous.completed.is_subset(&self.completed)
            && previous.calls.iter().all(|(id, stored)| self.calls.get(id) == Some(stored))
            && self.sync.preserves_calls(&previous.sync)
    }

    fn claimed(&self, id: CallId) -> bool {
        self.calls.contains_key(&id) || self.regulation.claimed(id) || self.sync.claimed(id)
    }

    fn note_execution(&mut self, id: CallId, target: EndpointId, before: CommitCut) {
        if self.ledger.current_cut().revision > before.revision {
            self.journal.push(JournalItem {
                id,
                target,
                commit: CommitRef {
                    position: before.revision,
                },
            });
        }
    }

    fn ready(&self, stored: &StoredCall) -> bool {
        let final_effect = matches!(
            stored.outcome.reply,
            OutcomeReply::Accepted(Reply::Credited | Reply::Refunded)
                | OutcomeReply::DuplicateSettlement(_)
        );
        if !final_effect {
            return true;
        }
        let binding = stored.payload.binding;
        self.publication(binding.origin).is_some()
            && self.ledger.lock_owner(binding.asset) != Some(binding.origin)
    }

    fn publication(&self, origin: OriginKey) -> Option<Publication> {
        let slot = self.origins.get(&origin)?;
        slot.published?;
        slot.settled?;
        Some(Publication {
            origin,
            decision: slot.decision?,
        })
    }

    fn origin_allowed(&self, payload: &CallPayload) -> bool {
        let slot = self.origins.get(&payload.binding.origin).copied();
        match payload.command {
            Command::Debit { .. } => slot
                .map_or(payload.origin_epoch == payload.cut.authority_epoch, |old| {
                    old.matches(payload)
                }),
            Command::RecordTerminal(evidence) => {
                evidence.binding == payload.binding
                    && slot.is_some_and(|old| {
                        old.matches(payload)
                            && old
                                .decision
                                .is_none_or(|decision| decision.kind == evidence.kind)
                    })
            }
            Command::Credit { .. } | Command::Reconcile { .. } => {
                slot.is_some_and(|old| old.matches_decision(payload, TerminalKind::Confirmed))
            }
            Command::Refund { .. } => {
                slot.is_some_and(|old| old.matches_decision(payload, TerminalKind::Reversed))
            }
            Command::PublishPrimary => {
                slot.is_some_and(|old| old.matches(payload) && old.settled.is_some())
            }
            _ => true,
        }
    }

    fn duplicate(&self, payload: &CallPayload) -> Option<Outcome> {
        let slot = self.origins.get(&payload.binding.origin)?;
        match payload.command {
            Command::RecordTerminal(evidence)
                if self.ledger.evidence(evidence.reference) == Some(evidence) =>
            {
                Some(Outcome::committed(
                    OutcomeReply::DuplicateDecision,
                    slot.decision?.commit,
                ))
            }
            Command::Credit { reference } | Command::Refund { reference, .. } => {
                let kind = slot.decision?.kind;
                let commit = slot.settled?;
                if self.ledger.evidence(reference)
                    != Some(TerminalEvidence {
                        binding: payload.binding,
                        kind,
                        reference,
                    })
                {
                    return None;
                }
                Some(Outcome::committed(
                    OutcomeReply::DuplicateSettlement(kind),
                    commit,
                ))
            }
            Command::PublishPrimary => Some(Outcome::committed(
                OutcomeReply::Accepted(Reply::Published),
                slot.published?,
            )),
            _ => None,
        }
    }

    fn execute(
        &mut self,
        route: Route,
        actor: AuthenticatedCaller,
        payload: &CallPayload,
    ) -> Outcome {
        let request = payload.request();
        if !self.ledger.request_admitted(route, actor, request) {
            return Outcome::plain(OutcomeReply::Rejected);
        }
        if matches!(payload.command, Command::PublishPrimary)
            && self.regulation.contains_origin(payload.binding.origin)
        {
            return self.publish_legal(payload);
        }
        if !self.origin_allowed(payload)
            || (matches!(
                payload.command,
                Command::Reserve { .. } | Command::Debit { .. }
            ) && self.regulation.contains_origin(payload.binding.origin))
            || (matches!(
                payload.command,
                Command::Dispatch { .. } | Command::Debit { .. }
            ) && self
                .regulation
                .protected(payload.binding.origin.domain, payload.binding.asset))
        {
            return Outcome::plain(OutcomeReply::Rejected);
        }
        if let Some(duplicate) = self.duplicate(payload) {
            return if self.ledger.receipt_credential_matches(actor, request) {
                duplicate
            } else {
                Outcome::plain(OutcomeReply::Rejected)
            };
        }
        let commit = CommitRef {
            position: self.ledger.current_cut().revision,
        };
        let reply = self.ledger.submit(route, actor, request, |_, _, _| true);
        match reply {
            Reply::Rejected => return Outcome::plain(OutcomeReply::Rejected),
            Reply::Busy => return Outcome::plain(OutcomeReply::Busy),
            _ => (),
        }

        let binding = payload.binding;
        match (payload.command, reply) {
            (Command::Debit { .. }, Reply::Debited) => {
                self.origins.entry(binding.origin).or_insert(OriginSlot {
                    binding,
                    epoch: payload.origin_epoch,
                    debit: commit,
                    decision: None,
                    settled: None,
                    published: None,
                });
            }
            (Command::RecordTerminal(evidence), Reply::Recorded) => {
                let slot = self
                    .origins
                    .get_mut(&binding.origin)
                    .expect("admitted terminal origin");
                slot.decision.get_or_insert(OriginDecision {
                    binding,
                    kind: evidence.kind,
                    origin_epoch: payload.origin_epoch,
                    commit,
                });
            }
            (
                Command::Credit { .. } | Command::Refund { .. },
                Reply::Credited | Reply::Refunded,
            ) => {
                let slot = self
                    .origins
                    .get_mut(&binding.origin)
                    .expect("admitted settlement origin");
                slot.settled.get_or_insert(commit);
            }
            (Command::PublishPrimary, Reply::Published) => {
                let slot = self
                    .origins
                    .get_mut(&binding.origin)
                    .expect("admitted publication origin");
                slot.published.get_or_insert(commit);
            }
            _ => (),
        }
        Outcome::committed(OutcomeReply::Accepted(reply), commit)
    }
}

/// Opaque durable image. Runtime reachability is outside the image.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Snapshot {
    primary: PrimarySnapshot,
    secondary: SecondaryQueue,
    read_history: ReadHistory,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        with = "crate::authority::recovery::ordered_map"
    )]
    wire_bindings: BTreeMap<crate::wire::admission::TransportKey, Vec<u8>>,
}

pub(crate) struct Authority {
    state: Snapshot,
    up: bool,
    connected: bool,
}

impl Authority {
    /// The ledger must be an untouched genesis so that all later financial
    /// effects pass through this authority's call and origin checks.
    pub(crate) fn new(ledger: Ledger, settlement_target: EndpointId) -> Option<Self> {
        if !ledger.is_genesis() {
            return None;
        }
        let primary = PrimarySnapshot {
            ledger,
            calls: BTreeMap::new(),
            completed: BTreeSet::new(),
            origins: BTreeMap::new(),
            regulation: RegulationState::default(),
            owners: BTreeMap::new(),
            journal: Vec::new(),
            sync: sync::State::default(),
        };
        let read_history = ReadHistory::new(&primary);
        Some(Self {
            state: Snapshot {
                primary,
                read_history,
                wire_bindings: BTreeMap::new(),
                secondary: SecondaryQueue {
                    target: settlement_target,
                    jobs: BTreeMap::new(),
                },
            },
            up: true,
            connected: true,
        })
    }

    fn access(
        &self,
        actor: AuthenticatedCaller,
        id: CallId,
        payload: &CallPayload,
        verify: impl FnOnce(AuthenticatedCaller, CallId, &CallPayload) -> bool,
    ) -> bool {
        id.namespace == actor.0
            && payload.caller == actor.0
            && self
                .state
                .primary
                .ledger
                .session_bound(actor, payload.session)
            && verify(actor, id, payload)
    }

    #[cfg(test)]
    pub fn submit(
        &mut self,
        route: Route,
        actor: AuthenticatedCaller,
        id: CallId,
        payload: &CallPayload,
        verify: impl FnOnce(AuthenticatedCaller, CallId, &CallPayload) -> bool,
    ) -> Collection {
        if !self.access(actor, id, payload, verify) {
            return Collection::Rejected;
        }
        self.submit_bound(route, actor, id, payload)
    }

    fn submit_bound(
        &mut self,
        route: Route,
        actor: AuthenticatedCaller,
        id: CallId,
        payload: &CallPayload,
    ) -> Collection {
        if !self.up {
            return Collection::Waiting;
        }
        if self.state.primary.regulation.claimed(id) || self.state.primary.sync.claimed(id) {
            return Collection::Rejected;
        }
        if self.state.primary.calls.contains_key(&id) {
            return self.finish(id, payload);
        }

        let mut primary = self.state.primary.clone();
        let before = primary.ledger.current_cut();
        let outcome = if self.connected {
            primary.execute(route, actor, payload)
        } else {
            Outcome::plain(OutcomeReply::Unavailable)
        };
        primary.note_execution(id, payload.endpoint, before);
        primary.calls.insert(
            id,
            StoredCall {
                payload: payload.clone(),
                outcome,
            },
        );
        self.commit_primary(primary);
        self.finish(id, payload)
    }

    fn commit_primary(&mut self, primary: PrimarySnapshot) {
        self.state.read_history.record(&primary);
        self.state.primary = primary;
    }

    fn retained_completion(&self, id: CallId, payload: &CallPayload) -> (Collection, bool) {
        let view = self.state.primary.calls.get(&id).map(|stored| {
            let matches = stored.payload == *payload;
            (matches, matches && self.state.primary.ready(stored), stored.outcome)
        });
        let (reply, complete) = retained_completion::retained_completion(view);
        let reply = match reply {
            retained_completion::Reply::Waiting => Collection::Waiting,
            retained_completion::Reply::Rejected => Collection::Rejected,
            retained_completion::Reply::Collected(outcome) => Collection::Collected(outcome),
        };
        (reply, complete)
    }

    fn observe(&self, id: CallId, payload: &CallPayload) -> Collection {
        self.retained_completion(id, payload).0
    }

    #[cfg(test)]
    pub fn collect(
        &mut self,
        actor: AuthenticatedCaller,
        id: CallId,
        payload: &CallPayload,
        verify: impl FnOnce(AuthenticatedCaller, CallId, &CallPayload) -> bool,
    ) -> Collection {
        if !self.access(actor, id, payload, verify)
            || self.state.primary.regulation.claimed(id)
            || self.state.primary.sync.claimed(id)
        {
            return Collection::Rejected;
        }
        if !self.up {
            return Collection::Waiting;
        }
        self.finish(id, payload)
    }

    fn finish(&mut self, id: CallId, payload: &CallPayload) -> Collection {
        let (reply, complete) = self.retained_completion(id, payload);
        if complete {
            self.state.primary.completed.insert(id);
        }
        reply
    }

    pub fn install_epoch(
        &mut self,
        actor: AuthenticatedCaller,
        epoch: u64,
        contexts: Vec<EndpointContext>,
        sessions: BTreeMap<SessionId, SessionBinding>,
    ) -> bool {
        let installed = self.up
            && self
                .state
                .primary
                .ledger
                .install_epoch(actor, epoch, contexts, sessions);
        if installed {
            self.state.read_history.record(&self.state.primary);
        }
        installed
    }

    #[cfg(test)]
    pub fn driver_connection(&mut self, connected: bool) {
        self.connected = connected;
    }

    #[cfg(test)]
    pub fn crash(&mut self) {
        self.up = false;
    }

    /// The adapter must supply a checked image of this authority. A stale or
    /// divergent image cannot replace the in-memory authority.
    #[cfg(test)]
    pub fn recover(&mut self, checked_snapshot: Option<&Snapshot>) -> bool {
        if self.up || !self.connected || checked_snapshot != Some(&self.state) {
            return false;
        }
        self.up = true;
        true
    }

    pub fn snapshot(&self) -> Snapshot {
        self.state.clone()
    }

    #[cfg(test)]
    pub fn primary_snapshot(&self) -> PrimarySnapshot {
        self.state.primary.clone()
    }

    #[cfg(test)]
    pub fn ledger_snapshot(&self) -> DurableLedger {
        self.state.primary.ledger.snapshot()
    }

    pub fn current_cut(&self) -> CommitCut {
        self.state.primary.ledger.current_cut()
    }

    #[cfg(test)]
    pub fn balance(&self, account: Account) -> u64 {
        self.state.primary.ledger.balance(account)
    }

    #[cfg(test)]
    pub fn lock_owner(&self, asset: AssetId) -> Option<OriginKey> {
        self.state.primary.ledger.lock_owner(asset)
    }

    #[cfg(test)]
    pub fn is_completed(&self, id: CallId) -> bool {
        self.state.primary.completed.contains(&id)
    }

    #[cfg(test)]
    pub fn completed_count(&self) -> usize {
        self.state.primary.completed.len()
    }

    pub fn outcome_count(&self) -> usize {
        self.state.primary.calls.len() + self.state.primary.sync.outcome_count()
    }

    #[cfg(test)]
    pub fn origin_debit(&self, origin: OriginKey) -> Option<CommitRef> {
        Some(self.state.primary.origins.get(&origin)?.debit)
    }

    #[cfg(test)]
    pub fn origin_decision(&self, origin: OriginKey) -> Option<OriginDecision> {
        self.state.primary.origins.get(&origin)?.decision
    }

    pub fn primary_publication(&self, origin: OriginKey) -> Option<Publication> {
        self.state.primary.publication(origin)
    }

    pub fn enqueue_secondary(&mut self, origin: OriginKey) -> Option<SettlementKey> {
        let publication = self.primary_publication(origin)?;
        Some(self.state.secondary.enqueue(publication))
    }

    pub fn dispatch_secondary(&mut self, key: SettlementKey) -> Option<SecondaryJob> {
        self.state.secondary.dispatch(key)
    }

    pub fn fail_secondary(&mut self, key: SettlementKey) -> bool {
        self.state.secondary.fail(key)
    }

    pub fn acknowledge_secondary(
        &mut self,
        ack: Acknowledgement,
        verify: impl FnOnce(&Acknowledgement) -> bool,
    ) -> bool {
        self.state.secondary.acknowledge(ack, verify)
    }

    #[cfg(test)]
    pub fn secondary_job(&self, key: SettlementKey) -> Option<SecondaryJob> {
        self.state.secondary.jobs.get(&key).copied()
    }

    #[cfg(test)]
    pub fn secondary_job_count(&self) -> usize {
        self.state.secondary.jobs.len()
    }
}

#[cfg(test)]
mod vector_tests;

#[allow(unexpected_cfgs)]
mod retained_completion;
