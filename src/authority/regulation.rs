//! Legal execution on the authority's protected ledger.
//!
//! Signatures, legal facts, permissions and trusted time enter through the
//! verified adapter boundary. The model consumes their exact bindings.

use super::reads::{ReadAuthority, ReadHistory};
use super::{CallPayload, CommitRef, Outcome, OutcomeReply, PrimarySnapshot};
use crate::lock_finality::{Binding, EndpointId, Ledger, Reply, TerminalKind};
use crate::{AssetId, AuthenticatedCaller, CallId, CommitCut, OriginKey, Principal, SessionId};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RegulatoryRoute {
    Normal,
    Administrative,
    Adapter,
    ForceInclusion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum LegalStage {
    SourceEmission,
    ReceivingCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Action {
    Freeze,
    Restrict,
    Seize,
    Confiscate,
    Unfreeze,
    Unrestrict,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Mode {
    Active,
    Restricted,
    Frozen,
    Seized,
    Confiscated,
}

impl Mode {
    pub(super) fn protected(self) -> bool {
        matches!(self, Self::Frozen | Self::Seized | Self::Confiscated)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Refusal {
    InvalidAuthority,
    InvalidState,
    InvalidBinding,
    MissingPriorFreeze,
    MissingPriorSeizure,
    AppealStillOpen,
    AppealDeadlineMismatch,
    MissingDestination,
    ConflictingOrder,
    Busy,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Order {
    pub binding: Binding,
    pub action: Action,
    pub officer: Principal,
    pub jurisdiction: u64,
    pub legal_basis: u64,
    pub scope: BTreeSet<AssetId>,
    pub issuance_epoch: u64,
    pub predecessor: Option<OriginKey>,
    pub appeal_deadline: Option<u64>,
    pub destination: Option<Principal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LegalPayload {
    pub message_id: u64,
    pub caller: Principal,
    pub session: SessionId,
    pub cut: CommitCut,
    pub binding: Binding,
    pub action: Action,
    pub origin_epoch: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct LegalCall<'a> {
    pub stage: LegalStage,
    pub route: RegulatoryRoute,
    pub actor: AuthenticatedCaller,
    pub id: CallId,
    pub expected: CommitCut,
    pub order: &'a Order,
    pub payload: LegalPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum LegalReply {
    Emitted(CommitRef),
    Applied(CommitRef),
    Refused(Refusal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Enrollment {
    pub asset: AssetId,
    pub source: EndpointId,
    pub receiver: EndpointId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LegalGrant {
    pub stage: LegalStage,
    pub route: RegulatoryRoute,
    pub officer: Principal,
    pub jurisdiction: u64,
    pub legal_basis: u64,
    pub asset: AssetId,
    pub action: Action,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SpendKind {
    Ordinary,
    Recover,
    Seize,
    Confiscate,
    Liquidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpendScope {
    pub root: Binding,
    pub sender: Principal,
    pub recipient: Principal,
    pub amount: u64,
    pub kind: SpendKind,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EnforcementOrder {
    pub scope: SpendScope,
    pub officer: Principal,
    pub jurisdiction: u64,
    pub legal_basis: u64,
    pub assets: BTreeSet<AssetId>,
    pub prior_seizure: Option<OriginKey>,
    pub appeal_deadline: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpendGrant {
    pub route: RegulatoryRoute,
    pub actor: Principal,
    pub epoch: u64,
    pub scope: SpendScope,
    pub jurisdiction: u64,
    pub legal_basis: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub enrollments: Vec<Enrollment>,
    pub legal: Vec<LegalGrant>,
    pub spend: Vec<SpendGrant>,
    pub clock_observers: BTreeSet<(Principal, u64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpendPayload {
    pub message_id: u64,
    pub caller: Principal,
    pub session: SessionId,
    pub cut: CommitCut,
    pub origin_epoch: u64,
    pub reference: CommitRef,
    pub scope: SpendScope,
}

#[derive(Clone, Copy, Debug)]
pub struct SpendCall<'a> {
    pub route: RegulatoryRoute,
    pub actor: AuthenticatedCaller,
    pub id: CallId,
    pub expected: CommitCut,
    pub payload: SpendPayload,
    pub enforcement: Option<&'a EnforcementOrder>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SpendReply {
    Executed { root: OriginKey, commit: CommitRef },
    Rejected,
    Busy,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LegalDecision {
    pub binding: Binding,
    pub action: Action,
    pub emitted: CommitRef,
    pub applied: CommitRef,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct LegalEvent {
    order: Order,
    emitted: CommitRef,
    applied: Option<CommitRef>,
    published: Option<CommitRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct LegalReceipt {
    stage: LegalStage,
    order: Order,
    payload: LegalPayload,
    reply: LegalReply,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct SpendReceipt {
    payload: SpendPayload,
    enforcement: Option<EnforcementOrder>,
    reply: SpendReply,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct RegulationState {
    policy: Policy,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    modes: BTreeMap<(EndpointId, AssetId), Mode>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    legal_events: BTreeMap<OriginKey, LegalEvent>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    freezes: BTreeMap<AssetId, OriginKey>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    seizures: BTreeMap<AssetId, OriginKey>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    legal_receipts: BTreeMap<CallId, LegalReceipt>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    spend_receipts: BTreeMap<CallId, SpendReceipt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct LegalRead {
    pub(super) binding: Binding,
    pub(super) published: bool,
    pub(super) decision: Option<LegalDecision>,
}

impl RegulationState {
    fn configured(policy: Policy, ledger: &Ledger) -> Option<Self> {
        let mut pairs = BTreeSet::new();
        let mut modes = BTreeMap::new();
        for &Enrollment {
            asset,
            source,
            receiver,
        } in &policy.enrollments
        {
            if source == receiver
                || !pairs.insert((asset, source, receiver))
                || !ledger.has_asset(asset)
                || !ledger.has_endpoint(source)
                || !ledger.has_endpoint(receiver)
            {
                return None;
            }
            modes.insert((source, asset), Mode::Active);
            modes.insert((receiver, asset), Mode::Active);
        }
        Some(Self {
            policy,
            modes,
            ..Self::default()
        })
    }

    pub(super) fn matches_applied_history(&self, ledger: &Ledger) -> bool {
        let Some(mut replay) = Self::configured(self.policy.clone(), ledger) else {
            return false;
        };
        let revision = ledger.current_cut().revision;
        let mut ordered = Vec::new();
        for (origin, event) in &self.legal_events {
            if *origin != event.order.binding.origin || event.emitted.position >= revision {
                return false;
            }
            if let Some(applied) = event.applied {
                if applied.position <= event.emitted.position || applied.position >= revision
                    || event.published.is_some_and(|published| published.position <= applied.position || published.position >= revision)
                {
                    return false;
                }
                ordered.push((applied.position, *origin, event));
            } else if event.published.is_some() {
                return false;
            }
        }
        ordered.sort_unstable_by_key(|(position, _, _)| *position);
        if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return false;
        }
        for (_, origin, event) in ordered {
            let Ok(mode) = replay.transition(&event.order, ledger.clock()) else {
                return false;
            };
            replay.applied(&event.order, mode);
            replay.legal_events.insert(origin, event.clone());
        }
        self.modes == replay.modes && self.freezes == replay.freezes && self.seizures == replay.seizures
    }

    pub(super) fn preserves_retained_regulation(&self, previous: &Self) -> bool {
        self.policy == previous.policy && previous.legal_events.iter().all(|(origin, old)| {
            self.legal_events.get(origin).is_some_and(|current| {
                current.order == old.order
                    && current.emitted == old.emitted
                    && old.applied.is_none_or(|position| current.applied == Some(position))
                    && old.published.is_none_or(|position| current.published == Some(position))
            })
        }) && previous.legal_receipts.iter().all(|(id, receipt)| {
            self.legal_receipts.get(id) == Some(receipt)
        }) && previous.spend_receipts.iter().all(|(id, receipt)| {
            self.spend_receipts.get(id) == Some(receipt)
        })
    }

    pub(super) fn has_disjoint_receipt_ids(&self, ordinary_claimed: impl Fn(&CallId) -> bool) -> bool {
        self.legal_receipts.keys().all(|id| {
            !ordinary_claimed(id) && !self.spend_receipts.contains_key(id)
        }) && self.spend_receipts.keys().all(|id| !ordinary_claimed(id))
    }

    pub(super) fn claimed(&self, id: CallId) -> bool {
        self.legal_receipts.contains_key(&id) || self.spend_receipts.contains_key(&id)
    }

    pub(super) fn exact_order_receipt(
        &self,
        id: CallId,
        stage: LegalStage,
        order: &Order,
        payload: LegalPayload,
    ) -> Option<LegalReply> {
        let receipt = self.legal_receipts.get(&id)?;
        (receipt.stage == stage && receipt.order == *order && receipt.payload == payload)
            .then_some(receipt.reply)
    }

    pub(super) fn exact_spend_receipt(
        &self,
        id: CallId,
        payload: SpendPayload,
        order: Option<&EnforcementOrder>,
    ) -> Option<SpendReply> {
        let receipt = self.spend_receipts.get(&id)?;
        (receipt.payload == payload && receipt.enforcement.as_ref() == order)
            .then_some(receipt.reply)
    }

    pub(super) fn contains_origin(&self, origin: OriginKey) -> bool {
        self.legal_events.contains_key(&origin)
    }

    pub(super) fn protected(&self, endpoint: EndpointId, asset: AssetId) -> bool {
        self.modes
            .get(&(endpoint, asset))
            .is_some_and(|mode| mode.protected())
    }

    pub(super) fn modes(&self) -> BTreeMap<(EndpointId, AssetId), Mode> {
        self.modes.clone()
    }

    pub(super) fn legal_reads(&self) -> BTreeMap<OriginKey, LegalRead> {
        self.legal_events
            .iter()
            .map(|(&origin, event)| {
                (
                    origin,
                    LegalRead {
                        binding: event.order.binding,
                        published: event.published.is_some(),
                        decision: event.applied.map(|applied| LegalDecision {
                            binding: event.order.binding,
                            action: event.order.action,
                            emitted: event.emitted,
                            applied,
                        }),
                    },
                )
            })
            .collect()
    }

    fn legal_granted(&self, call: &LegalCall<'_>, epoch: u64) -> bool {
        let order = call.order;
        self.policy.legal.contains(&LegalGrant {
            stage: call.stage,
            route: call.route,
            officer: call.actor.0,
            jurisdiction: order.jurisdiction,
            legal_basis: order.legal_basis,
            asset: order.binding.asset,
            action: order.action,
            epoch,
        })
    }

    fn predecessor(&self, key: OriginKey, action: Action, binding: Binding) -> Option<&Order> {
        let event = self.legal_events.get(&key)?;
        event.applied?;
        let before = &event.order;
        (before.action == action && before.binding.asset == binding.asset).then_some(before)
    }

    fn active_freeze(&self, binding: Binding) -> Option<OriginKey> {
        let key = *self.freezes.get(&binding.asset)?;
        self.predecessor(key, Action::Freeze, binding)?;
        Some(key)
    }

    fn active_seizure(&self, binding: Binding) -> Option<(OriginKey, &Order)> {
        let key = *self.seizures.get(&binding.asset)?;
        let order = self.predecessor(key, Action::Seize, binding)?;
        if order.predecessor != Some(self.active_freeze(binding)?) {
            return None;
        }
        Some((key, order))
    }

    fn deadline(recorded: &Order, supplied: Option<u64>, now: u64) -> Result<(), Refusal> {
        let deadline = supplied.ok_or(Refusal::AppealDeadlineMismatch)?;
        if recorded.appeal_deadline != Some(deadline) {
            return Err(Refusal::AppealDeadlineMismatch);
        }
        if now < deadline {
            return Err(Refusal::AppealStillOpen);
        }
        Ok(())
    }

    fn transition(&self, order: &Order, now: u64) -> Result<Mode, Refusal> {
        let b = order.binding;
        let source = self.modes.get(&(b.origin.domain, b.asset));
        let receiver = self.modes.get(&(b.destination, b.asset));
        let mode = source
            .filter(|_| source == receiver)
            .copied()
            .ok_or(Refusal::InvalidState)?;
        match order.action {
            Action::Freeze if mode == Mode::Active => Ok(Mode::Frozen),
            Action::Restrict if mode == Mode::Active => Ok(Mode::Restricted),
            Action::Seize => {
                if mode != Mode::Frozen
                    || order.predecessor.is_none()
                    || order.predecessor != self.active_freeze(b)
                {
                    return Err(Refusal::MissingPriorFreeze);
                }
                Ok(Mode::Seized)
            }
            Action::Confiscate => {
                let (key, seizure) = self.active_seizure(b).ok_or(Refusal::MissingPriorSeizure)?;
                if mode != Mode::Seized || order.predecessor != Some(key) {
                    return Err(Refusal::MissingPriorSeizure);
                }
                Self::deadline(seizure, order.appeal_deadline, now)?;
                if order.destination.is_none() {
                    return Err(Refusal::MissingDestination);
                }
                Ok(Mode::Confiscated)
            }
            Action::Unfreeze
                if mode == Mode::Frozen
                    && order.predecessor.is_some()
                    && order.predecessor == self.active_freeze(b) =>
            {
                Ok(Mode::Active)
            }
            Action::Unrestrict if mode == Mode::Restricted => Ok(Mode::Active),
            Action::Release
                if mode == Mode::Seized
                    && self
                        .active_seizure(b)
                        .is_some_and(|(key, _)| order.predecessor == Some(key)) =>
            {
                Ok(Mode::Active)
            }
            _ => Err(Refusal::InvalidState),
        }
    }

    fn applied(&mut self, order: &Order, mode: Mode) {
        let b = order.binding;
        for ((_, asset), current) in &mut self.modes {
            if *asset == b.asset {
                *current = mode;
            }
        }
        match order.action {
            Action::Freeze => {
                self.freezes.insert(b.asset, b.origin);
            }
            Action::Seize => {
                self.seizures.insert(b.asset, b.origin);
            }
            Action::Unfreeze => {
                self.freezes.remove(&b.asset);
            }
            Action::Release => {
                self.freezes.remove(&b.asset);
                self.seizures.remove(&b.asset);
            }
            _ => (),
        }
    }
}

impl PrimarySnapshot {
    pub(super) fn publish_legal(&mut self, payload: &CallPayload) -> Outcome {
        let Some(event) = self
            .regulation
            .legal_events
            .get_mut(&payload.binding.origin)
        else {
            return Outcome::plain(OutcomeReply::Rejected);
        };
        if event.order.binding != payload.binding
            || event.order.issuance_epoch != payload.origin_epoch
            || event.applied.is_none()
            || payload.credential.is_some()
        {
            return Outcome::plain(OutcomeReply::Rejected);
        }
        if let Some(commit) = event.published {
            return Outcome::committed(OutcomeReply::Accepted(Reply::Published), commit);
        }
        let Some(position) = self.ledger.commit_external_step() else {
            return Outcome::plain(OutcomeReply::Rejected);
        };
        let commit = CommitRef { position };
        event.published = Some(commit);
        Outcome::committed(OutcomeReply::Accepted(Reply::Published), commit)
    }

    fn apply_order(&mut self, call: &LegalCall<'_>) -> Result<LegalReply, Refusal> {
        let order = call.order;
        let cut = self.ledger.current_cut();
        let b = order.binding;
        if order.legal_basis == 0
            || !order.scope.contains(&b.asset)
            || !self.regulation.legal_granted(call, cut.authority_epoch)
        {
            return Err(Refusal::InvalidAuthority);
        }
        if !self.regulation.policy.enrollments.contains(&Enrollment {
            asset: b.asset,
            source: b.origin.domain,
            receiver: b.destination,
        }) || call.payload.binding != b
            || call.payload.action != order.action
            || call.payload.origin_epoch != order.issuance_epoch
            || order
                .destination
                .is_some_and(|destination| destination != b.recipient)
        {
            return Err(Refusal::InvalidBinding);
        }
        if call.expected != cut || call.payload.cut != cut {
            return Err(Refusal::Busy);
        }
        if self.origins.contains_key(&b.origin) || self.ledger.generation(b.origin).is_some() {
            return Err(Refusal::ConflictingOrder);
        }
        let existing = self.regulation.legal_events.get(&b.origin);
        if let Some(event) = existing.filter(|event| event.order == *order) {
            let retained = match call.stage {
                LegalStage::SourceEmission if order.issuance_epoch == cut.authority_epoch => {
                    Some(LegalReply::Emitted(event.emitted))
                }
                LegalStage::ReceivingCommit => event.applied.map(LegalReply::Applied),
                _ => None,
            };
            if let Some(reply) = retained {
                return Ok(reply);
            }
        }
        let mode = self.regulation.transition(order, self.ledger.clock())?;
        match call.stage {
            LegalStage::SourceEmission => {
                if order.issuance_epoch != cut.authority_epoch || existing.is_some() {
                    return Err(Refusal::ConflictingOrder);
                }
                let commit = CommitRef {
                    position: self
                        .ledger
                        .commit_external_step()
                        .ok_or(Refusal::Unavailable)?,
                };
                self.regulation.legal_events.insert(
                    b.origin,
                    LegalEvent {
                        order: order.clone(),
                        emitted: commit,
                        applied: None,
                        published: None,
                    },
                );
                Ok(LegalReply::Emitted(commit))
            }
            LegalStage::ReceivingCommit => {
                if !existing.is_some_and(|event| event.order == *order) {
                    return Err(Refusal::ConflictingOrder);
                }
                let commit = CommitRef {
                    position: self
                        .ledger
                        .commit_external_step()
                        .ok_or(Refusal::Unavailable)?,
                };
                self.regulation.applied(order, mode);
                self.regulation
                    .legal_events
                    .get_mut(&b.origin)
                    .expect("checked issued order")
                    .applied = Some(commit);
                Ok(LegalReply::Applied(commit))
            }
        }
    }

    fn apply_spend(&mut self, call: &SpendCall<'_>) -> SpendReply {
        let payload = call.payload;
        let scope = payload.scope;
        let root = scope.root;
        let cut = self.ledger.current_cut();
        if call.expected != cut || payload.cut != cut {
            return SpendReply::Busy;
        }
        let Some(&mode) = self.regulation.modes.get(&(root.destination, root.asset)) else {
            return SpendReply::Rejected;
        };
        let (jurisdiction, legal_basis) = match (scope.kind, call.enforcement) {
            (SpendKind::Ordinary, None) if !mode.protected() => (0, 0),
            (SpendKind::Ordinary, _) => return SpendReply::Rejected,
            (_, Some(order))
                if order.scope == scope
                    && order.officer == call.actor.0
                    && order.legal_basis != 0
                    && order.assets.contains(&root.asset) =>
            {
                if scope.kind == SpendKind::Confiscate {
                    let Some((key, seizure)) = self.regulation.active_seizure(root) else {
                        return SpendReply::Rejected;
                    };
                    if !matches!(mode, Mode::Seized | Mode::Confiscated)
                        || order.prior_seizure != Some(key)
                        || RegulationState::deadline(
                            seizure,
                            order.appeal_deadline,
                            self.ledger.clock(),
                        )
                        .is_err()
                    {
                        return SpendReply::Rejected;
                    }
                }
                (order.jurisdiction, order.legal_basis)
            }
            _ => return SpendReply::Rejected,
        };
        if !self.regulation.policy.spend.contains(&SpendGrant {
            route: call.route,
            actor: call.actor.0,
            epoch: cut.authority_epoch,
            scope,
            jurisdiction,
            legal_basis,
        }) {
            return SpendReply::Rejected;
        }
        let Some(slot) = self.origins.get(&root.origin) else {
            return SpendReply::Rejected;
        };
        let Some(decision) = slot.decision else {
            return SpendReply::Rejected;
        };
        if slot.binding != root
            || slot.epoch != payload.origin_epoch
            || decision.kind != TerminalKind::Confirmed
            || decision.commit != payload.reference
            || slot.settled.is_none()
            || slot.published.is_none()
        {
            return SpendReply::Rejected;
        }
        match self
            .ledger
            .spend_funding(root, scope.sender, scope.recipient, scope.amount)
        {
            Some(position) => SpendReply::Executed {
                root: root.origin,
                commit: CommitRef { position },
            },
            None => SpendReply::Rejected,
        }
    }
}

impl ReadAuthority {
    /// Enables legal state only at genesis using an authenticated policy loader.
    pub(crate) fn new_regulated(
        mut authority: super::Authority,
        provider: u64,
        policy: Policy,
    ) -> Option<Self> {
        if authority.current_cut().revision != 0 || authority.outcome_count() != 0 {
            return None;
        }
        authority.state.primary.regulation =
            RegulationState::configured(policy, &authority.state.primary.ledger)?;
        authority.state.read_history = ReadHistory::new(&authority.state.primary);
        Some(Self::new(authority, provider))
    }

    fn regulated_access(
        &self,
        actor: AuthenticatedCaller,
        id: CallId,
        caller: Principal,
        session: SessionId,
    ) -> bool {
        id.namespace == actor.0
            && caller == actor.0
            && self
                .authority
                .state
                .primary
                .ledger
                .session_bound(actor, session)
    }

    pub fn submit_order(
        &mut self,
        call: LegalCall<'_>,
        verify: impl FnOnce(&LegalCall<'_>) -> bool,
    ) -> LegalReply {
        if !self.regulated_access(
            call.actor,
            call.id,
            call.payload.caller,
            call.payload.session,
        ) || call.actor.0 != call.order.officer
            || !verify(&call)
        {
            return LegalReply::Refused(Refusal::InvalidAuthority);
        }
        if !self.authority.up {
            return LegalReply::Refused(Refusal::Unavailable);
        }
        let current = &self.authority.state.primary;
        if let Some(receipt) = current.regulation.legal_receipts.get(&call.id) {
            return if receipt.stage == call.stage
                && receipt.order == *call.order
                && receipt.payload == call.payload
            {
                receipt.reply
            } else {
                LegalReply::Refused(Refusal::ConflictingOrder)
            };
        }
        if current.regulation.spend_receipts.contains_key(&call.id)
            || current.calls.contains_key(&call.id)
        {
            return LegalReply::Refused(Refusal::ConflictingOrder);
        }
        let mut next = current.clone();
        let before = next.ledger.current_cut();
        let reply = if self.available() {
            next.apply_order(&call).unwrap_or_else(LegalReply::Refused)
        } else {
            LegalReply::Refused(Refusal::Unavailable)
        };
        let target = match call.stage {
            LegalStage::SourceEmission => call.order.binding.origin.domain,
            LegalStage::ReceivingCommit => call.order.binding.destination,
        };
        next.note_execution(call.id, target, before);
        next.regulation.legal_receipts.insert(
            call.id,
            LegalReceipt {
                stage: call.stage,
                order: call.order.clone(),
                payload: call.payload,
                reply,
            },
        );
        self.authority.commit_primary(next);
        reply
    }

    pub fn submit_spend(
        &mut self,
        call: SpendCall<'_>,
        verify: impl FnOnce(&SpendCall<'_>) -> bool,
    ) -> SpendReply {
        if !self.regulated_access(
            call.actor,
            call.id,
            call.payload.caller,
            call.payload.session,
        ) || !verify(&call)
        {
            return SpendReply::Rejected;
        }
        if !self.authority.up {
            return SpendReply::Unavailable;
        }
        let current = &self.authority.state.primary;
        if let Some(receipt) = current.regulation.spend_receipts.get(&call.id) {
            return if receipt.payload == call.payload
                && receipt.enforcement.as_ref() == call.enforcement
            {
                receipt.reply
            } else {
                SpendReply::Rejected
            };
        }
        if current.regulation.legal_receipts.contains_key(&call.id)
            || current.calls.contains_key(&call.id)
        {
            return SpendReply::Rejected;
        }
        let mut next = current.clone();
        let before = next.ledger.current_cut();
        let reply = if self.available() {
            next.apply_spend(&call)
        } else {
            SpendReply::Unavailable
        };
        next.note_execution(call.id, call.payload.scope.root.destination, before);
        next.regulation.spend_receipts.insert(
            call.id,
            SpendReceipt {
                payload: call.payload,
                enforcement: call.enforcement.cloned(),
                reply,
            },
        );
        self.authority.commit_primary(next);
        reply
    }

    /// The verifier is a trusted time-source adapter, not a client clock.
    pub fn observe_regulatory_time(
        &mut self,
        actor: AuthenticatedCaller,
        session: SessionId,
        expected: CommitCut,
        now: u64,
        verify: impl FnOnce(AuthenticatedCaller, CommitCut, u64) -> bool,
    ) -> bool {
        let current = &self.authority.state.primary;
        if !self.available()
            || expected != self.current_cut()
            || !current.ledger.session_bound(actor, session)
            || !current
                .regulation
                .policy
                .clock_observers
                .contains(&(actor.0, expected.authority_epoch))
            || !verify(actor, expected, now)
        {
            return false;
        }
        let mut next = current.clone();
        if !next.ledger.observe_clock(now) {
            return false;
        }
        self.authority.commit_primary(next);
        true
    }
}

#[cfg(test)]
mod vector_tests;
