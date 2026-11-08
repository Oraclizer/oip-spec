//! Checked in-memory lock and finality ledger.
//!
//! Authentication, envelope verification and terminal attestation are supplied
//! by trusted adapters. The ledger owns the only financial mutation path.

use crate::{
    AssetId, AuthenticatedCaller, CommitCut, OriginKey, Principal, SessionBinding, SessionId,
};
use std::collections::{BTreeMap, BTreeSet};

pub type EndpointId = u64;
pub type RecordRef = u64;

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct Account {
    pub endpoint: EndpointId,
    pub owner: Principal,
    pub asset: AssetId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Binding {
    pub origin: OriginKey,
    pub asset: AssetId,
    pub owner: Principal,
    pub destination: EndpointId,
    pub recipient: Principal,
    pub amount: u64,
}

impl Binding {
    pub fn source(self) -> Account {
        Account {
            endpoint: self.origin.domain,
            owner: self.owner,
            asset: self.asset,
        }
    }

    pub fn destination(self) -> Account {
        Account {
            endpoint: self.destination,
            owner: self.recipient,
            asset: self.asset,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    pub asset: AssetId,
    pub origin: OriginKey,
    pub holder: Principal,
    pub generation: u64,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TerminalKind {
    Confirmed,
    Reversed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TerminalEvidence {
    pub binding: Binding,
    pub kind: TerminalKind,
    pub reference: RecordRef,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum Route {
    Normal,
    Administrative,
    Adapter,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum Permission {
    Reserve,
    Dispatch,
    Debit,
    Cancel,
    Fence,
    Preempt,
    ObserveTime,
    Attest,
    Credit,
    Refund,
    Reconcile,
    Write,
    PublishPrimary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Command {
    Reserve {
        duration: u64,
    },
    Dispatch {
        generation: u64,
    },
    Debit {
        generation: u64,
    },
    Cancel {
        generation: u64,
    },
    Fence {
        generation: u64,
    },
    Preempt {
        duration: u64,
    },
    Timeout {
        elapsed: u64,
    },
    /// Terminal evidence verified by the attesting adapter.
    RecordTerminal(TerminalEvidence),
    Credit {
        reference: RecordRef,
    },
    Refund {
        generation: u64,
        reference: RecordRef,
    },
    Reconcile {
        generation: u64,
        reference: RecordRef,
    },
    Write {
        generation: u64,
        value: u64,
    },
    PublishPrimary,
}

impl Command {
    fn permission(self) -> Permission {
        match self {
            Self::Reserve { .. } => Permission::Reserve,
            Self::Dispatch { .. } => Permission::Dispatch,
            Self::Debit { .. } => Permission::Debit,
            Self::Cancel { .. } => Permission::Cancel,
            Self::Fence { .. } => Permission::Fence,
            Self::Preempt { .. } => Permission::Preempt,
            Self::Timeout { .. } => Permission::ObserveTime,
            Self::RecordTerminal(_) => Permission::Attest,
            Self::Credit { .. } => Permission::Credit,
            Self::Refund { .. } => Permission::Refund,
            Self::Reconcile { .. } => Permission::Reconcile,
            Self::Write { .. } => Permission::Write,
            Self::PublishPrimary => Permission::PublishPrimary,
        }
    }

    /// A present outer option requires a credential. A present inner option
    /// also binds the generation included in the signed command.
    fn lock_requirement(self) -> Option<Option<u64>> {
        match self {
            Self::Dispatch { generation }
            | Self::Debit { generation }
            | Self::Cancel { generation }
            | Self::Fence { generation }
            | Self::Refund { generation, .. }
            | Self::Reconcile { generation, .. }
            | Self::Write { generation, .. } => Some(Some(generation)),
            Self::Credit { .. } => Some(None),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'a> {
    pub endpoint: EndpointId,
    pub caller: Principal,
    pub session: SessionId,
    pub cut: CommitCut,
    pub binding: Binding,
    pub credential: Option<Credential>,
    /// Signed version vector. As in protocol vector lookup, absent entries are zero.
    pub versions: &'a [(AssetId, u64)],
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EndpointContext {
    pub endpoint: EndpointId,
    pub epoch: u64,
    pub grants: BTreeSet<(Principal, Route, Permission)>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    pub dependencies: BTreeMap<AssetId, BTreeSet<AssetId>>,
    pub write_permissions: BTreeSet<(Principal, AssetId, u64)>,
}

impl EndpointContext {
    fn footprint(&self, asset: AssetId) -> BTreeSet<AssetId> {
        let mut footprint = self.dependencies.get(&asset).cloned().unwrap_or_default();
        footprint.insert(asset);
        footprint
    }

    fn uses_registered_assets(&self, assets: &BTreeMap<AssetId, AssetData>) -> bool {
        self.dependencies.iter().all(|(asset, dependencies)| {
            assets.contains_key(asset)
                && dependencies
                    .iter()
                    .all(|member| assets.contains_key(member))
        }) && self
            .write_permissions
            .iter()
            .all(|(_, asset, _)| assets.contains_key(asset))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Held,
    Dispatched,
    Pending,
    Credited,
    Reconciled,
    Refunded,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Reply {
    Rejected,
    Busy,
    Reserved,
    SourceDispatched,
    Debited,
    Closed,
    Preempted,
    TimeObserved,
    Recorded,
    Credited,
    Reconciled,
    Refunded,
    DataUpdated,
    EvidenceRefreshed,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisError {
    InvalidContext,
    InvalidSupply,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AssetData {
    value: u64,
    version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct Reservation {
    binding: Binding,
    footprint: BTreeSet<AssetId>,
    holder: Principal,
    generation: u64,
    expires: u64,
    phase: Phase,
    terminal: Option<RecordRef>,
}

fn origin_key(origin: OriginKey) -> (EndpointId, u64) {
    (origin.domain, origin.event)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DurableLedger {
    cut: CommitCut,
    clock: u64,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    balances: BTreeMap<Account, u64>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    root_funding: BTreeMap<(OriginKey, Account), u64>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    assets: BTreeMap<AssetId, AssetData>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    active: BTreeMap<AssetId, OriginKey>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    reservations: BTreeMap<(EndpointId, u64), Reservation>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    evidence: BTreeMap<RecordRef, TerminalEvidence>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    contexts: BTreeMap<EndpointId, EndpointContext>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    sessions: BTreeMap<SessionId, SessionBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LedgerProjection {
    #[serde(with = "crate::authority::recovery::ordered_map")]
    pub(crate) balances: BTreeMap<Account, u64>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    pub(crate) root_funding: BTreeMap<(OriginKey, Account), u64>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    pub(crate) asset_values: BTreeMap<AssetId, u64>,
    pub(crate) locked_assets: BTreeSet<AssetId>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Ledger {
    state: DurableLedger,
    maintainers: BTreeSet<Principal>,
    #[serde(skip, default = "default_connected")]
    connected: bool,
}

fn default_connected() -> bool {
    true
}

impl Ledger {
    pub(crate) fn new(
        epoch: u64,
        contexts: Vec<EndpointContext>,
        sessions: BTreeMap<SessionId, SessionBinding>,
        maintainers: BTreeSet<Principal>,
        balances: BTreeMap<Account, u64>,
        supply: &BTreeMap<AssetId, u128>,
    ) -> Result<Self, GenesisError> {
        let contexts = Self::batch(epoch, contexts).ok_or(GenesisError::InvalidContext)?;
        if sessions
            .values()
            .any(|session| session.authority_epoch != epoch)
        {
            return Err(GenesisError::InvalidContext);
        }
        let assets = supply
            .keys()
            .map(|&asset| (asset, AssetData::default()))
            .collect();
        if !contexts
            .values()
            .all(|context| context.uses_registered_assets(&assets))
        {
            return Err(GenesisError::InvalidContext);
        }
        let mut totals = BTreeMap::<AssetId, u128>::new();
        for (&account, &amount) in &balances {
            if !contexts.contains_key(&account.endpoint) || !supply.contains_key(&account.asset) {
                return Err(GenesisError::InvalidSupply);
            }
            *totals.entry(account.asset).or_default() += u128::from(amount);
        }
        if supply
            .iter()
            .any(|(asset, amount)| totals.get(asset).copied().unwrap_or_default() != *amount)
        {
            return Err(GenesisError::InvalidSupply);
        }
        Ok(Self {
            state: DurableLedger {
                cut: CommitCut {
                    authority_epoch: epoch,
                    revision: 0,
                },
                clock: 0,
                balances,
                root_funding: BTreeMap::new(),
                assets,
                active: BTreeMap::new(),
                reservations: BTreeMap::new(),
                evidence: BTreeMap::new(),
                contexts,
                sessions,
            },
            maintainers,
            connected: true,
        })
    }

    fn batch(
        epoch: u64,
        contexts: Vec<EndpointContext>,
    ) -> Option<BTreeMap<EndpointId, EndpointContext>> {
        let mut batch = BTreeMap::new();
        for context in contexts {
            if context.epoch != epoch || batch.insert(context.endpoint, context).is_some() {
                return None;
            }
        }
        (!batch.is_empty()).then_some(batch)
    }

    /// Trusted maintenance entry point. All registered endpoints and sessions
    /// are validated before the replacement becomes visible.
    pub fn install_epoch(
        &mut self,
        actor: AuthenticatedCaller,
        epoch: u64,
        contexts: Vec<EndpointContext>,
        sessions: BTreeMap<SessionId, SessionBinding>,
    ) -> bool {
        let Some(contexts) = Self::batch(epoch, contexts) else {
            return false;
        };
        let Some(revision) = self.state.cut.revision.checked_add(contexts.len()) else {
            return false;
        };
        if !self.maintainers.contains(&actor.0)
            || epoch <= self.state.cut.authority_epoch
            || contexts.keys().ne(self.state.contexts.keys())
            || !contexts
                .values()
                .all(|context| context.uses_registered_assets(&self.state.assets))
            || sessions
                .values()
                .any(|session| session.authority_epoch != epoch)
        {
            return false;
        }
        self.state.contexts = contexts;
        self.state.sessions = sessions;
        self.state.cut = CommitCut {
            authority_epoch: epoch,
            revision,
        };
        true
    }

    /// A trusted driver signal affects availability without writing the ledger.
    #[cfg(test)]
    pub fn driver_connection(&mut self, connected: bool) {
        self.connected = connected;
    }

    pub(crate) fn project_reads(&self) -> LedgerProjection {
        LedgerProjection {
            balances: self.state.balances.clone(),
            root_funding: self.state.root_funding.clone(),
            asset_values: self
                .state
                .assets
                .iter()
                .map(|(&asset, data)| (asset, data.value))
                .collect(),
            locked_assets: self.state.active.keys().copied().collect(),
        }
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> DurableLedger {
        self.state.clone()
    }

    pub(crate) fn is_genesis(&self) -> bool {
        self.connected && self.state.cut.revision == 0
    }

    pub(crate) fn is_maintainer(&self, actor: AuthenticatedCaller) -> bool {
        self.maintainers.contains(&actor.0)
    }

    pub(crate) fn handover_sessions(
        &self,
        old: SessionId,
        new: SessionId,
        successor: Principal,
        epoch: u64,
    ) -> Option<BTreeMap<SessionId, SessionBinding>> {
        if old == new || self.state.sessions.contains_key(&new) {
            return None;
        }
        let mut sessions = self.state.sessions.clone();
        sessions.remove(&old)?;
        for binding in sessions.values_mut() {
            binding.authority_epoch = epoch;
        }
        sessions.insert(
            new,
            SessionBinding {
                principal: successor,
                authority_epoch: epoch,
            },
        );
        Some(sessions)
    }

    pub(crate) fn session_bound(&self, actor: AuthenticatedCaller, session: SessionId) -> bool {
        self.state.sessions.get(&session)
            == Some(&SessionBinding {
                principal: actor.0,
                authority_epoch: self.state.cut.authority_epoch,
            })
    }

    pub fn current_cut(&self) -> CommitCut {
        self.state.cut
    }

    pub fn balance(&self, account: Account) -> u64 {
        self.state
            .balances
            .get(&account)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn has_asset(&self, asset: AssetId) -> bool {
        self.state.assets.contains_key(&asset)
    }

    pub(crate) fn registered_assets(&self) -> impl Iterator<Item = &AssetId> {
        self.state.assets.keys()
    }

    pub(crate) fn has_consistent_endpoint_registry(&self) -> bool {
        !self.state.contexts.is_empty()
            && self.state.contexts.iter().all(|(endpoint, context)| {
                *endpoint == context.endpoint && context.epoch == self.state.cut.authority_epoch
            })
    }

    pub(crate) fn preserves_registered_endpoints(&self, previous: &Self) -> bool {
        self.state.contexts.keys().eq(previous.state.contexts.keys())
    }

    pub(crate) fn has_endpoint(&self, endpoint: EndpointId) -> bool {
        self.state.contexts.contains_key(&endpoint)
    }

    pub(crate) fn clock(&self) -> u64 {
        self.state.clock
    }

    pub(crate) fn commit_external_step(&mut self) -> Option<usize> {
        let position = self.state.cut.revision;
        self.state.cut.revision = position.checked_add(1)?;
        Some(position)
    }

    pub(crate) fn observe_clock(&mut self, now: u64) -> bool {
        if now < self.state.clock || self.commit_external_step().is_none() {
            return false;
        }
        self.state.clock = now;
        true
    }

    fn unallocated_balance(&self, account: Account) -> u64 {
        self.state
            .root_funding
            .iter()
            .filter_map(|((_, holder), amount)| (*holder == account).then_some(*amount))
            .try_fold(self.balance(account), u64::checked_sub)
            .unwrap_or_default()
    }

    pub(crate) fn spend_funding(
        &mut self,
        root: Binding,
        sender: Principal,
        recipient: Principal,
        amount: u64,
    ) -> Option<usize> {
        if amount == 0 {
            return None;
        }
        let source = Account {
            owner: sender,
            ..root.destination()
        };
        let destination = Account {
            owner: recipient,
            ..root.destination()
        };
        let from_key = (root.origin, source);
        let to_key = (root.origin, destination);
        let source_funding = self
            .state
            .root_funding
            .get(&from_key)
            .copied()?
            .checked_sub(amount)?;
        let source_balance = self.balance(source).checked_sub(amount)?;
        if source == destination {
            return self.commit_external_step();
        }
        let destination_funding = self
            .state
            .root_funding
            .get(&to_key)
            .copied()
            .unwrap_or_default()
            .checked_add(amount)?;
        let destination_balance = self.balance(destination).checked_add(amount)?;
        let position = self.commit_external_step()?;
        self.state.root_funding.insert(from_key, source_funding);
        self.state.root_funding.insert(to_key, destination_funding);
        self.state.balances.insert(source, source_balance);
        self.state.balances.insert(destination, destination_balance);
        Some(position)
    }

    pub fn pending(&self, origin: OriginKey) -> u64 {
        self.reservation(origin)
            .filter(|r| r.phase == Phase::Pending)
            .map_or(0, |r| r.binding.amount)
    }

    pub(crate) fn phase(&self, origin: OriginKey) -> Option<Phase> {
        self.reservation(origin)
            .map(|reservation| reservation.phase)
    }

    pub(crate) fn settled_origins(&self) -> impl Iterator<Item = OriginKey> + '_ {
        self.state.reservations.iter().filter_map(|(&(domain, event), reservation)| {
            matches!(reservation.phase, Phase::Credited | Phase::Reconciled | Phase::Refunded)
                .then_some(OriginKey { domain, event })
        })
    }

    pub(crate) fn open_source_binding(&self, origin: OriginKey) -> Option<Binding> {
        let reservation = self.reservation(origin)?;
        matches!(
            reservation.phase,
            Phase::Dispatched | Phase::Pending | Phase::Credited
        )
        .then_some(reservation.binding)
    }

    pub(crate) fn recovery_binding(&self, origin: OriginKey) -> Option<Binding> {
        let reservation = self.reservation(origin)?;
        (matches!(
            reservation.phase,
            Phase::Held | Phase::Dispatched | Phase::Pending | Phase::Credited
        ) && self.owns_footprint(reservation))
        .then_some(reservation.binding)
    }

    pub fn generation(&self, origin: OriginKey) -> Option<u64> {
        self.reservation(origin).map(|r| r.generation)
    }

    pub fn evidence(&self, reference: RecordRef) -> Option<TerminalEvidence> {
        self.state.evidence.get(&reference).copied()
    }

    pub fn lock_owner(&self, asset: AssetId) -> Option<OriginKey> {
        self.state.active.get(&asset).copied()
    }

    #[cfg(test)]
    pub fn asset_data(&self, asset: AssetId) -> Option<(u64, u64)> {
        self.state
            .assets
            .get(&asset)
            .map(|data| (data.value, data.version))
    }

    fn reservation(&self, origin: OriginKey) -> Option<&Reservation> {
        self.state.reservations.get(&origin_key(origin))
    }

    #[cfg(test)]
    pub fn submit_normal(
        &mut self,
        actor: AuthenticatedCaller,
        request: Request<'_>,
        verify: impl FnOnce(AuthenticatedCaller, Route, &Request<'_>) -> bool,
    ) -> Reply {
        self.submit(Route::Normal, actor, request, verify)
    }

    #[cfg(test)]
    pub fn submit_administrative(
        &mut self,
        actor: AuthenticatedCaller,
        request: Request<'_>,
        verify: impl FnOnce(AuthenticatedCaller, Route, &Request<'_>) -> bool,
    ) -> Reply {
        self.submit(Route::Administrative, actor, request, verify)
    }

    #[cfg(test)]
    pub fn submit_adapter(
        &mut self,
        actor: AuthenticatedCaller,
        request: Request<'_>,
        verify: impl FnOnce(AuthenticatedCaller, Route, &Request<'_>) -> bool,
    ) -> Reply {
        self.submit(Route::Adapter, actor, request, verify)
    }

    pub(crate) fn request_admitted(
        &self,
        route: Route,
        actor: AuthenticatedCaller,
        request: Request<'_>,
    ) -> bool {
        let endpoint = match request.command {
            Command::Credit { .. } => request.binding.destination,
            _ => request.binding.origin.domain,
        };
        let grant = (actor.0, route, request.command.permission());
        self.connected
            && request.caller == actor.0
            && request.cut == self.state.cut
            && request.endpoint == endpoint
            && self.state.assets.contains_key(&request.binding.asset)
            && self
                .state
                .contexts
                .contains_key(&request.binding.destination)
            && self
                .state
                .contexts
                .get(&endpoint)
                .is_some_and(|context| context.grants.contains(&grant))
            && self.session_bound(actor, request.session)
    }

    pub(crate) fn submit(
        &mut self,
        route: Route,
        actor: AuthenticatedCaller,
        request: Request<'_>,
        verify: impl FnOnce(AuthenticatedCaller, Route, &Request<'_>) -> bool,
    ) -> Reply {
        let Some(revision) = self.state.cut.revision.checked_add(1) else {
            return Reply::Rejected;
        };
        if !self.request_admitted(route, actor, request)
            || !verify(actor, route, &request)
            || !self.credential_matches(actor, request)
        {
            return Reply::Rejected;
        }
        let reply = self.apply(actor, request);
        if !matches!(reply, Reply::Rejected | Reply::Busy) {
            self.state.cut.revision = revision;
        }
        reply
    }

    fn bound_credential(
        &self,
        actor: AuthenticatedCaller,
        request: Request<'_>,
        signed_generation: Option<u64>,
    ) -> Option<&Reservation> {
        let token = request.credential?;
        let binding = request.binding;
        let current = self.reservation(binding.origin)?;
        (token.asset == binding.asset
            && token.origin == binding.origin
            && current.binding == binding
            && token.holder == current.holder
            && current.holder == actor.0
            && token.generation == current.generation
            && signed_generation.is_none_or(|g| g == current.generation)
            && token.epoch == self.state.cut.authority_epoch)
            .then_some(current)
    }

    fn credential_matches(&self, actor: AuthenticatedCaller, request: Request<'_>) -> bool {
        let Some(signed_generation) = request.command.lock_requirement() else {
            return request.credential.is_none();
        };
        self.bound_credential(actor, request, signed_generation)
            .is_some_and(|current| {
                self.state.active.get(&request.binding.asset) == Some(&request.binding.origin)
                    && (matches!(request.command, Command::Credit { .. })
                        || self.recorded_lease_matches(current, request))
            })
    }

    /// Receipt lookup uses the recorded holder and generation even when the
    /// settlement closed the lease. It cannot authorize any ledger effect.
    pub(crate) fn receipt_credential_matches(
        &self,
        actor: AuthenticatedCaller,
        request: Request<'_>,
    ) -> bool {
        match request.command.lock_requirement() {
            Some(generation) => self.bound_credential(actor, request, generation).is_some(),
            None => request.credential.is_none(),
        }
    }

    fn recorded_lease_matches(&self, reservation: &Reservation, request: Request<'_>) -> bool {
        let requires_current = matches!(
            request.command,
            Command::Dispatch { .. } | Command::Debit { .. } | Command::Write { .. }
        );
        self.owns_footprint(reservation)
            && self.versions_match(&reservation.footprint, request.versions)
            && (!requires_current
                || self.state.contexts[&request.endpoint].footprint(request.binding.asset)
                    == reservation.footprint)
    }

    fn owns_footprint(&self, reservation: &Reservation) -> bool {
        reservation
            .footprint
            .iter()
            .all(|asset| self.state.active.get(asset) == Some(&reservation.binding.origin))
    }

    fn versions_match(&self, footprint: &BTreeSet<AssetId>, versions: &[(AssetId, u64)]) -> bool {
        footprint.iter().all(|asset| {
            let expected = versions
                .iter()
                .find_map(|(id, version)| (id == asset).then_some(*version))
                .unwrap_or_default();
            expected == self.state.assets[asset].version
        })
    }

    fn apply(&mut self, actor: AuthenticatedCaller, request: Request<'_>) -> Reply {
        let binding = request.binding;
        if let Command::Reserve { duration } = request.command {
            return self.reserve(actor, request, duration);
        }
        let Some(mut reservation) = self.reservation(binding.origin).cloned() else {
            return Reply::Rejected;
        };
        if reservation.binding != binding {
            return Reply::Rejected;
        }
        let reply = match request.command {
            Command::Dispatch { .. }
                if reservation.phase == Phase::Held
                    && self.state.clock < reservation.expires
                    && binding.amount > 0
                    && self.unallocated_balance(binding.source()) >= binding.amount =>
            {
                reservation.phase = Phase::Dispatched;
                Reply::SourceDispatched
            }
            Command::Debit { .. }
                if self.state.clock < reservation.expires && binding.amount > 0 =>
            {
                if reservation.phase != Phase::Dispatched {
                    return Reply::Rejected;
                }
                if self.unallocated_balance(binding.source()) < binding.amount {
                    return Reply::Rejected;
                }
                let Some(balance) = self.balance(binding.source()).checked_sub(binding.amount)
                else {
                    return Reply::Rejected;
                };
                self.state.balances.insert(binding.source(), balance);
                reservation.phase = Phase::Pending;
                Reply::Debited
            }
            Command::Cancel { .. }
                if reservation.phase == Phase::Held && self.state.clock < reservation.expires =>
            {
                self.close(&mut reservation)
            }
            Command::Fence { .. }
                if reservation.phase == Phase::Dispatched
                    && self.state.clock < reservation.expires =>
            {
                self.close(&mut reservation)
            }
            Command::Preempt { duration } => self.preempt(actor, &mut reservation, duration),
            Command::Timeout { elapsed } => {
                let Some(now) = self.state.clock.checked_add(elapsed) else {
                    return Reply::Rejected;
                };
                self.state.clock = now;
                Reply::TimeObserved
            }
            Command::RecordTerminal(evidence) => self.record_terminal(&mut reservation, evidence),
            Command::PublishPrimary
                if matches!(
                    reservation.phase,
                    Phase::Credited | Phase::Reconciled | Phase::Refunded
                ) =>
            {
                Reply::Published
            }
            Command::Credit { reference } => {
                self.settle(&mut reservation, reference, TerminalKind::Confirmed)
            }
            Command::Refund { reference, .. } if self.state.clock < reservation.expires => {
                self.settle(&mut reservation, reference, TerminalKind::Reversed)
            }
            Command::Reconcile { reference, .. }
                if reservation.phase == Phase::Credited
                    && self.state.clock < reservation.expires
                    && self.exact_terminal(&reservation, reference, TerminalKind::Confirmed) =>
            {
                self.release_footprint(&reservation);
                reservation.phase = Phase::Reconciled;
                Reply::Reconciled
            }
            Command::Write { value, .. }
                if reservation.phase == Phase::Held
                    && self.state.clock < reservation.expires
                    && self.state.contexts[&request.endpoint]
                        .write_permissions
                        .contains(&(actor.0, binding.asset, value)) =>
            {
                let data = self
                    .state
                    .assets
                    .get_mut(&binding.asset)
                    .expect("registered asset");
                let Some(version) = data.version.checked_add(1) else {
                    return Reply::Rejected;
                };
                *data = AssetData { value, version };
                Reply::DataUpdated
            }
            _ => Reply::Rejected,
        };
        if reply != Reply::Rejected {
            self.state
                .reservations
                .insert(origin_key(binding.origin), reservation);
        }
        reply
    }

    fn reserve(
        &mut self,
        actor: AuthenticatedCaller,
        request: Request<'_>,
        duration: u64,
    ) -> Reply {
        let Some(expires) = self.state.clock.checked_add(duration) else {
            return Reply::Rejected;
        };
        let binding = request.binding;
        let footprint = self.state.contexts[&request.endpoint].footprint(binding.asset);
        if duration == 0
            || self
                .state
                .reservations
                .contains_key(&origin_key(binding.origin))
            || !self.versions_match(&footprint, request.versions)
        {
            return Reply::Rejected;
        }
        if footprint
            .iter()
            .any(|asset| self.state.active.contains_key(asset))
        {
            return Reply::Busy;
        }
        for &asset in &footprint {
            self.state.active.insert(asset, binding.origin);
        }
        self.state.reservations.insert(
            origin_key(binding.origin),
            Reservation {
                binding,
                footprint,
                holder: actor.0,
                generation: 0,
                expires,
                phase: Phase::Held,
                terminal: None,
            },
        );
        Reply::Reserved
    }

    fn release_footprint(&mut self, reservation: &Reservation) {
        for asset in &reservation.footprint {
            self.state.active.remove(asset);
        }
    }

    fn close(&mut self, reservation: &mut Reservation) -> Reply {
        self.release_footprint(reservation);
        reservation.phase = Phase::Closed;
        Reply::Closed
    }

    fn preempt(
        &self,
        actor: AuthenticatedCaller,
        reservation: &mut Reservation,
        duration: u64,
    ) -> Reply {
        let Some(expires) = self.state.clock.checked_add(duration) else {
            return Reply::Rejected;
        };
        let Some(generation) = reservation.generation.checked_add(1) else {
            return Reply::Rejected;
        };
        if duration == 0
            || self.state.clock < reservation.expires
            || !self.owns_footprint(reservation)
        {
            return Reply::Rejected;
        }
        reservation.holder = actor.0;
        reservation.generation = generation;
        reservation.expires = expires;
        Reply::Preempted
    }

    fn record_terminal(
        &mut self,
        reservation: &mut Reservation,
        evidence: TerminalEvidence,
    ) -> Reply {
        if evidence.binding != reservation.binding
            || self.state.evidence.contains_key(&evidence.reference)
        {
            return Reply::Rejected;
        }
        let reply = if let Some(primary) = reservation.terminal {
            if !self
                .state
                .evidence
                .get(&primary)
                .is_some_and(|original| original.kind == evidence.kind)
            {
                return Reply::Rejected;
            }
            Reply::EvidenceRefreshed
        } else {
            if reservation.phase != Phase::Pending {
                return Reply::Rejected;
            }
            reservation.terminal = Some(evidence.reference);
            Reply::Recorded
        };
        self.state.evidence.insert(evidence.reference, evidence);
        reply
    }

    fn exact_terminal(
        &self,
        reservation: &Reservation,
        reference: RecordRef,
        kind: TerminalKind,
    ) -> bool {
        reservation.terminal.is_some()
            && self.evidence(reference).is_some_and(|evidence| {
                evidence.kind == kind && evidence.binding == reservation.binding
            })
    }

    fn settle(
        &mut self,
        reservation: &mut Reservation,
        reference: RecordRef,
        kind: TerminalKind,
    ) -> Reply {
        if reservation.phase != Phase::Pending || !self.exact_terminal(reservation, reference, kind)
        {
            return Reply::Rejected;
        }
        let binding = reservation.binding;
        let (account, phase, reply) = match kind {
            TerminalKind::Confirmed => (binding.destination(), Phase::Credited, Reply::Credited),
            TerminalKind::Reversed => (binding.source(), Phase::Refunded, Reply::Refunded),
        };
        let Some(balance) = self.balance(account).checked_add(binding.amount) else {
            return Reply::Rejected;
        };
        self.state.balances.insert(account, balance);
        // Credit consumes pending mass but retains the lock until source
        // reconciliation. Reversal returns the funds and closes the lock.
        if kind == TerminalKind::Reversed {
            self.release_footprint(reservation);
        } else {
            self.state
                .root_funding
                .insert((binding.origin, account), binding.amount);
        }
        reservation.phase = phase;
        reply
    }
}

#[cfg(test)]
mod vector_tests;
