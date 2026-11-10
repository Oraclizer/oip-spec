//! Authenticated product boundary. The adapter is installed by the trusted
//! authority host and is not supplied by request callers.

use super::reads::{
    CacheEntry, CheckedExecution, CurrentRead, HistoricalRead, Query, ReadAuthority, ReadError,
    Reader, Value,
};
use super::regulation::{
    EnforcementOrder, LegalCall, LegalDecision, LegalPayload, LegalReply, LegalStage, Order,
    Policy, RegulatoryRoute, SpendCall, SpendPayload, SpendReply,
};
use super::sync;
use super::{
    Acknowledgement, Authority, CallPayload, Collection, OriginDecision, SecondaryJob,
    SettlementKey,
};
use crate::lock_finality::{
    Account, Command, EndpointContext, EndpointId, Ledger, Phase, Route, TerminalEvidence,
};
use crate::{
    AssetId, AuthenticatedCaller, CallId, CommitCut, OriginKey, Principal, SessionBinding,
    SessionId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub principal: Principal,
    pub domain: EndpointId,
    pub ocid: u64,
    pub rai: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionProof {
    pub session: SessionId,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Entry {
    Normal,
    Administrative,
    ForceInclusion,
    Upgrade,
    Adapter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Execute,
    EmitOrder,
    CommitOrder,
    Spend,
    Receipt,
    Current,
    Historical,
    Raw,
    Status,
    Journal,
    ReadOwner,
    TransferOwner,
    RecoverClaim,
    FullResync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadRequest {
    Current { query: Query, expected: CommitCut },
    Historical { query: Query, revision: usize },
    Raw(Query),
    Status(OriginKey),
    Journal,
    CaptureCache(Query),
    Owner(AssetId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    Asset(AssetId),
    Read(ReadRequest),
    Commitment(sync::Stream),
}

#[derive(Clone, Copy, Debug)]
pub enum Action<'a> {
    Ordinary(&'a CallPayload),
    Legal {
        stage: LegalStage,
        order: &'a Order,
        payload: LegalPayload,
    },
    Spend {
        payload: SpendPayload,
        enforcement: Option<&'a EnforcementOrder>,
    },
    SyncCommitment(sync::Call<'a>),
}

#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub target: EndpointId,
    pub id: CallId,
    pub expected: CommitCut,
    pub action: Action<'a>,
}

#[derive(Clone, Copy, Debug)]
pub enum Signed<'a> {
    Call {
        id: CallId,
        action: Action<'a>,
    },
    Read(ReadRequest),
    Recovery {
        origin: OriginKey,
        id: CallId,
        payload: &'a CallPayload,
    },
}

pub trait Security {
    type Token;
    type Signature;
    type MaintenanceToken;

    /// The ordered control service that owns revocation for this adapter.
    fn ordered_revocation_profile(&self) -> Option<super::recovery::RecoveryProfile> {
        None
    }

    fn requires_authority_binding(&self) -> bool {
        false
    }

    /// Commitment to the installed authority policy at this product epoch.
    fn authority_binding(&self, _epoch: u64) -> Option<[u8; 32]> {
        None
    }

    /// The policy the current provider may retain through an authorized
    /// epoch transition. Normal ingress still requires the active binding.
    fn prepared_authority_binding(&self, epoch: u64) -> Option<[u8; 32]> {
        self.authority_binding(epoch)
    }

    fn handover_policy_binding(
        &self, proposal: &Handover, _sessions: &BTreeMap<SessionId, SessionBinding>,
    ) -> Option<[u8; 32]> {
        self.prepared_authority_binding(proposal.epoch)
    }

    fn authenticate(&self, token: &Self::Token) -> Option<Identity>;

    fn authenticate_session(&self, token: &Self::Token, _proof: SessionProof) -> Option<Identity> {
        self.authenticate(token)
    }
    fn authenticate_maintenance(&self, token: &Self::MaintenanceToken) -> Option<Principal>;
    fn permit(
        &self,
        identity: Identity,
        target: EndpointId,
        operation: Operation,
        scope: Scope,
        epoch: u64,
    ) -> bool;
    fn permit_session(
        &self,
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        operation: Operation,
        scope: Scope,
    ) -> bool {
        self.permit(identity, target, operation, scope, proof.epoch)
    }
    fn verify_commitment_attestation(&self, _call: &sync::Call<'_>) -> bool {
        false
    }
    fn verify(
        &self,
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        operation: Operation,
        signed: Signed<'_>,
        signature: &Self::Signature,
    ) -> bool;
    fn verify_recovery_evidence(&self, _evidence: TerminalEvidence) -> bool {
        false
    }

    fn verify_terminal(
        &self,
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        evidence: TerminalEvidence,
    ) -> bool;
    fn verify_terminal_packet(
        &self, identity: Identity, proof: SessionProof, target: EndpointId,
        _payload: &CallPayload, evidence: TerminalEvidence, _signature: &Self::Signature,
    ) -> bool {
        self.verify_terminal(identity, proof, target, evidence)
    }

    fn verify_order(
        &self,
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        stage: LegalStage,
        order: &Order,
    ) -> bool;
    fn verify_enforcement(
        &self,
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        order: &EnforcementOrder,
    ) -> bool;
    fn verify_order_packet(
        &self, identity: Identity, proof: SessionProof, target: EndpointId,
        stage: LegalStage, _id: CallId, _payload: &LegalPayload, order: &Order,
        _signature: &Self::Signature,
    ) -> bool {
        self.verify_order(identity, proof, target, stage, order)
    }

    fn verify_enforcement_packet(
        &self, identity: Identity, proof: SessionProof, target: EndpointId,
        _id: CallId, _payload: &SpendPayload, order: &EnforcementOrder,
        _signature: &Self::Signature,
    ) -> bool {
        self.verify_enforcement(identity, proof, target, order)
    }

    fn verify_time(
        &self,
        maintainer: Principal,
        cut: CommitCut,
        now: u64,
        signature: &Self::Signature,
    ) -> bool;
    fn verify_ack(&self, acknowledgement: &Acknowledgement, signature: &Self::Signature) -> bool;
    fn approve(&self, identity: Identity, proposal: &Handover, signature: &Self::Signature)
    -> bool;
}

pub struct Credentials<'a, S: Security> {
    pub token: &'a S::Token,
    pub proof: SessionProof,
    pub signature: &'a S::Signature,
}

pub struct Consent<'a, S: Security> {
    pub token: &'a S::Token,
    pub signature: &'a S::Signature,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Handover {
    pub asset: AssetId,
    pub previous: Principal,
    pub successor: Principal,
    pub expected: CommitCut,
    pub old_session: SessionId,
    pub new_session: SessionId,
    pub epoch: u64,
    pub contexts: Vec<EndpointContext>,
}

pub struct Bootstrap {
    pub epoch: u64,
    pub provider: u64,
    pub settlement_target: EndpointId,
    pub contexts: Vec<EndpointContext>,
    pub sessions: BTreeMap<SessionId, SessionBinding>,
    pub maintainers: BTreeSet<Principal>,
    pub balances: BTreeMap<Account, u64>,
    pub supply: BTreeMap<AssetId, u128>,
    pub identities: Vec<Identity>,
    pub owners: BTreeMap<AssetId, Principal>,
    pub regulation: Option<Policy>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    Rejected,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionReply {
    Ordinary(CheckedExecution),
    Legal(LegalReply),
    Spend(SpendReply),
    SyncCommitment(sync::Outcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Receipt {
    Ordinary(Collection),
    Legal(LegalReply),
    Spend(SpendReply),
    SyncCommitment(sync::Outcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Transfer(OriginDecision),
    Legal(LegalDecision),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationStatus {
    pub phase: Option<Phase>,
    pub pending: u64,
    pub terminal: Option<Decision>,
    pub published: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Observation {
    Current(Result<CurrentRead, ReadError>),
    Historical(Result<HistoricalRead, ReadError>),
    Raw(Result<Value, ReadError>),
    Status(OperationStatus),
    Journal(Vec<CallId>),
    Cache(Result<CacheEntry, ReadError>),
    Owner(Option<Principal>),
}

#[derive(Clone, Copy)]
struct Claim {
    operation: Operation,
    caller: Principal,
    session: SessionId,
    epoch: u64,
    target: EndpointId,
    asset: AssetId,
}

impl Action<'_> {
    fn claim(self) -> Claim {
        match self {
            Self::Ordinary(payload) => Claim {
                operation: Operation::Execute,
                caller: payload.caller,
                session: payload.session,
                epoch: payload.cut.authority_epoch,
                target: payload.endpoint,
                asset: payload.binding.asset,
            },
            Self::Legal { stage, payload, .. } => {
                let (operation, target) = match stage {
                    LegalStage::SourceEmission => {
                        (Operation::EmitOrder, payload.binding.origin.domain)
                    }
                    LegalStage::ReceivingCommit => {
                        (Operation::CommitOrder, payload.binding.destination)
                    }
                };
                Claim {
                    operation,
                    target,
                    caller: payload.caller,
                    session: payload.session,
                    epoch: payload.cut.authority_epoch,
                    asset: payload.binding.asset,
                }
            }
            Self::Spend { payload, .. } => Claim {
                operation: Operation::Spend,
                caller: payload.caller,
                session: payload.session,
                epoch: payload.cut.authority_epoch,
                target: payload.scope.root.destination,
                asset: payload.scope.root.asset,
            },
            Self::SyncCommitment(call) => Claim {
                operation: Operation::Execute,
                caller: call.id.namespace,
                session: call.session,
                epoch: call.cut.authority_epoch,
                target: call.target,
                asset: call.stream.asset,
            },
        }
    }
}

impl ReadRequest {
    fn operation(self) -> Operation {
        match self {
            Self::Current { .. } | Self::CaptureCache(_) => Operation::Current,
            Self::Historical { .. } => Operation::Historical,
            Self::Raw(_) => Operation::Raw,
            Self::Status(_) => Operation::Status,
            Self::Journal => Operation::Journal,
            Self::Owner(_) => Operation::ReadOwner,
        }
    }

    fn target_matches(self, target: EndpointId) -> bool {
        let query = match self {
            Self::Current { query, .. }
            | Self::Historical { query, .. }
            | Self::Raw(query)
            | Self::CaptureCache(query) => query,
            Self::Status(origin) => return origin.domain == target,
            Self::Journal | Self::Owner(_) => return true,
        };
        match query {
            Query::AccountBalance(account)
            | Query::SourceBalance(account)
            | Query::DestinationBalance(account)
            | Query::RootBalance(_, account) => account.endpoint == target,
            Query::SourcePool(domain, _) | Query::RegulatoryState(domain, _) => domain == target,
            Query::TerminalReceipt(origin) => origin.domain == target,
            Query::ApplicationValue(_) | Query::Commitment(_) => true,
        }
    }
}

/// The only externally constructible stateful product service.
///
/// The lower-level ledger cannot be created by a client:
/// ```compile_fail
/// let _ = oip_spec::lock_finality::Ledger::new;
/// ```
/// The lower-level read authority cannot be created by a client:
/// ```compile_fail
/// let _ = oip_spec::authority::reads::ReadAuthority::new;
/// ```
pub(crate) struct ProductAuthority<S: Security> {
    pub(super) reads: ReadAuthority,
    pub(super) directory: BTreeMap<Principal, Identity>,
    pub(super) security: Arc<S>,
}

impl<S: Security> ProductAuthority<S> {
    pub(crate) fn bootstrap(initial: Bootstrap, security: S) -> Option<Self> {
        let mut directory = BTreeMap::new();
        let mut bindings = BTreeSet::new();
        for identity in initial.identities {
            if !bindings.insert((identity.domain, identity.ocid, identity.rai))
                || directory.insert(identity.principal, identity).is_some()
            {
                return None;
            }
        }
        if initial.owners.keys().ne(initial.supply.keys())
            || initial
                .owners
                .values()
                .any(|owner| !directory.contains_key(owner))
            || initial
                .sessions
                .values()
                .any(|binding| !directory.contains_key(&binding.principal))
            || directory.values().any(|identity| {
                identity.domain != initial.settlement_target
                    && !initial
                        .contexts
                        .iter()
                        .any(|context| context.endpoint == identity.domain)
            })
        {
            return None;
        }
        let ledger = Ledger::new(
            initial.epoch,
            initial.contexts,
            initial.sessions,
            initial.maintainers,
            initial.balances,
            &initial.supply,
        )
        .ok()?;
        let authority = Authority::new(ledger, initial.settlement_target)?;
        let mut reads = match initial.regulation {
            Some(policy) => ReadAuthority::new_regulated(authority, initial.provider, policy)?,
            None => ReadAuthority::new(authority, initial.provider),
        };
        reads.authority.state.primary.owners = initial.owners;
        Some(Self {
            reads,
            directory,
            security: Arc::new(security),
        })
    }

    pub(super) fn from_records(
        reads: ReadAuthority,
        directory: BTreeMap<Principal, Identity>,
        security: Arc<S>,
    ) -> Self {
        Self {
            reads,
            directory,
            security,
        }
    }

    pub(super) fn authenticate(&self, token: &S::Token) -> Result<Identity, EndpointError> {
        let identity = self
            .security
            .authenticate(token)
            .ok_or(EndpointError::Rejected)?;
        if self.directory.get(&identity.principal) != Some(&identity) {
            return Err(EndpointError::Rejected);
        }
        Ok(identity)
    }

    pub(super) fn active_identity(
        &self,
        token: &S::Token,
        proof: SessionProof,
    ) -> Result<Identity, EndpointError> {
        let identity = self.security.authenticate_session(token, proof)
            .ok_or(EndpointError::Rejected)?;
        if self.directory.get(&identity.principal) != Some(&identity)
            || proof.epoch != self.reads.current_cut().authority_epoch
            || !self
                .reads
                .authority
                .state
                .primary
                .ledger
                .session_bound(AuthenticatedCaller(identity.principal), proof.session)
        {
            return Err(EndpointError::Rejected);
        }
        Ok(identity)
    }

    pub(super) fn authorize_call(
        &self,
        auth: &Credentials<'_, S>,
        request: &Request<'_>,
        operation: Operation,
    ) -> Result<Identity, EndpointError> {
        let identity = self.active_identity(auth.token, auth.proof)?;
        let claim = request.action.claim();
        if identity.principal != request.id.namespace
            || claim.caller != identity.principal
            || claim.session != auth.proof.session
            || claim.epoch != auth.proof.epoch
            || claim.target != request.target
            || !self
                .reads
                .authority
                .state
                .primary
                .ledger
                .has_endpoint(request.target)
            || !self.permit_call(identity, auth.proof, request, operation)
            || !self.security.verify(
                identity,
                auth.proof,
                request.target,
                operation,
                Signed::Call {
                    id: request.id,
                    action: request.action,
                },
                auth.signature,
            )
        {
            return Err(EndpointError::Rejected);
        }
        Ok(identity)
    }

    fn permit_call(
        &self, identity: Identity, proof: SessionProof, request: &Request<'_>, operation: Operation,
    ) -> bool {
        let scope = Scope::Asset(request.action.claim().asset);
        if matches!(
            request.action,
            Action::SyncCommitment(_)
                | Action::Ordinary(CallPayload { command: Command::Write { .. }, .. })
        ) {
            self.security.permit_session(identity, proof, request.target, operation, scope)
        } else {
            self.security.permit(identity, request.target, operation, scope, proof.epoch)
        }
    }

    fn verify_facts(
        &self,
        identity: Identity,
        proof: SessionProof,
        request: &Request<'_>,
        operation: Operation,
        signature: &S::Signature,
    ) -> Result<(), EndpointError> {
        let facts_verified = match request.action {
            Action::Ordinary(payload) if operation != Operation::Receipt => match payload.command {
                Command::RecordTerminal(evidence) => {
                    self.security
                        .verify_terminal_packet(identity, proof, request.target, payload, evidence, signature)
                }
                _ => true,
            },
            Action::Legal { stage, order, payload } => self.security.verify_order_packet(
                identity, proof, request.target, stage, request.id, &payload, order, signature,
            ),
            Action::Spend { enforcement: Some(order), payload } => self.security.verify_enforcement_packet(
                identity, proof, request.target, request.id, &payload, order, signature,
            ),
            _ => true,
        };
        if !facts_verified {
            return Err(EndpointError::Rejected);
        }
        Ok(())
    }

    fn endorse_recovery(
        &self,
        auth: Option<&Credentials<'_, S>>,
        request: &Request<'_>,
        payload: &CallPayload,
    ) -> Result<(), EndpointError> {
        if !matches!(
            payload.command,
            Command::Cancel { .. }
                | Command::Fence { .. }
                | Command::Refund { .. }
                | Command::Reconcile { .. }
                | Command::Preempt { .. }
        ) {
            return Ok(());
        }
        let auth = auth.ok_or(EndpointError::Rejected)?;
        let identity = self.active_identity(auth.token, auth.proof)?;
        let primary = &self.reads.authority.state.primary;
        let binding = primary
            .ledger
            .recovery_binding(payload.binding.origin)
            .ok_or(EndpointError::Rejected)?;
        if binding != payload.binding
            || primary.owners.get(&binding.asset) != Some(&identity.principal)
            || !self.security.permit(
                identity,
                request.target,
                Operation::RecoverClaim,
                Scope::Asset(binding.asset),
                auth.proof.epoch,
            )
            || !self.security.verify(
                identity,
                auth.proof,
                request.target,
                Operation::RecoverClaim,
                Signed::Recovery {
                    origin: binding.origin,
                    id: request.id,
                    payload,
                },
                auth.signature,
            )
        {
            return Err(EndpointError::Rejected);
        }
        Ok(())
    }

    /// Routes carry no authority of their own.
    #[cfg(test)]
    pub(crate) fn execute(
        &mut self,
        _entry: Entry,
        auth: &Credentials<'_, S>,
        request: Request<'_>,
        endorsement: Option<&Credentials<'_, S>>,
    ) -> Result<ActionReply, EndpointError> {
        let operation = request.action.claim().operation;
        let identity = self.authorize_call(auth, &request, operation)?;
        self.verify_facts(identity, auth.proof, &request, operation, auth.signature)?;
        if let Action::Ordinary(payload) = request.action {
            self.endorse_recovery(endorsement, &request, payload)?;
        }
        self.execute_bound(identity, auth.proof, request)
    }

    fn execute_bound(
        &mut self,
        identity: Identity,
        proof: SessionProof,
        request: Request<'_>,
    ) -> Result<ActionReply, EndpointError> {
        let actor = AuthenticatedCaller(identity.principal);
        match request.action {
            Action::Ordinary(payload) => {
                Ok(ActionReply::Ordinary(self.reads.execute_at_checked_cut(
                    Route::Normal,
                    actor,
                    request.expected,
                    request.id,
                    payload,
                    |_, _, _| true,
                )))
            }
            Action::Legal {
                stage,
                order,
                payload,
            } => Ok(ActionReply::Legal(self.reads.submit_order(
                LegalCall {
                    stage,
                    route: RegulatoryRoute::Normal,
                    actor,
                    id: request.id,
                    expected: request.expected,
                    order,
                    payload,
                },
                |_| true,
            ))),
            Action::Spend {
                payload,
                enforcement,
            } => Ok(ActionReply::Spend(self.reads.submit_spend(
                SpendCall {
                    route: RegulatoryRoute::Normal,
                    actor,
                    id: request.id,
                    expected: request.expected,
                    payload,
                    enforcement,
                },
                |_| true,
            ))),
            Action::SyncCommitment(call) => {
                let security = &self.security;
                self.reads.authority.submit_commitment(
                    call,
                    || security.verify_commitment_attestation(&call),
                    || security.permit_session(
                        identity, proof, call.target, Operation::FullResync,
                        Scope::Commitment(call.stream),
                    ),
                ).map(ActionReply::SyncCommitment)
            }
        }
    }

    /// Receipt lookup is a read-only action, including at an unknown call ID.
    #[cfg(test)]
    pub(crate) fn receipt(
        &self,
        _entry: Entry,
        auth: &Credentials<'_, S>,
        request: Request<'_>,
    ) -> Result<Option<Receipt>, EndpointError> {
        let identity = self.authorize_call(auth, &request, Operation::Receipt)?;
        self.verify_facts(identity, auth.proof, &request, Operation::Receipt, auth.signature)?;
        self.observe_receipt(request)
    }

    pub(super) fn observe_receipt(&self, request: Request<'_>) -> Result<Option<Receipt>, EndpointError> {
        let authority = &self.reads.authority;
        if !authority.up {
            return Err(EndpointError::Unavailable);
        }
        let primary = &authority.state.primary;
        Ok(match request.action {
            Action::Ordinary(payload)
                if !primary.regulation.claimed(request.id) && !primary.sync.claimed(request.id) =>
            {
                Some(Receipt::Ordinary(authority.observe(request.id, payload)))
            }
            Action::Ordinary(_) => None,
            Action::Legal {
                stage,
                order,
                payload,
            } => primary
                .regulation
                .exact_order_receipt(request.id, stage, order, payload)
                .map(Receipt::Legal),
            Action::Spend {
                payload,
                enforcement,
            } => primary
                .regulation
                .exact_spend_receipt(request.id, payload, enforcement)
                .map(Receipt::Spend),
            Action::SyncCommitment(call) => primary.sync.receipt(call)?.map(Receipt::SyncCommitment),
        })
    }

    pub(super) fn execute_durable(
        &mut self,
        auth: &Credentials<'_, S>,
        request: Request<'_>,
        endorsement: Option<&Credentials<'_, S>>,
    ) -> Result<ActionReply, EndpointError> {
        let operation = request.action.claim().operation;
        let identity = self.authorize_call(auth, &request, operation)?;
        let authority = &self.reads.authority;
        if !authority.up {
            return Err(EndpointError::Unavailable);
        }
        let primary = &authority.state.primary;
        if primary.claimed(request.id) {
            if !self.permit_call(identity, auth.proof, &request, Operation::Receipt) {
                return Err(EndpointError::Rejected);
            }
            return self.finish_retained(request);
        }

        let signed_cut = match request.action {
            Action::Ordinary(payload) => payload.cut,
            Action::Legal { payload, .. } => payload.cut,
            Action::Spend { payload, .. } => payload.cut,
            Action::SyncCommitment(call) => call.cut,
        };
        if request.expected != signed_cut {
            return Err(EndpointError::Rejected);
        }
        self.verify_facts(identity, auth.proof, &request, operation, auth.signature)?;
        if let Action::Ordinary(payload) = request.action {
            self.endorse_recovery(endorsement, &request, payload)?;
            let refusal = if !self.reads.available() {
                Some(super::OutcomeReply::Unavailable)
            } else if signed_cut != self.reads.current_cut() {
                Some(super::OutcomeReply::Busy)
            } else {
                None
            };
            if let Some(refusal) = refusal {
                self.reads.authority.state.primary.calls.insert(
                    request.id,
                    super::StoredCall {
                        payload: payload.clone(),
                        outcome: super::Outcome::plain(refusal),
                    },
                );
                return self.finish_retained(request);
            }
        }
        self.execute_bound(identity, auth.proof, request)
    }

    fn finish_retained(&mut self, request: Request<'_>) -> Result<ActionReply, EndpointError> {
        let Some(receipt) = self.observe_receipt(request)? else {
            return Err(EndpointError::Rejected);
        };
        match receipt {
            Receipt::Ordinary(Collection::Rejected) => Err(EndpointError::Rejected),
            Receipt::Ordinary(_) => {
                let Action::Ordinary(payload) = request.action else {
                    unreachable!("ordinary receipt")
                };
                Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(
                    self.reads.authority.finish(request.id, payload),
                )))
            }
            Receipt::Legal(reply) => Ok(ActionReply::Legal(reply)),
            Receipt::Spend(reply) => Ok(ActionReply::Spend(reply)),
            Receipt::SyncCommitment(outcome) => Ok(ActionReply::SyncCommitment(outcome)),
        }
    }

    pub(super) fn receipt_durable(
        &self,
        auth: &Credentials<'_, S>,
        request: Request<'_>,
    ) -> Result<Option<Receipt>, EndpointError> {
        self.authorize_call(auth, &request, Operation::Receipt)?;
        self.observe_receipt(request)
    }

    pub fn read(
        &self,
        _entry: Entry,
        auth: &Credentials<'_, S>,
        target: EndpointId,
        request: ReadRequest,
        cache: Option<&CacheEntry>,
    ) -> Result<Observation, EndpointError> {
        let identity = self.active_identity(auth.token, auth.proof)?;
        let operation = request.operation();
        let primary = &self.reads.authority.state.primary;
        if !request.target_matches(target)
            || !primary.ledger.has_endpoint(target)
            || !self.security.permit(
                identity,
                target,
                operation,
                Scope::Read(request),
                auth.proof.epoch,
            )
            || !self.security.verify(
                identity,
                auth.proof,
                target,
                operation,
                Signed::Read(request),
                auth.signature,
            )
        {
            return Err(EndpointError::Rejected);
        }
        if !self.reads.available() {
            return Err(EndpointError::Unavailable);
        }
        let reader = Reader {
            actor: AuthenticatedCaller(identity.principal),
            session: auth.proof.session,
        };
        Ok(match request {
            ReadRequest::Current { query, expected } => Observation::Current(self.reads.current(
                reader,
                query,
                expected,
                cache,
                |_, _, _| true,
            )),
            ReadRequest::Historical { query, revision } => Observation::Historical(
                self.reads
                    .historical(reader, query, revision, |_, _, _| true),
            ),
            ReadRequest::Raw(query) => Observation::Raw(
                self.reads
                    .authority
                    .state
                    .read_history
                    .raw_value(self.reads.current_cut().revision, query),
            ),
            ReadRequest::Status(origin) => {
                let slot = primary.origins.get(&origin);
                let legal = primary.regulation.legal_reads();
                let record = legal.get(&origin);
                Observation::Status(OperationStatus {
                    phase: primary.ledger.phase(origin),
                    pending: primary.ledger.pending(origin),
                    terminal: slot
                        .and_then(|slot| slot.decision)
                        .map(Decision::Transfer)
                        .or_else(|| {
                            record
                                .and_then(|record| record.decision)
                                .map(Decision::Legal)
                        }),
                    published: slot.is_some_and(|slot| slot.published.is_some())
                        || record.is_some_and(|record| record.published),
                })
            }
            ReadRequest::Journal => Observation::Journal(
                primary
                    .journal
                    .iter()
                    .filter(|item| {
                        item.target == target
                            && item.id.namespace == identity.principal
                            && item.commit.position < self.reads.current_cut().revision
                    })
                    .map(|item| item.id)
                    .collect(),
            ),
            ReadRequest::CaptureCache(query) => {
                Observation::Cache(self.reads.capture_cache(reader, query, |_, _, _| true))
            }
            ReadRequest::Owner(asset) => Observation::Owner(primary.owners.get(&asset).copied()),
        })
    }

    pub fn maintenance(&mut self, token: &S::MaintenanceToken) -> Option<Maintenance<'_, S>> {
        let actor = AuthenticatedCaller(self.security.authenticate_maintenance(token)?);
        self.reads
            .authority
            .state
            .primary
            .ledger
            .is_maintainer(actor)
            .then_some(Maintenance {
                service: self,
                actor,
            })
    }
}

/// A short-lived authority-host capability. It does not expose the ledger.
pub(crate) struct Maintenance<'a, S: Security> {
    service: &'a mut ProductAuthority<S>,
    actor: AuthenticatedCaller,
}

impl<S: Security> Maintenance<'_, S> {
    pub fn install_epoch(
        &mut self,
        epoch: u64,
        contexts: Vec<EndpointContext>,
        sessions: BTreeMap<SessionId, SessionBinding>,
    ) -> bool {
        sessions
            .values()
            .all(|binding| self.service.directory.contains_key(&binding.principal))
            && self
                .service
                .reads
                .install_epoch(self.actor, epoch, contexts, sessions)
    }

    pub fn handover(
        &mut self,
        proposal: &Handover,
        previous: Consent<'_, S>,
        successor: Consent<'_, S>,
    ) -> bool {
        let service = &mut self.service;
        let cut = service.reads.current_cut();
        let old_proof = SessionProof {
            session: proposal.old_session,
            epoch: cut.authority_epoch,
        };
        let Ok(former) = service.active_identity(previous.token, old_proof) else {
            return false;
        };
        let Ok(incoming) = service.authenticate(successor.token) else {
            return false;
        };
        let primary = &service.reads.authority.state.primary;
        if !service.reads.available()
            || cut != proposal.expected
            || proposal.previous == proposal.successor
            || former.principal != proposal.previous
            || incoming.principal != proposal.successor
            || primary.owners.get(&proposal.asset) != Some(&proposal.previous)
            || !service.security.permit(
                former,
                former.domain,
                Operation::TransferOwner,
                Scope::Asset(proposal.asset),
                cut.authority_epoch,
            )
            || !service
                .security
                .approve(former, proposal, previous.signature)
            || !service
                .security
                .approve(incoming, proposal, successor.signature)
        {
            return false;
        }
        let mut next = primary.clone();
        let Some(sessions) = next.ledger.handover_sessions(
            proposal.old_session,
            proposal.new_session,
            proposal.successor,
            proposal.epoch,
        ) else {
            return false;
        };
        if service.security.requires_authority_binding()
            && service.security.handover_policy_binding(proposal, &sessions).is_none()
        {
            return false;
        }
        if !next.ledger.install_epoch(
            self.actor,
            proposal.epoch,
            proposal.contexts.clone(),
            sessions,
        ) {
            return false;
        }
        next.owners.insert(proposal.asset, proposal.successor);
        service.reads.authority.commit_primary(next);
        true
    }

    pub fn observe_time(
        &mut self,
        session: SessionId,
        expected: CommitCut,
        now: u64,
        signature: &S::Signature,
    ) -> bool {
        let security = &self.service.security;
        self.service.reads.observe_regulatory_time(
            self.actor,
            session,
            expected,
            now,
            |actor, cut, ticks| security.verify_time(actor.0, cut, ticks, signature),
        )
    }

    pub fn enqueue_secondary(&mut self, origin: OriginKey) -> Option<SettlementKey> {
        self.service.reads.enqueue_secondary(origin)
    }

    pub fn dispatch_secondary(&mut self, key: SettlementKey) -> Option<SecondaryJob> {
        self.service.reads.dispatch_secondary(key)
    }

    pub fn fail_secondary(&mut self, key: SettlementKey) -> bool {
        self.service.reads.fail_secondary(key)
    }

    pub fn acknowledge_secondary(
        &mut self,
        acknowledgement: Acknowledgement,
        signature: &S::Signature,
    ) -> bool {
        let security = &self.service.security;
        self.service
            .reads
            .acknowledge_secondary(acknowledgement, |ack| security.verify_ack(ack, signature))
    }
}

#[cfg(test)]
mod vector_tests;
