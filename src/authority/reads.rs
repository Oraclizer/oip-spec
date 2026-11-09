//! Revision-labelled, authenticated observations of the same authority that executes calls.

#[cfg(test)]
use super::Snapshot;
use super::recovery::RecoveryProfile;
use super::regulation::{LegalDecision, LegalRead, Mode};
use super::sync::{Commitment, Stream};
use super::{
    Acknowledgement, Authority, CallPayload, Collection, OriginDecision, PrimarySnapshot,
    SecondaryJob, SettlementKey,
};
use crate::lock_finality::{Account, EndpointContext, EndpointId, Ledger, LedgerProjection, Route};
use crate::{
    AssetId, AuthenticatedCaller, CallId, CommitCut, OriginKey, SessionBinding, SessionId,
};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Query {
    ApplicationValue(AssetId),
    AccountBalance(Account),
    SourceBalance(Account),
    DestinationBalance(Account),
    RootBalance(OriginKey, Account),
    RegulatoryState(EndpointId, AssetId),
    TerminalReceipt(OriginKey),
    /// Unallocated source units across accounts at this exact domain and asset.
    SourcePool(EndpointId, AssetId),
    Commitment(Stream),
}

impl Query {
    fn touches(self, binding: crate::lock_finality::Binding) -> bool {
        match self {
            Self::ApplicationValue(asset) => binding.asset == asset,
            Self::AccountBalance(account) => {
                binding.source() == account
                    || (binding.asset == account.asset && binding.destination == account.endpoint)
            }
            Self::SourceBalance(account) => binding.source() == account,
            Self::SourcePool(domain, asset) => {
                binding.origin.domain == domain && binding.asset == asset
            }
            Self::DestinationBalance(account) => {
                binding.destination == account.endpoint && binding.asset == account.asset
            }
            Self::RootBalance(origin, _) | Self::TerminalReceipt(origin) => {
                binding.origin == origin
            }
            Self::RegulatoryState(_, asset) => binding.asset == asset,
            Self::Commitment(_) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadKind {
    Current,
    Historical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reader {
    pub actor: AuthenticatedCaller,
    pub session: SessionId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    Busy,
    Unavailable,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Value {
    Units(u64),
    Receipt(Option<OriginDecision>),
    LegalReceipt(LegalDecision),
    Regulatory(Option<Mode>),
    /// A source pool can span multiple account-sized balances.
    WideUnits(u128),
    Commitment(Option<Commitment>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CurrentRead {
    pub cut: CommitCut,
    pub value: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalRead {
    pub revision: usize,
    pub value: Value,
}

#[derive(Clone)]
pub struct CacheEntry {
    source: Arc<()>,
    profile: Option<RecoveryProfile>,
    provider: u64,
    query: Query,
    observed: CurrentRead,
}

/// A portable cache candidate. All fields are untrusted until revalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CacheClaim {
    pub profile: RecoveryProfile,
    pub provider: u64,
    pub query: Query,
    pub observed: CurrentRead,
}

impl fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheEntry").finish_non_exhaustive()
    }
}

impl PartialEq for CacheEntry {
    fn eq(&self, other: &Self) -> bool {
        self.matches_source(other.profile, &other.source)
            && self.provider == other.provider
            && self.query == other.query
            && self.observed == other.observed
    }
}

impl Eq for CacheEntry {}

impl CacheEntry {
    fn matches_source(&self, profile: Option<RecoveryProfile>, source: &Arc<()>) -> bool {
        match (self.profile, profile) {
            (Some(cached), Some(current)) => cached == current,
            (None, None) => Arc::ptr_eq(&self.source, source),
            _ => false,
        }
    }
    pub fn claim(&self) -> Option<CacheClaim> {
        Some(CacheClaim {
            profile: self.profile?,
            provider: self.provider,
            query: self.query,
            observed: self.observed,
        })
    }

    pub(super) fn from_claim(claim: &CacheClaim) -> Self {
        Self {
            source: Arc::new(()),
            profile: Some(claim.profile),
            provider: claim.provider,
            query: claim.query,
            observed: claim.observed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckedExecution {
    Forwarded(Collection),
    Busy,
    Unavailable,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct OriginRead {
    binding: crate::lock_finality::Binding,
    published: bool,
    decision: Option<OriginDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct ReadProjection {
    ledger: LedgerProjection,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    origins: BTreeMap<OriginKey, OriginRead>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    legal: BTreeMap<OriginKey, LegalRead>,
    #[serde(with = "crate::authority::recovery::ordered_map")]
    modes: BTreeMap<(EndpointId, AssetId), Mode>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        with = "crate::authority::recovery::ordered_map"
    )]
    commitments: BTreeMap<Stream, Commitment>,
}

impl ReadProjection {
    fn capture(primary: &PrimarySnapshot) -> Self {
        Self {
            ledger: primary.ledger.project_reads(),
            legal: primary.regulation.legal_reads(),
            modes: primary.regulation.modes(),
            commitments: primary.sync.entries.clone(),
            origins: primary
                .origins
                .iter()
                .map(|(&key, slot)| {
                    (
                        key,
                        OriginRead {
                            binding: slot.binding,
                            published: slot.published.is_some(),
                            decision: slot.decision,
                        },
                    )
                })
                .collect(),
        }
    }

    fn value(&self, query: Query) -> Result<Value, ReadError> {
        if self
            .origins
            .values()
            .any(|origin| !origin.published && query.touches(origin.binding))
            || self
                .legal
                .values()
                .any(|origin| !origin.published && query.touches(origin.binding))
        {
            return Err(ReadError::Busy);
        }
        if matches!(query, Query::ApplicationValue(asset) if self.ledger.locked_assets.contains(&asset))
        {
            return Err(ReadError::Busy);
        }
        self.raw_value(query)
    }

    fn source_pool(&self, domain: EndpointId, asset: AssetId) -> Result<Value, ReadError> {
        if !self.ledger.asset_values.contains_key(&asset) {
            return Err(ReadError::Unavailable);
        }
        let in_pool = |account: &Account| account.endpoint == domain && account.asset == asset;
        let total = self
            .ledger
            .balances
            .iter()
            .filter(|(account, _)| in_pool(account))
            .try_fold(0u128, |sum, (_, units)| sum.checked_add(u128::from(*units)))
            .ok_or(ReadError::Unavailable)?;
        let allocated = self
            .ledger
            .root_funding
            .iter()
            .filter(|((_, account), _)| in_pool(account))
            .try_fold(0u128, |sum, (_, units)| sum.checked_add(u128::from(*units)))
            .ok_or(ReadError::Unavailable)?;
        let unallocated = total.checked_sub(allocated).ok_or(ReadError::Unavailable)?;
        Ok(u64::try_from(unallocated).map_or(Value::WideUnits(unallocated), Value::Units))
    }

    fn raw_value(&self, query: Query) -> Result<Value, ReadError> {
        match query {
            Query::ApplicationValue(asset) => self
                .ledger
                .asset_values
                .get(&asset)
                .copied()
                .map(Value::Units)
                .ok_or(ReadError::Unavailable),
            Query::AccountBalance(account) => {
                if !self.ledger.asset_values.contains_key(&account.asset) {
                    return Err(ReadError::Unavailable);
                }
                Ok(Value::Units(
                    self.ledger
                        .balances
                        .get(&account)
                        .copied()
                        .unwrap_or_default(),
                ))
            }
            Query::SourceBalance(account) | Query::DestinationBalance(account) => {
                if !self.ledger.asset_values.contains_key(&account.asset) {
                    return Err(ReadError::Unavailable);
                }
                let funded = self
                    .ledger
                    .root_funding
                    .iter()
                    .filter_map(|((_, owner), amount)| (*owner == account).then_some(*amount))
                    .try_fold(0u64, u64::checked_add)
                    .ok_or(ReadError::Unavailable)?;
                if matches!(query, Query::DestinationBalance(_)) {
                    Ok(Value::Units(funded))
                } else {
                    let total = self
                        .ledger
                        .balances
                        .get(&account)
                        .copied()
                        .unwrap_or_default();
                    Ok(Value::Units(
                        total.checked_sub(funded).ok_or(ReadError::Unavailable)?,
                    ))
                }
            }
            Query::SourcePool(domain, asset) => self.source_pool(domain, asset),
            Query::RootBalance(origin, account) => Ok(Value::Units(
                self.ledger
                    .root_funding
                    .get(&(origin, account))
                    .copied()
                    .unwrap_or_default(),
            )),
            Query::RegulatoryState(endpoint, asset) => Ok(Value::Regulatory(
                self.modes.get(&(endpoint, asset)).copied(),
            )),
            Query::TerminalReceipt(origin) => {
                if let Some(legal) = self.legal.get(&origin).and_then(|entry| entry.decision) {
                    return Ok(Value::LegalReceipt(legal));
                }
                Ok(Value::Receipt(
                    self.origins.get(&origin).and_then(|slot| slot.decision),
                ))
            }
            Query::Commitment(stream) => {
                if !self.ledger.asset_values.contains_key(&stream.asset) {
                    return Err(ReadError::Unavailable);
                }
                Ok(Value::Commitment(self.commitments.get(&stream).copied()))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct ReadHistory {
    prefixes: Vec<Arc<ReadProjection>>,
}

impl ReadHistory {
    pub(super) fn new(genesis: &PrimarySnapshot) -> Self {
        Self {
            prefixes: vec![Arc::new(ReadProjection::capture(genesis))],
        }
    }

    #[cfg(test)]
    pub(super) fn raw_value_at(&self, revision: usize, query: Query) -> Result<Value, ReadError> {
        self.prefixes
            .get(revision)
            .ok_or(ReadError::Unavailable)?
            .raw_value(query)
    }

    pub(super) fn record(&mut self, primary: &PrimarySnapshot) {
        let revision = primary.ledger.current_cut().revision;
        if revision >= self.prefixes.len() {
            let next = Arc::new(ReadProjection::capture(primary));
            // A batched context installation advances several authority log
            // positions, all with the same financial and application view.
            self.prefixes.resize(revision + 1, next);
        }
    }

    pub(super) fn matches_current(&self, primary: &PrimarySnapshot) -> bool {
        self.prefixes.len().checked_sub(1) == Some(primary.ledger.current_cut().revision)
            && self.prefixes.last().is_some_and(|current| {
                current.as_ref() == &ReadProjection::capture(primary)
            })
    }

    pub(super) fn has_consistent_asset_registry(&self, ledger: &Ledger) -> bool {
        self.prefixes
            .iter()
            .all(|prefix| prefix.ledger.asset_values.keys().eq(ledger.registered_assets()))
    }

    pub(super) fn preserves_preceding_history(&self, previous: &Self) -> bool {
        self.prefixes.starts_with(&previous.prefixes)
    }

    pub(super) fn raw_value(&self, revision: usize, query: Query) -> Result<Value, ReadError> {
        self.prefixes
            .get(revision)
            .ok_or(ReadError::Unavailable)?
            .raw_value(query)
    }

    pub(super) fn commitment_at(&self, revision: usize, stream: Stream) -> Option<Commitment> {
        self.prefixes.get(revision)?.commitments.get(&stream).copied()
    }

    fn value(&self, revision: usize, query: Query) -> Result<Value, ReadError> {
        self.prefixes
            .get(revision)
            .ok_or(ReadError::Unavailable)?
            .value(query)
    }
}

#[cfg(test)]
/// Comparable recovery token with no public state projection.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ReadEndpointSnapshot(Snapshot);

#[cfg(test)]
impl fmt::Debug for ReadEndpointSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadEndpointSnapshot")
            .finish_non_exhaustive()
    }
}

/// The read endpoint owns its authority and routes every effect through the
/// checked execution boundary. Its read policy is a trusted adapter input.
pub(crate) struct ReadAuthority {
    pub(super) authority: Authority,
    pub(super) provider: u64,
    source: Arc<()>,
    pub(super) profile: Option<RecoveryProfile>,
}

impl ReadAuthority {
    pub(crate) fn new(authority: Authority, provider: u64) -> Self {
        Self {
            authority,
            provider,
            source: Arc::new(()),
            profile: None,
        }
    }

    pub fn current_cut(&self) -> CommitCut {
        self.authority.current_cut()
    }

    pub(super) fn available(&self) -> bool {
        self.authority.up && self.authority.connected
    }

    fn authorize(
        &self,
        reader: Reader,
        kind: ReadKind,
        query: Query,
        permitted: impl FnOnce(AuthenticatedCaller, ReadKind, Query) -> bool,
    ) -> Result<(), ReadError> {
        if !self
            .authority
            .state
            .primary
            .ledger
            .session_bound(reader.actor, reader.session)
            || !permitted(reader.actor, kind, query)
        {
            return Err(ReadError::Rejected);
        }
        if !self.available() {
            return Err(ReadError::Unavailable);
        }
        Ok(())
    }

    pub fn current(
        &self,
        reader: Reader,
        query: Query,
        expected: CommitCut,
        cache: Option<&CacheEntry>,
        permitted: impl FnOnce(AuthenticatedCaller, ReadKind, Query) -> bool,
    ) -> Result<CurrentRead, ReadError> {
        self.authorize(reader, ReadKind::Current, query, permitted)?;
        let cut = self.current_cut();
        if expected != cut {
            return Err(ReadError::Busy);
        }
        let value = self
            .authority
            .state
            .read_history
            .value(cut.revision, query)?;
        if let Some(entry) = cache {
            if entry.query != query
                || entry.provider != self.provider
                || !entry.matches_source(self.profile, &self.source)
                || entry.observed.cut.revision != cut.revision
                || entry.observed.cut.authority_epoch != cut.authority_epoch
                || entry.observed.value != value
            {
                return Err(ReadError::Busy);
            }
            return Ok(CurrentRead {
                cut,
                value: entry.observed.value,
            });
        }
        Ok(CurrentRead { cut, value })
    }

    pub fn capture_cache(
        &self,
        reader: Reader,
        query: Query,
        permitted: impl FnOnce(AuthenticatedCaller, ReadKind, Query) -> bool,
    ) -> Result<CacheEntry, ReadError> {
        let observed = self.current(reader, query, self.current_cut(), None, permitted)?;
        Ok(CacheEntry {
            source: self.source.clone(),
            profile: self.profile,
            provider: self.provider,
            query,
            observed,
        })
    }

    pub fn historical(
        &self,
        reader: Reader,
        query: Query,
        revision: usize,
        permitted: impl FnOnce(AuthenticatedCaller, ReadKind, Query) -> bool,
    ) -> Result<HistoricalRead, ReadError> {
        self.authorize(reader, ReadKind::Historical, query, permitted)?;
        let value = self.authority.state.read_history.value(revision, query)?;
        Ok(HistoricalRead { revision, value })
    }

    pub fn execute_at_checked_cut(
        &mut self,
        route: Route,
        actor: AuthenticatedCaller,
        expected: CommitCut,
        id: CallId,
        payload: &CallPayload,
        verify: impl FnOnce(AuthenticatedCaller, CallId, &CallPayload) -> bool,
    ) -> CheckedExecution {
        if !self.authority.access(actor, id, payload, verify) {
            return CheckedExecution::Rejected;
        }
        if !self.available() {
            return CheckedExecution::Unavailable;
        }
        let actual = self.current_cut();
        if expected.revision != actual.revision
            || expected.authority_epoch != actual.authority_epoch
            || payload.cut != actual
        {
            return CheckedExecution::Busy;
        }
        CheckedExecution::Forwarded(self.authority.submit_bound(route, actor, id, payload))
    }

    #[cfg(test)]
    pub fn collect(
        &mut self,
        actor: AuthenticatedCaller,
        id: CallId,
        payload: &CallPayload,
        verify: impl FnOnce(AuthenticatedCaller, CallId, &CallPayload) -> bool,
    ) -> Collection {
        self.authority.collect(actor, id, payload, verify)
    }

    pub fn install_epoch(
        &mut self,
        actor: AuthenticatedCaller,
        epoch: u64,
        contexts: Vec<EndpointContext>,
        sessions: BTreeMap<SessionId, SessionBinding>,
    ) -> bool {
        self.authority
            .install_epoch(actor, epoch, contexts, sessions)
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> ReadEndpointSnapshot {
        ReadEndpointSnapshot(self.authority.snapshot())
    }

    pub fn enqueue_secondary(&mut self, origin: OriginKey) -> Option<SettlementKey> {
        self.authority.enqueue_secondary(origin)
    }

    pub fn dispatch_secondary(&mut self, key: SettlementKey) -> Option<SecondaryJob> {
        self.authority.dispatch_secondary(key)
    }

    pub fn fail_secondary(&mut self, key: SettlementKey) -> bool {
        self.authority.fail_secondary(key)
    }

    pub fn acknowledge_secondary(
        &mut self,
        ack: Acknowledgement,
        verify: impl FnOnce(&Acknowledgement) -> bool,
    ) -> bool {
        self.authority.acknowledge_secondary(ack, verify)
    }
}

#[cfg(test)]
mod vector_tests;
