//! Typed adjacent exchanges at the authenticated persistent commit boundary.

use super::{AuthenticatedHead, PersistentAuthority, RecoveryError, SourceAction, source_probe_at};
use crate::authority::identity::{
    Action, ActionReply, Consent, Credentials, EndpointError, Entry, Handover, Observation,
    ProductAuthority, ReadRequest, Receipt, Request, Security,
};
use crate::authority::reads::{CacheClaim, CacheEntry, Query};
use crate::authority::{Acknowledgement, SecondaryJob, SettlementKey};
use crate::lock_finality::{EndpointContext, EndpointId, TerminalEvidence};
use crate::{CommitCut, OriginKey, SessionBinding, SessionId};
use std::collections::{BTreeMap, BTreeSet};

/// Closed set of actual service operations. It contains neither a caller
/// footprint nor an executable closure.
pub enum ServiceAction<'a, S: Security> {
    Execute {
        auth: &'a Credentials<'a, S>,
        request: Request<'a>,
        endorsement: Option<&'a Credentials<'a, S>>,
    },
    Receipt {
        auth: &'a Credentials<'a, S>,
        request: Request<'a>,
    },
    Read {
        auth: &'a Credentials<'a, S>,
        target: EndpointId,
        request: ReadRequest,
        cache: Option<&'a CacheClaim>,
    },
    SourceProbe {
        maintenance: &'a S::MaintenanceToken,
        origin: OriginKey,
        evidence: Option<TerminalEvidence>,
    },
    Handover {
        maintenance: &'a S::MaintenanceToken,
        proposal: &'a Handover,
        previous: &'a Consent<'a, S>,
        successor: &'a Consent<'a, S>,
    },
    InstallEpoch {
        maintenance: &'a S::MaintenanceToken,
        epoch: u64,
        contexts: &'a [EndpointContext],
        sessions: &'a BTreeMap<SessionId, SessionBinding>,
    },
    ObserveTime {
        maintenance: &'a S::MaintenanceToken,
        session: SessionId,
        expected: CommitCut,
        now: u64,
        signature: &'a S::Signature,
    },
    Enqueue {
        maintenance: &'a S::MaintenanceToken,
        origin: OriginKey,
    },
    Dispatch {
        maintenance: &'a S::MaintenanceToken,
        key: SettlementKey,
    },
    Fail {
        maintenance: &'a S::MaintenanceToken,
        key: SettlementKey,
    },
    Acknowledge {
        maintenance: &'a S::MaintenanceToken,
        acknowledgement: Acknowledgement,
        signature: &'a S::Signature,
    },
}

pub struct Occurrence<'a, S: Security> {
    /// Reply association only. It never authorizes an operation.
    pub label: u64,
    pub action: ServiceAction<'a, S>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ServiceReply {
    Executed(ActionReply),
    Receipt(Option<Receipt>),
    Observation(Observation),
    Source(SourceAction),
    Changed(bool),
    Enqueued(Option<SettlementKey>),
    Dispatched(Option<SecondaryJob>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct OccurrenceReply {
    pub label: u64,
    pub reply: Result<ServiceReply, RecoveryError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exchange {
    Exchanged,
    Serialized,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ScheduleReport {
    /// One decision for each requested adjacent swap, in request order.
    pub exchanges: Vec<Exchange>,
    /// Exact replies in the original occurrence order.
    pub replies: Vec<OccurrenceReply>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleError {
    InvalidPlan,
    Recovery(RecoveryError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Dependency {
    Authority,
    Revision,
    CompletionHistory,
    ReadProvider,
    Origin(OriginKey),
    Publication(OriginKey),
    Settlement(SettlementKey),
}

#[derive(Clone, Copy)]
pub(super) enum Class {
    Observation {
        origin: Option<OriginKey>,
        publication: Option<OriginKey>,
    },
    Slot {
        key: SettlementKey,
        publication: Option<OriginKey>,
    },
    Serial,
}

impl Class {
    pub(super) fn observation(origin: Option<OriginKey>) -> Self {
        Self::Observation {
            origin,
            publication: None,
        }
    }

    fn footprint(self) -> (BTreeSet<Dependency>, BTreeSet<Dependency>) {
        let common = [
            Dependency::Authority,
            Dependency::Revision,
            Dependency::CompletionHistory,
            Dependency::ReadProvider,
        ];
        match self {
            Self::Observation {
                origin,
                publication,
            } => {
                let mut reads = BTreeSet::from(common);
                reads.extend(origin.map(Dependency::Origin));
                reads.extend(publication.map(Dependency::Publication));
                (reads, BTreeSet::new())
            }
            Self::Slot { key, publication } => {
                let slot = Dependency::Settlement(key);
                let mut reads = BTreeSet::from([Dependency::Authority, slot]);
                reads.extend(publication.map(Dependency::Publication));
                (reads, BTreeSet::from([slot]))
            }
            Self::Serial => (BTreeSet::from(common), BTreeSet::from(common)),
        }
    }

    pub(super) fn compatible(self, other: Self) -> bool {
        let (a_read, a_write) = self.footprint();
        let (b_read, b_write) = other.footprint();
        a_write.is_disjoint(&b_read)
            && b_write.is_disjoint(&a_read)
            && a_write.is_disjoint(&b_write)
    }

    fn serial(self) -> bool {
        matches!(self, Self::Serial)
    }
}

pub(super) fn query_origin(request: ReadRequest) -> Option<OriginKey> {
    let query = match request {
        ReadRequest::Status(origin) => return Some(origin),
        ReadRequest::Current { query, .. }
        | ReadRequest::Historical { query, .. }
        | ReadRequest::Raw(query)
        | ReadRequest::CaptureCache(query) => query,
        _ => return None,
    };
    match query {
        Query::RootBalance(origin, _) | Query::TerminalReceipt(origin) => Some(origin),
        _ => None,
    }
}

fn receipt_origin(request: Request<'_>) -> OriginKey {
    match request.action {
        Action::Ordinary(payload) => payload.binding.origin,
        Action::Legal { payload, .. } => payload.binding.origin,
        Action::Spend { payload, .. } => payload.scope.root.origin,
    }
}

pub(super) fn slot(key: SettlementKey) -> Class {
    Class::Slot {
        key,
        publication: None,
    }
}

impl<S: Security> ServiceAction<'_, S> {
    fn classify(&self, product: &mut ProductAuthority<S>) -> Class {
        match self {
            Self::Receipt { request, .. } => Class::observation(Some(receipt_origin(*request))),
            Self::Read { request, .. } => Class::observation(query_origin(*request)),
            Self::SourceProbe { origin, .. } => Class::observation(Some(*origin)),
            Self::Enqueue {
                maintenance,
                origin,
            } if product.maintenance(maintenance).is_some() => {
                match product.reads.authority.primary_publication(*origin) {
                    Some(published) => Class::Slot {
                        key: published.key(),
                        publication: Some(*origin),
                    },
                    None => Class::Observation {
                        origin: None,
                        publication: Some(*origin),
                    },
                }
            }
            Self::Dispatch { maintenance, key } | Self::Fail { maintenance, key }
                if product.maintenance(maintenance).is_some() =>
            {
                slot(*key)
            }
            Self::Acknowledge {
                maintenance,
                acknowledgement,
                ..
            } if product.maintenance(maintenance).is_some() => slot(acknowledgement.key),
            _ => Class::Serial,
        }
    }

    fn run(&self, product: &mut ProductAuthority<S>) -> Result<ServiceReply, RecoveryError> {
        let rejected = RecoveryError::Endpoint(EndpointError::Rejected);
        match self {
            Self::Execute {
                auth,
                request,
                endorsement,
            } => product
                .execute_durable(auth, *request, *endorsement)
                .map(ServiceReply::Executed)
                .map_err(RecoveryError::Endpoint),
            Self::Receipt { auth, request } => product
                .receipt_durable(auth, *request)
                .map(ServiceReply::Receipt)
                .map_err(RecoveryError::Endpoint),
            Self::Read {
                auth,
                target,
                request,
                cache,
            } => {
                let cache = cache.map(CacheEntry::from_claim);
                product
                    .read(Entry::Normal, auth, *target, *request, cache.as_ref())
                    .map(ServiceReply::Observation)
                    .map_err(RecoveryError::Endpoint)
            }
            Self::SourceProbe {
                maintenance,
                origin,
                evidence,
            } => {
                source_probe_at(product, maintenance, *origin, *evidence).map(ServiceReply::Source)
            }
            Self::Handover {
                maintenance,
                proposal,
                previous,
                successor,
            } => {
                let mut host = product.maintenance(maintenance).ok_or(rejected)?;
                Ok(ServiceReply::Changed(host.handover(
                    proposal,
                    Consent {
                        token: previous.token,
                        signature: previous.signature,
                    },
                    Consent {
                        token: successor.token,
                        signature: successor.signature,
                    },
                )))
            }
            Self::InstallEpoch {
                maintenance,
                epoch,
                contexts,
                sessions,
            } => {
                let mut host = product.maintenance(maintenance).ok_or(rejected)?;
                Ok(ServiceReply::Changed(host.install_epoch(
                    *epoch,
                    contexts.to_vec(),
                    (*sessions).clone(),
                )))
            }
            Self::ObserveTime {
                maintenance,
                session,
                expected,
                now,
                signature,
            } => {
                let mut host = product.maintenance(maintenance).ok_or(rejected)?;
                Ok(ServiceReply::Changed(
                    host.observe_time(*session, *expected, *now, signature),
                ))
            }
            Self::Enqueue {
                maintenance,
                origin,
            } => {
                let mut host = product.maintenance(maintenance).ok_or(rejected)?;
                Ok(ServiceReply::Enqueued(host.enqueue_secondary(*origin)))
            }
            Self::Dispatch { maintenance, key } => {
                let mut host = product.maintenance(maintenance).ok_or(rejected)?;
                Ok(ServiceReply::Dispatched(host.dispatch_secondary(*key)))
            }
            Self::Fail { maintenance, key } => {
                let mut host = product.maintenance(maintenance).ok_or(rejected)?;
                Ok(ServiceReply::Changed(host.fail_secondary(*key)))
            }
            Self::Acknowledge {
                maintenance,
                acknowledgement,
                signature,
            } => {
                let mut host = product.maintenance(maintenance).ok_or(rejected)?;
                Ok(ServiceReply::Changed(
                    host.acknowledge_secondary(*acknowledgement, signature),
                ))
            }
        }
    }
}

impl<S: Security, H: AuthenticatedHead> PersistentAuthority<S, H> {
    /// Attempt the requested adjacent exchanges in each compatible run. Swap
    /// positions refer to the evolving permutation. Shared authority actions
    /// are revalidated in input order. Connection attachment replacement is
    /// available separately through the exclusive reconnect operation.
    pub fn schedule(
        &mut self,
        occurrences: &[Occurrence<'_, S>],
        adjacent: &[usize],
    ) -> Result<ScheduleReport, ScheduleError> {
        self.require_native_client().map_err(ScheduleError::Recovery)?;
        let mut labels = BTreeSet::new();
        if occurrences
            .iter()
            .any(|occurrence| !labels.insert(occurrence.label))
            || adjacent
                .iter()
                .any(|&i| i.checked_add(1).is_none_or(|j| j >= occurrences.len()))
        {
            return Err(ScheduleError::InvalidPlan);
        }
        self.transact(|product| schedule_at(product, occurrences, adjacent))
            .map_err(ScheduleError::Recovery)
    }
}

fn schedule_at<S: Security>(
    product: &mut ProductAuthority<S>,
    occurrences: &[Occurrence<'_, S>],
    adjacent: &[usize],
) -> ScheduleReport {
    let mut order: Vec<_> = (0..occurrences.len()).collect();
    let mut exchanges = vec![Exchange::Serialized; adjacent.len()];
    let mut replies: Vec<Option<OccurrenceReply>> = (0..occurrences.len()).map(|_| None).collect();
    let mut start = 0;
    while start < order.len() {
        let mut end = start + 1;
        if !occurrences[order[start]].action.classify(product).serial() {
            while end < order.len() && !occurrences[order[end]].action.classify(product).serial() {
                end += 1;
            }
        }
        // In this run only queue slots can change. Classifications resolve
        // from the same immutable primary publication and remain valid across
        // all local queue writes. A shared action starts a new run and cut.
        for (attempt, &left) in adjacent.iter().enumerate() {
            if left < start || left + 1 >= end {
                continue;
            }
            let a = occurrences[order[left]].action.classify(product);
            let b = occurrences[order[left + 1]].action.classify(product);
            if a.compatible(b) {
                order.swap(left, left + 1);
                exchanges[attempt] = Exchange::Exchanged;
            }
        }
        for &original in &order[start..end] {
            let occurrence = &occurrences[original];
            replies[original] = Some(OccurrenceReply {
                label: occurrence.label,
                reply: occurrence.action.run(product),
            });
        }
        start = end;
    }
    ScheduleReport {
        exchanges,
        replies: replies
            .into_iter()
            .map(|reply| reply.expect("every occurrence executed once"))
            .collect(),
    }
}

#[cfg(test)]
mod vector_tests;
