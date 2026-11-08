//! Explicit signed maintenance on the complete independent witness cut.

use super::{
    AuthorityClock, Ed25519Profile, Ed25519Security, INVALID, MaintenanceToken, preimage,
    verify_strict, verifying_key,
};
use crate::authority::identity::{EndpointError, Security};
use crate::authority::recovery::ordered::OrderedPublication;
use crate::authority::recovery::{
    AuthenticatedHead, PersistentAuthority, PublicationGuard, RecoveryError, RecoveryProfile,
};
use crate::authority::{SecondaryJob, SettlementKey};
use crate::wire::codec::WireError;
use crate::{CommitCut, OriginKey, Principal, SessionId};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ops::ControlFlow;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceAuthority {
    pub time: Option<[u8; 32]>,
    pub queue: Option<[u8; 32]>,
}

pub(super) fn valid_authorities(config: &Ed25519Profile, keys: &mut BTreeSet<[u8; 32]>) -> bool {
    config
        .maintenance_authorities
        .iter()
        .all(|(actor, authority)| {
            config.maintainers.contains(actor)
                && [authority.time, authority.queue]
                    .into_iter()
                    .flatten()
                    .all(|key| verifying_key(&key).is_some() && keys.insert(key))
        })
}

pub enum MaintenanceIntent {
    ObserveTime { session: SessionId },
    Enqueue { origin: OriginKey },
    Dispatch { key: SettlementKey },
    Fail { key: SettlementKey },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Action {
    ObserveTime { session: SessionId, observed: u64 },
    Enqueue { origin: OriginKey },
    Dispatch { key: SettlementKey },
    Fail { key: SettlementKey },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceRequest {
    profile: RecoveryProfile,
    principal: Principal,
    cut: CommitCut,
    selection: [u8; 32],
    action: Action,
}

impl MaintenanceRequest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        preimage(b"oip/reference-ordered-maintenance/v1\0", self)
    }

    fn key(&self, config: &Ed25519Profile) -> Option<[u8; 32]> {
        let authority = config.maintenance_authorities.get(&self.principal)?;
        match self.action {
            Action::ObserveTime { .. } => authority.time,
            _ => authority.queue,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SignedMaintenance {
    request: MaintenanceRequest,
    signature: Vec<u8>,
}

/// The host holds this role key separately from the maintenance token issuer.
pub struct MaintenanceSigner(SigningKey);

impl MaintenanceSigner {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn sign<C: AuthorityClock>(
        &self,
        security: &Ed25519Security<C>,
        request: &MaintenanceRequest,
    ) -> Result<Vec<u8>, WireError> {
        if request.key(&security.config) != Some(self.0.verifying_key().to_bytes())
            || !current_scope(security, request)
        {
            return Err(INVALID);
        }
        let signature = self.0.sign(&request.signing_bytes()?).to_bytes().to_vec();
        serde_json::to_vec(&SignedMaintenance {
            request: request.clone(),
            signature,
        })
        .map_err(|_| WireError::InvalidFormat)
    }
}

fn decode_signed(bytes: &[u8]) -> Result<SignedMaintenance, WireError> {
    let value: SignedMaintenance =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidFormat)?;
    if serde_json::to_vec(&value).map_err(|_| WireError::InvalidFormat)? != bytes {
        return Err(WireError::InvalidFormat);
    }
    Ok(value)
}

fn current_scope<C: AuthorityClock>(
    security: &Ed25519Security<C>,
    request: &MaintenanceRequest,
) -> bool {
    if request.profile != security.config.profile
        || request.cut.authority_epoch != security.config.authority_epoch
    {
        return false;
    }
    match request.action {
        Action::ObserveTime { observed, .. } => {
            observed > 0
                && security
                    .clock
                    .unix_seconds()
                    .is_some_and(|now| observed <= now)
        }
        _ => true,
    }
}

fn verify<C: AuthorityClock>(security: &Ed25519Security<C>, signed: &SignedMaintenance) -> bool {
    current_scope(security, &signed.request)
        && signed.request.key(&security.config).is_some_and(|key| {
            signed
                .request
                .signing_bytes()
                .is_ok_and(|bytes| verify_strict(&key, &bytes, &signed.signature))
        })
}

pub(super) fn verify_time<C: AuthorityClock>(
    security: &Ed25519Security<C>,
    actor: Principal,
    cut: CommitCut,
    observed: u64,
    signature: &[u8],
) -> bool {
    decode_signed(signature).is_ok_and(|signed| {
        signed.request.principal == actor && signed.request.cut == cut
            && matches!(signed.request.action, Action::ObserveTime { observed: time, .. } if time == observed)
            && verify(security, &signed)
    })
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthorizedDispatch {
    profile: RecoveryProfile,
    job: SecondaryJob,
}

impl AuthorizedDispatch {
    pub fn profile(&self) -> RecoveryProfile {
        self.profile
    }

    pub fn job(&self) -> SecondaryJob {
        self.job
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum MaintenanceReply {
    Observed(bool),
    Enqueued(Option<SettlementKey>),
    Dispatched(Option<AuthorizedDispatch>),
    Failed(bool),
}

impl<C: AuthorityClock, H: AuthenticatedHead> PersistentAuthority<Ed25519Security<C>, H> {
    /// Observe the exact independent authority cut. The host clock, not the
    /// caller, supplies the value of a time observation.
    pub fn prepare_reference_maintenance(
        &mut self,
        token: &MaintenanceToken,
        intent: MaintenanceIntent,
    ) -> Result<MaintenanceRequest, RecoveryError> {
        let security = self.security.clone();
        let profile = self.profile;
        self.transact_guarded(
            |anchor, head, product| {
                let result = (|| {
                    let control = anchor.ordered_wire_control().ok_or(RecoveryError::Hold)?;
                    let observed = control.observe().map_err(hold)?;
                    let cut = product.reads.current_cut();
                    let principal = security.authenticate_maintenance(token).ok_or(rejected())?;
                    if observed.head() != Some(head) || product.maintenance(token).is_none() {
                        return Err(RecoveryError::Hold);
                    }
                    observed
                        .authorize_principal(principal)
                        .map_err(|_| rejected())?;
                    let action = match intent {
                        MaintenanceIntent::ObserveTime { session } => Action::ObserveTime {
                            session,
                            observed: security.clock.unix_seconds().ok_or(RecoveryError::Hold)?,
                        },
                        MaintenanceIntent::Enqueue { origin } => Action::Enqueue { origin },
                        MaintenanceIntent::Dispatch { key } => Action::Dispatch { key },
                        MaintenanceIntent::Fail { key } => Action::Fail { key },
                    };
                    let request = MaintenanceRequest {
                        profile,
                        principal,
                        cut,
                        selection: control.selection_binding(&observed).map_err(hold)?,
                        action,
                    };
                    if request.key(&security.config).is_none() {
                        return Err(rejected());
                    }
                    Ok(request)
                })();
                ControlFlow::Break(result)
            },
            false,
            || Ok(None),
        )?
    }

    /// Consume only a signed request bound to the current ordered selection.
    /// No reply escapes before the ordered publication is confirmed.
    pub fn execute_reference_maintenance(
        &mut self,
        token: &MaintenanceToken,
        signature: &[u8],
    ) -> Result<MaintenanceReply, RecoveryError> {
        let signed = decode_signed(signature).map_err(|_| rejected())?;
        let signature = signature.to_vec();
        let security = self.security.clone();
        let profile = self.profile;
        let guard = Cell::new(None);
        self.transact_guarded(
            |anchor, head, product| {
                let result = (|| {
                    if security.authenticate_maintenance(token) != Some(signed.request.principal)
                        || !verify(security.as_ref(), &signed)
                    {
                        return Err(rejected());
                    }
                    let control = anchor.ordered_wire_control().ok_or(RecoveryError::Hold)?;
                    let observed = control.observe().map_err(hold)?;
                    if observed.head() != Some(head)
                        || signed.request.cut != product.reads.current_cut()
                        || control.selection_binding(&observed).map_err(hold)?
                            != signed.request.selection
                    {
                        return Err(RecoveryError::Hold);
                    }
                    observed
                        .authorize_principal(signed.request.principal)
                        .map_err(|_| rejected())?;
                    let mut host = product.maintenance(token).ok_or(rejected())?;
                    let reply = match signed.request.action {
                        Action::ObserveTime { session, observed } => MaintenanceReply::Observed(
                            host.observe_time(session, signed.request.cut, observed, &signature),
                        ),
                        Action::Enqueue { origin } => {
                            MaintenanceReply::Enqueued(host.enqueue_secondary(origin))
                        }
                        Action::Dispatch { key } => MaintenanceReply::Dispatched(
                            host.dispatch_secondary(key)
                                .map(|job| AuthorizedDispatch { profile, job }),
                        ),
                        Action::Fail { key } => MaintenanceReply::Failed(host.fail_secondary(key)),
                    };
                    guard.set(Some(OrderedPublication {
                        cut: observed,
                        debit: None,
                    }));
                    Ok(reply)
                })();
                match result {
                    Ok(reply) => ControlFlow::Continue(Ok(reply)),
                    Err(error) => ControlFlow::Break(Err(error)),
                }
            },
            true,
            || {
                if security.authenticate_maintenance(token) != Some(signed.request.principal)
                    || !verify(security.as_ref(), &signed)
                {
                    return Err(rejected());
                }
                Ok(Some(PublicationGuard::Ordered(
                    guard.take().ok_or(RecoveryError::Hold)?,
                )))
            },
        )?
    }
}

fn rejected() -> RecoveryError {
    RecoveryError::Endpoint(EndpointError::Rejected)
}

fn hold(_: crate::authority::recovery::HeadError) -> RecoveryError {
    RecoveryError::Hold
}

#[cfg(test)]
pub(in crate::authority::recovery) fn future_time_signature(
    mut request: MaintenanceRequest,
    observed: u64,
    key: &SigningKey,
) -> Vec<u8> {
    let Action::ObserveTime { session, .. } = request.action else {
        panic!("time observation");
    };
    request.action = Action::ObserveTime { session, observed };
    let signature = key
        .sign(&request.signing_bytes().unwrap())
        .to_bytes()
        .to_vec();
    serde_json::to_vec(&SignedMaintenance { request, signature }).unwrap()
}
