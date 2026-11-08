//! Purpose-specific Ed25519 legal orders and enforcement authorizations.

use super::{
    AuthorityClock, Ed25519Profile, Ed25519Security, INVALID, preimage, verify_strict,
    verifying_key,
};
use crate::authority::regulation::{
    Action, EnforcementOrder, LegalPayload, LegalStage, Order, SpendPayload,
};
use crate::wire::codec::WireError;
use crate::{AssetId, CallId};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegalAuthority {
    pub key: [u8; 32],
    pub jurisdiction: u64,
    pub legal_basis: u64,
    pub assets: BTreeSet<AssetId>,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnforcementAuthority {
    pub key: [u8; 32],
    pub jurisdiction: u64,
    pub legal_basis: u64,
    pub assets: BTreeSet<AssetId>,
}

pub(super) fn valid_authorities(config: &Ed25519Profile, keys: &mut BTreeSet<[u8; 32]>) -> bool {
    config.legal_authorities.iter().all(|(actor, authority)| {
        config.peers.contains_key(actor)
            && !authority.assets.is_empty()
            && !authority.actions.is_empty()
            && verifying_key(&authority.key).is_some()
            && keys.insert(authority.key)
    }) && config.enforcement_authorities.values().all(|authority| {
        !authority.assets.is_empty()
            && verifying_key(&authority.key).is_some()
            && keys.insert(authority.key)
    })
}

fn legal_message(
    config: &Ed25519Profile,
    target: u64,
    stage: LegalStage,
    id: CallId,
    payload: &LegalPayload,
    order: &Order,
) -> Result<([u8; 32], Vec<u8>), WireError> {
    let authority = config
        .legal_authorities
        .get(&order.officer)
        .ok_or(INVALID)?;
    let (expected, stage_tag) = match stage {
        LegalStage::SourceEmission => (order.binding.origin.domain, 1u8),
        LegalStage::ReceivingCommit => (order.binding.destination, 2u8),
    };
    if target != expected
        || payload.caller != order.officer
        || id.namespace != order.officer
        || payload.cut.authority_epoch != config.authority_epoch
        || order.issuance_epoch != config.authority_epoch
        || payload.binding != order.binding
        || payload.action != order.action
        || order.jurisdiction != authority.jurisdiction
        || order.legal_basis != authority.legal_basis
        || !order.scope.contains(&order.binding.asset)
        || !order.scope.is_subset(&authority.assets)
        || !authority.actions.contains(&order.action)
    {
        return Err(INVALID);
    }
    Ok((
        authority.key,
        preimage(
            b"oip/reference-legal-order/v1\0",
            &(config.profile, target, stage_tag, id, payload, order),
        )?,
    ))
}

fn enforcement_message(
    config: &Ed25519Profile,
    target: u64,
    id: CallId,
    payload: &SpendPayload,
    order: &EnforcementOrder,
) -> Result<([u8; 32], Vec<u8>), WireError> {
    let authority = config
        .enforcement_authorities
        .get(&order.officer)
        .ok_or(INVALID)?;
    if target != order.scope.root.destination
        || payload.scope != order.scope
        || id.namespace != payload.caller
        || payload.cut.authority_epoch != config.authority_epoch
        || order.jurisdiction != authority.jurisdiction
        || order.legal_basis != authority.legal_basis
        || !order.assets.contains(&order.scope.root.asset)
        || !order.assets.is_subset(&authority.assets)
    {
        return Err(INVALID);
    }
    Ok((
        authority.key,
        preimage(
            b"oip/reference-enforcement-order/v1\0",
            &(config.profile, target, id, payload, order),
        )?,
    ))
}

/// Trusted legal authority. The role key issues only registered scoped orders.
pub struct LegalIssuer(SigningKey);

impl LegalIssuer {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn issue<C: AuthorityClock>(
        &self,
        security: &Ed25519Security<C>,
        target: u64,
        stage: LegalStage,
        id: CallId,
        payload: &LegalPayload,
        order: &Order,
    ) -> Result<Vec<u8>, WireError> {
        let (key, message) = legal_message(&security.config, target, stage, id, payload, order)?;
        if key != self.0.verifying_key().to_bytes() {
            return Err(INVALID);
        }
        Ok(self.0.sign(&message).to_bytes().to_vec())
    }
}

pub struct EnforcementIssuer(SigningKey);

impl EnforcementIssuer {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn issue<C: AuthorityClock>(
        &self,
        security: &Ed25519Security<C>,
        target: u64,
        id: CallId,
        payload: &SpendPayload,
        order: &EnforcementOrder,
    ) -> Result<Vec<u8>, WireError> {
        let (key, message) = enforcement_message(&security.config, target, id, payload, order)?;
        if key != self.0.verifying_key().to_bytes() {
            return Err(INVALID);
        }
        Ok(self.0.sign(&message).to_bytes().to_vec())
    }
}

pub(super) fn verify_order(
    config: &Ed25519Profile,
    target: u64,
    stage: LegalStage,
    id: CallId,
    payload: &LegalPayload,
    order: &Order,
    proof: &[u8],
) -> bool {
    legal_message(config, target, stage, id, payload, order)
        .is_ok_and(|(key, message)| verify_strict(&key, &message, proof))
}

pub(super) fn verify_enforcement(
    config: &Ed25519Profile,
    target: u64,
    id: CallId,
    payload: &SpendPayload,
    order: &EnforcementOrder,
    proof: &[u8],
) -> bool {
    enforcement_message(config, target, id, payload, order)
        .is_ok_and(|(key, message)| verify_strict(&key, &message, proof))
}
