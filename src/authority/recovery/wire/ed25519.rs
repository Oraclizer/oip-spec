//! Registered Ed25519 identity and wire supply for the ordered reference profile.

use super::response::{ResponseParameters, ResponseSigner};
use super::schedule::WireScheduleLimits;
use super::{WireSecurity, commitment_read_at, read_at};
use crate::authority::identity::{
    Action, Handover, Identity, Operation, ReadRequest, Scope, Security, SessionProof, Signed,
};
use crate::authority::reads::Query;
use crate::authority::sync;
use crate::authority::recovery::RecoveryProfile;
use crate::authority::regulation::{
    EnforcementOrder, LegalPayload, LegalStage, Order, SpendPayload,
};
use crate::authority::{Acknowledgement, CallPayload};
use crate::lock_finality::{Command, TerminalEvidence};
use crate::wire::admission::{Boundary, check_signature};
use crate::wire::threshold::ThresholdRoster;
use crate::wire::codec::{WireError, decode_core, decode_packet, encode_core};
use crate::wire::generated::{Core, core::Body};
use crate::wire::negotiation::Channel;
use crate::wire::operands::{Operands, decode, decode_response_for_signing};
use crate::{AssetId, CommitCut, Principal, SessionId};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

const INVALID: WireError = WireError::InvalidSource;

pub mod ack;
pub mod dispatch;
pub mod handover;
pub mod legal;
pub mod maintenance;
pub mod source;
mod supply;
pub use supply::claim_recovery_signing_bytes;

pub trait AuthorityClock {
    fn unix_seconds(&self) -> Option<u64>;
}

pub struct SystemClock;

impl AuthorityClock for SystemClock {
    fn unix_seconds(&self) -> Option<u64> {
        Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointGrant {
    pub execute: BTreeSet<AssetId>,
    pub receipts: BTreeSet<AssetId>,
    pub current: Vec<Query>,
    pub journal: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub historical: Vec<Query>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<Query>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub status: BTreeSet<crate::OriginKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache: Vec<Query>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub owner: BTreeSet<AssetId>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub recovery: BTreeSet<AssetId>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub legal: BTreeSet<AssetId>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub spend: BTreeSet<AssetId>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub transfer_owner: BTreeSet<AssetId>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub full_resync: BTreeSet<sync::Stream>,
}

pub type SessionGrants = BTreeMap<u64, EndpointGrant>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerRegistration {
    pub identity: Identity,
    pub key_id: u64,
    pub public_key: [u8; 32],
    pub sessions: BTreeMap<SessionId, SessionGrants>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ed25519Profile {
    pub profile: RecoveryProfile,
    pub authority_epoch: u64,
    pub endpoint: u64,
    pub route_scope: u64,
    pub local_principal: Principal,
    pub local_key_id: u64,
    pub response_key: [u8; 32],
    pub session_issuer: [u8; 32],
    pub maintenance_issuer: [u8; 32],
    pub peers: BTreeMap<Principal, PeerRegistration>,
    pub maintainers: BTreeSet<Principal>,
    pub max_token_seconds: u64,
    pub response_ttl_seconds: u64,
    pub asset_ttl_floor: u64,
    pub future_skew: u64,
    pub max_frame: usize,
    pub max_nesting: usize,
    pub schedule_limits: Option<[usize; 2]>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub other_endpoints: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sources: source::SourceAuthorities,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub maintenance_authorities: BTreeMap<Principal, maintenance::MaintenanceAuthority>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub legal_authorities: BTreeMap<Principal, legal::LegalAuthority>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub enforcement_authorities: BTreeMap<Principal, legal::EnforcementAuthority>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub acknowledgers: BTreeMap<u64, Principal>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub handover_maintainers: BTreeSet<Principal>,
    /// The largest signed delivery TTL in seconds that this configuration
    /// admits. Absent sets no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delivery_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "source::SyncPolicy::is_empty")]
    pub sync: source::SyncPolicy,
}

/// Explicit current envelope policy. Existing SINGLE profile literals and
/// serialized profiles stay valid; an empty roster preserves their identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfiguredEd25519Profile {
    #[serde(flatten)]
    pub single: Ed25519Profile,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threshold_rosters: Vec<ThresholdRoster>,
}

impl<'de> Deserialize<'de> for ConfiguredEd25519Profile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize the JSON object directly: serde's flattened intermediate
        // map otherwise loses numeric-key decoding for existing peer maps.
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let object = value.as_object_mut().ok_or_else(|| serde::de::Error::custom("expected profile object"))?;
        let threshold_rosters = object.remove("threshold_rosters")
            .map(serde_json::from_value).transpose().map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let single = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self { single, threshold_rosters })
    }
}

impl From<Ed25519Profile> for ConfiguredEd25519Profile {
    fn from(single: Ed25519Profile) -> Self {
        Self { single, threshold_rosters: Vec::new() }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionClaims {
    pub profile: RecoveryProfile,
    pub epoch: u64,
    pub identity: Identity,
    pub session: SessionId,
    pub issuer: [u8; 32],
    pub grants_sha256: [u8; 32],
    pub issued_seconds: u64,
    pub expires_seconds: u64,
}

impl SessionClaims {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        preimage(b"oip/reference-session/v1\0", self)
    }
}

pub struct SessionToken {
    pub claims: SessionClaims,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum MaintenanceRole {
    ReferenceControl,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MaintenanceClaims {
    pub role: MaintenanceRole,
    pub profile: RecoveryProfile,
    pub epoch: u64,
    pub principal: Principal,
    pub issuer: [u8; 32],
    pub issued_seconds: u64,
    pub expires_seconds: u64,
}

impl MaintenanceClaims {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        preimage(b"oip/reference-maintenance/v1\0", self)
    }
}

pub struct MaintenanceToken {
    pub claims: MaintenanceClaims,
    pub signature: [u8; 64],
}

/// Held by the trusted session issuer after external caller authentication.
/// The issuer signs only a registration already present in the policy.
pub struct SessionIssuer(SigningKey);

impl SessionIssuer {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn issue<C: AuthorityClock>(
        &self,
        security: &Ed25519Security<C>,
        principal: Principal,
        session: SessionId,
        valid_seconds: u64,
    ) -> Result<SessionToken, WireError> {
        if self.0.verifying_key().to_bytes() != security.config.session_issuer {
            return Err(INVALID);
        }
        let (issued, expires) = security.issuance_window(valid_seconds)?;
        let claims = security
            .session_claims(principal, session, issued, expires)
            .ok_or(INVALID)?;
        let signature = self.0.sign(&claims.signing_bytes()?).to_bytes();
        Ok(SessionToken { claims, signature })
    }
}

/// Held separately by the trusted maintenance issuer.
pub struct MaintenanceIssuer(SigningKey);

impl MaintenanceIssuer {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn issue<C: AuthorityClock>(
        &self,
        security: &Ed25519Security<C>,
        principal: Principal,
        valid_seconds: u64,
    ) -> Result<MaintenanceToken, WireError> {
        let config = &security.config;
        if self.0.verifying_key().to_bytes() != config.maintenance_issuer
            || !config.maintainers.contains(&principal)
        {
            return Err(INVALID);
        }
        let (issued_seconds, expires_seconds) = security.issuance_window(valid_seconds)?;
        let claims = MaintenanceClaims {
            role: MaintenanceRole::ReferenceControl,
            profile: config.profile,
            epoch: config.authority_epoch,
            principal,
            issuer: config.maintenance_issuer,
            issued_seconds,
            expires_seconds,
        };
        let signature = self.0.sign(&claims.signing_bytes()?).to_bytes();
        Ok(MaintenanceToken { claims, signature })
    }
}

/// Installed by the trusted host. The private response key is never part of
/// the profile fingerprint, and this handle is not returned by request APIs.
pub struct Ed25519Security<C> {
    config: Ed25519Profile,
    threshold_rosters: Vec<ThresholdRoster>,
    binding: [u8; 32],
    next: Option<handover::SuccessorPolicy>,
    response_key: SigningKey,
    clock: C,
}

impl<C: AuthorityClock> Ed25519Security<C> {
    pub fn new(
        config: Ed25519Profile,
        response_key: SigningKey,
        clock: C,
    ) -> Result<Self, WireError> {
        Self::new_configured(config.into(), response_key, clock)
    }

    pub fn new_configured(
        configured: ConfiguredEd25519Profile,
        response_key: SigningKey,
        clock: C,
    ) -> Result<Self, WireError> {
        let binding = configured_policy_binding(&configured)?;
        let ConfiguredEd25519Profile { single: config, threshold_rosters } = configured;
        if response_key.verifying_key().to_bytes() != config.response_key {
            return Err(INVALID);
        }
        Ok(Self {
            config,
            threshold_rosters,
            binding,
            next: None,
            response_key,
            clock,
        })
    }

    /// Return the exact claims an external issuer can authorize. This does not
    /// mint a token or expose an issuer private key.
    pub fn session_claims(
        &self,
        principal: Principal,
        session: SessionId,
        issued_seconds: u64,
        expires_seconds: u64,
    ) -> Option<SessionClaims> {
        let peer = self.config.peers.get(&principal)?;
        let grants = peer.sessions.get(&session)?;
        let grants_sha256 =
            Sha256::digest(preimage(b"oip/reference-session-grants/v1\0", grants).ok()?).into();
        Some(SessionClaims {
            profile: self.config.profile,
            epoch: self.config.authority_epoch,
            identity: peer.identity,
            session,
            issuer: self.config.session_issuer,
            grants_sha256,
            issued_seconds,
            expires_seconds,
        })
    }

    fn issuance_window(&self, valid_seconds: u64) -> Result<(u64, u64), WireError> {
        if valid_seconds == 0 || valid_seconds > self.config.max_token_seconds {
            return Err(INVALID);
        }
        let now = self.clock.unix_seconds().ok_or(INVALID)?;
        Ok((now, now.checked_add(valid_seconds).ok_or(INVALID)?))
    }

    fn local_endpoint(&self, target: u64) -> bool {
        target == self.config.endpoint || self.config.other_endpoints.contains(&target)
    }

    fn current_token(&self, issued: u64, expires: u64) -> bool {
        let Some(now) = self.clock.unix_seconds() else {
            return false;
        };
        issued <= now
            && now <= expires
            && expires
                .checked_sub(issued)
                .is_some_and(|age| age <= self.config.max_token_seconds)
    }

    fn grant(
        &self,
        identity: Identity,
        session: SessionId,
        target: u64,
        operation: Operation,
        scope: Scope,
    ) -> bool {
        self.config
            .peers
            .get(&identity.principal)
            .filter(|peer| peer.identity == identity)
            .and_then(|peer| peer.sessions.get(&session))
            .and_then(|grants| grants.get(&target))
            .is_some_and(|grant| permits(grant, operation, scope))
    }
}

fn authority_policy_binding(config: &Ed25519Profile) -> Result<[u8; 32], WireError> {
    let role_keys = [
        config.response_key,
        config.session_issuer,
        config.maintenance_issuer,
    ];
    let mut keys: BTreeSet<_> = role_keys.into_iter().collect();
    if keys.len() != role_keys.len()
        || keys.iter().any(|key| verifying_key(key).is_none())
        || !config.handover_maintainers.is_subset(&config.maintainers)
        || config.peers.is_empty()
        || config.max_frame == 0
        || config.max_nesting < 2
        || config.max_token_seconds == 0
        || config.response_ttl_seconds == 0
    {
        return Err(INVALID);
    }
    for (&principal, peer) in &config.peers {
        if principal != peer.identity.principal
            || peer.sessions.is_empty()
            || verifying_key(&peer.public_key).is_none()
            || !keys.insert(peer.public_key)
        {
            return Err(INVALID);
        }
    }
    if !maintenance::valid_authorities(config, &mut keys)
        || !legal::valid_authorities(config, &mut keys)
        || !ack::valid_receivers(config)
        || !source::valid_authorities(&config.sources, &keys)
        || !config.sync.valid(&keys)
    {
        return Err(INVALID);
    }
    Ok(Sha256::digest(preimage(b"oip/reference-authority-policy/v1\0", config)?).into())
}

fn configured_policy_binding(configured: &ConfiguredEd25519Profile) -> Result<[u8; 32], WireError> {
    let config = &configured.single;
    let original = authority_policy_binding(config)?;
    if configured.threshold_rosters.is_empty() {
        return Ok(original);
    }
    let mut scopes = BTreeSet::new();
    for roster in &configured.threshold_rosters {
        if !roster.valid()
            || roster.deployment != config.profile.deployment
            || roster.epoch != config.authority_epoch
            || !config.peers.get(&roster.principal).is_some_and(|peer| peer.identity.domain == roster.source)
            || !scopes.insert((roster.deployment, roster.source, roster.principal, roster.key_id, roster.epoch))
        {
            return Err(INVALID);
        }
    }
    Ok(Sha256::digest(preimage(b"oip/reference-threshold-policy/v1\0", &(original, &configured.threshold_rosters))?).into())
}

fn verify_registered_envelope(
    packet: &crate::wire::codec::CanonicalPacket,
    peer: &PeerRegistration,
    rosters: &[ThresholdRoster],
) -> bool {
    let checked = check_signature(packet, &BTreeSet::from([1, 2]), &peer.public_key, rosters);
    #[cfg(test)] crate::wire::threshold::trace::record("authority-envelope", packet, rosters, &checked);
    (packet.core().signature_scheme == Some(2) || packet.core().key_id == Some(peer.key_id))
        && checked.is_ok()
}

fn permits(grant: &EndpointGrant, operation: Operation, scope: Scope) -> bool {
    match (operation, scope) {
        (Operation::Execute, Scope::Asset(asset)) => grant.execute.contains(&asset),
        (Operation::FullResync, Scope::Commitment(stream)) => grant.full_resync.contains(&stream),
        (Operation::Receipt, Scope::Asset(asset)) => grant.receipts.contains(&asset),
        (Operation::Journal, Scope::Read(ReadRequest::Journal)) => grant.journal,
        (Operation::Historical, Scope::Read(ReadRequest::Historical { query, .. })) => {
            grant.historical.contains(&query)
        }
        (Operation::Raw, Scope::Read(ReadRequest::Raw(query))) => grant.raw.contains(&query),
        (Operation::Status, Scope::Read(ReadRequest::Status(origin))) => {
            grant.status.contains(&origin)
        }
        (Operation::Current, Scope::Read(ReadRequest::CaptureCache(query))) => {
            grant.cache.contains(&query)
        }
        (Operation::ReadOwner, Scope::Read(ReadRequest::Owner(asset))) => {
            grant.owner.contains(&asset)
        }
        (Operation::RecoverClaim, Scope::Asset(asset)) => grant.recovery.contains(&asset),
        (Operation::TransferOwner, Scope::Asset(asset)) => grant.transfer_owner.contains(&asset),
        (Operation::EmitOrder | Operation::CommitOrder, Scope::Asset(asset)) => {
            grant.legal.contains(&asset)
        }
        (Operation::Spend, Scope::Asset(asset)) => grant.spend.contains(&asset),
        (Operation::Current, Scope::Read(ReadRequest::Current { query, .. })) => {
            grant.current.contains(&query)
        }
        _ => false,
    }
}

fn preimage(domain: &[u8], fields: &impl Serialize) -> Result<Vec<u8>, WireError> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(fields).map_err(|_| WireError::InvalidFormat)?);
    Ok(bytes)
}

fn verifying_key(raw: &[u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(raw)
        .ok()
        .filter(|key| !key.is_weak())
}

fn verify_strict(key: &[u8; 32], bytes: &[u8], signature: &[u8]) -> bool {
    verifying_key(key)
        .zip(Signature::from_slice(signature).ok())
        .is_some_and(|(key, signature)| key.verify_strict(bytes, &signature).is_ok())
}

fn spend_proof(
    config: &Ed25519Profile,
    target: u64,
    id: crate::CallId,
    payload: &SpendPayload,
    order: Option<&EnforcementOrder>,
    proof: Option<&[u8]>,
) -> bool {
    match (order, proof) {
        (None, None) => true,
        (Some(order), Some(proof)) => {
            legal::verify_enforcement(config, target, id, payload, order, proof)
        }
        _ => false,
    }
}

fn supported_call(command: Command) -> bool {
    matches!(
        command,
        Command::Reserve { .. }
            | Command::Dispatch { .. }
            | Command::Debit { .. }
            | Command::RecordTerminal(_)
            | Command::Credit { .. }
            | Command::Refund { .. }
            | Command::Cancel { .. }
            | Command::Fence { .. }
            | Command::Preempt { .. }
            | Command::Reconcile { .. }
            | Command::Write { .. }
            | Command::PublishPrimary
    )
}

fn supported_frame(core: &Core, sync: &source::SyncPolicy) -> bool {
    match core.body.as_ref() {
        Some(Body::StateSync(op)) => {
            matches!(op.opcode, Some(1..=6)) || (sync.accept_sync && op.opcode == Some(7))
        }
        Some(Body::RegulatoryAction(op)) => matches!(op.opcode, Some(1..=3)),
        Some(Body::Ack(op)) => op.opcode == Some(1),
        Some(Body::Query(op)) => {
            matches!(op.opcode, Some(1..=8)) || (sync.accept_current && op.opcode == Some(9))
        }
        Some(Body::LockManagement(op)) => matches!(op.opcode, Some(1..=7)),
        Some(Body::Governance(op)) => op.opcode == Some(1),
        _ => false,
    }
}

impl<C: AuthorityClock> Security for Ed25519Security<C> {
    type Token = SessionToken;
    type Signature = Vec<u8>;
    type MaintenanceToken = MaintenanceToken;

    fn ordered_revocation_profile(&self) -> Option<RecoveryProfile> {
        Some(self.config.profile)
    }

    fn requires_authority_binding(&self) -> bool {
        true
    }

    fn authority_binding(&self, epoch: u64) -> Option<[u8; 32]> {
        (epoch == self.config.authority_epoch).then_some(self.binding)
    }

    fn prepared_authority_binding(&self, epoch: u64) -> Option<[u8; 32]> {
        self.authority_binding(epoch).or_else(|| {
            self.next
                .as_ref()
                .filter(|next| next.epoch() == epoch)
                .map(|next| next.binding())
        })
    }

    fn handover_policy_binding(
        &self,
        proposal: &Handover,
        sessions: &BTreeMap<SessionId, crate::SessionBinding>,
    ) -> Option<[u8; 32]> {
        self.handover_policy(proposal)?.bind_sessions(sessions)
    }

    fn authenticate(&self, token: &SessionToken) -> Option<Identity> {
        let claim = &token.claims;
        let expected = self.session_claims(
            claim.identity.principal,
            claim.session,
            claim.issued_seconds,
            claim.expires_seconds,
        )?;
        if *claim != expected
            || !self.current_token(claim.issued_seconds, claim.expires_seconds)
            || !verify_strict(
                &self.config.session_issuer,
                &claim.signing_bytes().ok()?,
                &token.signature,
            )
        {
            return None;
        }
        Some(claim.identity)
    }

    fn authenticate_session(&self, token: &SessionToken, proof: SessionProof) -> Option<Identity> {
        if token.claims.epoch != proof.epoch || token.claims.session != proof.session {
            return None;
        }
        self.authenticate(token)
    }

    fn authenticate_maintenance(&self, token: &MaintenanceToken) -> Option<Principal> {
        let claim = &token.claims;
        if claim.role != MaintenanceRole::ReferenceControl
            || claim.profile != self.config.profile
            || claim.epoch != self.config.authority_epoch
            || claim.issuer != self.config.maintenance_issuer
            || !self.config.maintainers.contains(&claim.principal)
            || !self.current_token(claim.issued_seconds, claim.expires_seconds)
            || !verify_strict(
                &self.config.maintenance_issuer,
                &claim.signing_bytes().ok()?,
                &token.signature,
            )
        {
            return None;
        }
        Some(claim.principal)
    }

    fn permit(
        &self,
        identity: Identity,
        target: u64,
        operation: Operation,
        scope: Scope,
        epoch: u64,
    ) -> bool {
        epoch == self.config.authority_epoch
            && self
                .config
                .peers
                .get(&identity.principal)
                .is_some_and(|peer| {
                    peer.identity == identity
                        && peer
                            .sessions
                            .keys()
                            .any(|session| self.grant(identity, *session, target, operation, scope))
                })
    }

    fn permit_session(
        &self, identity: Identity, proof: SessionProof, target: u64, operation: Operation, scope: Scope,
    ) -> bool {
        proof.epoch == self.config.authority_epoch
            && self.grant(identity, proof.session, target, operation, scope)
    }

    fn verify_commitment_attestation(&self, call: &sync::Call<'_>) -> bool {
        self.config.sync.accept_sync
            && self.config.profile.deployment == call.deployment
            && self.config.sync.verifies(call)
    }

    fn verify(
        &self,
        identity: Identity,
        proof: SessionProof,
        target: u64,
        operation: Operation,
        signed: Signed<'_>,
        signature: &Vec<u8>,
    ) -> bool {
        let Some(peer) = self.config.peers.get(&identity.principal) else {
            return false;
        };
        if peer.identity != identity
            || proof.epoch != self.config.authority_epoch
            || !self.local_endpoint(target)
        {
            return false;
        }
        if let (
            Operation::RecoverClaim,
            Signed::Recovery {
                origin,
                id,
                payload,
            },
        ) = (operation, signed)
        {
            return origin == payload.binding.origin
                && self.grant(
                    identity,
                    proof.session,
                    target,
                    operation,
                    Scope::Asset(payload.binding.asset),
                )
                && claim_recovery_signing_bytes(
                    self.config.profile,
                    identity,
                    proof,
                    target,
                    origin,
                    id,
                    payload,
                )
                .is_ok_and(|message| verify_strict(&peer.public_key, &message, signature));
        }
        let Ok(packet) = decode_packet(signature, self.config.max_frame) else {
            return false;
        };
        let core = packet.core();
        if core.version != Some(6)
            || core.purpose != Some(1)
            || core.deployment != Some(self.config.profile.deployment)
            || core.source_domain != Some(identity.domain)
            || core.target_domain != Some(target)
            || core.principal != Some(identity.principal)
            || core.authority_epoch != Some(proof.epoch)
            || core.route_scope != Some(self.config.route_scope)
            || !verify_registered_envelope(&packet, peer, &self.threshold_rosters)
        {
            return false;
        }
        let mut exact = Cow::Borrowed(packet.core_bytes());
        let operand = match decode(core, self.config.max_nesting) {
            Ok(Operands::Receipt { session, original })
                if operation == Operation::Receipt
                    && session == proof.session
                    && crate::wire::operands::same_original(core, &original) =>
            {
                let decoded = decode(&original, self.config.max_nesting - 1);
                if matches!(decoded, Ok(Operands::SyncCommitment { .. })) {
                    let Ok(bytes) = encode_core(&original) else { return false };
                    exact = Cow::Owned(bytes);
                }
                decoded
            }
            other => other,
        };
        match (operation, signed, operand) {
            (
                Operation::Execute | Operation::Receipt,
                Signed::Call { id, action: Action::SyncCommitment(expected) },
                Ok(Operands::SyncCommitment { id: decoded, session, asset, .. }),
            ) => {
                self.config.sync.accept_sync
                    && id == decoded
                    && session == proof.session
                    && exact.as_ref() == expected.exact
                    && self.grant(identity, proof.session, target, operation, Scope::Asset(asset))
            }
            (
                Operation::Current,
                Signed::Read(expected),
                Ok(read @ Operands::CurrentCommitment { session, .. }),
            ) => {
                self.config.sync.accept_current
                    && session == proof.session
                    && commitment_read_at(&read, proof.epoch) == Some(expected)
                    && self.grant(identity, proof.session, target, operation, Scope::Read(expected))
            }
            (
                Operation::Execute | Operation::Receipt,
                Signed::Call {
                    id,
                    action: Action::Ordinary(expected),
                },
                Ok(Operands::Ordinary {
                    id: decoded,
                    payload,
                    proofs,
                }),
            ) => {
                id == decoded
                    && payload == *expected
                    && payload.session == proof.session
                    && supported_call(payload.command)
                    && supply::terminal_proof(&self.config, &payload, &proofs)
                    && self.grant(
                        identity,
                        proof.session,
                        target,
                        operation,
                        Scope::Asset(payload.binding.asset),
                    )
            }
            (
                Operation::EmitOrder | Operation::CommitOrder | Operation::Receipt,
                Signed::Call {
                    id,
                    action:
                        Action::Legal {
                            stage,
                            order,
                            payload,
                        },
                },
                Ok(Operands::Legal {
                    id: decoded,
                    stage: selected_stage,
                    payload: decoded_payload,
                    order: decoded_order,
                    proof: certificate,
                }),
            ) => {
                id == decoded
                    && stage == selected_stage
                    && payload == decoded_payload
                    && *order == decoded_order
                    && payload.session == proof.session
                    && legal::verify_order(
                        &self.config,
                        target,
                        stage,
                        id,
                        &payload,
                        order,
                        &certificate,
                    )
                    && self.grant(
                        identity,
                        proof.session,
                        target,
                        operation,
                        Scope::Asset(payload.binding.asset),
                    )
            }
            (
                Operation::Spend | Operation::Receipt,
                Signed::Call {
                    id,
                    action:
                        Action::Spend {
                            payload,
                            enforcement,
                        },
                },
                Ok(Operands::Spend {
                    id: decoded,
                    payload: decoded_payload,
                    authorization,
                    proof: certificate,
                }),
            ) => {
                id == decoded
                    && payload == decoded_payload
                    && enforcement == authorization.as_ref()
                    && payload.session == proof.session
                    && spend_proof(
                        &self.config,
                        target,
                        id,
                        &payload,
                        enforcement,
                        certificate.as_deref(),
                    )
                    && self.grant(
                        identity,
                        proof.session,
                        target,
                        operation,
                        Scope::Asset(payload.scope.root.asset),
                    )
            }
            (
                Operation::Current
                | Operation::Historical
                | Operation::Raw
                | Operation::Status
                | Operation::Journal
                | Operation::ReadOwner,
                Signed::Read(expected),
                Ok(Operands::Read(read)),
            ) => {
                read.session() == proof.session
                    && read_at(read, proof.epoch) == expected
                    && self.grant(
                        identity,
                        proof.session,
                        target,
                        operation,
                        Scope::Read(expected),
                    )
            }
            _ => false,
        }
    }

    fn verify_terminal(&self, _: Identity, _: SessionProof, _: u64, _: TerminalEvidence) -> bool {
        false
    }
    fn verify_terminal_packet(
        &self,
        _: Identity,
        proof: SessionProof,
        target: u64,
        payload: &CallPayload,
        evidence: TerminalEvidence,
        signature: &Vec<u8>,
    ) -> bool {
        if proof.epoch != self.config.authority_epoch
            || target != payload.endpoint
            || payload.command != Command::RecordTerminal(evidence)
        {
            return false;
        }
        let Ok(packet) = decode_packet(signature, self.config.max_frame) else {
            return false;
        };
        matches!(decode(packet.core(), self.config.max_nesting),
            Ok(Operands::Ordinary { payload: decoded, proofs, .. })
                if decoded == *payload && supply::terminal_proof(&self.config, payload, &proofs))
    }

    fn verify_order(&self, _: Identity, _: SessionProof, _: u64, _: LegalStage, _: &Order) -> bool {
        false
    }
    fn verify_enforcement(
        &self,
        _: Identity,
        _: SessionProof,
        _: u64,
        _: &EnforcementOrder,
    ) -> bool {
        false
    }
    fn verify_order_packet(
        &self,
        _: Identity,
        proof: SessionProof,
        target: u64,
        stage: LegalStage,
        id: crate::CallId,
        payload: &LegalPayload,
        order: &Order,
        signature: &Vec<u8>,
    ) -> bool {
        let Ok(packet) = decode_packet(signature, self.config.max_frame) else {
            return false;
        };
        proof.epoch == self.config.authority_epoch
            && matches!(
                decode(packet.core(), self.config.max_nesting),
                Ok(Operands::Legal { id: actual, stage: decoded_stage, payload: decoded_payload, order: decoded_order, proof: certificate })
                    if actual == id && decoded_stage == stage && decoded_payload == *payload && decoded_order == *order
                        && legal::verify_order(&self.config, target, stage, id, payload, order, &certificate)
            )
    }

    fn verify_enforcement_packet(
        &self,
        _: Identity,
        proof: SessionProof,
        target: u64,
        id: crate::CallId,
        payload: &SpendPayload,
        order: &EnforcementOrder,
        signature: &Vec<u8>,
    ) -> bool {
        let Ok(packet) = decode_packet(signature, self.config.max_frame) else {
            return false;
        };
        proof.epoch == self.config.authority_epoch
            && matches!(
                decode(packet.core(), self.config.max_nesting),
                Ok(Operands::Spend { id: actual, payload: decoded_payload, authorization: Some(decoded_order), proof: Some(certificate) })
                    if actual == id && decoded_payload == *payload && decoded_order == *order
                        && legal::verify_enforcement(&self.config, target, id, payload, order, &certificate)
            )
    }

    fn verify_time(
        &self,
        actor: Principal,
        cut: CommitCut,
        observed: u64,
        signature: &Vec<u8>,
    ) -> bool {
        maintenance::verify_time(self, actor, cut, observed, signature)
    }
    fn verify_ack(&self, acknowledgement: &Acknowledgement, signature: &Vec<u8>) -> bool {
        ack::verify_ack(&self.config, &self.threshold_rosters, acknowledgement, signature)
    }
    fn approve(&self, identity: Identity, proposal: &Handover, signature: &Vec<u8>) -> bool {
        self.verify_consent(identity, proposal, signature)
    }
}

impl<C: AuthorityClock> WireSecurity for Ed25519Security<C> {
    fn threshold_rosters(&self) -> &[ThresholdRoster] {
        &self.threshold_rosters
    }

    fn verify_original_signature(&self, channel: &Channel, packet: &crate::wire::codec::CanonicalPacket) -> Result<(), WireError> {
        if packet.core().signature_scheme == Some(2)
            && !packet.core().principal.and_then(|id| self.config.peers.get(&id)).is_some_and(|peer| {
                peer.identity.domain == channel.remote() && peer.public_key == channel.peer_keys()[1]
            })
        {
            return Err(WireError::InvalidThresholdSignature);
        }
        check_signature(packet, &channel.profile().schemes, &channel.peer_keys()[1], &self.threshold_rosters)
    }

    fn channel_current(&self, channel: &Channel) -> bool {
        channel.profile().version == 6
            && channel.deployment() == self.config.profile.deployment
            && self.local_endpoint(channel.local())
            && channel.peer_keys()[0] == self.config.response_key
            && self.config.peers.values().any(|peer| {
                peer.identity.domain == channel.remote()
                    && peer.public_key == channel.peer_keys()[1]
            })
    }

    fn frame_limit(&self, _: &Channel) -> usize {
        self.config.max_frame
    }

    fn accepts_operation(&self, _: &Channel, core: &Core) -> bool {
        supported_frame(core, &self.config.sync)
    }

    fn max_delivery_ttl(&self, _: &Channel) -> Option<u64> {
        self.config.max_delivery_ttl_seconds
    }

    fn wire_boundary(&self, channel: &Channel, core: &Core, live: CommitCut) -> Option<Boundary> {
        let principal = core.principal?;
        let peer = self.config.peers.get(&principal)?;
        if !self.channel_current(channel)
            || !supported_frame(core, &self.config.sync)
            || (matches!(core.body, Some(Body::Ack(_)))
                && self.config.acknowledgers.get(&channel.remote()) != Some(&principal))
            || live.authority_epoch != self.config.authority_epoch
            || peer.identity.domain != channel.remote()
            || peer.public_key != channel.peer_keys()[1]
        {
            return None;
        }
        Some(Boundary {
            deployment: self.config.profile.deployment,
            source: channel.remote(),
            target: channel.local(),
            principal,
            key_id: if core.signature_scheme == Some(2) { core.key_id? } else { peer.key_id },
            epoch: live.authority_epoch,
            route_scope: self.config.route_scope,
            now: self.clock.unix_seconds()?,
            asset_ttl_floor: self.config.asset_ttl_floor,
            future_skew: self.config.future_skew,
            max_frame: self.config.max_frame,
            max_nesting: self.config.max_nesting,
            version_floor: 6,
            critical_allowed: false,
            public_key: peer.public_key,
        })
    }

    fn legacy_configured(&self, _: &Channel) -> bool {
        false
    }
    fn verify_operand_proof(&self, core: &Core, operands: &Operands) -> bool {
        let Some(target) = core.target_domain else {
            return false;
        };
        match operands {
            Operands::Ordinary {
                payload, proofs, ..
            } => supply::terminal_proof(&self.config, payload, proofs),
            Operands::Handover {
                proposal, proofs, ..
            } => [proposal.previous, proposal.successor]
                .into_iter()
                .zip(proofs)
                .all(|(principal, proof)| {
                    self.config
                        .peers
                        .get(&principal)
                        .is_some_and(|peer| self.verify_consent(peer.identity, proposal, proof))
                }),
            Operands::Legal {
                id,
                stage,
                payload,
                order,
                proof,
            } => legal::verify_order(&self.config, target, *stage, *id, payload, order, proof),
            Operands::Spend {
                id,
                payload,
                authorization,
                proof,
            } => spend_proof(
                &self.config,
                target,
                *id,
                payload,
                authorization.as_ref(),
                proof.as_deref(),
            ),
            _ => false,
        }
    }

    fn ack_maintenance_principal(&self, token: &MaintenanceToken) -> Option<Principal> {
        let principal = self.authenticate_maintenance(token)?;
        self.config.maintenance_authorities.get(&principal)?.queue?;
        Some(principal)
    }

    fn handover_maintenance_principal(&self, token: &MaintenanceToken) -> Option<Principal> {
        let principal = self.authenticate_maintenance(token)?;
        self.config
            .handover_maintainers
            .contains(&principal)
            .then_some(principal)
    }

    fn matches_recovery_endorsement(
        &self,
        operands: &Operands,
        signature: Option<&Vec<u8>>,
    ) -> bool {
        match operands {
            Operands::Ordinary {
                payload, proofs, ..
            } if supply::lock_recovery(payload.command) => {
                matches!((proofs.as_slice(), signature), ([proof], Some(signature)) if proof == signature)
            }
            _ => true,
        }
    }

    fn matches_handover_consents(
        &self,
        operands: &Operands,
        previous: &Vec<u8>,
        successor: &Vec<u8>,
    ) -> bool {
        matches!(operands, Operands::Handover { proofs, .. } if &proofs[0] == previous && &proofs[1] == successor)
    }

    fn matches_signed_packet(&self, bytes: &[u8], signature: &Vec<u8>) -> bool {
        bytes == signature
    }

    fn requires_clock_observation(&self) -> bool {
        self.config
            .maintenance_authorities
            .values()
            .any(|authority| authority.time.is_some())
    }

    fn ordered_schedule_limits(&self) -> Option<WireScheduleLimits> {
        let [max_occurrences, max_adjacent_swaps] = self.config.schedule_limits?;
        Some(WireScheduleLimits {
            max_occurrences,
            max_adjacent_swaps,
        })
    }

    fn response_signer(&self) -> Option<&dyn ResponseSigner> {
        Some(self)
    }
}

impl<C: AuthorityClock> ResponseSigner for Ed25519Security<C> {
    fn parameters(
        &self,
        channel: &Channel,
        response_binding: [u8; 32],
    ) -> Option<ResponseParameters> {
        if !self.channel_current(channel) {
            return None;
        }
        let now = self.clock.unix_seconds()?;
        #[cfg(test)] super::response::source_trace::clock("parameters_clock",now);
        let mut uuid_hash = Sha256::new();
        uuid_hash.update(b"oip/reference-response-uuid/v1\0");
        uuid_hash.update(self.binding);
        uuid_hash.update(response_binding);
        uuid_hash.update(now.to_be_bytes());
        let uuid_digest=uuid_hash.finalize();
        #[cfg(test)] super::response::source_trace::uuid_digest(&uuid_digest);
        let mut uuid: [u8; 16] = uuid_digest[..16].try_into().ok()?;
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        let parameters=ResponseParameters {
            principal: self.config.local_principal,
            key_id: self.config.local_key_id,
            authority_epoch: self.config.authority_epoch,
            issued_seconds: now,
            ttl_seconds: self.config.response_ttl_seconds,
            uuid,
            route_scope: self.config.route_scope,
        };
        #[cfg(test)] super::response::source_trace::parameters(response_binding,&parameters);
        Some(parameters)
    }

    fn sign(&self, preimage: &[u8]) -> Option<[u8; 64]> {
        #[cfg(test)] super::response::source_trace::signer_attempt(preimage);
        let framed = preimage.strip_prefix(b"OIP\0ENVELOPE\0")?;
        let (length, bytes) = framed.split_first_chunk::<4>()?;
        if u32::from_be_bytes(*length) as usize != bytes.len() {
            return None;
        }
        let core = decode_core(bytes).ok()?;
        let now = self.clock.unix_seconds()?;
        #[cfg(test)] super::response::source_trace::clock("signing_clock",now);
        let issued = core.issued_seconds?;
        if issued > now || now > issued.checked_add(self.config.response_ttl_seconds)? {
            return None;
        }
        if core.version != Some(6)
            || core.purpose != Some(1)
            || core.deployment != Some(self.config.profile.deployment)
            || !core
                .source_domain
                .is_some_and(|source| self.local_endpoint(source))
            || !self
                .config
                .peers
                .values()
                .any(|peer| Some(peer.identity.domain) == core.target_domain)
            || core.principal != Some(self.config.local_principal)
            || core.key_id != Some(self.config.local_key_id)
            || core.authority_epoch != Some(self.config.authority_epoch)
            || core.route_scope != Some(self.config.route_scope)
            || core.ttl_seconds != Some(self.config.response_ttl_seconds)
            || core.signature_scheme != Some(1)
            || !matches!(
                decode_response_for_signing(&core, self.config.max_nesting).ok()?,
                Operands::Response { .. }
            )
        {
            return None;
        }
        let signature=self.response_key.sign(preimage).to_bytes();
        #[cfg(test)] super::response::source_trace::curve_signature(&signature);
        Some(signature)
    }
}

#[cfg(test)]
mod vector_tests;
