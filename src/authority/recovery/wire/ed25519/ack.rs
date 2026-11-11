//! Acknowledgements issued only from actual durable receiver records.

use super::{
    AuthorityClock, Ed25519Profile, INVALID, maintenance::AuthorizedDispatch,
};
use crate::authority::recovery::ordered::etcd::EtcdTransport;
use crate::authority::recovery::{HeadError, RecoveryProfile};
use crate::authority::{Acknowledgement, Publication, SettlementKey, SettlementStatus};
use crate::lock_finality::TerminalKind;
use crate::wire::codec::{WireError, decode_packet, encode_core, encode_packet, signing_bytes};
use crate::wire::generated::{Core, Operation, Packet, core::Body};
use crate::wire::negotiation::Channel;
use crate::wire::operands::{Operands, decode};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize)]
struct ReceiverState {
    profile: RecoveryProfile,
    target: u64,
    receipts: Vec<Publication>,
}

/// The receiving service owns this independently configured durable store.
pub struct ReceiverJournal {
    transport: EtcdTransport,
    profile: RecoveryProfile,
    target: u64,
}

impl ReceiverJournal {
    pub fn new(transport: EtcdTransport, profile: RecoveryProfile, target: u64) -> Self {
        Self {
            transport,
            profile,
            target,
        }
    }

    /// Accept an exact dispatched job from the ordered authority. Application
    /// callers cannot construct an AuthorizedDispatch from a publication alone.
    pub fn record(&self, dispatched: &AuthorizedDispatch) -> Result<bool, HeadError> {
        let job = dispatched.job();
        if dispatched.profile() != self.profile
            || job.target != self.target
            || job.status != SettlementStatus::InFlight
            || job.attempts == 0
            || job.commitment.origin != job.commitment.decision.binding.origin
        {
            return Err(HeadError);
        }
        let (observed, mut state) = self.read()?;
        let key = job.commitment.key();
        match state
            .receipts
            .binary_search_by_key(&key, |receipt| receipt.key())
        {
            Ok(index) if state.receipts[index] == job.commitment => return Ok(false),
            Ok(_) => return Err(HeadError),
            Err(index) => state.receipts.insert(index, job.commitment),
        }
        let value = serde_json::to_vec(&state).map_err(|_| HeadError)?;
        if self.transport.replace(&observed, &value) == Ok(true) {
            return Ok(true);
        }
        if self.receipt(key)? == job.commitment {
            Ok(false)
        } else {
            Err(HeadError)
        }
    }

    fn receipt(&self, key: SettlementKey) -> Result<Publication, HeadError> {
        let (_, state) = self.read()?;
        let index = state
            .receipts
            .binary_search_by_key(&key, |receipt| receipt.key())
            .map_err(|_| HeadError)?;
        Ok(state.receipts[index])
    }

    fn read(
        &self,
    ) -> Result<
        (
            crate::authority::recovery::ordered::ControlValue,
            ReceiverState,
        ),
        HeadError,
    > {
        let raw = self.transport.current()?;
        let state: ReceiverState = if raw.bytes.is_empty() {
            ReceiverState {
                profile: self.profile,
                target: self.target,
                receipts: Vec::new(),
            }
        } else {
            let state = serde_json::from_slice(&raw.bytes).map_err(|_| HeadError)?;
            if serde_json::to_vec(&state).map_err(|_| HeadError)? != raw.bytes {
                return Err(HeadError);
            }
            state
        };
        if state.profile != self.profile
            || state.target != self.target
            || state
                .receipts
                .windows(2)
                .any(|pair| pair[0].key() >= pair[1].key())
            || state
                .receipts
                .iter()
                .any(|receipt| receipt.origin != receipt.decision.binding.origin)
        {
            return Err(HeadError);
        }
        Ok((raw, state))
    }
}

/// The receiving role owns a dedicated key. It can only emit acknowledgements
/// of its own durable receiver journal.
pub struct AckIssuer(SigningKey);

impl AckIssuer {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn issue<C: AuthorityClock>(
        &self,
        config: &Ed25519Profile,
        clock: &C,
        channel: &Channel,
        journal: &ReceiverJournal,
        key: SettlementKey,
    ) -> Result<Vec<u8>, WireError> {
        let commitment = journal.receipt(key).map_err(|_| INVALID)?;
        let (principal, peer) = receiver(config, journal.target).ok_or(INVALID)?;
        let binding = commitment.decision.binding;
        let time = clock.unix_seconds().ok_or(INVALID)?;
        if journal.profile != config.profile
            || peer.public_key != self.0.verifying_key().to_bytes()
            || channel.profile().version != 6
            || channel.deployment() != config.profile.deployment
            || channel.local() != journal.target
            || channel.remote() != binding.destination
            || channel.peer_keys() != &[peer.public_key, config.response_key]
            || time > channel.expires()
        {
            return Err(INVALID);
        }
        let kind = match commitment.decision.kind {
            TerminalKind::Confirmed => 1,
            TerminalKind::Reversed => 2,
        };
        let mut placeholder = [0u8; 16];
        placeholder[6] = 0x40;
        placeholder[8] = 0x80;
        let mut amount = vec![0; 24];
        amount.extend_from_slice(&binding.amount.to_be_bytes());
        let atomicity = channel
            .profile()
            .atomicities
            .first()
            .copied()
            .ok_or(INVALID)?;
        let mut core = Core {
            version: Some(6),
            purpose: Some(1),
            deployment: Some(config.profile.deployment),
            source_domain: Some(journal.target),
            target_domain: Some(binding.destination),
            principal: Some(principal),
            key_id: Some(peer.key_id),
            authority_epoch: Some(config.authority_epoch),
            issued_seconds: Some(time),
            ttl_seconds: Some(config.response_ttl_seconds),
            uuid: Some(placeholder.to_vec()),
            family: Some(5),
            primary: Some(1),
            secondary: None,
            signature_scheme: Some(1),
            atomicity: Some(atomicity),
            priority: Some(3),
            route_scope: Some(config.route_scope),
            body: Some(Body::Ack(Operation {
                opcode: Some(1),
                appeal_deadline: None,
                blobs: vec![amount],
                words: vec![
                    binding.origin.domain,
                    binding.origin.event,
                    u64::try_from(key.commit.position).map_err(|_| INVALID)?,
                    journal.target,
                    binding.asset,
                    binding.owner,
                    binding.destination,
                    binding.recipient,
                    commitment.decision.origin_epoch,
                    kind,
                ],
            })),
        };
        let mut uuid_hash = Sha256::new();
        uuid_hash.update(b"oip/reference-receiver-ack-uuid/v1\0");
        uuid_hash.update(encode_core(&core)?);
        let mut uuid: [u8; 16] = uuid_hash.finalize()[..16].try_into().map_err(|_| INVALID)?;
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        core.uuid = Some(uuid.to_vec());
        let signature = self
            .0
            .sign(&signing_bytes(&encode_core(&core)?)?)
            .to_bytes()
            .to_vec();
        encode_packet(&Packet {
            core: Some(core),
            signature: Some(signature),
        })
    }
}

fn receiver(config: &Ed25519Profile, target: u64) -> Option<(u64, &super::PeerRegistration)> {
    let principal = *config.acknowledgers.get(&target)?;
    let peer = config.peers.get(&principal)?;
    (peer.identity.domain == target).then_some((principal, peer))
}

pub(super) fn valid_receivers(config: &Ed25519Profile) -> bool {
    let mut ids = BTreeSet::new();
    config.acknowledgers.keys().all(|&target| {
        receiver(config, target).is_some_and(|(principal, peer)| {
            ids.insert(principal)
                && peer.sessions.values().all(|grants| {
                    grants
                        .values()
                        .all(|grant| *grant == super::EndpointGrant::default())
                })
        })
    })
}

pub(super) fn verify_ack(config: &Ed25519Profile, rosters: &[crate::wire::threshold::ThresholdRoster], ack: &Acknowledgement, bytes: &[u8]) -> bool {
    let Some((principal, peer)) = receiver(config, ack.target) else {
        return false;
    };
    let Ok(packet) = decode_packet(bytes, config.max_frame) else {
        return false;
    };
    let core = packet.core();
    core.version == Some(6)
        && core.purpose == Some(1)
        && core.deployment == Some(config.profile.deployment)
        && core.source_domain == Some(ack.target)
        && core.target_domain == Some(ack.commitment.decision.binding.destination)
        && core.principal == Some(principal)
        && core.authority_epoch == Some(config.authority_epoch)
        && core.route_scope == Some(config.route_scope)
        && super::verify_registered_envelope(&packet, peer, rosters)
        && matches!(decode(core, config.max_nesting), Ok(Operands::Ack(decoded)) if decoded == *ack)
}
