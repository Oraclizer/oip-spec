use super::codec::{Result, WireError};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offer {
    pub deployment: u64,
    pub sender: u64,
    pub receiver: u64,
    pub challenge: u64,
    pub expires: u64,
    pub versions: BTreeSet<u64>,
    pub families: BTreeSet<u64>,
    pub atomicities: BTreeSet<u64>,
    pub schemes: BTreeSet<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub version: u64,
    pub families: BTreeSet<u64>,
    pub atomicities: BTreeSet<u64>,
    pub schemes: BTreeSet<u64>,
}

impl Profile {
    pub fn allows(&self, family: u64, opcode: u64) -> bool {
        self.families.contains(&family)
            && (self.version != 5 || (matches!(family, 4 | 6) && (1..=2).contains(&opcode)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    profile: Profile,
    deployment: u64,
    local: u64,
    remote: u64,
    expires: u64,
    challenge: u64,
    peer_keys: [[u8; 32]; 2],
}

impl Channel {
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    pub fn deployment(&self) -> u64 {
        self.deployment
    }
    pub fn local(&self) -> u64 {
        self.local
    }
    pub fn remote(&self) -> u64 {
        self.remote
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn challenge(&self) -> u64 {
        self.challenge
    }
    pub fn peer_keys(&self) -> &[[u8; 32]; 2] {
        &self.peer_keys
    }
}

pub struct Negotiation {
    pub deployment: u64,
    pub local: u64,
    pub remote: u64,
    pub challenge: u64,
    pub now: u64,
    pub floor: u64,
    pub legacy_allowed: bool,
    pub local_key: [u8; 32],
    pub remote_key: [u8; 32],
}

pub struct SignedOffers<'a> {
    pub local: &'a Offer,
    pub remote: &'a Offer,
    pub local_signature: &'a [u8],
    pub remote_signature: &'a [u8],
    pub confirmation: &'a [u8],
}

fn append_set(out: &mut Vec<u8>, set: &BTreeSet<u64>) {
    out.extend((set.len() as u64).to_be_bytes());
    for value in set {
        out.extend(value.to_be_bytes());
    }
}

pub fn offer_bytes(offer: &Offer) -> Vec<u8> {
    let mut out = b"OIP\0HEARTBEAT-OFFER\0".to_vec();
    for value in [
        offer.deployment,
        offer.sender,
        offer.receiver,
        offer.challenge,
        offer.expires,
    ] {
        out.extend(value.to_be_bytes());
    }
    for set in [
        &offer.versions,
        &offer.families,
        &offer.atomicities,
        &offer.schemes,
    ] {
        append_set(&mut out, set);
    }
    out
}

pub fn confirmation_bytes(local: &Offer, remote: &Offer, profile: &Profile) -> Vec<u8> {
    let mut out = b"OIP\0HEARTBEAT-PROFILE\0".to_vec();
    for offer in [local, remote] {
        let bytes = offer_bytes(offer);
        out.extend((bytes.len() as u64).to_be_bytes());
        out.extend(bytes);
    }
    out.extend(profile.version.to_be_bytes());
    for set in [&profile.families, &profile.atomicities, &profile.schemes] {
        append_set(&mut out, set);
    }
    out
}

pub(crate) fn verify(key: &[u8; 32], bytes: &[u8], signature: &[u8]) -> bool {
    fn canonical_point(point: &[u8]) -> bool {
        let Some(mut y) = <[u8; 32]>::try_from(point).ok() else {
            return false;
        };
        y[31] &= 127;
        let mut prime = [255u8; 32];
        prime[0] = 237;
        prime[31] = 127;
        y.iter().rev().cmp(prime.iter().rev()).is_lt()
    }
    if !canonical_point(key) || !signature.get(..32).is_some_and(canonical_point) {
        return false;
    }
    VerifyingKey::from_bytes(key)
        .and_then(|key| {
            let sig = Signature::from_slice(signature)?;
            key.verify_strict(bytes, &sig)
        })
        .is_ok()
}

pub fn select_profile(
    local: &Offer,
    remote: &Offer,
    floor: u64,
    legacy_allowed: bool,
) -> Result<Profile> {
    let version = [6, 5]
        .into_iter()
        .find(|&version| {
            version >= floor
                && (version != 5 || legacy_allowed)
                && local.versions.contains(&version)
                && remote.versions.contains(&version)
        })
        .ok_or(WireError::UnsupportedVersion)?;
    Ok(Profile {
        version,
        families: local
            .families
            .intersection(&remote.families)
            .copied()
            .filter(|family| version != 5 || matches!(family, 4 | 6))
            .collect(),
        atomicities: local
            .atomicities
            .intersection(&remote.atomicities)
            .copied()
            .collect(),
        schemes: local
            .schemes
            .intersection(&remote.schemes)
            .copied()
            .filter(|scheme| version != 5 || *scheme == 1)
            .collect(),
    })
}

pub fn negotiate(context: &Negotiation, signed: SignedOffers<'_>) -> Result<Channel> {
    let local = signed.local;
    let remote = signed.remote;
    if local.deployment != context.deployment
        || remote.deployment != context.deployment
        || local.sender != context.local
        || local.receiver != context.remote
        || remote.sender != context.remote
        || remote.receiver != context.local
        || local.challenge != context.challenge
        || remote.challenge != context.challenge
        || local.expires < context.now
        || remote.expires < context.now
    {
        return Err(WireError::InvalidSource);
    }
    if !verify(
        &context.local_key,
        &offer_bytes(local),
        signed.local_signature,
    ) || !verify(
        &context.remote_key,
        &offer_bytes(remote),
        signed.remote_signature,
    ) {
        return Err(WireError::InvalidSignature);
    }
    let profile = select_profile(local, remote, context.floor, context.legacy_allowed)?;
    if !verify(
        &context.remote_key,
        &confirmation_bytes(local, remote, &profile),
        signed.confirmation,
    ) {
        return Err(WireError::InvalidSignature);
    }
    Ok(Channel {
        profile,
        deployment: context.deployment,
        local: context.local,
        remote: context.remote,
        expires: local.expires.min(remote.expires),
        challenge: context.challenge,
        peer_keys: [context.local_key, context.remote_key],
    })
}
