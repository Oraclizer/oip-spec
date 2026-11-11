use super::codec::{
    CanonicalPacket, Result, WireError, body, check_declared_version, decode_packet,
};
use super::generated::Core;
use super::negotiation::{Profile, verify};
use super::threshold::{ThresholdRoster, verify_threshold};
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "operation_tests.rs"]
mod operation_tests;

#[cfg(test)]
#[path = "threshold_tests.rs"]
mod threshold_tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Boundary {
    pub deployment: u64,
    pub source: u64,
    pub target: u64,
    pub principal: u64,
    pub key_id: u64,
    pub epoch: u64,
    pub route_scope: u64,
    pub now: u64,
    pub asset_ttl_floor: u64,
    pub future_skew: u64,
    pub max_frame: usize,
    pub max_nesting: usize,
    pub version_floor: u64,
    pub critical_allowed: bool,
    pub public_key: [u8; 32],
}

pub fn check_scope(core: &Core, profile: &Profile, boundary: &Boundary) -> Result<()> {
    check_versioned_scope(core, profile, boundary, 6)
}

pub(super) fn check_versioned_scope(
    core: &Core,
    profile: &Profile,
    boundary: &Boundary,
    version: u64,
) -> Result<()> {
    if profile.version != version
        || core.version != Some(version)
        || boundary.version_floor > version
        || !body(core).is_ok_and(|(family, op)| {
            op.opcode
                .is_some_and(|opcode| profile.allows(family, opcode))
        })
        || !core
            .atomicity
            .is_some_and(|mode| profile.atomicities.contains(&mode))
    {
        return Err(WireError::UnsupportedVersion);
    }
    if core.purpose != Some(1)
        || core.deployment != Some(boundary.deployment)
        || core.source_domain != Some(boundary.source)
        || core.target_domain != Some(boundary.target)
        || core.principal != Some(boundary.principal)
        || core.key_id != Some(boundary.key_id)
        || core.authority_epoch != Some(boundary.epoch)
        || core.route_scope != Some(boundary.route_scope)
        || (core.priority == Some(0) && !boundary.critical_allowed)
    {
        return Err(WireError::InvalidSource);
    }
    let sent = core.issued_seconds.ok_or(WireError::InvalidFormat)?;
    let expiry = wire_expiry(core, boundary)?;
    let latest = boundary
        .now
        .checked_add(boundary.future_skew)
        .ok_or(WireError::TtlInvalid)?;
    if sent > latest {
        return Err(WireError::TtlInvalid);
    }
    if expiry < boundary.now {
        return Err(WireError::TtlExpired);
    }
    Ok(())
}

pub(crate) fn wire_expiry(core: &Core, boundary: &Boundary) -> Result<u64> {
    let sent = core.issued_seconds.ok_or(WireError::InvalidFormat)?;
    let ttl = core.ttl_seconds.ok_or(WireError::InvalidFormat)?.max(boundary.asset_ttl_floor);
    sent.checked_add(ttl).ok_or(WireError::TtlInvalid)
}

pub fn admit_packet(
    packet: &CanonicalPacket,
    profile: &Profile,
    boundary: &Boundary,
) -> Result<()> {
    // Existing direct callers already supply a canonical Packet. Preserve
    // their scope/signature order independently of the configured frame gate.
    check_scope(packet.core(), profile, boundary)?;
    check_signature(packet, &profile.schemes, &boundary.public_key, &[])
}

pub fn admit_packet_configured(
    packet: &CanonicalPacket,
    profile: &Profile,
    boundary: &Boundary,
    rosters: &[ThresholdRoster],
) -> Result<()> {
    if packet.encode()?.len() > boundary.max_frame {
        return Err(WireError::InvalidFormat);
    }
    check_scope(packet.core(), profile, boundary)?;
    check_signature(packet, &profile.schemes, &boundary.public_key, rosters)
}

/// Signature admission only. Callers must first bound/decode the complete frame
/// and apply their scope/delivery checks. The channel key stays the SINGLE key.
pub(crate) fn check_signature(
    packet: &CanonicalPacket,
    schemes: &std::collections::BTreeSet<u64>,
    public_key: &[u8; 32],
    rosters: &[ThresholdRoster],
) -> Result<()> {
    let scheme = packet
        .core()
        .signature_scheme
        .ok_or(WireError::InvalidFormat)?;
    if scheme == 2 {
        if !schemes.contains(&2) {
            return Err(WireError::InvalidThresholdSignature);
        }
        return verify_threshold(packet, rosters);
    }
    if !schemes.contains(&scheme)
        || !verify(
            public_key,
            &packet.signing_bytes()?,
            packet.signature(),
        )
    {
        return Err(WireError::InvalidSignature);
    }
    Ok(())
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct TransportKey {
    deployment: u64,
    source: u64,
    principal: u64,
    uuid: [u8; 16],
}

impl TransportKey {
    pub fn for_core(core: &Core) -> Result<Self> {
        let bad = WireError::InvalidFormat;
        Ok(Self {
            deployment: core.deployment.ok_or(bad)?,
            source: core.source_domain.ok_or(bad)?,
            principal: core.principal.ok_or(bad)?,
            uuid: core
                .uuid
                .as_deref()
                .ok_or(bad)?
                .try_into()
                .map_err(|_| bad)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arrival {
    First,
    Identical,
}

pub fn compare_binding(retained: Option<&Vec<u8>>, exact: &[u8]) -> Result<Arrival> {
    match retained {
        None => Ok(Arrival::First),
        Some(bytes) if bytes == exact => Ok(Arrival::Identical),
        Some(_) => Err(WireError::ReplayConflict),
    }
}

#[derive(Default)]
pub struct TransportBindings(BTreeMap<TransportKey, Vec<u8>>);

impl TransportBindings {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn receive(
        &mut self,
        bytes: &[u8],
        profile: &Profile,
        boundary: &Boundary,
        attest: impl FnOnce(&Core) -> bool,
    ) -> Result<(Arrival, CanonicalPacket)> {
        self.receive_configured(bytes, profile, boundary, &[], attest)
    }

    pub fn receive_configured(
        &mut self,
        bytes: &[u8],
        profile: &Profile,
        boundary: &Boundary,
        rosters: &[ThresholdRoster],
        attest: impl FnOnce(&Core) -> bool,
    ) -> Result<(Arrival, CanonicalPacket)> {
        if profile.version != 6 {
            return Err(WireError::UnsupportedVersion);
        }
        check_declared_version(bytes, boundary.max_frame)?;
        let packet = decode_packet(bytes, boundary.max_frame)?;
        admit_packet_configured(&packet, profile, boundary, rosters)?;
        if !attest(packet.core()) {
            return Err(WireError::InvalidSource);
        }
        super::operands::decode(packet.core(), boundary.max_nesting)?;
        let key = TransportKey::for_core(packet.core())?;
        let arrival = compare_binding(self.0.get(&key), packet.core_bytes())?;
        if arrival == Arrival::First {
            self.0.insert(key, packet.core_bytes().to_vec());
        }
        Ok((arrival, packet))
    }
}
