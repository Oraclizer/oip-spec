//! The explicitly selected common v0.5 reference adapter.

use super::admission::{Boundary, check_versioned_scope};
use super::codec::{Result, WireError, encode_core};
use super::generated::{Core, Operation, core::Body};
use super::negotiation::{Profile, verify};
use serde::{Deserialize, Serialize};

const BAD: WireError = WireError::InvalidFormat;

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

pub fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(BAD);
    }
    fn digit(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(BAD),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

/// The reference compatibility record is a configured codec for the common
/// Query and Heartbeat subset, rather than implicit version fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyCore {
    pub version: u64,
    pub deployment: u64,
    pub source: u64,
    pub target: u64,
    pub principal: u64,
    pub key: u64,
    pub epoch: u64,
    pub sent: u64,
    pub ttl: u64,
    pub uuid: String,
    pub family: u64,
    pub opcode: u64,
    pub words: Vec<u64>,
    pub atomicity: u64,
    pub scope: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPacket {
    pub core: LegacyCore,
    pub signature: String,
}

impl LegacyPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| BAD)
    }
}

impl LegacyCore {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"OIP\0LEGACY\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| BAD)?);
        Ok(bytes)
    }

    fn typed(&self) -> Result<Core> {
        let op = Operation {
            opcode: Some(self.opcode),
            words: self.words.clone(),
            blobs: Vec::new(),
            appeal_deadline: None,
        };
        let body = match (self.family, self.opcode) {
            (4, 1 | 2) => Body::Query(op),
            (6, 1 | 2) => Body::Heartbeat(op),
            _ => return Err(WireError::UnsupportedVersion),
        };
        let core = Core {
            version: Some(self.version),
            purpose: Some(1),
            deployment: Some(self.deployment),
            source_domain: Some(self.source),
            target_domain: Some(self.target),
            principal: Some(self.principal),
            key_id: Some(self.key),
            authority_epoch: Some(self.epoch),
            issued_seconds: Some(self.sent),
            ttl_seconds: Some(self.ttl),
            uuid: Some(unhex(&self.uuid)?),
            family: Some(self.family),
            primary: Some(1),
            secondary: None,
            signature_scheme: Some(1),
            body: Some(body),
            atomicity: Some(self.atomicity),
            priority: Some(3),
            route_scope: Some(self.scope),
        };
        encode_core(&core)?;
        Ok(core)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedLegacy {
    core: Core,
    exact: Vec<u8>,
}

impl ValidatedLegacy {
    pub fn core(&self) -> &Core {
        &self.core
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}

pub fn decode_shape(bytes: &[u8], max_frame: usize) -> Result<Core> {
    if bytes.len() > max_frame {
        return Err(BAD);
    }
    let packet: LegacyPacket = serde_json::from_slice(bytes).map_err(|_| BAD)?;
    if packet.encode()? != bytes {
        return Err(BAD);
    }
    packet.core.typed()
}

pub fn receive(bytes: &[u8], profile: &Profile, boundary: &Boundary) -> Result<ValidatedLegacy> {
    if profile.version != 5 {
        return Err(WireError::UnsupportedVersion);
    }
    if bytes.len() > boundary.max_frame {
        return Err(BAD);
    }
    let packet: LegacyPacket = serde_json::from_slice(bytes).map_err(|_| BAD)?;
    if packet.encode()? != bytes {
        return Err(BAD);
    }
    let core = packet.core.typed()?;
    check_versioned_scope(&core, profile, boundary, 5)?;
    if !profile.schemes.contains(&1)
        || !verify(
            &boundary.public_key,
            &packet.core.signing_bytes()?,
            &unhex(&packet.signature)?,
        )
    {
        return Err(WireError::InvalidSignature);
    }
    super::operands::decode(&core, boundary.max_nesting)?;
    Ok(ValidatedLegacy {
        core,
        exact: serde_json::to_vec(&packet.core).map_err(|_| BAD)?,
    })
}
