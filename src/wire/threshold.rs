//! Current, host-configured Ed25519 threshold envelope registrations.
use super::codec::{CanonicalPacket, Result, WireError};
use super::generated::Core;
use super::negotiation::{valid_public_key, verify};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[cfg(test)]
#[path = "threshold_trace.rs"]
pub(crate) mod trace;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThresholdRoster {
    pub deployment: u64,
    pub source: u64,
    pub principal: u64,
    pub key_id: u64,
    pub epoch: u64,
    pub quorum: u64,
    pub members: Vec<(u64, [u8; 32])>,
}

impl ThresholdRoster {
    pub fn valid(&self) -> bool {
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        self.quorum != 0
            && u64::try_from(self.members.len()).is_ok_and(|n| self.quorum <= n)
            && self.members.iter().all(|(id, key)| {
                ids.insert(*id) && keys.insert(*key) && valid_public_key(key)
            })
    }

    pub fn matches(&self, core: &Core) -> bool {
        core.deployment == Some(self.deployment)
            && core.source_domain == Some(self.source)
            && core.principal == Some(self.principal)
            && core.key_id == Some(self.key_id)
            && core.authority_epoch == Some(self.epoch)
    }
}

/// Select exactly one current registration; registration ambiguity is a refusal.
pub(crate) fn select<'a>(rosters: &'a [ThresholdRoster], core: &Core) -> Option<&'a ThresholdRoster> {
    let mut matches = rosters.iter().filter(|roster| roster.matches(core));
    let selected = matches.next()?;
    (matches.next().is_none() && selected.valid()).then_some(selected)
}

pub(crate) fn verify_threshold(packet: &CanonicalPacket, rosters: &[ThresholdRoster]) -> Result<()> {
    let bad = WireError::InvalidThresholdSignature;
    let roster = select(rosters, packet.core()).ok_or(bad)?;
    let signature = packet.signature();
    // The caller bounds the complete Packet before this count is read. Derive
    // the available records first, and never allocate from the claimed count.
    let (count, records) = signature.split_first_chunk::<8>().ok_or(bad)?;
    if !records.len().is_multiple_of(72) {
        return Err(bad);
    }
    let available = u64::try_from(records.len() / 72).map_err(|_| bad)?;
    let count = u64::from_be_bytes(*count);
    if count != available || count < roster.quorum
        || count > u64::try_from(roster.members.len()).map_err(|_| bad)?
    {
        return Err(bad);
    }
    let message = packet.signing_bytes()?;
    let mut previous = None;
    for record in records.chunks_exact(72) {
        let id = u64::from_be_bytes(record[..8].try_into().map_err(|_| bad)?);
        if previous.is_some_and(|previous| id <= previous) {
            return Err(bad);
        }
        previous = Some(id);
        let key = roster.members.iter().find(|(member, _)| *member == id)
            .map(|(_, key)| key).ok_or(bad)?;
        if !verify(key, &message, &record[8..]) {
            return Err(bad);
        }
    }
    Ok(())
}
