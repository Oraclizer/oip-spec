//! Canonical OIP packet bytes. Generated messages are data, not authority.

use super::generated::{Core, Operation, Packet, core::Body, operation::AppealDeadline};
use prost::Message;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    InvalidFormat,
    UnsupportedVersion,
    InvalidSource,
    InvalidSignature,
    InvalidThresholdSignature,
    TtlExpired,
    TtlInvalid,
    ReplayConflict,
    RequestUnresolved,
    Cancelled,
    DeadlineExpired,
    ResponseLost,
    ProductRejected,
    Recovery(crate::authority::recovery::RecoveryError),
}

pub(super) type Result<T> = std::result::Result<T, WireError>;

const BAD: WireError = WireError::InvalidFormat;

#[derive(Clone, Copy)]
pub(super) enum Field<'a> {
    Varint(u32, u64),
    Fixed64(u32),
    Bytes(u32, &'a [u8]),
}

pub(super) fn varint(mut number: u64, bytes: &mut Vec<u8>) {
    while number >= 128 {
        bytes.push((number as u8 & 127) | 128);
        number >>= 7;
    }
    bytes.push(number as u8);
}

fn take_varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0;
    for index in 0..10 {
        let (byte, rest) = input.split_first().ok_or(BAD)?;
        *input = rest;
        if index == 9 && *byte > 1 {
            return Err(BAD);
        }
        value |= u64::from(byte & 127) << (index * 7);
        if byte & 128 == 0 {
            if index > 0 && *byte == 0 {
                return Err(BAD);
            }
            return Ok(value);
        }
    }
    Err(BAD)
}

fn take_bytes<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8]> {
    let (value, tail) = input.split_at_checked(size).ok_or(BAD)?;
    *input = tail;
    Ok(value)
}

pub(super) fn fields(mut input: &[u8]) -> Result<Vec<Field<'_>>> {
    let mut result = Vec::new();
    while !input.is_empty() {
        let key = take_varint(&mut input)?;
        let tag = u32::try_from(key >> 3).map_err(|_| BAD)?;
        if !(1..=(1 << 29) - 1).contains(&tag) {
            return Err(BAD);
        }
        let value = match key & 7 {
            0 => Field::Varint(tag, take_varint(&mut input)?),
            1 => {
                take_bytes(&mut input, 8)?;
                Field::Fixed64(tag)
            }
            2 => {
                let size = usize::try_from(take_varint(&mut input)?).map_err(|_| BAD)?;
                Field::Bytes(tag, take_bytes(&mut input, size)?)
            }
            _ => return Err(BAD),
        };
        result.push(value);
    }
    Ok(result)
}

pub(super) fn field_varint(tag: u32, value: u64, bytes: &mut Vec<u8>) {
    varint(u64::from(tag) << 3, bytes);
    varint(value, bytes);
}

pub(super) fn field_fixed64(tag: u32, value: u64, bytes: &mut Vec<u8>) {
    varint((u64::from(tag) << 3) | 1, bytes);
    bytes.extend(value.to_le_bytes());
}

pub(super) fn field_bytes(tag: u32, value: &[u8], bytes: &mut Vec<u8>) {
    varint((u64::from(tag) << 3) | 2, bytes);
    varint(value.len() as u64, bytes);
    bytes.extend(value);
}

pub(super) fn body(core: &Core) -> Result<(u64, &Operation)> {
    Ok(match core.body.as_ref().ok_or(BAD)? {
        Body::StateSync(op) => (1, op),
        Body::RegulatoryAction(op) => (2, op),
        Body::LockManagement(op) => (3, op),
        Body::Query(op) => (4, op),
        Body::Ack(op) => (5, op),
        Body::Heartbeat(op) => (6, op),
        Body::Governance(op) => (7, op),
    })
}

fn opcode_allowed(family: u64, opcode: u64) -> bool {
    [6, 3, 8, 8, 2, 2, 2]
        .get((family.saturating_sub(1)) as usize)
        .is_some_and(|last| (1..=*last).contains(&opcode))
        && family != 0
}

fn encode_operation(op: &Operation) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    field_varint(1, op.opcode.ok_or(BAD)?, &mut out);
    for word in &op.words {
        field_fixed64(2, *word, &mut out);
    }
    for blob in &op.blobs {
        field_bytes(3, blob, &mut out);
    }
    match op.appeal_deadline {
        None => (),
        Some(AppealDeadline::AppealDeadlineIndefinite(true)) => field_varint(4, 1, &mut out),
        Some(AppealDeadline::AppealDeadlineIndefinite(false)) => return Err(BAD),
        Some(AppealDeadline::AppealDeadlineUtcSeconds(time)) => field_fixed64(5, time, &mut out),
    }
    Ok(out)
}

fn validate_operation_bytes(bytes: &[u8]) -> Result<()> {
    let values = fields(bytes)?;
    let [Field::Varint(1, _), rest @ ..] = values.as_slice() else {
        return Err(BAD);
    };
    let words = rest
        .iter()
        .take_while(|field| matches!(field, Field::Fixed64(2)))
        .count();
    let tail = &rest[words..];
    let blobs = tail
        .iter()
        .take_while(|field| matches!(field, Field::Bytes(3, _)))
        .count();
    match &tail[blobs..] {
        [] | [Field::Varint(4, 1)] | [Field::Fixed64(5)] => Ok(()),
        _ => Err(BAD),
    }
}

fn validate_core_bytes(bytes: &[u8]) -> Result<()> {
    let values = fields(bytes)?;
    let [
        Field::Varint(1, _),
        Field::Varint(2, _),
        Field::Fixed64(3),
        Field::Fixed64(4),
        Field::Fixed64(5),
        Field::Fixed64(6),
        Field::Fixed64(7),
        Field::Fixed64(8),
        Field::Fixed64(9),
        Field::Fixed64(10),
        Field::Bytes(11, _),
        Field::Varint(12, family),
        Field::Varint(13, _),
        tail @ ..,
    ] = values.as_slice()
    else {
        return Err(BAD);
    };
    let tail = if matches!(tail.first(), Some(Field::Varint(14, _))) {
        &tail[1..]
    } else {
        tail
    };
    let [
        Field::Varint(15, _),
        Field::Bytes(tag, op),
        Field::Varint(23, _),
        Field::Varint(24, _),
        Field::Fixed64(25),
    ] = tail
    else {
        return Err(BAD);
    };
    if !(1..=7).contains(family) || u64::from(*tag) != 15 + family {
        return Err(BAD);
    }
    validate_operation_bytes(op)
}

pub fn encode_core(core: &Core) -> Result<Vec<u8>> {
    let (family, op) = body(core)?;
    let uuid: &[u8; 16] = core
        .uuid
        .as_deref()
        .ok_or(BAD)?
        .try_into()
        .map_err(|_| BAD)?;
    let primary = core.primary.ok_or(BAD)?;
    let scheme = core.signature_scheme.ok_or(BAD)?;
    let atomicity = core.atomicity.ok_or(BAD)?;
    let priority = core.priority.ok_or(BAD)?;
    if core.family != Some(family)
        || uuid[6] >> 4 != 4
        || uuid[8] >> 6 != 2
        || !(1..=5).contains(&primary)
        || !matches!(scheme, 1 | 2)
        || !(1..=3).contains(&atomicity)
        || priority > 4
        || (priority == 0 && atomicity != 3)
        || !opcode_allowed(family, op.opcode.ok_or(BAD)?)
    {
        return Err(BAD);
    }
    let mut out = Vec::new();
    field_varint(1, core.version.ok_or(BAD)?, &mut out);
    field_varint(2, core.purpose.ok_or(BAD)?, &mut out);
    for (index, item) in [
        core.deployment,
        core.source_domain,
        core.target_domain,
        core.principal,
        core.key_id,
        core.authority_epoch,
        core.issued_seconds,
        core.ttl_seconds,
    ]
    .into_iter()
    .enumerate()
    {
        field_fixed64(index as u32 + 3, item.ok_or(BAD)?, &mut out);
    }
    field_bytes(11, uuid, &mut out);
    field_varint(12, family, &mut out);
    field_varint(13, primary, &mut out);
    if let Some(secondary) = core.secondary {
        field_varint(14, secondary, &mut out);
    }
    field_varint(15, scheme, &mut out);
    field_bytes(15 + family as u32, &encode_operation(op)?, &mut out);
    field_varint(23, atomicity, &mut out);
    field_varint(24, priority, &mut out);
    field_fixed64(25, core.route_scope.ok_or(BAD)?, &mut out);
    Ok(out)
}

pub fn decode_core(bytes: &[u8]) -> Result<Core> {
    validate_core_bytes(bytes)?;
    let core = Core::decode(bytes).map_err(|_| BAD)?;
    if encode_core(&core)? != bytes {
        return Err(BAD);
    }
    Ok(core)
}

pub fn encode_packet(packet: &Packet) -> Result<Vec<u8>> {
    let core = packet.core.as_ref().ok_or(BAD)?;
    let signature = packet.signature.as_deref().ok_or(BAD)?;
    if (core.signature_scheme == Some(1) && signature.len() != 64)
        || (core.signature_scheme == Some(2) && signature.is_empty())
    {
        return Err(BAD);
    }
    let bytes = encode_core(core)?;
    let _ = u32::try_from(bytes.len()).map_err(|_| BAD)?;
    let mut out = Vec::new();
    field_bytes(1, &bytes, &mut out);
    field_bytes(2, signature, &mut out);
    Ok(out)
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalPacket {
    packet: Packet,
    core_bytes: Vec<u8>,
}

impl CanonicalPacket {
    pub fn core(&self) -> &Core {
        self.packet.core.as_ref().expect("validated core")
    }
    pub fn signature(&self) -> &[u8] {
        self.packet
            .signature
            .as_deref()
            .expect("validated signature presence")
    }
    pub fn core_bytes(&self) -> &[u8] {
        &self.core_bytes
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_packet(&self.packet)
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(&self.core_bytes)
    }
}

pub fn decode_packet(bytes: &[u8], max_frame: usize) -> Result<CanonicalPacket> {
    if bytes.len() > max_frame {
        return Err(BAD);
    }
    let values = fields(bytes)?;
    let [Field::Bytes(1, core), Field::Bytes(2, _)] = values.as_slice() else {
        return Err(BAD);
    };
    let checked_core = decode_core(core)?;
    let packet = Packet::decode(bytes).map_err(|_| BAD)?;
    if packet.core.as_ref() != Some(&checked_core) || encode_packet(&packet)? != bytes {
        return Err(BAD);
    }
    Ok(CanonicalPacket {
        packet,
        core_bytes: core.to_vec(),
    })
}

/// The version that a received frame declares: the varint of core field 1
/// when the frame starts with packet field 1 and the core it carries starts
/// with field 1. Nothing else in the frame is read, so the answer does not
/// depend on fields that a later version may add. A frame that does not start
/// this way declares no version, and the canonical decoder reports it.
pub fn declared_version(bytes: &[u8]) -> Option<u64> {
    let mut input = bytes;
    if take_varint(&mut input).ok()? != (1 << 3) | 2 {
        return None;
    }
    let size = usize::try_from(take_varint(&mut input).ok()?).ok()?;
    let mut core = input.get(..size)?;
    if take_varint(&mut core).ok()? != 1 << 3 {
        return None;
    }
    take_varint(&mut core).ok()
}

/// The version check that runs in front of the canonical decoder and the
/// admission gate. A frame within the size limit that declares a version
/// other than 6 receives UnsupportedVersion, whatever fields follow. Every
/// other frame continues to the canonical checks unchanged.
pub fn check_declared_version(bytes: &[u8], max_frame: usize) -> Result<()> {
    if bytes.len() > max_frame {
        return Err(BAD);
    }
    match declared_version(bytes) {
        Some(version) if version != 6 => Err(WireError::UnsupportedVersion),
        _ => Ok(()),
    }
}

pub fn signing_bytes(core: &[u8]) -> Result<Vec<u8>> {
    let mut out = b"OIP\0ENVELOPE\0".to_vec();
    out.extend(u32::try_from(core.len()).map_err(|_| BAD)?.to_be_bytes());
    out.extend(core);
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unsigned256(pub [u8; 32]);

impl Unsigned256 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| BAD)?))
    }

    pub fn product_amount(self) -> Result<u64> {
        if self.0[..24].iter().any(|&byte| byte != 0) {
            return Err(BAD);
        }
        Ok(u64::from_be_bytes(self.0[24..].try_into().unwrap()))
    }
}
