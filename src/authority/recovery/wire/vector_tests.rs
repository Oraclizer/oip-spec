use super::super::vector_tests::{
    DEFAULT_PROFILE, FORMER, HOST, JournalPath, Rules, Service, TestAnchor, YES, accepted, binding,
    cut, payload, submit,
};
use super::*;
use crate::authority::identity::Observation;
use crate::authority::recovery::RecoveryProfile;
use crate::authority::reads::{CheckedExecution, Value};
use crate::authority::{Collection, Outcome, OutcomeReply};
use crate::lock_finality::{Command, Reply};
use crate::vector_tests::{Vector, parse_vectors};
use crate::wire::{
    admission::TransportBindings,
    codec::{Unsigned256, decode_core, encode_core, encode_packet, signing_bytes},
    generated::{Operation, Packet, core::Body, operation::AppealDeadline},
    legacy::{LegacyCore, LegacyPacket, hex, unhex},
    negotiation::{
        Negotiation, Profile, SignedOffers, confirmation_bytes, negotiate, offer_bytes,
        select_profile,
    },
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;

const VECTORS: &str = include_str!("../../../../tests/vectors/wire-conformance.tsv");
const SOURCE_POOL_VECTORS: &str =
    include_str!("../../../../tests/vectors/source-pool-projection.tsv");
static LATE_CLOCK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static LIVE_LEGAL_PROOF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
const UUID: [u8; 16] = [0, 1, 2, 3, 4, 5, 64, 7, 128, 9, 10, 11, 12, 13, 14, 15];

fn remote_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn local_key() -> SigningKey {
    SigningKey::from_bytes(&[6; 32])
}

fn profile() -> Profile {
    Profile {
        version: 6,
        families: (1..=7).collect(),
        atomicities: (1..=3).collect(),
        schemes: BTreeSet::from([1, 2]),
    }
}

pub(in crate::authority::recovery) fn signed(mut core: Core) -> Vec<u8> {
    if core.signature_scheme.is_none() {
        core.signature_scheme = Some(1);
    }
    let signature = remote_key().sign(&signing_bytes(&encode_core(&core).unwrap()).unwrap());
    encode_packet(&Packet {
        core: Some(core),
        signature: Some(signature.to_bytes().to_vec()),
    })
    .unwrap()
}

/// A packet around exact Core bytes, signed like [signed]. The bytes need not
/// be canonical, so a test can build frames that the encoder refuses.
pub(in crate::authority::recovery) fn raw_frame(core: &[u8]) -> Vec<u8> {
    let signature = remote_key().sign(&signing_bytes(core).unwrap());
    let mut frame = vec![0x0a];
    let mut size = u64::try_from(core.len()).unwrap();
    while size >= 0x80 {
        frame.push(u8::try_from(size & 0x7f).unwrap() | 0x80);
        size >>= 7;
    }
    frame.push(u8::try_from(size).unwrap());
    frame.extend_from_slice(core);
    frame.extend([0x12, 0x40]);
    frame.extend(signature.to_bytes());
    frame
}

fn canonical() -> Core {
    Core {
        version: Some(6),
        purpose: Some(1),
        deployment: Some(7),
        source_domain: Some(0),
        target_domain: Some(2),
        principal: Some(7),
        key_id: Some(9),
        authority_epoch: Some(9),
        issued_seconds: Some(100),
        ttl_seconds: Some(5),
        uuid: Some(UUID.to_vec()),
        family: Some(4),
        primary: Some(1),
        secondary: Some(77),
        signature_scheme: Some(1),
        atomicity: Some(3),
        priority: Some(3),
        route_scope: Some(1),
        body: Some(Body::Query(Operation {
            opcode: Some(1),
            words: vec![1, 0, 1, 17],
            blobs: Vec::new(),
            appeal_deadline: None,
        })),
    }
}

fn from_vector(row: &Vector<'_>) -> Core {
    assert_eq!(row.field("family"), "query");
    Core {
        version: Some(row.number("version")),
        deployment: Some(row.number("deployment")),
        source_domain: Some(row.number("source")),
        target_domain: Some(row.number("target")),
        principal: Some(row.number("principal")),
        key_id: Some(row.number("key")),
        authority_epoch: Some(row.number("epoch")),
        issued_seconds: Some(row.number("sent")),
        ttl_seconds: Some(row.number("ttl")),
        secondary: Some(row.number("secondary")),
        atomicity: Some(row.number("atomicity")),
        priority: Some(row.number("priority")),
        route_scope: Some(row.number("scope")),
        body: Some(Body::Query(Operation {
            opcode: Some(row.number("opcode")),
            words: vec![
                row.number("session"),
                row.number("revision"),
                1,
                row.number("asset"),
            ],
            blobs: Vec::new(),
            appeal_deadline: None,
        })),
        ..canonical()
    }
}

fn boundary() -> Boundary {
    Boundary {
        deployment: 7,
        source: 0,
        target: 2,
        principal: 7,
        key_id: 9,
        epoch: 9,
        route_scope: 1,
        now: 105,
        asset_ttl_floor: 2,
        future_skew: 0,
        max_frame: 1024 * 1024,
        max_nesting: 4,
        version_floor: 5,
        critical_allowed: false,
        public_key: remote_key().verifying_key().to_bytes(),
    }
}

fn offer(sender: u64, receiver: u64, versions: &[u64]) -> Offer {
    Offer {
        deployment: 7,
        sender,
        receiver,
        challenge: 3,
        expires: 200,
        versions: versions.iter().copied().collect(),
        families: (1..=7).collect(),
        atomicities: (1..=3).collect(),
        schemes: BTreeSet::from([1, 2]),
    }
}

fn negotiated_from(
    remote_domain: u64,
    target: u64,
    local_versions: &[u64],
    remote_versions: &[u64],
    floor: u64,
    authenticated: bool,
    requested: Option<u64>,
) -> Result<Channel, WireError> {
    let local = offer(target, remote_domain, local_versions);
    let remote = offer(remote_domain, target, remote_versions);
    let context = Negotiation {
        deployment: 7,
        local: target,
        remote: remote_domain,
        challenge: 3,
        now: 105,
        floor,
        legacy_allowed: true,
        local_key: local_key().verifying_key().to_bytes(),
        remote_key: remote_key().verifying_key().to_bytes(),
    };
    let mut profile = select_profile(&local, &remote, floor, true)?;
    if let Some(requested) = requested {
        profile.version = requested;
    }
    let local_sig = local_key().sign(&offer_bytes(&local)).to_bytes();
    let mut remote_sig = remote_key().sign(&offer_bytes(&remote)).to_bytes();
    if !authenticated {
        remote_sig[0] ^= 1;
    }
    let confirm = remote_key()
        .sign(&confirmation_bytes(&local, &remote, &profile))
        .to_bytes();
    negotiate(
        &context,
        SignedOffers {
            local: &local,
            remote: &remote,
            local_signature: &local_sig,
            remote_signature: &remote_sig,
            confirmation: &confirm,
        },
    )
}

fn negotiated(
    target: u64,
    local: &[u64],
    remote: &[u64],
    floor: u64,
    authenticated: bool,
    requested: Option<u64>,
) -> Result<Channel, WireError> {
    negotiated_from(0, target, local, remote, floor, authenticated, requested)
}
pub(in crate::authority::recovery) fn channel(target: u64) -> Channel {
    negotiated(target, &[5, 6], &[5, 6], 5, true, None).unwrap()
}

impl WireSecurity for Rules {
    fn ordered_schedule_limits(&self) -> Option<schedule::WireScheduleLimits> {
        self.ordered_clock.as_ref().map(|_| schedule::WireScheduleLimits {
            max_occurrences: 4,
            max_adjacent_swaps: 3,
        })
    }

    fn response_signer(&self) -> Option<&dyn response::ResponseSigner> {
        self.ordered_clock.as_ref().map(|_| self as &dyn response::ResponseSigner)
    }

    fn channel_current(&self, channel: &Channel) -> bool {
        channel.deployment() == 7
            && matches!(channel.remote(), 0 | 99)
            && channel.challenge() == 3
            && channel.peer_keys()
                == &[
                    local_key().verifying_key().to_bytes(),
                    remote_key().verifying_key().to_bytes(),
                ]
    }
    fn frame_limit(&self, _: &Channel) -> usize {
        self.frame_limit.as_ref().map_or(boundary().max_frame, |limit| {
            limit.load(std::sync::atomic::Ordering::SeqCst)
        })
    }
    fn accepts_operation(&self, _: &Channel, core: &Core) -> bool {
        let opcode = match core.body.as_ref() {
            Some(
                Body::StateSync(op)
                | Body::RegulatoryAction(op)
                | Body::LockManagement(op)
                | Body::Query(op)
                | Body::Ack(op)
                | Body::Heartbeat(op)
                | Body::Governance(op),
            ) => op.opcode,
            None => None,
        };
        !matches!((core.family, opcode), (Some(family), Some(opcode))
            if self.refused_operations.contains(&(family, opcode)))
    }
    fn max_delivery_ttl(&self, _: &Channel) -> Option<u64> {
        self.max_delivery_ttl
    }
    fn wire_boundary(&self, channel: &Channel, core: &Core, live: CommitCut) -> Option<Boundary> {
        if let Some(hook) = &self.ordered_boundary_hook {
            hook();
        }
        let now = if let Some(clock) = &self.ordered_clock {
            clock.load(std::sync::atomic::Ordering::SeqCst)
        } else if core.uuid.as_deref().and_then(|uuid| uuid.first()) == Some(&88)
            && LATE_CLOCK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 2
        {
            106
        } else {
            105
        };
        Some(Boundary {
            source: channel.remote(),
            principal: if channel.remote() == 99 { 99 } else { 7 },
            target: channel.local(),
            epoch: live.authority_epoch,
            now,
            ..boundary()
        })
    }
    fn legacy_configured(&self, _: &Channel) -> bool {
        true
    }
    fn verify_operand_proof(&self, core: &Core, operands: &Operands) -> bool {
        if core.uuid.as_deref().and_then(|uuid| uuid.first()) == Some(&90)
            && !LIVE_LEGAL_PROOF.load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        match operands {
            Operands::Ordinary { proofs, .. } => proofs.iter().all(|proof| proof == b"verified"),
            Operands::Legal { proof, .. } => proof == b"verified",
            Operands::Spend { proof, .. } => proof.as_deref() == Some(b"verified"),
            Operands::Handover { proofs, .. } => proofs.iter().all(|proof| proof == b"verified"),
            Operands::Install { proof, .. } => proof == b"verified",
            _ => false,
        }
    }
}

#[cfg(test)]
pub(in crate::authority::recovery) mod ordered_tests;

pub(in crate::authority::recovery) fn wire_auth() -> WireCredentials<'static, Rules> {
    WireCredentials {
        token: &FORMER,
        signature: &YES,
        maintenance: Some(&HOST),
        endorsement: None,
        previous: None,
        successor: None,
    }
}

pub(in crate::authority::recovery) fn core_with(
    family: u64,
    opcode: u64,
    target: u64,
    tag: u8,
    words: Vec<u64>,
    blobs: Vec<Vec<u8>>,
) -> Core {
    let mut uuid = UUID;
    uuid[0] = tag;
    let op = Operation {
        opcode: Some(opcode),
        words,
        blobs,
        appeal_deadline: None,
    };
    let body = match family {
        1 => Body::StateSync(op),
        2 => Body::RegulatoryAction(op),
        3 => Body::LockManagement(op),
        4 => Body::Query(op),
        5 => Body::Ack(op),
        6 => Body::Heartbeat(op),
        7 => Body::Governance(op),
        _ => panic!("unknown test family"),
    };
    Core {
        target_domain: Some(target),
        uuid: Some(uuid.to_vec()),
        family: Some(family),
        body: Some(body),
        ..canonical()
    }
}

pub(in crate::authority::recovery) fn uint256(value: u64) -> Vec<u8> {
    let mut bytes = vec![0; 24];
    bytes.extend(value.to_be_bytes());
    bytes
}

pub(in crate::authority::recovery) fn debit_core(revision: u64) -> Core {
    core_with(
        1,
        1,
        0,
        2,
        vec![
            33, 33, 2, revision, 9, 0, 17, 17, 7, 2, 3, 1, 17, 0, 17, 7, 0, 9, 1, 17, 0, 0,
        ],
        vec![uint256(5)],
    )
}

fn seed_dispatch(service: &mut Service) {
    let b = binding();
    let reserve = payload(service, b, 10, Command::Reserve { duration: 20 });
    accepted(submit(service, &reserve, 10), Reply::Reserved);
    let dispatch = payload(service, b, 11, Command::Dispatch { generation: 0 });
    accepted(submit(service, &dispatch, 11), Reply::SourceDispatched);
    assert_eq!(cut(service).revision, 2);
}

fn wire_bindings(service: &mut Service) -> usize {
    service
        .transact(|product| product.reads.authority.state.wire_bindings.len())
        .unwrap()
}

fn arrival(result: Result<(Arrival, CanonicalPacket), WireError>) -> &'static str {
    match result {
        Ok((Arrival::First, _)) => "first",
        Ok((Arrival::Identical, _)) => "identical",
        Err(WireError::ReplayConflict) => "conflict",
        Err(WireError::TtlExpired) => "ttl_expired",
        Err(_) => "rejected",
    }
}

pub(in crate::authority::recovery) fn operation(core: &mut Core) -> &mut Operation {
    match core.body.as_mut().unwrap() {
        Body::Query(op) | Body::StateSync(op) | Body::Ack(op) => op,
        _ => panic!("unexpected fixture body"),
    }
}

fn observe_row(row: &Vector<'_>) -> String {
    let core = canonical();
    let profile = profile();
    let mut boundary = boundary();
    match row.id {
        "canonical-query-core" => {
            let core = encode_core(&from_vector(row)).unwrap();
            format!(
                "core_hex={};preimage_hex={}",
                hex(&core),
                hex(&signing_bytes(&core).unwrap())
            )
        }
        "exact-wire-message-roundtrip" => {
            let packet = Packet {
                core: Some(core),
                signature: Some(vec![0; row.number("signature_length") as usize]),
            };
            let bytes = encode_packet(&packet).unwrap();
            let parsed = decode_packet(&bytes, boundary.max_frame);
            format!(
                "parse={};encode_equal={}",
                parsed.is_ok(),
                parsed.is_ok_and(|parsed| parsed.encode().unwrap() == bytes)
            )
        }
        "large-fixed64-word" => {
            assert_eq!(row.field("wire_type"), "fixed64");
            let mut core = core;
            operation(&mut core).words[0] = row.number("value");
            let mut decoded = decode_core(&encode_core(&core).unwrap()).unwrap();
            let word = operation(&mut decoded).words[0];
            format!("exact_value={word};length={}", word.to_le_bytes().len())
        }
        "unsigned256-lossless-before-product-range-check" => {
            let bytes = unhex(row.field("amount_hex")).unwrap();
            assert_eq!(bytes.len(), row.number("length") as usize);
            let amount = Unsigned256::from_bytes(&bytes).unwrap();
            assert_eq!(row.number("product_amount_max"), u64::MAX);
            format!(
                "wire_roundtrip={};product_conversion_rejected={}",
                amount.0 == bytes.as_slice(),
                amount.product_amount().is_err()
            )
        }
        "three-deadline-presence-states" => {
            assert_eq!(row.field("cases"), "absent,indefinite,finite_0");
            let items = [
                None,
                Some(AppealDeadline::AppealDeadlineIndefinite(true)),
                Some(AppealDeadline::AppealDeadlineUtcSeconds(0)),
            ];
            let mut bytes = BTreeSet::new();
            let mut exact = true;
            for deadline in items {
                let mut core = core.clone();
                operation(&mut core).appeal_deadline = deadline.clone();
                let encoded = encode_core(&core).unwrap();
                let mut decoded = decode_core(&encoded).unwrap();
                exact &= operation(&mut decoded).appeal_deadline == deadline;
                bytes.insert(encoded);
            }
            format!(
                "distinct_bytes={};distinct_semantics={exact}",
                bytes.len() == 3
            )
        }
        "overlong-tag-rejected-before-normalization" => format!(
            "decoded={}",
            decode_core(&unhex(row.field("raw_hex")).unwrap()).is_ok()
        ),
        "duplicate-singular-core-field"
        | "two-oneof-body-members"
        | "header-family-body-mismatch"
        | "unknown-primary-enum" => {
            let mut raw = encode_core(&core).unwrap();
            match row.id {
                "duplicate-singular-core-field" => {
                    assert_eq!(row.number("duplicate_tag"), 1);
                    raw.splice(2..2, [8, 6]);
                }
                "two-oneof-body-members" => {
                    assert_eq!(row.field("body_tags"), "19,20");
                    let before = raw.windows(3).position(|w| w == [0xb8, 1, 3]).unwrap();
                    raw.splice(before..before, [0xa2, 1, 2, 8, 1]);
                }
                "header-family-body-mismatch" => {
                    assert_eq!(row.number("declared_family"), 4);
                    let at = raw.windows(2).position(|w| w == [0x9a, 1]).unwrap();
                    raw[at] = 0x82 | ((row.number("body_tag") as u8 & 15) << 3);
                }
                _ => {
                    let at = raw.windows(2).position(|w| w == [0x68, 1]).unwrap();
                    raw[at + 1] = row.number("primary") as u8;
                }
            }
            format!("decoded={}", decode_core(&raw).is_ok())
        }
        "unknown-secondary-retains-signed-original" => {
            let a = Core {
                secondary: Some(row.number("secondary_a")),
                ..core.clone()
            };
            let b = Core {
                secondary: Some(row.number("secondary_b")),
                ..core
            };
            format!(
                "bytes_equal={};authority_projection_equal={}",
                encode_core(&a).unwrap() == encode_core(&b).unwrap(),
                decode(&a, 4).unwrap() == decode(&b, 4).unwrap()
            )
        }
        "invalid-signature-first-cannot-poison-valid-uuid" => {
            boundary.now = row.number("now");
            let mut bindings = TransportBindings::default();
            let good = signed(core);
            let mut bad = good.clone();
            *bad.last_mut().unwrap() ^= 1;
            let first = bindings.receive(&bad, &profile, &boundary, |_| true);
            let unchanged = bindings.is_empty();
            let second = bindings.receive(&good, &profile, &boundary, |_| true);
            format!(
                "first_rejected={};first_cache_unchanged={unchanged};second={}",
                first.is_err(),
                arrival(second)
            )
        }
        "current-source-key-and-epoch-required" => {
            let mut bindings = TransportBindings::default();
            let mut rejected = true;
            for field in row.field("alternatives").split(',') {
                let mut changed = core.clone();
                match field {
                    "wrong_source" => changed.source_domain = Some(1),
                    "wrong_target" => changed.target_domain = Some(3),
                    "wrong_key" => changed.key_id = Some(10),
                    "wrong_epoch" => changed.authority_epoch = Some(8),
                    "wrong_scope" => changed.route_scope = Some(2),
                    _ => panic!("unknown variant"),
                }
                rejected &= matches!(
                    bindings.receive(&signed(changed), &profile, &boundary, |_| true),
                    Err(WireError::InvalidSource)
                );
            }
            format!(
                "rejected={rejected};cache_unchanged={}",
                bindings.is_empty()
            )
        }
        "ttl-inclusive-expiry"
        | "ttl-expired-even-with-retained-uuid"
        | "trusted-ttl-floor-and-checked-arithmetic" => {
            boundary.now = row.number("now");
            let mut bindings = TransportBindings::default();
            let core = Core {
                issued_seconds: Some(row.number("sent")),
                ttl_seconds: Some(
                    row.input
                        .get("ttl")
                        .unwrap_or_else(|| row.input.get("sender_ttl").unwrap())
                        .parse()
                        .unwrap(),
                ),
                ..core
            };
            let bytes = signed(core.clone());
            if row.id == "ttl-expired-even-with-retained-uuid" {
                let earlier = Boundary {
                    now: 105,
                    ..boundary
                };
                bindings
                    .receive(&bytes, &profile, &earlier, |_| true)
                    .unwrap();
                let count = bindings.len();
                let result = bindings.receive(&bytes, &profile, &boundary, |_| true);
                return format!(
                    "reply={};cache_unchanged={}",
                    arrival(result),
                    bindings.len() == count
                );
            }
            boundary.asset_ttl_floor = row.number("asset_floor");
            let admitted = bindings
                .receive(&bytes, &profile, &boundary, |_| true)
                .is_ok();
            if row.id == "ttl-inclusive-expiry" {
                return format!("admitted={admitted}");
            }
            let overflow = Core {
                issued_seconds: Some(u64::MAX),
                ttl_seconds: Some(1),
                ..core
            };
            let result = bindings.receive(&signed(overflow), &profile, &boundary, |_| true);
            format!(
                "floor_case_admitted={admitted};overflow_case_rejected={}",
                result.unwrap_err() == WireError::TtlInvalid
            )
        }
        "same-uuid-changed-exact-signed-core" => {
            let mut bindings = TransportBindings::default();
            let first = signed(core.clone());
            assert_eq!(
                arrival(bindings.receive(&first, &profile, &boundary, |_| true)),
                "first"
            );
            let mut changed = core;
            operation(&mut changed).words[3] += 1;
            let second = bindings.receive(&signed(changed), &profile, &boundary, |_| true);
            let retained =
                arrival(bindings.receive(&first, &profile, &boundary, |_| true)) == "identical";
            format!("second={};original_retained={retained}", arrival(second))
        }
        "complete-uuid-with-distinct-upper-octets" => {
            let a = TransportKey::for_core(&Core {
                uuid: Some(unhex(row.field("uuid_a")).unwrap()),
                ..core.clone()
            })
            .unwrap();
            let b = TransportKey::for_core(&Core {
                uuid: Some(unhex(row.field("uuid_b")).unwrap()),
                ..core
            })
            .unwrap();
            format!("identity_keys_equal={}", a == b)
        }
        "typed-ordinary-debit-operands" => {
            let mut core = debit_core(2);
            let Body::StateSync(op) = core.body.as_mut().unwrap() else {
                unreachable!()
            };
            op.words[12] = row.number("credential_asset");
            op.words[13] = row.number("origin_domain");
            op.words[14] = row.number("origin_event");
            op.words[15] = row.number("holder");
            op.words[16] = row.number("credential_generation");
            op.words[17] = row.number("epoch");
            op.words[20] = row.number("asset_version");
            let decoded = decode(&decode_core(&encode_core(&core).unwrap()).unwrap(), 4).unwrap();
            let Operands::Ordinary { payload, .. } = decoded else {
                panic!("missing actual debit operand")
            };
            let token = payload.credential.unwrap();
            let exact = token.asset == row.number("credential_asset")
                && token.origin.event == row.number("origin_event")
                && token.holder == row.number("holder")
                && token.epoch == row.number("epoch");
            format!(
                "exact_credential={exact};exact_generation={}",
                payload.command
                    == Command::Debit {
                        generation: row.number("credential_generation")
                    }
            )
        }
        other => service_row(row, other),
    }
}

fn versions(row: &Vector<'_>, key: &str) -> Vec<u64> {
    row.field(key)
        .split(',')
        .map(|value| value.parse().unwrap())
        .collect()
}

fn legacy_packet(family: u64, opcode: u64, tag: u8, words: Vec<u64>) -> Vec<u8> {
    let mut uuid = UUID;
    uuid[0] = tag;
    let core = LegacyCore {
        version: 5,
        deployment: 7,
        source: 0,
        target: 2,
        principal: 7,
        key: 9,
        epoch: 9,
        sent: 100,
        ttl: 5,
        uuid: hex(&uuid),
        family,
        opcode,
        words,
        atomicity: 3,
        scope: 1,
    };
    let signature = remote_key().sign(&core.signing_bytes().unwrap());
    LegacyPacket {
        core,
        signature: hex(&signature.to_bytes()),
    }
    .encode()
    .unwrap()
}

fn service_row(row: &Vector<'_>, id: &str) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    match id {
        "explicit-authenticated-legacy-common-profile" => {
            assert_eq!(row.field("common_operation"), "query");
            let channel = negotiated(
                2,
                &versions(row, "local_versions"),
                &versions(row, "remote_versions"),
                row.number("floor"),
                row.field("auth") == "true",
                None,
            )
            .unwrap();
            let result = service.receive_wire(
                &channel,
                Entry::Adapter,
                &legacy_packet(4, 1, 1, vec![1, 0, 1, 17]),
                &wire_auth(),
                DeliveryWindow::default(),
            );
            let accepted = matches!(
                result,
                Ok(Received {
                    reply: WireReply::Observation(Observation::Current(Ok(_))),
                    ..
                })
            );
            format!(
                "selected={};legacy_common_query={accepted};fallback=false",
                channel.profile().version
            )
        }
        "highest-common-no-authenticated-downgrade" => {
            let local = versions(row, "local_versions");
            let remote = versions(row, "remote_versions");
            let floor = row.number("floor");
            let auth = row.field("auth") == "true";
            let current = negotiated(2, &local, &remote, floor, auth, None).unwrap();
            let lower = negotiated(
                2,
                &local,
                &remote,
                floor,
                auth,
                Some(row.number("requested_lower")),
            );
            format!(
                "selected={};lower_rejected={}",
                current.profile().version,
                lower.is_err()
            )
        }
        "unauthenticated-offer-and-no-parse-fallback" => {
            let selected = negotiated(
                2,
                &versions(row, "local_versions"),
                &versions(row, "remote_versions"),
                5,
                row.field("auth") == "true",
                None,
            );
            let legacy = legacy_packet(4, 1, 1, vec![1, 0, 1, 17]);
            let modern = service.receive_wire(
                &channel(2),
                Entry::Normal,
                &legacy,
                &wire_auth(),
                DeliveryWindow::default(),
            );
            let legacy_called = modern.is_ok();
            assert_eq!(row.field("modern_parse_failed"), "true");
            format!(
                "selected={};legacy_called={legacy_called}",
                if selected.is_err() {
                    "none"
                } else {
                    "selected"
                }
            )
        }
        "precommit-cancel-does-not-bind-or-execute" => {
            assert_eq!(row.field("before_commit"), "true");
            let head = anchor.head();
            let before = wire_bindings(&mut service);
            let result = service.receive_wire(
                &channel(2),
                Entry::ForceInclusion,
                &signed(canonical()),
                &wire_auth(),
                DeliveryWindow {
                    cancelled: row.field("cancelled") == "true",
                    ..DeliveryWindow::default()
                },
            );
            assert_eq!(result, Err(WireError::Cancelled), "{}", row.id);
            format!(
                "dedup_unchanged={};authority_unchanged={}",
                before == wire_bindings(&mut service),
                anchor.head() == head
            )
        }
        "wire-query-consumes-signed-product-cut" => {
            assert_eq!(row.field("op"), "current");
            let core = core_with(
                4,
                1,
                row.number("target"),
                0,
                vec![
                    row.number("session"),
                    row.number("revision"),
                    1,
                    row.number("asset"),
                ],
                Vec::new(),
            );
            let result = service.receive_wire(
                &channel(row.number("target")),
                Entry::Upgrade,
                &signed(core),
                &wire_auth(),
                DeliveryWindow::default(),
            );
            let exact = matches!(result,Ok(Received{reply:WireReply::Observation(Observation::Current(Ok(value))),..})
                if value.cut.authority_epoch==row.number("epoch") && value.cut.revision==row.number("revision") as usize);
            format!("exact_current_request={exact};independent_raw_request=false")
        }
        "postcommit-delivery-loss-recovers-exact-result" => {
            assert_eq!(row.field("committed"), "true");
            assert_eq!(row.field("fresh_receipt_authorized"), "true");
            seed_dispatch(&mut service);
            let debit = debit_core(2);
            let bytes = signed(debit.clone());
            let failed = service.receive_wire(
                &channel(0),
                Entry::Adapter,
                &bytes,
                &wire_auth(),
                DeliveryWindow {
                    response_lost: row.field("response_lost") == "true",
                    ..DeliveryWindow::default()
                },
            );
            assert_eq!(failed, Err(WireError::ResponseLost));
            let cut_after = cut(&mut service);
            drop(service);
            let mut service = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
            let fresh = core_with(4, 8, 0, 3, vec![2], vec![encode_core(&debit).unwrap()]);
            let reply = service.receive_wire(
                &channel(0),
                Entry::Normal,
                &signed(fresh),
                &wire_auth(),
                DeliveryWindow::default(),
            );
            let retained = matches!(
                reply,
                Ok(Received {
                    reply: WireReply::Receipt(Some(Receipt::Ordinary(Collection::Collected(
                        Outcome {
                            reply: OutcomeReply::Accepted(Reply::Debited),
                            ..
                        }
                    )))),
                    ..
                })
            );
            format!(
                "effect_repeated={};retained_result={retained}",
                cut(&mut service) != cut_after
            )
        }
        other => panic!("unknown wire vector {other}"),
    }
}

#[test]
fn proof_derived_wire_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id));
        assert_eq!(observe_row(&row), row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 25);
}

#[test]
fn library_receive_reads_the_declared_version_before_decoding() {
    use crate::wire::codec::{check_declared_version, declared_version};
    let core = encode_core(&canonical()).unwrap();
    assert_eq!(raw_frame(&core), signed(canonical()));
    let declared = |version: u8, extension: &[u8]| {
        let mut bytes = core.clone();
        assert_eq!(bytes[..2], [0x08, 6]);
        bytes[1] = version;
        bytes.extend_from_slice(extension);
        raw_frame(&bytes)
    };
    // Core field 26 is not defined by version 6.
    let field_26 = [0xd0, 0x01, 0x01];
    let receive = |frame: &[u8]| {
        TransportBindings::default()
            .receive(frame, &profile(), &boundary(), |_| true)
            .map(|(arrival, _)| arrival)
    };
    assert_eq!(receive(&declared(6, &[])), Ok(Arrival::First));
    for (frame, expected) in [
        (declared(5, &[]), WireError::UnsupportedVersion),
        (declared(7, &[]), WireError::UnsupportedVersion),
        (declared(7, &field_26), WireError::UnsupportedVersion),
        (declared(6, &field_26), WireError::InvalidFormat),
    ] {
        assert_eq!(receive(&frame), Err(expected));
    }
    let later = declared(7, &field_26);
    assert_eq!(declared_version(&later), Some(7));
    // The size limit applies before the version is read.
    assert_eq!(check_declared_version(&later, later.len() - 1), Err(WireError::InvalidFormat));
    assert_eq!(check_declared_version(&later, later.len()), Err(WireError::UnsupportedVersion));
    // A frame that does not start with the version declares none and goes on
    // to the canonical decoder.
    assert_eq!(declared_version(&[]), None);
    assert_eq!(declared_version(&[0x0a, 0x02, 0x10, 0x01]), None);
    assert_eq!(declared_version(&[0x0a, 0x05, 0x08, 0x07]), None);
    assert_eq!(check_declared_version(&[0x0a, 0x02, 0x10, 0x01], 16), Ok(()));
}

#[test]
fn complete_uuid_binding_is_anchored_and_bad_arrival_cannot_poison_it() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    let mut good = canonical();
    good.target_domain = Some(2);
    let bytes = signed(good.clone());
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() ^= 1;
    let before = anchor.head();
    assert_eq!(
        service.receive_wire(
            &channel(2),
            Entry::Normal,
            &bad,
            &wire_auth(),
            DeliveryWindow::default()
        ),
        Err(WireError::InvalidSignature),
        "bad-wire-signature-does-not-bind"
    );
    assert_eq!(anchor.head(), before);
    let reply = service
        .receive_wire(
            &channel(2),
            Entry::Normal,
            &bytes,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(reply.arrival, Arrival::First);
    let committed = anchor.head();
    drop(service);
    let mut service = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
    assert_eq!(wire_bindings(&mut service), 1);
    let identical = service
        .receive_wire(
            &channel(2),
            Entry::Adapter,
            &bytes,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(identical.arrival, Arrival::Identical);
    assert_eq!(identical.reply, reply.reply);
    assert_eq!(anchor.head(), committed);
    operation(&mut good).words[3] = 22;
    assert_eq!(
        service.receive_wire(
            &channel(2),
            Entry::ForceInclusion,
            &signed(good),
            &wire_auth(),
            DeliveryWindow::default()
        ),
        Err(WireError::ReplayConflict),
        "persistent-uuid-conflict"
    );
    assert_eq!(anchor.head(), committed);
}

#[test]
fn explicit_legacy_heartbeat_reaches_its_typed_consumer() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    let legacy = negotiated(2, &[5, 6], &[5], 5, true, None).unwrap();
    let bytes = legacy_packet(6, 2, 7, vec![3, 190]);
    let reply = service
        .receive_wire(
            &legacy,
            Entry::Adapter,
            &bytes,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(
        reply.reply,
        WireReply::Liveness {
            challenge: 3,
            expires: 190
        }
    );
    assert!(
        service
            .receive_wire(
                &channel(2),
                Entry::Adapter,
                &bytes,
                &wire_auth(),
                DeliveryWindow::default()
            )
            .is_err()
    );
}

#[test]
fn configured_threshold_without_adapter_is_typed_refusal() {
    let mut core = canonical();
    core.signature_scheme = Some(2);
    let bytes = encode_packet(&Packet {
        core: Some(core),
        signature: Some(vec![1]),
    })
    .unwrap();
    let mut bindings = TransportBindings::default();
    assert_eq!(
        bindings
            .receive(&bytes, &profile(), &boundary(), |_| true)
            .unwrap_err(),
        WireError::InvalidThresholdSignature
    );
    assert!(bindings.is_empty());
}

#[test]
fn go_generated_frames_execute_on_the_same_persistent_authority() {
    let original = debit_core(2);
    let receipt = core_with(4, 8, 0, 3, vec![2], vec![encode_core(&original).unwrap()]);
    let corpus = if let Some(path) = std::env::var_os("OIP_GO_WIRE_CORPUS") {
        std::fs::read_to_string(path).unwrap()
    } else {
        format!(
            "query={}\ndebit={}\nreceipt={}\nlegacy_query={}\nlegacy_heartbeat={}\n",
            hex(&signed(canonical())),
            hex(&signed(original.clone())),
            hex(&signed(receipt.clone())),
            hex(&legacy_packet(4, 1, 5, vec![1, 0, 1, 17])),
            hex(&legacy_packet(6, 2, 7, vec![3, 190])),
        )
    };
    let fixtures: std::collections::BTreeMap<_, _> = corpus
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    let query = unhex(fixtures["query"]).unwrap();
    let debit = unhex(fixtures["debit"]).unwrap();
    let fresh_receipt = unhex(fixtures["receipt"]).unwrap();
    assert_eq!(query, signed(canonical()));
    assert_eq!(debit, signed(original));
    assert_eq!(fresh_receipt, signed(receipt));
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    let query_reply = service
        .receive_wire(
            &channel(2),
            Entry::Normal,
            &query,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(
        matches!(query_reply.reply, WireReply::Observation(Observation::Current(Ok(value))) if value.value==Value::Units(0))
    );
    let legacy = negotiated(2, &[5, 6], &[5], 5, true, None).unwrap();
    let old_query = unhex(fixtures["legacy_query"]).unwrap();
    let old_heartbeat = unhex(fixtures["legacy_heartbeat"]).unwrap();
    let reply = service
        .receive_wire(
            &legacy,
            Entry::Adapter,
            &old_query,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(
        matches!(reply.reply, WireReply::Observation(Observation::Current(Ok(value))) if value.value == Value::Units(0))
    );
    let reply = service
        .receive_wire(
            &legacy,
            Entry::Adapter,
            &old_heartbeat,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(
        reply.reply,
        WireReply::Liveness {
            challenge: 3,
            expires: 190
        }
    );
    assert!(
        service
            .receive_wire(
                &channel(2),
                Entry::Adapter,
                &old_query,
                &wire_auth(),
                DeliveryWindow::default()
            )
            .is_err()
    );

    seed_dispatch(&mut service);
    let lost = service.receive_wire(
        &channel(0),
        Entry::ForceInclusion,
        &debit,
        &wire_auth(),
        DeliveryWindow {
            response_lost: true,
            ..DeliveryWindow::default()
        },
    );
    assert_eq!(lost, Err(WireError::ResponseLost));
    let committed = cut(&mut service);
    drop(service);
    let mut service = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
    let reply = service
        .receive_wire(
            &channel(0),
            Entry::Normal,
            &fresh_receipt,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    let WireReply::Receipt(Some(Receipt::Ordinary(exact))) = reply.reply else {
        panic!("missing exact retained outcome")
    };
    assert!(matches!(
        exact,
        Collection::Collected(Outcome {
            reply: OutcomeReply::Accepted(Reply::Debited),
            ..
        })
    ));
    assert_eq!(
        service
            .transact(|product| product
                .reads
                .authority
                .state
                .primary
                .ledger
                .pending(binding().origin))
            .unwrap(),
        5
    );
    assert_eq!(cut(&mut service), committed);
    let before = anchor.head();
    let retry = service
        .receive_wire(
            &channel(0),
            Entry::Adapter,
            &debit,
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(retry.arrival, Arrival::Identical);
    assert_eq!(
        retry.reply,
        WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(exact)))
    );
    assert_eq!(anchor.head(), before);
}

#[test]
fn deadline_after_flush_still_blocks_the_authenticated_head() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    LATE_CLOCK.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut core = core_with(4, 1, 2, 88, vec![1, 0, 1, 17], Vec::new());
    core.ttl_seconds = Some(20);
    let before = anchor.head();
    let length = path.file().metadata().unwrap().len();
    let result = service.receive_wire(
        &channel(2),
        Entry::Adapter,
        &signed(core),
        &wire_auth(),
        DeliveryWindow {
            deadline: Some(105),
            ..DeliveryWindow::default()
        },
    );
    assert_eq!(
        result,
        Err(WireError::DeadlineExpired),
        "wire-deadline-before-cas"
    );
    assert_eq!(anchor.head(), before);
    assert!(path.file().metadata().unwrap().len() > length);
    assert_eq!(wire_bindings(&mut service), 0);
}

fn prefix(service: &mut Service, id: u64, b: crate::lock_finality::Binding) -> Vec<u64> {
    vec![
        id,
        id,
        2,
        cut(service).revision as u64,
        9,
        b.origin.domain,
        b.origin.event,
        b.asset,
        b.owner,
        b.destination,
        b.recipient,
    ]
}

#[test]
fn legal_spend_ack_and_governance_use_the_decoded_persistent_consumer() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let ack_identity = crate::authority::identity::Identity {
        principal: 99,
        domain: 99,
        ocid: 199,
        rai: 299,
    };
    let mut initial = super::super::vector_tests::genesis(10, 1);
    initial.identities.push(ack_identity);
    let mut service = PersistentAuthority::initialize(
        path.file(),
        anchor.clone(),
        super::super::vector_tests::attachment(DEFAULT_PROFILE, true),
        initial,
    )
    .unwrap();
    let (_, root) = super::super::vector_tests::fund_root(&mut service);
    let binding = binding();
    let freeze = crate::lock_finality::Binding {
        origin: crate::OriginKey {
            domain: 0,
            event: 20,
        },
        amount: 0,
        ..binding
    };
    use std::sync::atomic::Ordering::Relaxed;
    let mut emitted = None;
    for (opcode, target, sequence) in [(1, 0, 40), (2, 2, 41)] {
        let mut words = prefix(&mut service, sequence, freeze);
        words.extend([1, 7, 1, 1, 9, 1, 17, 0, 0]);
        let core = core_with(
            2,
            opcode,
            target,
            if opcode == 1 { 90 } else { sequence as u8 },
            words,
            vec![uint256(0), b"verified".to_vec()],
        );
        let bytes = signed(core);
        if opcode == 1 {
            LIVE_LEGAL_PROOF.store(false, Relaxed);
            let previous_head = anchor.head();
            assert_eq!(
                service.receive_wire(
                    &channel(target),
                    Entry::Administrative,
                    &bytes,
                    &wire_auth(),
                    DeliveryWindow::default()
                ),
                Err(WireError::InvalidSource)
            );
            assert_eq!(anchor.head(), previous_head);
            LIVE_LEGAL_PROOF.store(true, Relaxed);
        }
        let reply = service
            .receive_wire(
                &channel(target),
                Entry::Administrative,
                &bytes,
                &wire_auth(),
                DeliveryWindow::default(),
            )
            .unwrap();
        assert!(matches!(
            reply.reply,
            WireReply::Executed(ActionReply::Legal(
                crate::authority::regulation::LegalReply::Emitted(_)
                    | crate::authority::regulation::LegalReply::Applied(_)
            ))
        ));
        if opcode == 1 {
            emitted = Some((bytes, reply.reply));
        }
    }
    let (emitted_bytes, original_reply) = emitted.unwrap();
    let previous_head = anchor.head();
    LIVE_LEGAL_PROOF.store(false, Relaxed);
    let replay = service.receive_wire(
        &channel(0),
        Entry::ForceInclusion,
        &emitted_bytes,
        &wire_auth(),
        DeliveryWindow::default(),
    );
    LIVE_LEGAL_PROOF.store(true, Relaxed);
    assert_eq!(
        replay,
        Ok(Received {
            arrival: Arrival::Identical,
            reply: original_reply
        }),
        "exact-retained-wire-legal-proof"
    );
    assert_eq!(anchor.head(), previous_head);
    let mut words = prefix(&mut service, 42, freeze);
    words.extend([0, 0]);
    let publish = core_with(1, 5, 0, 42, words, vec![uint256(0)]);
    let published = service
        .receive_wire(
            &channel(0),
            Entry::Upgrade,
            &signed(publish),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(matches!(
        published.reply,
        WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
            Collection::Collected(Outcome {
                reply: OutcomeReply::Accepted(Reply::Published),
                ..
            })
        )))
    ));
    let mut words = prefix(&mut service, 43, binding);
    words.extend([root.position as u64, 3, 4, 1, 7, 1, 1, 1, 17, 0]);
    let spend = core_with(
        2,
        3,
        2,
        43,
        words,
        vec![uint256(5), uint256(1), b"verified".to_vec()],
    );
    let spent = service
        .receive_wire(
            &channel(2),
            Entry::ForceInclusion,
            &signed(spend),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(matches!(spent.reply,WireReply::Executed(ActionReply::Spend(
        crate::authority::regulation::SpendReply::Executed {root,..}
    )) if root == binding.origin));
    let rev = cut(&mut service).revision as u64;
    let source = core_with(4, 1, 0, 44, vec![2, rev, 2, 0, 17], Vec::new());
    let source = service
        .receive_wire(
            &channel(0),
            Entry::Normal,
            &signed(source),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(
        matches!(source.reply,WireReply::Observation(Observation::Current(Ok(value))) if value.value==Value::Units(5))
    );
    let destination = core_with(4, 1, 2, 45, vec![2, rev, 3, 2, 17, 4], Vec::new());
    let destination = service
        .receive_wire(
            &channel(2),
            Entry::Normal,
            &signed(destination),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(
        matches!(destination.reply,WireReply::Observation(Observation::Current(Ok(value))) if value.value==Value::Units(1))
    );
    let state = core_with(4, 1, 2, 46, vec![2, rev, 5, 2, 17], Vec::new());
    let state = service
        .receive_wire(
            &channel(2),
            Entry::Normal,
            &signed(state),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(
        matches!(state.reply,WireReply::Observation(Observation::Current(Ok(value)))
        if value.value==Value::Regulatory(Some(crate::authority::regulation::Mode::Frozen)))
    );

    let key = service
        .enqueue_secondary(&HOST, binding.origin)
        .unwrap()
        .unwrap();
    let job = service.dispatch_secondary(&HOST, key).unwrap().unwrap();
    let mut ack = core_with(
        5,
        1,
        2,
        47,
        vec![0, 17, root.position as u64, job.target, 17, 7, 2, 3, 9, 1],
        vec![uint256(5)],
    );
    ack.source_domain = Some(99);
    ack.principal = Some(99);
    let ack_channel = negotiated_from(99, 2, &[5, 6], &[5, 6], 5, true, None).unwrap();
    let ack_auth = WireCredentials {
        token: &ack_identity,
        ..wire_auth()
    };
    let ack = service
        .receive_wire(
            &ack_channel,
            Entry::Adapter,
            &signed(ack),
            &ack_auth,
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(ack.reply, WireReply::Acknowledged(true));

    let previous = Consent {
        token: &FORMER,
        signature: &YES,
    };
    let successor = Consent {
        token: &super::super::vector_tests::SUCCESSOR,
        signature: &YES,
    };
    let auth = WireCredentials {
        previous: Some(&previous),
        successor: Some(&successor),
        ..wire_auth()
    };
    let context = serde_json::to_vec(&super::super::vector_tests::contexts(10)).unwrap();
    let handover = core_with(
        7,
        1,
        0,
        48,
        vec![1, cut(&mut service).revision as u64, 17, 7, 8, 1, 3, 10],
        vec![context, b"verified".to_vec(), b"verified".to_vec()],
    );
    let handed = service
        .receive_wire(
            &channel(0),
            Entry::Administrative,
            &signed(handover),
            &auth,
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(handed.reply, WireReply::Changed(true));
    assert_eq!(
        service
            .transact(|product| product
                .reads
                .authority
                .state
                .primary
                .owners
                .get(&17)
                .copied())
            .unwrap(),
        Some(8)
    );

    let sessions: Vec<_> = super::super::vector_tests::sessions(11)
        .into_iter()
        .collect();
    let mut install = core_with(
        7,
        2,
        0,
        49,
        vec![2, cut(&mut service).revision as u64, 11],
        vec![
            serde_json::to_vec(&super::super::vector_tests::contexts(11)).unwrap(),
            serde_json::to_vec(&sessions).unwrap(),
            b"verified".to_vec(),
        ],
    );
    install.authority_epoch = Some(10);
    let changed = service
        .receive_wire(
            &channel(0),
            Entry::Upgrade,
            &signed(install),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(changed.reply, WireReply::Changed(true));
    assert_eq!(cut(&mut service).authority_epoch, 11);
}

#[test]
fn wire_debit_consumes_signed_generation_without_substitution() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    seed_dispatch(&mut service);
    let mut bad = debit_core(2);
    let op = operation(&mut bad);
    *op.words.last_mut().unwrap() = 1;
    let reply = service
        .receive_wire(
            &channel(0),
            Entry::Adapter,
            &signed(bad),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert!(
        matches!(
            reply.reply,
            WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
                Collection::Collected(Outcome {
                    reply: OutcomeReply::Rejected,
                    ..
                })
            )))
        ),
        "wire-debit-signed-generation"
    );
    assert_eq!(
        service
            .transact(|product| product
                .reads
                .authority
                .state
                .primary
                .ledger
                .pending(binding().origin))
            .unwrap(),
        0
    );
}

fn source_pool_projection_case(row: &Vector<'_>) -> String {
    use super::super::vector_tests::{SUCCESSOR, auth, contexts};
    use crate::authority::reads::ReadError;

    let domain = row.number("source");
    let asset = row.number("asset");
    let former = row.number("former");
    let successor = row.number("successor");
    let old_epoch = row.number("old_epoch");
    let new_epoch = row.number("new_epoch");
    let has_pending = row.id == "pending-source-pool-survives-handover";
    let initial = row.number(if has_pending {
        "source_initial"
    } else {
        "old_owner_balance"
    });
    assert_eq!(
        (domain, asset, former, successor, old_epoch),
        (0, 17, 7, 8, 9)
    );

    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, initial, 1);
    if has_pending {
        assert_eq!(row.field("old_cut"), "after_debit_before_handover");
        assert_eq!(row.number("debit"), binding().amount);
        seed_dispatch(&mut service);
        let debit = payload(
            &mut service,
            binding(),
            33,
            Command::Debit { generation: 0 },
        );
        accepted(submit(&mut service, &debit, 33), Reply::Debited);
    } else {
        assert_eq!(row.field("old_cut"), "before_handover");
    }
    let old_cut = cut(&mut service);
    let proposal = crate::authority::identity::Handover {
        asset,
        previous: former,
        successor,
        expected: old_cut,
        old_session: 1,
        new_session: 3,
        epoch: new_epoch,
        contexts: contexts(new_epoch),
    };
    assert!(
        service
            .handover(
                &HOST,
                &proposal,
                Consent {
                    token: &FORMER,
                    signature: &YES
                },
                Consent {
                    token: &SUCCESSOR,
                    signature: &YES
                },
            )
            .unwrap()
    );

    let live = cut(&mut service);
    assert_eq!(live.authority_epoch, new_epoch);
    let source_query = |service: &mut Service, opcode, revision: Option<usize>, tag| {
        let mut words = vec![2];
        words.extend(revision.map(|revision| revision as u64));
        words.extend([2, domain, asset]);
        let mut query = core_with(4, opcode, domain, tag, words, vec![]);
        query.authority_epoch = Some(new_epoch);
        service
            .receive_wire(
                &channel(domain),
                Entry::Normal,
                &signed(query),
                &wire_auth(),
                DeliveryWindow::default(),
            )
            .unwrap()
            .reply
    };
    let current = source_query(&mut service, 1, Some(live.revision), 193);
    let historical = source_query(&mut service, 2, Some(old_cut.revision), 192);
    if has_pending {
        assert_eq!(
            current,
            WireReply::Observation(Observation::Current(Err(ReadError::Busy))),
            "source-pool-waits-for-any-related-holder"
        );
        assert_eq!(
            historical,
            WireReply::Observation(Observation::Historical(Err(ReadError::Busy))),
            "source-pool-old-prefix-preserves-visibility"
        );
        let WireReply::Observation(Observation::Raw(Ok(Value::Units(current)))) =
            source_query(&mut service, 3, None, 194)
        else {
            panic!("expected signed raw pending source pool");
        };
        let (old, pending) = service
            .transact(|product| {
                let state = &product.reads.authority.state;
                (
                    state
                        .read_history
                        .raw_value_at(old_cut.revision, Query::SourcePool(domain, asset)),
                    state.primary.ledger.pending(binding().origin),
                )
            })
            .unwrap();
        let Ok(Value::Units(old)) = old else {
            panic!("expected stored old source pool");
        };
        return format!("current_pool={current};old_prefix_pool={old};pending={pending}");
    }

    let (
        WireReply::Observation(Observation::Current(Ok(crate::authority::reads::CurrentRead {
            value: Value::Units(current),
            ..
        }))),
        WireReply::Observation(Observation::Historical(Ok(
            crate::authority::reads::HistoricalRead {
                value: Value::Units(old),
                ..
            },
        ))),
    ) = (current, historical)
    else {
        panic!("expected signed current and historical source pool");
    };
    let old_rule = service
        .read(
            Entry::Normal,
            &auth(&FORMER, 2, new_epoch),
            domain,
            ReadRequest::Raw(Query::SourceBalance(Account {
                endpoint: domain,
                asset,
                owner: successor,
            })),
            None,
        )
        .unwrap();
    let Observation::Raw(Ok(Value::Units(old_rule))) = old_rule else {
        panic!("expected old owner-only source pool control");
    };
    assert_eq!(old_rule, row.number("new_owner_balance"));

    format!("current_pool={current};old_prefix_pool={old};owner_lookup_mutation={old_rule}")
}

#[test]
fn proof_derived_source_pool_projection_vectors() {
    let rows = parse_vectors(SOURCE_POOL_VECTORS).collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    for id in [
        "owner-only-source-projection-removal",
        "pending-source-pool-survives-handover",
    ] {
        let row = rows
            .iter()
            .find(|row| row.id == id)
            .expect("frozen source pool vector");
        assert_eq!(source_pool_projection_case(row), row.expected, "{id}");
    }
}

#[test]
fn signed_source_pool_sums_holders_and_excludes_destination_allocations() {
    use super::super::vector_tests::{attachment, auth, fund_root, genesis};
    use crate::authority::reads::ReadError;

    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut initial = genesis(10, 1);
    let bound = binding();
    let recipient = bound.destination();
    let other_holder = Account {
        owner: 4,
        ..recipient
    };
    let recipient_initial = u64::MAX - bound.amount;
    initial.balances.insert(recipient, recipient_initial);
    initial.balances.insert(other_holder, 20);
    *initial.supply.get_mut(&bound.asset).unwrap() += u128::from(recipient_initial) + 20;
    let mut service = PersistentAuthority::initialize(
        path.file(),
        anchor,
        attachment(DEFAULT_PROFILE, true),
        initial,
    )
    .unwrap();
    fund_root(&mut service);
    let live = cut(&mut service);
    let expected = Value::WideUnits(u128::from(u64::MAX) + 15);
    for (opcode, revision, tag) in [(1, live.revision, 201), (2, 0, 202)] {
        let query = core_with(
            4,
            opcode,
            2,
            tag,
            vec![1, revision as u64, 2, 2, 17],
            vec![],
        );
        let reply = service
            .receive_wire(
                &channel(2),
                Entry::Normal,
                &signed(query),
                &wire_auth(),
                DeliveryWindow::default(),
            )
            .unwrap();
        let value = match reply.reply {
            WireReply::Observation(Observation::Current(Ok(value))) => value.value,
            WireReply::Observation(Observation::Historical(Ok(value))) => value.value,
            other => panic!("expected a source pool reply, got {other:?}"),
        };
        assert_eq!(value, expected, "wide-unallocated-source-pool");
    }

    let capture = core_with(4, 6, 2, 203, vec![1, 2, 2, 17], vec![]);
    let reply = service
        .receive_wire(
            &channel(2),
            Entry::Adapter,
            &signed(capture),
            &wire_auth(),
            DeliveryWindow::default(),
        )
        .unwrap();
    let WireReply::Observation(Observation::Cache(Ok(cache))) = reply.reply else {
        panic!("expected source pool cache");
    };
    let claim = cache.claim().unwrap();
    assert_eq!(claim.query, Query::SourcePool(2, 17));
    assert_eq!(claim.observed.value, expected);
    let wire_claim = serde_json::to_vec(&claim).unwrap();
    let claim = serde_json::from_slice(&wire_claim).unwrap();

    for (domain, result) in [(2, Ok(expected)), (0, Err(ReadError::Busy))] {
        let view = service
            .read(
                Entry::Normal,
                &auth(&FORMER, 1, live.authority_epoch),
                domain,
                ReadRequest::Current {
                    query: Query::SourcePool(domain, 17),
                    expected: live,
                },
                Some(&claim),
            )
            .unwrap();
        let Observation::Current(read) = view else {
            panic!("expected current source pool cache lookup");
        };
        assert_eq!(read.map(|read| read.value), result);
    }

    let mut mismatched = core_with(
        4,
        1,
        0,
        204,
        vec![1, live.revision as u64, 2, 2, 17],
        vec![],
    );
    mismatched.authority_epoch = Some(live.authority_epoch);
    assert_eq!(
        service.receive_wire(
            &channel(0),
            Entry::Normal,
            &signed(mismatched),
            &wire_auth(),
            DeliveryWindow::default()
        ),
        Err(WireError::ProductRejected)
    );
}

#[test]
fn ordered_adapter_rejects_a_strict_anchor_and_raw_entry() {
    use super::super::vector_tests::{attachment, auth, genesis};
    use std::sync::{Arc, atomic::AtomicU64};

    let anchor = TestAnchor::new();
    let path = JournalPath::create();
    let mut attached = attachment(DEFAULT_PROFILE, true);
    attached.security.ordered_clock = Some(Arc::new(AtomicU64::new(105)));
    let mut service = PersistentAuthority::initialize(
        path.file(), anchor.clone(), attached, genesis(10, 1),
    ).unwrap();
    let before = anchor.head();
    let query = signed(core_with(4, 1, 0, 112, vec![2, 0, 2, 0, 17], vec![]));
    assert_eq!(
        service.receive_wire(&channel(0), Entry::Adapter, &query, &wire_auth(), DeliveryWindow::default()),
        Err(WireError::InvalidSource),
    );

    let reserve = payload(&mut service, binding(), 10, Command::Reserve { duration: 20 });
    let request = Request {
        id: CallId { namespace: FORMER.principal, sequence: 10 },
        expected: reserve.cut,
        target: 0,
        action: Action::Ordinary(&reserve),
    };
    assert_eq!(
        service.execute(Entry::ForceInclusion, &auth(&FORMER, reserve.session, reserve.cut.authority_epoch), request, None),
        Err(RecoveryError::Endpoint(crate::authority::identity::EndpointError::Rejected)),
    );
    assert_eq!(anchor.head(), before);
    assert_eq!(wire_bindings(&mut service), 0);
}

#[test]
fn signed_wire_mutation_without_publication_support_holds_before_append() {
    use super::super::{AnchorHead, AuthenticatedHead, HeadError, RecoveryProfile};
    use super::super::vector_tests::{attachment, genesis};

    struct NoPublication(TestAnchor);

    impl AuthenticatedHead for NoPublication {
        type AttachmentProof = (RecoveryProfile, bool);

        fn verify_attachment(&self, profile: RecoveryProfile, connected: bool, proof: &Self::AttachmentProof) -> bool {
            self.0.verify_attachment(profile, connected, proof)
        }

        fn current(&self) -> Result<Option<AnchorHead>, HeadError> {
            self.0.current()
        }

        fn compare_and_set(&self, expected: Option<AnchorHead>, candidate: AnchorHead) -> Result<bool, HeadError> {
            self.0.compare_and_set(expected, candidate)
        }
    }

    let anchor = TestAnchor::new();
    let path = JournalPath::create();
    let mut endpoint = PersistentAuthority::initialize(path.file(), NoPublication(anchor.clone()),
        attachment(DEFAULT_PROFILE, true), genesis(10, 1)).unwrap();
    let old = anchor.head();
    let bytes = path.file().metadata().unwrap().len();
    let query = signed(core_with(4, 1, 0, 112, vec![2, 0, 2, 0, 17], vec![]));
    assert_eq!(endpoint.receive_wire(&channel(0), Entry::Adapter, &query, &wire_auth(), DeliveryWindow::default()),
        Err(WireError::Recovery(RecoveryError::Hold)));
    assert_eq!(anchor.head(), old);
    assert_eq!(path.file().metadata().unwrap().len(), bytes);
}
