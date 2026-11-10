use super::*;
use crate::authority::recovery::vector_tests::{DEFAULT_PROFILE, FORMER};
use crate::authority::recovery::wire::vector_tests::{debit_core, operation, signed};
use crate::wire::operands::decode;

mod signing_vectors;
mod sync_tests;
mod write_tests;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn config() -> Ed25519Profile {
    let readonly = EndpointGrant {
        execute: BTreeSet::new(),
        receipts: BTreeSet::from([17]),
        current: vec![Query::SourcePool(0, 17)],
        journal: true,
        ..EndpointGrant::default()
    };
    let executing = EndpointGrant {
        execute: BTreeSet::from([17]),
        ..readonly.clone()
    };
    Ed25519Profile {
        profile: DEFAULT_PROFILE,
        authority_epoch: 9,
        endpoint: 0,
        route_scope: 1,
        local_principal: 42,
        local_key_id: 3,
        response_key: key(6).verifying_key().to_bytes(),
        session_issuer: key(8).verifying_key().to_bytes(),
        maintenance_issuer: key(9).verifying_key().to_bytes(),
        peers: BTreeMap::from([(
            7,
            PeerRegistration {
                identity: FORMER,
                key_id: 9,
                public_key: key(7).verifying_key().to_bytes(),
                sessions: BTreeMap::from([
                    (1, BTreeMap::from([(0, readonly)])),
                    (2, BTreeMap::from([(0, executing)])),
                ]),
            },
        )]),
        maintainers: BTreeSet::from([7]),
        max_token_seconds: 600,
        response_ttl_seconds: 30,
        asset_ttl_floor: 2,
        future_skew: 0,
        max_frame: 1024 * 1024,
        max_nesting: 4,
        schedule_limits: Some([8, 8]),
        other_endpoints: BTreeSet::new(),
        sources: BTreeMap::new(),
        maintenance_authorities: BTreeMap::new(),
        legal_authorities: BTreeMap::new(),
        enforcement_authorities: BTreeMap::new(),
        acknowledgers: BTreeMap::new(),
        handover_maintainers: BTreeSet::new(),
        max_delivery_ttl_seconds: None,
        sync: source::SyncPolicy::default(),
    }
}

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl AuthorityClock for FixedClock {
    fn unix_seconds(&self) -> Option<u64> {
        Some(self.0)
    }
}

fn token<C: AuthorityClock>(
    security: &Ed25519Security<C>,
    session: SessionId,
    now: u64,
) -> SessionToken {
    let claims = security.session_claims(7, session, now, now + 300).unwrap();
    let signature = key(8).sign(&claims.signing_bytes().unwrap()).to_bytes();
    SessionToken { claims, signature }
}

#[test]
fn reference_ed25519_binds_issuer_identity_session_scope_and_signature() {
    let security = Ed25519Security::new(config(), key(6), FixedClock(105)).unwrap();
    let mut valid = token(&security, 2, 100);
    let proof = SessionProof {
        session: 2,
        epoch: 9,
    };
    assert_eq!(security.authenticate_session(&valid, proof), Some(FORMER));
    assert_eq!(
        security.authenticate_session(
            &valid,
            SessionProof {
                session: 1,
                ..proof
            }
        ),
        None
    );
    assert_eq!(
        security.authenticate_session(&valid, SessionProof { epoch: 10, ..proof }),
        None
    );

    valid.claims.identity.rai = 999;
    valid.signature = key(8)
        .sign(&valid.claims.signing_bytes().unwrap())
        .to_bytes();
    assert_eq!(security.authenticate(&valid), None);
    let mut wrong_scope = token(&security, 2, 100);
    wrong_scope.claims.grants_sha256[0] ^= 1;
    wrong_scope.signature = key(8)
        .sign(&wrong_scope.claims.signing_bytes().unwrap())
        .to_bytes();
    assert_eq!(security.authenticate(&wrong_scope), None);
    let mut wrong_issuer = token(&security, 2, 100);
    wrong_issuer.signature = key(9)
        .sign(&wrong_issuer.claims.signing_bytes().unwrap())
        .to_bytes();
    assert_eq!(security.authenticate(&wrong_issuer), None);

    let packet = signed(debit_core(2));
    let canonical = decode_packet(&packet, packet.len()).unwrap();
    let Operands::Ordinary { id, payload, .. } = decode(canonical.core(), 2).unwrap() else {
        panic!("Debit");
    };
    let verified = |id, payload, bytes| {
        security.verify(
            FORMER,
            proof,
            0,
            Operation::Execute,
            Signed::Call {
                id,
                action: Action::Ordinary(payload),
            },
            bytes,
        )
    };
    assert!(verified(id, &payload, &packet));
    assert!(!verified(
        crate::CallId { namespace: 8, ..id },
        &payload,
        &packet
    ));
    let mut wrong_operand = payload.clone();
    wrong_operand.command = Command::Debit { generation: 1 };
    assert!(!verified(id, &wrong_operand, &packet));
    let mut other_packet = debit_core(2);
    other_packet.uuid.as_mut().unwrap()[0] ^= 1;
    assert!(!security.matches_signed_packet(&packet, &signed(other_packet)));
    let mut signed_readonly = debit_core(2);
    operation(&mut signed_readonly).words[2] = 1;
    let signed_readonly = signed(signed_readonly);
    let decoded = decode_packet(&signed_readonly, signed_readonly.len()).unwrap();
    let Operands::Ordinary { id, payload, .. } = decode(decoded.core(), 2).unwrap() else {
        panic!("Debit");
    };
    assert!(!security.verify(
        FORMER,
        SessionProof {
            session: 1,
            epoch: 9
        },
        0,
        Operation::Execute,
        Signed::Call {
            id,
            action: Action::Ordinary(&payload)
        },
        &signed_readonly
    ));
}

#[test]
fn reference_ed25519_issuer_constructs_only_registered_current_tokens() {
    let security = Ed25519Security::new(config(), key(6), FixedClock(105)).unwrap();
    let issuer = SessionIssuer::new(key(8));
    let token = issuer.issue(&security, 7, 2, 15).unwrap();
    assert_eq!(token.claims.issued_seconds, 105);
    assert_eq!(token.claims.expires_seconds, 120);
    assert_eq!(security.authenticate(&token), Some(FORMER));
    assert!(issuer.issue(&security, 8, 2, 15).is_err());
    assert!(issuer.issue(&security, 7, 3, 15).is_err());
    assert!(issuer.issue(&security, 7, 2, 601).is_err());
    assert!(
        SessionIssuer::new(key(9))
            .issue(&security, 7, 2, 15)
            .is_err()
    );

    let issuer = MaintenanceIssuer::new(key(9));
    let token = issuer.issue(&security, 7, 15).unwrap();
    assert_eq!(security.authenticate_maintenance(&token), Some(7));
    assert!(issuer.issue(&security, 8, 15).is_err());
    assert!(
        MaintenanceIssuer::new(key(8))
            .issue(&security, 7, 15)
            .is_err()
    );
}

#[test]
fn reference_ed25519_maintenance_uses_a_separate_issuer_and_role() {
    let security = Ed25519Security::new(config(), key(6), FixedClock(105)).unwrap();
    let claims = MaintenanceClaims {
        role: MaintenanceRole::ReferenceControl,
        profile: DEFAULT_PROFILE,
        epoch: 9,
        principal: 7,
        issuer: key(9).verifying_key().to_bytes(),
        issued_seconds: 100,
        expires_seconds: 120,
    };
    let signature = key(9).sign(&claims.signing_bytes().unwrap()).to_bytes();
    assert_eq!(
        security.authenticate_maintenance(&MaintenanceToken {
            claims: claims.clone(),
            signature
        }),
        Some(7)
    );
    let signature = key(8).sign(&claims.signing_bytes().unwrap()).to_bytes();
    assert_eq!(
        security.authenticate_maintenance(&MaintenanceToken { claims, signature }),
        None
    );
}

#[test]
fn reference_ed25519_rejects_unbound_legacy_policy_at_any_epoch() {
    use crate::authority::recovery::vector_tests::{JournalPath, TestAnchor, attachment};
    use crate::authority::recovery::{Attachment, PersistentAuthority, RecoveryError};
    use std::io::Read;
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    drop(path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1));
    let mut original = Vec::new();
    path.file().read_to_end(&mut original).unwrap();
    drop(
        PersistentAuthority::open(
            path.file(),
            anchor.clone(),
            attachment(DEFAULT_PROFILE, true),
        )
        .unwrap(),
    );
    let mut reopened = Vec::new();
    path.file().read_to_end(&mut reopened).unwrap();
    assert_eq!(reopened, original);
    for epoch in [9, 10] {
        let mut candidate = config();
        candidate.authority_epoch = epoch;
        let security = Ed25519Security::new(candidate, key(6), FixedClock(105)).unwrap();
        assert!(matches!(
            PersistentAuthority::open(
                path.file(),
                anchor.clone(),
                Attachment {
                    profile: DEFAULT_PROFILE,
                    proof: (DEFAULT_PROFILE, true),
                    security,
                    source_connected: true,
                }
            ),
            Err(RecoveryError::AttachmentRejected)
        ));
    }
}

#[test]
fn reference_ed25519_keeps_query_grants_distinct() {
    let query = Query::SourcePool(0, 17);
    let origin = crate::OriginKey {
        domain: 0,
        event: 17,
    };
    let mut grant = EndpointGrant::default();
    let requests = [
        (
            Operation::Historical,
            ReadRequest::Historical { query, revision: 0 },
        ),
        (Operation::Raw, ReadRequest::Raw(query)),
        (Operation::Status, ReadRequest::Status(origin)),
        (Operation::Current, ReadRequest::CaptureCache(query)),
        (Operation::ReadOwner, ReadRequest::Owner(17)),
    ];
    grant.current.push(query);
    assert!(requests.iter().all(|&(operation, request)| !permits(
        &grant,
        operation,
        Scope::Read(request)
    )));
    grant.historical.push(query);
    grant.raw.push(query);
    grant.status.insert(origin);
    grant.cache.push(query);
    grant.owner.insert(17);
    assert!(requests.iter().all(|&(operation, request)| permits(
        &grant,
        operation,
        Scope::Read(request)
    )));
    assert!(!permits(
        &grant,
        Operation::ReadOwner,
        Scope::Read(ReadRequest::Owner(18))
    ));
    assert!(!permits(
        &grant,
        Operation::Raw,
        Scope::Read(ReadRequest::Raw(Query::ApplicationValue(17)))
    ));
}

#[test]
fn reference_ed25519_profile_accepts_only_the_operations_it_executes() {
    use crate::authority::recovery::wire::vector_tests::{channel, core_with};
    let security = Ed25519Security::new(config(), key(6), FixedClock(105)).unwrap();
    let channel = channel(0);
    let refused = BTreeSet::from([(3, 8), (5, 2), (6, 1), (6, 2), (7, 2)]);
    let mut accepted = 0;
    for (family, count) in (1..=7).zip([6, 3, 8, 8, 2, 2, 2]) {
        for opcode in 1..=count {
            let core = core_with(family, opcode, 0, 1, Vec::new(), Vec::new());
            let accepts = security.accepts_operation(&channel, &core);
            assert_eq!(accepts, !refused.contains(&(family, opcode)), "{family}/{opcode}");
            accepted += usize::from(accepts);
        }
    }
    assert_eq!(accepted, 26);
    assert_eq!(security.max_delivery_ttl(&channel), None);
    let limited = Ed25519Profile {
        max_delivery_ttl_seconds: Some(30),
        ..config()
    };
    let limited = Ed25519Security::new(limited, key(6), FixedClock(105)).unwrap();
    assert_eq!(limited.max_delivery_ttl(&channel), Some(30));
}

#[cfg(target_os = "linux")]
mod live;

pub(super) mod reference_execution_trace;
mod signed_response_fixture;

mod client_value_tests;
