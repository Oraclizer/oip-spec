//! Fixed reference serializer inputs, signatures, digests and source certificate.
use super::*;
use crate::authority::recovery::vector_tests::SUCCESSOR;
use crate::lock_finality::{TerminalEvidence, TerminalKind};
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}
fn input(id: &str, bytes: Vec<u8>, signer: Option<u8>) -> Value {
    let zero = bytes.iter().position(|byte| *byte == 0).unwrap();
    let domain = std::str::from_utf8(&bytes[..zero]).unwrap();
    let value = std::str::from_utf8(&bytes[zero + 1..]).unwrap();
    let (public, signature) = signer
        .map(|seed| {
            let signer = key(seed);
            let signature = signer.sign(&bytes).to_bytes();
            assert!(verify_strict(
                &signer.verifying_key().to_bytes(),
                &bytes,
                &signature
            ));
            (
                Some(hex(&signer.verifying_key().to_bytes())),
                Some(hex(&signature)),
            )
        })
        .unwrap_or((None, None));
    json!({"id":id,"domain":domain,"json_utf8":value,"input_hex":hex(&bytes),
        "sha256":hex(&Sha256::digest(&bytes)),"public_key":public,"signature":signature})
}
fn operand(name: &str) -> Operands {
    let row: Value = include_str!("../../../../../../tests/vectors/wire-operations.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|row| row["id"] == format!("{name}/valid"))
        .unwrap();
    let bytes = unhex(row["packet_hex"].as_str().unwrap());
    let packet = decode_packet(&bytes, bytes.len()).unwrap();
    decode(packet.core(), 4).unwrap()
}

#[test]
fn fixed_reference_signing_inputs_and_source_certificate() {
    let mut cfg = config();
    cfg.peers.insert(
        8,
        PeerRegistration {
            identity: SUCCESSOR,
            key_id: 12,
            public_key: key(10).verifying_key().to_bytes(),
            sessions: BTreeMap::from([(1, cfg.peers[&7].sessions[&1].clone())]),
        },
    );
    cfg.legal_authorities.insert(
        7,
        legal::LegalAuthority {
            key: key(18).verifying_key().to_bytes(),
            jurisdiction: 1,
            legal_basis: 1,
            assets: BTreeSet::from([17]),
            actions: vec![crate::authority::regulation::Action::Freeze],
        },
    );
    cfg.enforcement_authorities.insert(
        7,
        legal::EnforcementAuthority {
            key: key(19).verifying_key().to_bytes(),
            jurisdiction: 1,
            legal_basis: 1,
            assets: BTreeSet::from([17]),
        },
    );
    let security = Ed25519Security::new(cfg.clone(), key(6), FixedClock(105)).unwrap();
    let session = security.session_claims(7, 2, 100, 400).unwrap();
    let grants = preimage(
        b"oip/reference-session-grants/v1\0",
        &cfg.peers[&7].sessions[&2],
    )
    .unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&grants)),
        session.grants_sha256
    );
    let maintenance = MaintenanceClaims {
        role: MaintenanceRole::ReferenceControl,
        profile: cfg.profile,
        epoch: 9,
        principal: 7,
        issuer: key(9).verifying_key().to_bytes(),
        issued_seconds: 9_007_199_254_740_993,
        expires_seconds: 9_007_199_254_741_293,
    };
    let policy = preimage(b"oip/reference-authority-policy/v1\0", &cfg).unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&policy)),
        authority_policy_binding(&cfg).unwrap()
    );
    let request: maintenance::MaintenanceRequest = serde_json::from_value(json!({
        "profile":cfg.profile,"principal":7,"cut":{"authority_epoch":9,"revision":2},
        "selection":vec![0u8;32],"action":{"ObserveTime":{"session":2,"observed":105}}
    }))
    .unwrap();
    let mut next = cfg.clone();
    next.authority_epoch = 10;
    next.response_key = key(16).verifying_key().to_bytes();
    let successor_grants = next.peers[&7].sessions[&2].clone();
    next.peers.get_mut(&7).unwrap().sessions.remove(&2);
    next.peers.get_mut(&8).unwrap().sessions = BTreeMap::from([(3, successor_grants)]);
    let Operands::Handover { proposal, .. } = operand("OwnerHandover") else {
        panic!("handover")
    };
    let ready = security
        .successor_readiness_signing_bytes(&next, &proposal.contexts)
        .unwrap();
    let readiness = key(16).sign(&ready).to_bytes();
    let security = security
        .with_successor(next, proposal.contexts.clone(), &readiness)
        .unwrap();
    let consent = security
        .handover_consent_signing_bytes(FORMER, &proposal)
        .unwrap();
    let Operands::Ordinary { id, payload, .. } = operand("Debit") else {
        panic!("debit")
    };
    let recovery = claim_recovery_signing_bytes(
        cfg.profile,
        FORMER,
        SessionProof {
            session: 2,
            epoch: 9,
        },
        0,
        payload.binding.origin,
        id,
        &payload,
    )
    .unwrap();
    let Operands::Legal {
        id: legal_id,
        stage,
        payload: legal_payload,
        order,
        ..
    } = operand("EmitLegalOrder")
    else {
        panic!("legal")
    };
    let legal_message = preimage(
        b"oip/reference-legal-order/v1\0",
        &(cfg.profile, 0u64, 1u8, legal_id, &legal_payload, &order),
    )
    .unwrap();
    let legal_signature = legal::LegalIssuer::new(key(18))
        .issue(&security, 0, stage, legal_id, &legal_payload, &order)
        .unwrap();
    assert_eq!(legal_signature, key(18).sign(&legal_message).to_bytes());
    let Operands::Spend {
        id: spend_id,
        payload: spend_payload,
        authorization: Some(enforcement),
        ..
    } = operand("EnforcementSpend")
    else {
        panic!("spend")
    };
    let enforcement_message = preimage(
        b"oip/reference-enforcement-order/v1\0",
        &(cfg.profile, 2u64, spend_id, &spend_payload, &enforcement),
    )
    .unwrap();
    let enforcement_signature = legal::EnforcementIssuer::new(key(19))
        .issue(&security, 2, spend_id, &spend_payload, &enforcement)
        .unwrap();
    assert_eq!(
        enforcement_signature,
        key(19).sign(&enforcement_message).to_bytes()
    );
    let statement = source::SourceStatement {
        profile: cfg.profile,
        origin_epoch: 9,
        evidence: TerminalEvidence {
            binding: payload.binding,
            kind: TerminalKind::Confirmed,
            reference: 2,
        },
    };
    let quorum = preimage(b"oip/source-terminal-quorum/v1\0", &statement).unwrap();
    let certificate = source::SourceCertificate {
        statement,
        votes: vec![source::SourceVote {
            signer: 1,
            signature: key(21).sign(&quorum).to_bytes().to_vec(),
        }],
    };
    let source_rules = BTreeMap::from([(
        payload.binding.origin.domain,
        BTreeMap::from([(
            9,
            source::SourceAuthority {
                issuer: key(20).verifying_key().to_bytes(),
                quorum: 1,
                signers: BTreeMap::from([(1, key(21).verifying_key().to_bytes())]),
            },
        )]),
    )]);
    let certificate_bytes = certificate.canonical_bytes().unwrap();
    assert!(source::verify_certificate(
        &source_rules,
        statement,
        &certificate_bytes
    ));
    let mut changed = certificate.clone();
    changed.votes[0].signature[0] ^= 1;
    assert!(!source::verify_certificate(
        &source_rules,
        statement,
        &changed.canonical_bytes().unwrap()
    ));
    let vectors = vec![
        input("session", session.signing_bytes().unwrap(), Some(8)),
        input("session-grants", grants, None),
        input("maintenance", maintenance.signing_bytes().unwrap(), Some(9)),
        input("authority-policy", policy, None),
        input(
            "ordered-maintenance",
            request.signing_bytes().unwrap(),
            Some(17),
        ),
        input("successor-ready", ready, Some(16)),
        input("handover-consent", consent, Some(7)),
        input("legal-order", legal_message, Some(18)),
        input("enforcement-order", enforcement_message, Some(19)),
        input("claim-recovery", recovery, Some(7)),
        input(
            "source-terminal-record",
            statement.record_signing_bytes().unwrap(),
            Some(20),
        ),
        input("source-terminal-quorum", quorum, Some(21)),
    ];
    let output = json!({"format":1,"vectors":vectors,"source_certificate":{
        "json_utf8":String::from_utf8(certificate_bytes.clone()).unwrap(),
        "hex":hex(&certificate_bytes),"sha256":hex(&Sha256::digest(&certificate_bytes))}});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/reference-signing-inputs.json");
    if std::env::var_os("OIP_WRITE_SIGNING_VECTORS").is_some() {
        std::fs::write(path, serde_json::to_string_pretty(&output).unwrap() + "\n").unwrap();
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(output, expected);
    }
}

#[test]
fn generated_operation_table_matches_the_actual_reference_filter() {
    use crate::authority::recovery::wire::vector_tests::channel;
    let security = Ed25519Security::new(config(), key(6), FixedClock(105)).unwrap();
    let channel = channel(0);
    let mut count = 0;
    for line in include_str!("../../../../../../tests/vectors/wire-operations.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        if !row["id"].as_str().unwrap().ends_with("/valid") {
            continue;
        }
        let bytes = unhex(row["packet_hex"].as_str().unwrap());
        let packet = decode_packet(&bytes, bytes.len()).unwrap();
        let actual = security.accepts_operation(&channel, packet.core());
        assert_eq!(
            actual,
            row["reference_accepts"].as_bool().unwrap(),
            "{}",
            row["id"]
        );
        count += 1;
    }
    assert_eq!(count, 31);
}
