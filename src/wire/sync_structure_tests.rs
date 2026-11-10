use super::codec::{WireError, body, decode_core, decode_packet, encode_core};
use super::generated::{Core, Operation, core::Body, operation::AppealDeadline};
use super::operands::{Operands, SyncMode, decode, decode_before_response_status};
use super::source_attestation::{self, InvalidSourceAttestation};
use crate::CallId;
use sha2::{Digest, Sha256};
use std::fmt::Write;

const INPUTS: &str = include_str!("../../tests/vectors/sync-structure-vectors.tsv");
const EXPECTED: &str = include_str!("../../tests/vectors/sync-structure-observations.tsv");
const BAD: WireError = WireError::InvalidFormat;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}

fn fixture(case: &str) -> Vec<u8> {
    let encoded = INPUTS
        .lines()
        .find_map(|row| {
            let [kind, id, encoded] = row.split('\t').collect::<Vec<_>>()[..] else {
                panic!("invalid fixture row {row}");
            };
            assert_eq!(kind, "I");
            (id == case).then_some(encoded)
        })
        .unwrap();
    (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
        .collect()
}

fn decimals(words: impl IntoIterator<Item = u64>) -> String {
    words
        .into_iter()
        .map(|word| word.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn packet_observation(name: &str, core_fixture: &str) -> String {
    let input = fixture(name);
    let packet = decode_packet(&input, input.len()).unwrap();
    assert_eq!(packet.encode().unwrap(), input);
    assert_eq!(packet.core_bytes(), fixture(core_fixture));
    let core = packet.core();
    assert_eq!(encode_core(core).unwrap(), packet.core_bytes());
    let (family, operation) = body(core).unwrap();
    let header = decimals([
        core.version.unwrap(),
        core.deployment.unwrap(),
        core.source_domain.unwrap(),
        core.target_domain.unwrap(),
        core.principal.unwrap(),
        core.authority_epoch.unwrap(),
        family,
        operation.opcode.unwrap(),
    ]);
    let (words, blobs) = match decode(core, 1).unwrap() {
        Operands::SyncCommitment {
            id,
            message_reference,
            session,
            cut,
            origin_epoch,
            origin_domain,
            origin_event,
            asset,
            source_position,
            mode,
            commitment,
            predecessor,
            source_attestation,
        } => {
            assert_eq!(Some(id.namespace), core.principal);
            assert_eq!(Some(cut.authority_epoch), core.authority_epoch);
            (
                decimals([
                    1,
                    message_reference,
                    id.sequence,
                    session,
                    cut.revision as u64,
                    origin_epoch,
                    origin_domain,
                    origin_event,
                    asset,
                    source_position,
                    mode as u64,
                ]),
                [
                    hex(&commitment),
                    predecessor
                        .as_ref()
                        .map_or_else(String::new, |value| hex(value)),
                    hex(&source_attestation),
                ]
                .join(","),
            )
        }
        Operands::CurrentCommitment {
            session,
            revision,
            asset,
            origin_domain,
        } => (
            decimals([2, session, revision as u64, asset, origin_domain]),
            String::new(),
        ),
        other => panic!("unexpected operands in {name}: {other:?}"),
    };
    format!(
        "P\t{name}\t{header}\t{}\t{}\t{}\t{words}\t{blobs}",
        hex(packet.core_bytes()),
        hex(&packet.signing_bytes().unwrap()),
        hex(core.uuid.as_deref().unwrap()),
    )
}

#[test]
fn sync_structure_replays_frozen_core_packet_and_proof_bytes() {
    assert_eq!(
        hex(&Sha256::digest(INPUTS.as_bytes())),
        "5f31e25ff66e939bd98a4032932c88c8a917092700f3a08f965f304b01ca9afc",
    );
    assert_eq!(
        hex(&Sha256::digest(EXPECTED.as_bytes())),
        "9e24011939707da3f2f78d630ce434be0124b5691d0980f7c824f21649b54f03",
    );
    for id in ["sync-core", "query-core"] {
        let bytes = fixture(id);
        let core = decode_core(&bytes).unwrap();
        assert_eq!(encode_core(&core).unwrap(), bytes);
        assert!(decode(&core, 1).is_ok(), "{id}");
    }
    let mut actual = vec![
        packet_observation("sync-packet", "sync-core"),
        packet_observation("query-packet", "query-core"),
    ];
    let bytes = fixture("source-proof");
    let statement_bytes = fixture("source-statement");
    let proof = source_attestation::decode(&bytes).unwrap();
    let statement = proof.statement;
    assert_eq!(proof.signed_bytes, statement_bytes);
    assert_eq!(
        source_attestation::decode_statement(&statement_bytes),
        Ok(statement)
    );
    assert_eq!(statement.signing_bytes(), statement_bytes);
    assert_eq!(
        source_attestation::encode(&statement, &proof.signatures).unwrap(),
        bytes
    );
    let words = decimals(
        [
            1,
            1,
            statement.deployment,
            statement.origin_domain,
            statement.origin_epoch,
            statement.roster_id,
            statement.asset,
            statement.origin_event,
            statement.source_position,
            u64::from(statement.predecessor.is_some()),
            proof.signatures.len() as u64,
        ]
        .into_iter()
        .chain(proof.signatures.iter().map(|signature| signature.signer_id)),
    );
    let blobs = [
        hex(proof.signed_bytes),
        hex(&statement.commitment),
        statement
            .predecessor
            .as_ref()
            .map_or_else(String::new, |value| hex(value)),
    ]
    .into_iter()
    .chain(
        proof
            .signatures
            .iter()
            .map(|signature| hex(&signature.signature)),
    )
    .collect::<Vec<_>>()
    .join(",");
    actual.push(format!("A\tsource-proof\t{words}\t{blobs}"));
    for id in ["proof-truncated", "proof-trailing-octet"] {
        assert_eq!(
            source_attestation::decode(&fixture(id)),
            Err(InvalidSourceAttestation)
        );
        actual.push(format!("R\t{id}\trejected"));
    }
    let actual = actual.join("\n") + "\n";
    assert_eq!(actual, EXPECTED);
    if let Some(path) = std::env::var_os("OIP_SYNC_STRUCTURE_OUTPUT") {
        std::fs::write(path, actual).unwrap();
    }
}

fn operation(core: &mut Core) -> &mut Operation {
    match core.body.as_mut().unwrap() {
        Body::StateSync(op) | Body::Query(op) | Body::Ack(op) => op,
        _ => panic!("unexpected family"),
    }
}

fn typed(core: &Core, max_nesting: usize) -> Result<Operands, WireError> {
    let canonical = encode_core(core).and_then(|bytes| decode_core(&bytes))?;
    decode(&canonical, max_nesting)
}

#[test]
fn commitment_operands_separate_shape_errors_from_opaque_proofs() {
    let sync = decode_core(&fixture("sync-core")).unwrap();
    let query = decode_core(&fixture("query-core")).unwrap();
    let sync_mutations: [fn(&mut Operation); 8] = [
        |op| {
            op.words.pop();
        },
        |op| op.words.push(0),
        |op| op.words[9] = 0,
        |op| op.blobs[0].clear(),
        |op| op.blobs[1].clear(),
        |op| {
            op.blobs.pop();
        },
        |op| op.blobs.push(vec![]),
        |op| op.appeal_deadline = Some(AppealDeadline::AppealDeadlineIndefinite(true)),
    ];
    for (index, mutate) in sync_mutations.into_iter().enumerate() {
        let mut malformed = sync.clone();
        mutate(operation(&mut malformed));
        assert_eq!(typed(&malformed, 1), Err(BAD), "sync mutation {index}");
    }
    let query_mutations: [fn(&mut Operation); 4] = [
        |op| {
            op.words.pop();
        },
        |op| op.words.push(0),
        |op| op.blobs.push(vec![]),
        |op| op.appeal_deadline = Some(AppealDeadline::AppealDeadlineUtcSeconds(1)),
    ];
    for (index, mutate) in query_mutations.into_iter().enumerate() {
        let mut malformed = query.clone();
        mutate(operation(&mut malformed));
        assert_eq!(typed(&malformed, 1), Err(BAD), "query mutation {index}");
    }
    for mode in [SyncMode::Initial, SyncMode::FullResync] {
        let mut snapshot = sync.clone();
        operation(&mut snapshot).words[9] = mode as u64;
        assert_eq!(typed(&snapshot, 1), Err(BAD));
        operation(&mut snapshot).blobs[1].clear();
        assert!(matches!(
            typed(&snapshot, 1),
            Ok(Operands::SyncCommitment { mode: found, predecessor: None, .. }) if found == mode
        ));
    }
    for invalid_proof in [
        vec![],
        fixture("proof-truncated"),
        fixture("proof-trailing-octet"),
    ] {
        let mut request = sync.clone();
        operation(&mut request).blobs[2] = invalid_proof.clone();
        let Operands::SyncCommitment {
            source_attestation, ..
        } = typed(&request, 1).unwrap()
        else {
            panic!("sync operand");
        };
        assert_eq!(source_attestation, invalid_proof);
        assert_eq!(
            source_attestation::decode(&source_attestation),
            Err(InvalidSourceAttestation)
        );
    }
}

#[test]
fn source_attestation_requires_exact_domain_words_presence_count_and_order() {
    let proof_bytes = fixture("source-proof");
    let proof = source_attestation::decode(&proof_bytes).unwrap();
    let statement_len = proof.signed_bytes.len();
    let count = statement_len..statement_len + 8;
    let first_signer = count.end;
    let second_signer = first_signer + 8 + 64;
    for offset in [0, 30, 38, 127] {
        let mut malformed = proof_bytes.clone();
        malformed[offset] ^= 2;
        assert_eq!(
            source_attestation::decode(&malformed),
            Err(InvalidSourceAttestation)
        );
    }
    let mut malformed = proof_bytes.clone();
    malformed[count].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        source_attestation::decode(&malformed),
        Err(InvalidSourceAttestation)
    );
    for signer_id in [proof.signatures[0].signer_id, 0] {
        let mut malformed = proof_bytes.clone();
        malformed[second_signer..second_signer + 8].copy_from_slice(&signer_id.to_be_bytes());
        assert_eq!(
            source_attestation::decode(&malformed),
            Err(InvalidSourceAttestation)
        );
    }
    let mut descending = proof.signatures;
    descending.reverse();
    assert_eq!(
        source_attestation::encode(&proof.statement, &descending),
        Err(InvalidSourceAttestation)
    );
    let mut snapshot = proof.statement;
    snapshot.predecessor = None;
    let snapshot_bytes = snapshot.signing_bytes();
    assert_eq!(snapshot_bytes.len(), statement_len - 32);
    assert_eq!(
        source_attestation::decode_statement(&snapshot_bytes),
        Ok(snapshot)
    );
    assert_eq!(
        source_attestation::decode_statement(&proof_bytes),
        Err(InvalidSourceAttestation)
    );
}

fn receipt(original: &Core) -> Core {
    let mut receipt = original.clone();
    receipt.family = Some(4);
    receipt.body = Some(Body::Query(Operation {
        opcode: Some(8),
        words: vec![60],
        blobs: vec![encode_core(original).unwrap()],
        appeal_deadline: None,
    }));
    receipt
}

fn response(original: &Core, id: CallId, code: u64, commit: Option<u64>) -> Core {
    let mut response = original.clone();
    response.source_domain = original.target_domain;
    response.target_domain = original.source_domain;
    response.family = Some(5);
    let mut words = vec![
        id.namespace,
        id.sequence,
        1,
        code,
        u64::from(commit.is_some()),
    ];
    words.extend(commit);
    response.body = Some(Body::Ack(Operation {
        opcode: Some(2),
        words,
        blobs: vec![encode_core(original).unwrap()],
        appeal_deadline: None,
    }));
    response
}

#[test]
fn synchronization_receipts_and_responses_bind_the_exact_original() {
    let original = decode_core(&fixture("sync-core")).unwrap();
    let Operands::SyncCommitment { id, .. } = decode(&original, 1).unwrap() else {
        panic!("sync operand");
    };
    let exact_receipt = receipt(&original);
    assert_eq!(typed(&exact_receipt, 1), Err(BAD));
    assert_eq!(
        typed(&exact_receipt, 2),
        Ok(Operands::Receipt {
            session: 60,
            original: Box::new(original.clone()),
        })
    );
    for (retained, depth) in [(&original, 2), (&exact_receipt, 3)] {
        for (code, commit) in [(29, Some(77)), (39, None), (40, None), (41, None)] {
            let valid = response(retained, id, code, commit);
            let expected = Operands::Response {
                id,
                kind: 1,
                code,
                commit: commit.map(|position| crate::authority::CommitRef {
                    position: position as usize,
                }),
                original: encode_core(retained).unwrap(),
            };
            assert_eq!(typed(&valid, depth), Ok(expected));
            assert_eq!(typed(&valid, depth - 1), Err(BAD));
            let wrong_presence = response(
                retained,
                id,
                code,
                if commit.is_some() { None } else { Some(77) },
            );
            assert_eq!(typed(&wrong_presence, depth), Err(BAD));
            assert!(decode_before_response_status(&wrong_presence, depth).is_ok());
            let wrong_id = CallId {
                namespace: id.namespace,
                sequence: id.sequence + 1,
            };
            assert_eq!(
                typed(&response(retained, wrong_id, code, commit), depth),
                Err(BAD)
            );
            let mut wrong_kind = valid;
            operation(&mut wrong_kind).words[2] = 2;
            assert_eq!(typed(&wrong_kind, depth), Err(BAD));
        }
    }
    let mut wrong_epoch = exact_receipt;
    wrong_epoch.authority_epoch = Some(original.authority_epoch.unwrap() + 1);
    assert_eq!(
        typed(&response(&wrong_epoch, id, 41, None), 3),
        Err(WireError::InvalidSource)
    );
    let query = decode_core(&fixture("query-core")).unwrap();
    assert_eq!(typed(&receipt(&query), 2), Err(BAD));
    let query_response = response(&query, id, 99, None);
    assert_eq!(typed(&query_response, 2), Err(BAD));
    assert_eq!(decode_before_response_status(&query_response, 2), Err(BAD));
}

#[test]
fn raw_sync_response_checks_known_codes_and_leaves_signed_status_until_correlation() {
    let original = decode_core(&fixture("sync-core")).unwrap();
    let Operands::SyncCommitment { id, .. } = decode(&original, 1).unwrap() else {
        panic!("sync operand");
    };
    for (original, depth) in [(original.clone(), 2), (receipt(&original), 3)] {
        for (code, kind, commit, accepted) in [
            (1, 1, None, true),
            (2, 1, None, true),
            (3, 1, None, true),
            (1, 1, Some(77), false),
            (4, 1, None, false),
            (12, 1, Some(77), false),
            (28, 1, Some(77), false),
            (30, 1, None, false),
            (38, 1, None, false),
            (50, 2, None, true),
            (56, 2, None, true),
            (50, 1, None, false),
            (70, 3, None, true),
            (77, 3, None, true),
            (70, 2, None, false),
            (99, 1, Some(77), true),
            (99, 1, None, true),
            (99, 2, None, true),
            (99, 3, None, true),
        ] {
            let mut reply = response(&original, id, code, commit);
            operation(&mut reply).words[2] = kind;
            assert_eq!(
                typed(&reply, depth).is_ok(),
                accepted,
                "{code}, {kind}, {commit:?}"
            );
            assert!(
                decode_before_response_status(&reply, depth).is_ok(),
                "{code}"
            );
        }
    }
}
