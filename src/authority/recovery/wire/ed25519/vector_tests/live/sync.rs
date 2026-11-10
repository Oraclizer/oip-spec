use super::super::reference_execution_trace::channel_for;
use super::super::sync_tests::{
    STREAM, call, enabled, entry, initial, statement, verified_response,
};
use super::*;
use crate::authority::CommitRef;
use crate::authority::identity::{ActionReply, Receipt};
use crate::authority::reads::{CurrentRead, Value};
use crate::authority::recovery::wire::ed25519::source::{
    CommitmentAuthorities, SignedCommitment, SourceAuthority, SourceJournal, SourceReader,
    SourceSigner,
};
use crate::authority::recovery::{HeadError, exact_image};
use crate::authority::sync::Outcome;
use crate::wire::admission::{Arrival, TransportKey};
use crate::wire::operands::SyncMode;
use crate::wire::source_attestation::{self, SourceStatement};
use serde_json::json;

mod trace;

const SOURCE: &str = "commitment-source";
const MARK: &str = "commitment-source-mark";
const AUTHORITY: &str = "commitment-product";
const STREAM_SESSION: u64 = 2;
type Service =
    PersistentAuthority<Ed25519Security<FixedClock>, WitnessHead<Ed25519WitnessAuthority>>;

fn transport(role: &str, case: &str) -> EtcdTransport {
    EtcdTransport::new(etcd_config(role, case)).unwrap()
}

fn authorities() -> CommitmentAuthorities {
    let rule = |seeds: [u8; 3]| SourceAuthority {
        issuer: key(seeds[0]).verifying_key().to_bytes(),
        quorum: 2,
        signers: BTreeMap::from([
            (101, key(seeds[1]).verifying_key().to_bytes()),
            (102, key(seeds[2]).verifying_key().to_bytes()),
        ]),
    };
    BTreeMap::from([(
        30,
        BTreeMap::from([
            (6, BTreeMap::from([(11, rule([20, 21, 22]))])),
            (7, BTreeMap::from([(14, rule([24, 25, 26]))])),
        ]),
    )])
}

fn writer() -> SourceJournal {
    SourceJournal::new_with_commitments(
        transport("SOURCE", SOURCE),
        transport("SOURCE_WITNESS", MARK),
        DEFAULT_PROFILE,
        BTreeMap::new(),
        authorities(),
    )
    .unwrap()
}

fn reader() -> SourceReader {
    SourceReader::new_with_commitments(
        transport("SOURCE_READER", SOURCE),
        transport("SOURCE_WITNESS_READER", MARK),
        DEFAULT_PROFILE,
        BTreeMap::new(),
        authorities(),
    )
    .unwrap()
}

fn signed_record(statement: SourceStatement, issuer: u8) -> SignedCommitment {
    let bytes = SignedCommitment::record_signing_bytes(&statement);
    SignedCommitment::new(statement, key(issuer).sign(&bytes).to_bytes())
}

fn selected_proof(source: &SourceReader, seeds: [u8; 2]) -> (SourceStatement, Vec<u8>) {
    let selection = source.selected_commitment(STREAM).unwrap();
    let second_reader = reader();
    let votes = [
        SourceSigner::new(102, key(seeds[1]))
            .issue_commitment(&second_reader, &selection)
            .unwrap(),
        SourceSigner::new(101, key(seeds[0]))
            .issue_commitment(source, &selection)
            .unwrap(),
    ];
    assert!(selection.proof(&votes[..1]).is_err());
    let proof = selection.proof(&votes).unwrap();
    let decoded = source_attestation::decode(&proof).unwrap();
    assert_eq!(decoded.statement, selection.statement());
    assert_eq!(decoded.signed_bytes, selection.statement().signing_bytes());
    assert_eq!(
        decoded
            .signatures
            .iter()
            .map(|vote| vote.signer_id)
            .collect::<Vec<_>>(),
        [101, 102]
    );
    println!(
        "sync-source-proof\t{}\t{}\t{}\t{:x}\t{:x}",
        decoded.statement.origin_epoch,
        decoded.statement.origin_event,
        decoded.statement.source_position,
        Sha256::digest(decoded.signed_bytes),
        Sha256::digest(&proof),
    );
    (selection.statement(), proof)
}

fn provider() -> Ed25519Security<FixedClock> {
    Ed25519Security::new(enabled(), key(6), FixedClock(105)).unwrap()
}

fn attach_provider(
    anchor: &WitnessHead<Ed25519WitnessAuthority>,
) -> Attachment<Ed25519Security<FixedClock>, [u8; 64]> {
    let proof = WitnessAttachmentIssuer::new(key(12))
        .issue(anchor, true)
        .unwrap();
    Attachment {
        profile: DEFAULT_PROFILE,
        source_connected: true,
        proof,
        security: provider(),
    }
}

fn verify_ack(
    original: &[u8],
    response: &[u8],
    code: ResponseCode,
    position: Option<usize>,
) -> serde_json::Value {
    let actual = verified_response(original, response);
    assert_eq!(actual.code, ResponseStatus::Known(code));
    assert_eq!(
        actual.commit,
        position.map(|position| CommitRef { position })
    );
    let packet = decode_packet(response, response.len()).unwrap();
    let Operands::Response { kind, .. } = decode(packet.core(), 2).unwrap() else {
        panic!("signed response operand");
    };
    json!({
        "id": actual.id, "kind": kind, "code": actual.code.known().unwrap() as u64,
        "commit_position": actual.commit.map(|commit| commit.position),
        "response_packet_hex": trace::hex(response),
    })
}

#[test]
#[ignore = "requires four independent local Linux etcd mTLS stores with empty commitment keys"]
fn sync_product_live_selected_source_and_receiver_recover_independently() {
    let source = writer();
    let view = reader();
    assert!(view.selected_commitment(STREAM).is_err());
    assert_eq!(source.initialize(), Ok(true));
    assert_eq!(source.initialize(), Ok(false));
    let first = statement(STREAM, 50, 80, 0, None);
    assert_eq!(
        source.record_commitment(&signed_record(first, 24)),
        Err(HeadError)
    );
    assert_eq!(
        source.record_commitment(&signed_record(first, 20)),
        Ok(true)
    );
    assert_eq!(
        source.record_commitment(&signed_record(first, 20)),
        Ok(false)
    );
    let (observed, proof) = selected_proof(&view, [21, 22]);
    assert_eq!(observed, first);
    let first_selection = view.selected_commitment(STREAM).unwrap();
    let source_storage = transport("SOURCE_RESTORE", SOURCE);
    let first_bytes = source_storage.current().unwrap();

    let base = std::env::temp_dir().join(format!("oip-sync-live-{}", std::process::id()));
    fs::create_dir(&base).unwrap();
    let archive = base.join("archive");
    fs::create_dir(&archive).unwrap();
    let writer_id = WitnessWriter {
        generation: 1,
        identity: [21; 32],
    };
    let anchor = head_at(&archive, writer_id, AUTHORITY);
    let path = JournalPath::create();
    let attached = attach_provider(&anchor);
    let provision = anchor
        .prepare_genesis(
            &mut path.file(),
            initial(),
            provider(),
            true,
            &attached.proof,
        )
        .unwrap();
    let provision_bytes = provision.authorization_message().unwrap();
    anchor
        .provision_genesis(
            &provision,
            &attached.proof,
            &key(13).sign(&provision_bytes).to_bytes(),
        )
        .unwrap();
    let mut service = PersistentAuthority::open(path.file(), anchor, attached).unwrap();
    let client = SessionIssuer::new(key(8))
        .issue(&service.security, 7, STREAM_SESSION, 300)
        .unwrap();
    let inbound = channel_for(6, 7);
    let mut trace = trace::Trace::new(&service, &inbound);
    let absent = signed_at(
        core_with(
            4,
            9,
            0,
            50,
            vec![STREAM_SESSION, 0, STREAM.asset, STREAM.origin_domain],
            vec![],
        ),
        7,
        100,
        240,
    );
    trace.input(&mut service, "absent-current-query", &absent, &client);
    let received = service
        .receive_wire(
            &inbound,
            Entry::Normal,
            &absent,
            &credentials(&client, &absent),
            DeliveryWindow::default(),
        )
        .unwrap();
    let WireReply::Observation(Observation::Current(Ok(current))) = received.reply else {
        panic!("current commitment observation");
    };
    assert_eq!(
        current,
        CurrentRead {
            cut: CommitCut {
                authority_epoch: 9,
                revision: 0
            },
            value: Value::Commitment(None),
        }
    );
    trace.observed(&mut service, "absent-current-query", json!(current));
    let submit = |statement: &SourceStatement, mode, revision, label, proof| {
        signed_at(
            call(statement, mode, STREAM_SESSION, revision, label, proof),
            7,
            100,
            240,
        )
    };
    let first_packet = submit(&first, SyncMode::Initial, 0, 51, proof);
    let creds = credentials(&client, &first_packet);
    trace.input(&mut service, "initial", &first_packet, &client);
    let ack = service
        .receive_wire_response(
            &inbound,
            Entry::Normal,
            &first_packet,
            &creds,
            DeliveryWindow::default(),
        )
        .unwrap();
    let result = verify_ack(
        &first_packet,
        &ack,
        ResponseCode::StateCommitmentSynced,
        Some(0),
    );
    trace.observed(&mut service, "initial", result);
    let first_head = service.anchor.current().unwrap().unwrap();
    println!(
        "sync-live\tinitial\t29\t0\t{:x}",
        Sha256::digest(first_head.digest)
    );

    drop(source);
    drop(view);
    let source = writer();
    let view = reader();
    assert_eq!(source.initialize(), Ok(false));
    let same_position = SourceStatement {
        origin_event: 51,
        ..first
    };
    assert_eq!(
        source.record_commitment(&signed_record(same_position, 20)),
        Err(HeadError)
    );
    let wrong_predecessor = statement(STREAM, 51, 81, 3, Some([1; 32]));
    assert_eq!(
        source.record_commitment(&signed_record(wrong_predecessor, 20)),
        Err(HeadError)
    );
    let next = statement(STREAM, 51, 81, 3, Some(first.commitment));
    assert_eq!(source.record_commitment(&signed_record(next, 20)), Ok(true));
    assert!(
        SourceSigner::new(101, key(21))
            .issue_commitment(&view, &first_selection)
            .is_err()
    );
    let (next_selected, next_proof) = selected_proof(&view, [21, 22]);
    assert_eq!(next_selected, next);

    let latest = source_storage.current().unwrap();
    assert_eq!(
        source_storage.replace(&latest, &first_bytes.bytes),
        Ok(true)
    );
    assert!(view.selected_commitment(STREAM).is_err());
    assert!(
        SourceSigner::new(101, key(21))
            .issue_commitment(&view, &first_selection)
            .is_err()
    );
    assert_eq!(source.repair_selected(), Ok(true));
    assert_eq!(selected_proof(&view, [21, 22]), (next, next_proof.clone()));
    println!("sync-live\tjournal-rollback-refused-and-repaired\t81");

    let query = signed_at(
        core_with(
            4,
            9,
            0,
            52,
            vec![STREAM_SESSION, 1, STREAM.asset, STREAM.origin_domain],
            vec![],
        ),
        7,
        100,
        240,
    );
    trace.input(&mut service, "source-ahead-current-query", &query, &client);
    let actual = service
        .receive_wire(
            &inbound,
            Entry::Normal,
            &query,
            &credentials(&client, &query),
            DeliveryWindow::default(),
        )
        .unwrap();
    let WireReply::Observation(Observation::Current(Ok(current))) = actual.reply else {
        panic!("current commitment observation");
    };
    assert_eq!(
        current,
        CurrentRead {
            cut: CommitCut {
                authority_epoch: 9,
                revision: 1
            },
            value: Value::Commitment(Some(entry(first))),
        }
    );
    trace.observed(&mut service, "source-ahead-current-query", json!(current));
    println!("sync-live\tindependent-source-81-receiver-80\t1");

    let removed = submit(&next, SyncMode::Incremental, 1, 53, vec![]);
    trace.input(&mut service, "proof-removed", &removed, &client);
    let rejection = service
        .receive_wire_response(
            &inbound,
            Entry::Normal,
            &removed,
            &credentials(&client, &removed),
            DeliveryWindow::default(),
        )
        .unwrap();
    let result = verify_ack(
        &removed,
        &rejection,
        ResponseCode::SourceAttestationRejected,
        None,
    );
    trace.observed(&mut service, "proof-removed", result);
    println!("sync-live\tproof-removed\t41\t-");
    let next_packet = submit(&next, SyncMode::Incremental, 1, 54, next_proof);
    trace.input(&mut service, "response-lost", &next_packet, &client);
    let lost = service.receive_wire(
        &inbound,
        Entry::Normal,
        &next_packet,
        &credentials(&client, &next_packet),
        DeliveryWindow {
            response_lost: true,
            ..DeliveryWindow::default()
        },
    );
    assert_eq!(lost, Err(WireError::ResponseLost));
    trace.observed(
        &mut service,
        "response-lost",
        json!({"wire_error": format!("{:?}", lost.unwrap_err())}),
    );
    let head = service.anchor.current().unwrap().unwrap();
    drop(service);
    let anchor = head_at(&archive, writer_id, AUTHORITY);
    let attached = attach_provider(&anchor);
    let mut service = PersistentAuthority::open(path.file(), anchor, attached).unwrap();
    trace.input(&mut service, "reopened-exact-retry", &next_packet, &client);
    let retry = service
        .receive_wire(
            &inbound,
            Entry::Normal,
            &next_packet,
            &credentials(&client, &next_packet),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(retry.arrival, Arrival::Identical);
    assert_eq!(
        retry.reply,
        WireReply::Executed(ActionReply::SyncCommitment(Outcome::Synced(CommitRef {
            position: 1
        })))
    );
    let WireReply::Executed(ActionReply::SyncCommitment(outcome)) = retry.reply else {
        unreachable!()
    };
    trace.observed(
        &mut service,
        "reopened-exact-retry",
        json!({"arrival": format!("{:?}", retry.arrival), "outcome": outcome}),
    );
    assert_eq!(service.anchor.current().unwrap(), Some(head));
    let original = decode_packet(&next_packet, next_packet.len()).unwrap();
    let receipt = signed_at(
        core_with(
            4,
            8,
            0,
            55,
            vec![STREAM_SESSION],
            vec![original.core_bytes().to_vec()],
        ),
        7,
        100,
        240,
    );
    trace.input(&mut service, "exact-receipt", &receipt, &client);
    let result = service
        .receive_wire(
            &inbound,
            Entry::Normal,
            &receipt,
            &credentials(&client, &receipt),
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(
        result.reply,
        WireReply::Receipt(Some(Receipt::SyncCommitment(Outcome::Synced(CommitRef {
            position: 1
        }))))
    );
    let WireReply::Receipt(Some(Receipt::SyncCommitment(outcome))) = result.reply else {
        unreachable!()
    };
    trace.observed(&mut service, "exact-receipt", json!(outcome));
    println!(
        "sync-live\treopen-exact-retry-and-receipt\t29\t1\t{:x}",
        Sha256::digest(head.digest)
    );

    let selected = service.anchor.current().unwrap().unwrap();
    let record = exact_image(&mut service.file, selected).unwrap();
    let bindings = &record.image.authority.wire_bindings;
    let original_key = TransportKey::for_core(original.core()).unwrap();
    assert_eq!(
        bindings.get(&original_key).map(Vec::as_slice),
        Some(original.core_bytes())
    );

    let mut changed = original.core().clone();
    let Some(Body::StateSync(operation)) = &mut changed.body else {
        panic!("expected synchronization original");
    };
    operation.words[0] ^= 1;
    assert_eq!(TransportKey::for_core(&changed).unwrap(), original_key);
    assert_ne!(encode_core(&changed).unwrap(), original.core_bytes());

    let mut missing = original.core().clone();
    missing.uuid.as_mut().unwrap()[0] = 254;
    let missing_key = TransportKey::for_core(&missing).unwrap();
    assert_ne!(missing_key, original_key);
    assert!(!bindings.contains_key(&missing_key));

    let journal_length = service.file.metadata().unwrap().len();
    for (case, label, embedded, expected) in [
        (
            "receipt-original-uuid-conflict",
            57,
            changed,
            WireError::ReplayConflict,
        ),
        (
            "receipt-original-uuid-missing",
            58,
            missing,
            WireError::RequestUnresolved,
        ),
    ] {
        let receipt_core = core_with(
            4,
            8,
            0,
            label,
            vec![STREAM_SESSION],
            vec![encode_core(&embedded).unwrap()],
        );
        assert!(!bindings.contains_key(&TransportKey::for_core(&receipt_core).unwrap()));
        let receipt = signed_at(receipt_core, 7, 100, 240);
        trace.input(&mut service, case, &receipt, &client);
        let actual = service
            .receive_wire(
                &inbound,
                Entry::Normal,
                &receipt,
                &credentials(&client, &receipt),
                DeliveryWindow::default(),
            )
            .unwrap_err();
        assert_eq!(actual, expected);
        assert_eq!(service.anchor.current().unwrap(), Some(selected));
        assert_eq!(service.file.metadata().unwrap().len(), journal_length);
        let code = match actual {
            WireError::ReplayConflict => ResponseCode::ReplayConflict as u64,
            WireError::RequestUnresolved => ResponseCode::Unresolved as u64,
            other => panic!("unexpected receipt error {other:?}"),
        };
        trace.observed(
            &mut service,
            case,
            json!({"wire_error": format!("{actual:?}"), "code": code}),
        );
        println!(
            "sync-live\t{case}\t{code}\t{}",
            trace::hex(&selected.digest)
        );
    }

    let rotated = SourceStatement {
        origin_epoch: 7,
        roster_id: 14,
        origin_event: 52,
        source_position: 82,
        ..next
    };
    let replay_position = SourceStatement {
        source_position: 81,
        ..rotated
    };
    assert_eq!(
        source.record_commitment(&signed_record(replay_position, 24)),
        Err(HeadError)
    );
    assert_eq!(
        source.record_commitment(&signed_record(rotated, 24)),
        Err(HeadError)
    ); // predecessor 80
    let rotated = SourceStatement {
        predecessor: Some(next.commitment),
        ..rotated
    };
    assert_eq!(
        source.record_commitment(&signed_record(rotated, 24)),
        Ok(true)
    );
    let (observed, rotated_proof) = selected_proof(&view, [25, 26]);
    assert_eq!(observed, rotated);
    let future_roster = submit(&rotated, SyncMode::Incremental, 2, 56, rotated_proof);
    trace.input(
        &mut service,
        "origin-roster-not-selected",
        &future_roster,
        &client,
    );
    let rejected = service
        .receive_wire_response(
            &inbound,
            Entry::Normal,
            &future_roster,
            &credentials(&client, &future_roster),
            DeliveryWindow::default(),
        )
        .unwrap();
    let result = verify_ack(
        &future_roster,
        &rejected,
        ResponseCode::SourceAttestationRejected,
        None,
    );
    trace.observed(&mut service, "origin-roster-not-selected", result);
    trace.write();
    println!("sync-live\tindependent-origin-roster-not-selected-at-receiver\t41\t-");
    drop(service);
    fs::remove_dir_all(base).unwrap();
}
