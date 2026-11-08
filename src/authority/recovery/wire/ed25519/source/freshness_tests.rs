use super::*;
use crate::authority::recovery::ordered::etcd::EtcdConfig;
use crate::authority::recovery::ordered::witness::vector_tests::config;
use crate::authority::recovery::vector_tests::{DEFAULT_PROFILE, binding};
use crate::lock_finality::TerminalKind;
use std::fs;
use std::path::Path;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn authorities() -> SourceAuthorities {
    let authority = SourceAuthority {
        issuer: key(20).verifying_key().to_bytes(),
        quorum: 2,
        signers: BTreeMap::from([
            (1, key(21).verifying_key().to_bytes()),
            (2, key(22).verifying_key().to_bytes()),
        ]),
    };
    BTreeMap::from([(0, BTreeMap::from([(9, authority)]))])
}

fn signed(event: u64, kind: TerminalKind, reference: u64) -> SignedSourceDecision {
    let mut binding = binding();
    binding.origin.event = event;
    let statement = SourceStatement {
        profile: DEFAULT_PROFILE,
        origin_epoch: 9,
        evidence: TerminalEvidence {
            binding,
            kind,
            reference,
        },
    };
    SignedSourceDecision {
        statement,
        signature: key(20)
            .sign(&statement.record_signing_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    }
}

fn witness_config(role: &str, case: &str) -> EtcdConfig {
    config(role, &format!("{case}-selection"))
}

fn fixture(case: &str) -> (SourceJournal, SourceReader, EtcdTransport) {
    let writer = SourceJournal::new(
        EtcdTransport::new(config("SOURCE", case)).unwrap(),
        EtcdTransport::new(witness_config("SOURCE_WITNESS", case)).unwrap(),
        DEFAULT_PROFILE,
        authorities(),
    )
    .unwrap();
    let reader = SourceReader::new(
        EtcdTransport::new(config("SOURCE_READER", case)).unwrap(),
        EtcdTransport::new(witness_config("SOURCE_WITNESS_READER", case)).unwrap(),
        DEFAULT_PROFILE,
        authorities(),
    )
    .unwrap();
    let restore = EtcdTransport::new(config("SOURCE_RESTORE", case)).unwrap();
    (writer, reader, restore)
}

fn votes(
    reader: &SourceReader,
    origin: OriginKey,
) -> [Result<(SourceStatement, SourceVote), WireError>; 2] {
    [
        SourceSigner::new(1, key(21)).issue(reader, origin),
        SourceSigner::new(2, key(22)).issue(reader, origin),
    ]
}

fn held(reader: &SourceReader, decision: &SignedSourceDecision) {
    assert_eq!(
        votes(reader, origin_of(decision)),
        [Err(INVALID), Err(INVALID)]
    );
}

fn restore(transport: &EtcdTransport, bytes: &[u8]) {
    let previous = transport.current().unwrap();
    assert_eq!(transport.replace(&previous, bytes), Ok(true));
}

fn disconnect_certificate<T>(file: &str, call: impl FnOnce() -> T) -> T {
    let file = Path::new(file);
    let saved = file.with_extension("offline");
    assert!(!saved.exists());
    fs::rename(file, &saved).unwrap();
    let result = call();
    fs::rename(&saved, file).unwrap();
    result
}

#[test]
#[ignore = "requires independent Linux source and source witness mTLS stores"]
fn source_live_rejects_restored_and_unselected_bytes() {
    let case = "freshness";
    let (source, reader, rollback) = fixture(case);
    let a = signed(17, TerminalKind::Confirmed, 31);
    let b = signed(17, TerminalKind::Reversed, 32);
    let second = signed(18, TerminalKind::Confirmed, 33);
    let pending = signed(19, TerminalKind::Reversed, 34);
    let opposite = signed(19, TerminalKind::Confirmed, 35);
    let later = signed(20, TerminalKind::Confirmed, 36);
    let mut crossed = witness_config("SOURCE_WITNESS", case);
    let local_restore = config("SOURCE_RESTORE", case);
    crossed.client_cert = local_restore.client_cert;
    crossed.client_key = local_restore.client_key;
    let crossed = EtcdTransport::new(crossed).unwrap();
    assert!(crossed.current().is_err());

    held(&reader, &a);
    assert_eq!(source.record(&a), Err(HeadError));
    assert_eq!(source.initialize(), Ok(true));
    assert_eq!(source.initialize(), Ok(false));
    let empty = rollback.current().unwrap();
    let initial_selection = reader.witness.current().unwrap();
    let mut limited = config("SOURCE", case);
    limited.max_control_bytes = empty.bytes.len();
    let bounded = SourceJournal::new(
        EtcdTransport::new(limited).unwrap(),
        EtcdTransport::new(witness_config("SOURCE_WITNESS", case)).unwrap(),
        DEFAULT_PROFILE,
        authorities(),
    )
    .unwrap();
    assert_eq!(bounded.record(&a), Err(HeadError));
    assert!(rollback.current().unwrap() == empty);
    assert!(reader.witness.current().unwrap() == initial_selection);
    println!("too-small source value limit left both exact values unchanged");
    assert_eq!(source.record(&a), Ok(true));
    let confirmed_a = reader.witness.current().unwrap();
    let original_votes = votes(&reader, origin_of(&a));
    assert!(original_votes.iter().all(Result::is_ok));
    assert_eq!(source.record(&a), Ok(false));
    assert!(reader.witness.current().unwrap() == confirmed_a);
    println!(
        "source-fresh-original journal={:?} witness={:?} decision=Confirmed31",
        Mark::of(&rollback.current().unwrap()),
        Mark::of(&confirmed_a)
    );

    restore(&rollback, &empty.bytes);
    assert!(reader.witness.current().unwrap() == confirmed_a);
    assert_eq!(source.record(&b), Err(HeadError));
    held(&reader, &a);
    assert_eq!(source.repair_selected(), Ok(true));
    assert_eq!(votes(&reader, origin_of(&a)), original_votes);
    assert_eq!(source.record(&b), Err(HeadError));
    let first = rollback.current().unwrap();
    println!(
        "source-restored-empty held Reversed32 and both votes; exact repair recovered the same votes"
    );

    assert_eq!(source.record(&second), Ok(true));
    let two = rollback.current().unwrap();
    let confirmed_two = reader.witness.current().unwrap();
    restore(&rollback, &first.bytes);
    assert!(reader.witness.current().unwrap() == confirmed_two);
    assert_eq!(source.record(&later), Err(HeadError));
    held(&reader, &a);
    held(&reader, &second);
    assert_eq!(source.repair_selected(), Ok(true));
    assert!(rollback.current().unwrap().bytes == two.bytes);
    assert_eq!(votes(&reader, origin_of(&a)), original_votes);
    assert!(votes(&reader, origin_of(&second)).iter().all(Result::is_ok));
    println!(
        "source-restored-authentic-prefix held {:?} against selected {:?}; exact repair restored two decisions",
        Mark::of(&first),
        Mark::of(&two)
    );

    let live = rollback.current().unwrap();
    restore(&rollback, &live.bytes);
    held(&reader, &a);
    assert_eq!(source.repair_selected(), Ok(true));
    assert_eq!(votes(&reader, origin_of(&a)), original_votes);

    // Drive the actual append phases to the two process-stop boundaries.
    let (reservation, before) = source.reserve_append(&pending).unwrap();
    let prepared_state = before
        .state
        .appended(Mark::of(&reservation), pending.clone())
        .unwrap();
    let prepared = source.prepare(before.journal, &prepared_state).unwrap();
    assert!(rollback.current().unwrap() == prepared);
    let writer_config = witness_config("SOURCE_WITNESS", case);
    let while_unavailable =
        disconnect_certificate(&writer_config.client_cert, || source.record(&pending));
    assert_eq!(while_unavailable, Err(HeadError));
    held(&reader, &pending);
    held(&reader, &a);
    assert_eq!(source.record(&opposite), Err(HeadError));
    assert_eq!(source.record(&later), Err(HeadError));
    assert_eq!(source.repair_selected(), Err(HeadError));
    assert!(reader.witness.current().unwrap() == reservation);

    // The witness selected the addition. A caller that lost the result
    // must independently read it back before recognizing completion.
    let _unobserved_reply = source.publish(&reservation, prepared_state, prepared);
    let after = reader.witness.current().unwrap();
    assert!(after.revision > reservation.revision);
    let reader_config = witness_config("SOURCE_WITNESS_READER", case);
    let unavailable_votes = disconnect_certificate(&reader_config.client_cert, || {
        votes(&reader, origin_of(&pending))
    });
    assert_eq!(unavailable_votes, [Err(INVALID), Err(INVALID)]);
    assert_eq!(source.record(&pending), Ok(false));
    assert!(reader.witness.current().unwrap() == after);
    assert!(
        votes(&reader, origin_of(&pending))
            .iter()
            .all(Result::is_ok)
    );
    assert_eq!(source.record(&opposite), Err(HeadError));
    println!(
        "source-unconfirmed-append reserved {:?}, then selected {:?}; unavailable readers held and exact retry made no write",
        Mark::of(&reservation),
        Mark::of(&after)
    );
}

#[test]
#[ignore = "requires independent Linux source and source witness mTLS stores"]
fn source_live_selects_one_competing_signed_decision() {
    let case = "freshness-competition";
    let (source, reader, _) = fixture(case);
    let a = signed(17, TerminalKind::Confirmed, 31);
    let b = signed(17, TerminalKind::Reversed, 32);
    assert_eq!(source.initialize(), Ok(true));
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| source.record(&a));
        let right = scope.spawn(|| source.record(&b));
        (left.join().unwrap(), right.join().unwrap())
    });
    let winner = match (left, right) {
        (Ok(true), Err(HeadError)) => a.statement,
        (Err(HeadError), Ok(true)) => b.statement,
        result => panic!("unexpected race result: {result:?}"),
    };
    let [left, right] = votes(&reader, origin_of(&a));
    assert_eq!(left.unwrap().0, winner);
    assert_eq!(right.unwrap().0, winner);
    println!(
        "source-competing-original winner={:?} witness={:?}",
        winner.evidence,
        Mark::of(&reader.witness.current().unwrap())
    );
}

#[test]
#[ignore = "requires isolated Linux source fixture configuration"]
fn source_live_rejects_non_independent_configuration() {
    let case = "freshness";
    let journal = || EtcdTransport::new(config("SOURCE_READER", case)).unwrap();
    let witness = || witness_config("SOURCE_WITNESS_READER", case);
    let rejects = |changed| {
        assert!(
            SourceReader::new(
                journal(),
                EtcdTransport::new(changed).unwrap(),
                DEFAULT_PROFILE,
                authorities()
            )
            .is_err()
        );
    };
    let mut same_endpoint = witness();
    same_endpoint.endpoint = config("SOURCE_READER", case).endpoint;
    rejects(same_endpoint);
    let mut same_cluster = witness();
    same_cluster.cluster_id = config("SOURCE_READER", case).cluster_id;
    rejects(same_cluster);
    let mut same_trust = witness();
    same_trust.ca_cert = config("SOURCE_READER", case).ca_cert;
    rejects(same_trust);
    let mut same_key = witness();
    same_key.key = config("SOURCE_READER", case).key;
    rejects(same_key);
    println!(
        "source-no-independent-witness rejects common endpoint, cluster, trust or configured key"
    );
}
