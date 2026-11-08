use super::*;
use crate::OriginKey;
use crate::authority::identity::{ActionReply, Credentials, Receipt};
use crate::authority::reads::{CheckedExecution, Value};
use crate::authority::recovery::vector_tests::binding;
use crate::authority::recovery::wire::ed25519::source::{
    SignedSourceDecision, SourceAuthorities, SourceAuthority, SourceCertificate, SourceJournal,
    SourceReader, SourceSigner, SourceStatement,
};
use crate::authority::{Collection, OutcomeReply};
use crate::lock_finality::{Binding, Phase, Reply, TerminalKind};

type Service<C = SystemClock> =
    PersistentAuthority<Ed25519Security<C>, WitnessHead<Ed25519WitnessAuthority>>;

pub(super) fn rules() -> SourceAuthorities {
    let source = SourceAuthority {
        issuer: key(20).verifying_key().to_bytes(),
        quorum: 2,
        signers: BTreeMap::from([
            (1, key(21).verifying_key().to_bytes()),
            (2, key(22).verifying_key().to_bytes()),
        ]),
    };
    BTreeMap::from([(0, BTreeMap::from([(8, source.clone()), (9, source)]))])
}

fn source_provider() -> Ed25519Security<SystemClock> {
    let mut config = actual_config();
    config.sources = rules();
    config.other_endpoints.insert(2);
    let origin = binding().origin;
    let query = Query::SourcePool(0, 17);
    let grant = EndpointGrant {
        execute: BTreeSet::from([17, 22]),
        receipts: BTreeSet::from([17, 22]),
        current: vec![query],
        journal: true,
        historical: vec![query],
        raw: vec![query],
        status: BTreeSet::from([origin]),
        cache: vec![query],
        owner: BTreeSet::from([17]),
        recovery: BTreeSet::from([17, 22]),
        ..EndpointGrant::default()
    };
    config
        .peers
        .get_mut(&7)
        .unwrap()
        .sessions
        .insert(2, BTreeMap::from([(0, grant.clone()), (2, grant)]));
    Ed25519Security::new(config, key(6), SystemClock).unwrap()
}

pub(super) fn source_witness(role: &str, case: &str) -> EtcdTransport {
    EtcdTransport::new(etcd_config(role, &format!("{case}-selection"))).unwrap()
}

pub(super) fn source_writer(case: &str) -> SourceJournal {
    let journal = SourceJournal::new(
        EtcdTransport::new(etcd_config("SOURCE", case)).unwrap(),
        source_witness("SOURCE_WITNESS", case),
        DEFAULT_PROFILE,
        rules(),
    )
    .unwrap();
    assert_eq!(journal.initialize(), Ok(true));
    journal
}

pub(super) fn source_reader(case: &str) -> SourceReader {
    SourceReader::new(
        EtcdTransport::new(etcd_config("SOURCE_READER", case)).unwrap(),
        source_witness("SOURCE_WITNESS_READER", case),
        DEFAULT_PROFILE,
        rules(),
    )
    .unwrap()
}

pub(super) fn source_record(
    b: Binding,
    kind: TerminalKind,
    reference: u64,
) -> SignedSourceDecision {
    let statement = SourceStatement {
        profile: DEFAULT_PROFILE,
        origin_epoch: 9,
        evidence: TerminalEvidence {
            binding: b,
            kind,
            reference,
        },
    };
    let signature = key(20)
        .sign(&statement.record_signing_bytes().unwrap())
        .to_bytes()
        .to_vec();
    SignedSourceDecision {
        statement,
        signature,
    }
}

pub(super) fn certificate(reader: &SourceReader, origin: OriginKey) -> SourceCertificate {
    let (statement, left) = SourceSigner::new(1, key(21)).issue(reader, origin).unwrap();
    let (right_statement, right) = SourceSigner::new(2, key(22)).issue(reader, origin).unwrap();
    assert_eq!(statement, right_statement);
    SourceCertificate {
        statement,
        votes: vec![left, right],
    }
}

pub(super) fn cut<C: AuthorityClock>(service: &mut Service<C>) -> CommitCut {
    service
        .transact(|product| product.reads.current_cut())
        .unwrap()
}

pub(super) fn mass<C: AuthorityClock>(service: &mut Service<C>, b: Binding) -> (u64, u64, u64) {
    service
        .transact(|product| {
            let ledger = &product.reads.authority.state.primary.ledger;
            (
                ledger.balance(b.source()),
                ledger.pending(b.origin),
                ledger.balance(b.destination()),
            )
        })
        .unwrap()
}

pub(super) fn call(
    family: u64,
    opcode: u64,
    endpoint: u64,
    label: u8,
    revision: usize,
    b: Binding,
    credential: bool,
    tail: &[u64],
    proof: Option<&SourceCertificate>,
) -> Vec<u8> {
    let id = u64::from(label);
    let mut words = vec![
        id,
        id,
        2,
        revision as u64,
        9,
        b.origin.domain,
        b.origin.event,
        b.asset,
        b.owner,
        b.destination,
        b.recipient,
        u64::from(credential),
    ];
    if credential {
        words.extend([b.asset, b.origin.domain, b.origin.event, 7, 0, 9]);
    }
    words.extend([1, b.asset, 0]);
    words.extend_from_slice(tail);
    let mut blobs = vec![uint256(b.amount)];
    if let Some(proof) = proof {
        blobs.push(proof.canonical_bytes().unwrap());
    }
    signed_at(
        core_with(family, opcode, endpoint, label, words, blobs),
        7,
        now(),
        90,
    )
}

pub(super) fn consume<C: AuthorityClock>(
    service: &mut Service<C>,
    endpoint: u64,
    token: &SessionToken,
    packet: &Vec<u8>,
) -> Result<WireReply, WireError> {
    service
        .receive_wire(
            &channel_at(6, 7, endpoint, 0),
            Entry::Normal,
            packet,
            &credentials(token, packet),
            DeliveryWindow::default(),
        )
        .map(|received| received.reply)
}

pub(super) fn owner_consume<C: AuthorityClock>(
    service: &mut Service<C>,
    token: &SessionToken,
    packet: &Vec<u8>,
) -> WireReply {
    let decoded = decode_packet(packet, packet.len()).unwrap();
    let Operands::Ordinary { id, payload, .. } = decode(decoded.core(), 4).unwrap() else {
        panic!("ordinary");
    };
    let proof = SessionProof {
        session: payload.session,
        epoch: 9,
    };
    let message = claim_recovery_signing_bytes(
        DEFAULT_PROFILE,
        FORMER,
        proof,
        payload.endpoint,
        payload.binding.origin,
        id,
        &payload,
    )
    .unwrap();
    let signature = key(7).sign(&message).to_bytes().to_vec();
    let endorsement = Credentials {
        token,
        proof,
        signature: &signature,
    };
    service
        .receive_wire(
            &channel_at(6, 7, payload.endpoint, 0),
            Entry::Normal,
            packet,
            &WireCredentials {
                endorsement: Some(&endorsement),
                ..credentials(token, packet)
            },
            DeliveryWindow::default(),
        )
        .unwrap()
        .reply
}

pub(super) fn ordinary(reply: WireReply) -> Collection {
    let WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(collection))) = reply
    else {
        panic!("ordinary outcome {reply:?}");
    };
    collection
}

pub(super) fn did(reply: WireReply, expected: Reply) {
    let result = ordinary(reply);
    assert!(
        matches!(result, Collection::Collected(outcome) if outcome.reply == OutcomeReply::Accepted(expected)),
        "expected {expected:?}, received {result:?}",
    );
}

fn signed_receipt(
    service: &mut Service,
    endpoint: u64,
    token: &SessionToken,
    packet: &[u8],
    tag: u8,
) -> Result<WireReply, WireError> {
    let original = decode_packet(packet, packet.len()).unwrap();
    let bytes = signed_at(
        core_with(
            4,
            8,
            endpoint,
            tag,
            vec![2],
            vec![original.core_bytes().to_vec()],
        ),
        7,
        now(),
        90,
    );
    consume(service, endpoint, token, &bytes)
}

pub(super) fn start<C: AuthorityClock>(
    service: &mut Service<C>,
    token: &SessionToken,
    b: Binding,
    first: u8,
) {
    let r = cut(service).revision;
    let reserve = call(3, 1, 0, first, r, b, false, &[20], None);
    did(
        consume(service, 0, token, &reserve).unwrap(),
        Reply::Reserved,
    );
    let dispatch = call(3, 2, 0, first + 1, r + 1, b, true, &[0], None);
    did(
        consume(service, 0, token, &dispatch).unwrap(),
        Reply::SourceDispatched,
    );
    let debit = call(1, 1, 0, first + 2, r + 2, b, true, &[0], None);
    did(consume(service, 0, token, &debit).unwrap(), Reply::Debited);
}

#[test]
#[ignore = "requires isolated Linux source, authority and witness etcd"]
fn reference_source_live_exact_terminal_credit_refund_and_queries() {
    let root = std::env::temp_dir().join(format!("oip-source-live-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let archive = root.join("archive");
    fs::create_dir(&archive).unwrap();
    let journal = source_writer("source");
    let read_transport = EtcdTransport::new(etcd_config("SOURCE_READER", "source")).unwrap();
    let readable = read_transport.current().unwrap();
    assert!(
        read_transport
            .replace(&readable, b"reader must not write")
            .is_err()
    );
    assert!(read_transport.current().unwrap() == readable);
    let read_witness = source_witness("SOURCE_WITNESS_READER", "source");
    let witness_value = read_witness.current().unwrap();
    assert!(
        read_witness
            .replace(&witness_value, b"reader must not write")
            .is_err()
    );
    let reader = SourceReader::new(read_transport, read_witness, DEFAULT_PROFILE, rules()).unwrap();
    let b = binding();
    assert!(
        SourceSigner::new(1, key(21))
            .issue(&reader, b.origin)
            .is_err()
    );
    let a = source_record(b, TerminalKind::Confirmed, 41);
    let other = source_record(b, TerminalKind::Confirmed, 42);
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| journal.record(&a));
        let right = scope.spawn(|| journal.record(&other));
        (left.join().unwrap(), right.join().unwrap())
    });
    assert_ne!(left == Ok(true), right == Ok(true));
    let confirmed = certificate(&reader, b.origin);
    let ref_ = confirmed.statement.evidence.reference;
    assert_eq!(ref_, if left == Ok(true) { 41 } else { 42 });
    assert_eq!(
        journal.record(if ref_ == 41 { &a } else { &other }),
        Ok(false)
    );
    assert!(
        journal
            .record(&source_record(b, TerminalKind::Reversed, ref_))
            .is_err()
    );
    assert!(
        SourceSigner::new(1, key(22))
            .issue(&reader, b.origin)
            .is_err()
    );

    let second = Binding {
        origin: OriginKey {
            domain: 0,
            event: 22,
        },
        asset: 22,
        ..b
    };
    assert_eq!(
        journal.record(&source_record(second, TerminalKind::Reversed, 43)),
        Ok(true)
    );
    let reversed = certificate(&reader, second.origin);

    let anchor = head_at(
        &archive,
        WitnessWriter {
            generation: 1,
            identity: [23; 32],
        },
        "source",
    );
    let supplied = source_provider();
    let issuer = SessionIssuer::new(key(8));
    let token = issuer.issue(&supplied, 7, 2, 300).unwrap();
    let read_only = issuer.issue(&supplied, 7, 1, 300).unwrap();
    let attached = attachment(&anchor, source_provider());
    let path = JournalPath::create();
    let mut initial = genesis(10, 1);
    initial.balances.insert(second.source(), 5);
    initial.supply.insert(second.asset, 5);
    initial.owners.insert(second.asset, 7);
    let proof = anchor
        .prepare_genesis(
            &mut path.file(),
            initial,
            source_provider(),
            true,
            &attached.proof,
        )
        .unwrap();
    let signature = key(13).sign(&proof.authorization_message().unwrap());
    anchor
        .provision_genesis(&proof, &attached.proof, &signature.to_bytes())
        .unwrap();
    let mut service = PersistentAuthority::open(path.file(), anchor, attached).unwrap();
    start(&mut service, &token, b, 10);
    assert_eq!(mass(&mut service, b), (5, 5, 0));
    let r = cut(&mut service).revision;
    let timeout = call(3, 8, 0, 13, r, b, false, &[10], None);
    assert_eq!(
        consume(&mut service, 0, &token, &timeout),
        Err(WireError::InvalidSource),
    );
    assert_eq!(mass(&mut service, b), (5, 5, 0));

    let mut invalid = Vec::new();
    let mut empty = confirmed.clone();
    empty.votes.clear();
    invalid.push(empty);
    let mut insufficient = confirmed.clone();
    insufficient.votes.pop();
    invalid.push(insufficient);
    let mut duplicate = confirmed.clone();
    duplicate.votes[1] = duplicate.votes[0].clone();
    invalid.push(duplicate);
    let mut wrong_purpose = confirmed.clone();
    wrong_purpose.votes[0].signature = key(21)
        .sign(&wrong_purpose.statement.record_signing_bytes().unwrap())
        .to_bytes()
        .to_vec();
    invalid.push(wrong_purpose);
    let mut forged = confirmed.clone();
    forged.votes[0].signature[0] ^= 1;
    invalid.push(forged);
    let mut wrong_ref = confirmed.clone();
    wrong_ref.statement.evidence.reference ^= 8;
    invalid.push(wrong_ref);
    let mut wrong_amount = confirmed.clone();
    wrong_amount.statement.evidence.binding.amount += 1;
    invalid.push(wrong_amount);
    let mut wrong_recipient = confirmed.clone();
    wrong_recipient.statement.evidence.binding.recipient += 1;
    invalid.push(wrong_recipient);
    let mut wrong_epoch = confirmed.clone();
    wrong_epoch.statement.origin_epoch = 8;
    invalid.push(wrong_epoch);
    let r = cut(&mut service).revision;
    let before = service.anchor.current().unwrap();
    for proof in invalid {
        let packet = call(1, 2, 0, 14, r, b, false, &[1, ref_], Some(&proof));
        assert_eq!(
            consume(&mut service, 0, &token, &packet),
            Err(WireError::InvalidSource)
        );
    }
    assert_eq!(service.anchor.current().unwrap(), before);

    let terminal = call(1, 2, 0, 14, r, b, false, &[1, ref_], Some(&confirmed));
    did(
        consume(&mut service, 0, &token, &terminal).unwrap(),
        Reply::Recorded,
    );
    let r = cut(&mut service).revision;
    let wrong = call(1, 3, 2, 15, r, b, true, &[ref_ ^ 8], None);
    assert!(
        matches!(ordinary(consume(&mut service, 2, &token, &wrong).unwrap()),
        Collection::Collected(outcome) if outcome.reply == OutcomeReply::Rejected)
    );
    assert_eq!(mass(&mut service, b), (5, 5, 0));
    let bad_refund = call(1, 4, 0, 16, r, b, true, &[0, ref_], Some(&confirmed));
    assert_eq!(
        consume(&mut service, 0, &token, &bad_refund),
        Err(WireError::InvalidSource)
    );
    let credit = call(1, 3, 2, 17, r, b, true, &[ref_], None);
    assert_eq!(
        ordinary(consume(&mut service, 2, &token, &credit).unwrap()),
        Collection::Waiting
    );
    assert_eq!(mass(&mut service, b), (5, 0, 5));
    let r = cut(&mut service).revision;
    let reconcile = call(3, 6, 0, 18, r, b, true, &[0, ref_], Some(&confirmed));
    did(
        owner_consume(&mut service, &token, &reconcile),
        Reply::Reconciled,
    );
    let r = cut(&mut service).revision;
    let publish = call(1, 5, 0, 19, r, b, false, &[], None);
    did(
        consume(&mut service, 0, &token, &publish).unwrap(),
        Reply::Published,
    );
    let original = ordinary(consume(&mut service, 2, &token, &credit).unwrap());
    assert!(
        matches!(original, Collection::Collected(outcome) if outcome.reply == OutcomeReply::Accepted(Reply::Credited))
    );
    assert_eq!(
        signed_receipt(&mut service, 2, &token, &credit, 20).unwrap(),
        WireReply::Receipt(Some(Receipt::Ordinary(original)))
    );
    let mut altered = decode_packet(&credit, credit.len()).unwrap().core().clone();
    altered.uuid.as_mut().unwrap()[0] ^= 1;
    let altered = signed_at(altered, 7, now(), 90);
    assert_eq!(
        signed_receipt(&mut service, 2, &token, &altered, 21),
        Err(WireError::RequestUnresolved)
    );
    assert_eq!(mass(&mut service, b), (5, 0, 5));

    start(&mut service, &token, second, 22);
    assert_eq!(mass(&mut service, second), (0, 5, 0));
    let r = cut(&mut service).revision;
    let terminal = call(1, 2, 0, 25, r, second, false, &[2, 43], Some(&reversed));
    did(
        consume(&mut service, 0, &token, &terminal).unwrap(),
        Reply::Recorded,
    );
    let r = cut(&mut service).revision;
    let refund = call(1, 4, 0, 26, r, second, true, &[0, 43], Some(&reversed));
    let result = owner_consume(&mut service, &token, &refund);
    assert!(matches!(ordinary(result), Collection::Waiting));
    assert_eq!(mass(&mut service, second), (5, 0, 0));
    let r = cut(&mut service).revision;
    let publish = call(1, 5, 0, 27, r, second, false, &[], None);
    did(
        consume(&mut service, 0, &token, &publish).unwrap(),
        Reply::Published,
    );
    let expected = ordinary(owner_consume(&mut service, &token, &refund));
    assert!(
        matches!(expected, Collection::Collected(outcome) if outcome.reply == OutcomeReply::Accepted(Reply::Refunded))
    );
    assert_eq!(
        signed_receipt(&mut service, 0, &token, &refund, 28).unwrap(),
        WireReply::Receipt(Some(Receipt::Ordinary(expected)))
    );
    println!(
        "actual independent source chose ref {ref_}; exact wire Credit/Refund/receipts and timeout passed"
    );

    let observations = [
        (2, vec![0, 2, 0, 17]), // Historical at genesis
        (3, vec![2, 0, 17]),    // Raw source pool
        (4, vec![0, 17]),       // Exact origin status
        (6, vec![2, 0, 17]),    // Provider cache capture
        (7, vec![17]),          // Owner
    ];
    for (opcode, words) in observations {
        let mut allowed = vec![2];
        allowed.extend(&words);
        let packet = signed_at(
            core_with(4, opcode, 0, 60 + opcode as u8, allowed, Vec::new()),
            7,
            now(),
            90,
        );
        let observed = consume(&mut service, 0, &token, &packet).unwrap();
        assert!(match (opcode, observed) {
            (2, WireReply::Observation(Observation::Historical(Ok(value)))) =>
                value.value == Value::Units(10),
            (3, WireReply::Observation(Observation::Raw(Ok(value)))) => value == Value::Units(5),
            (4, WireReply::Observation(Observation::Status(status))) =>
                status.phase == Some(Phase::Reconciled),
            (6, WireReply::Observation(Observation::Cache(Ok(_)))) => true,
            (7, WireReply::Observation(Observation::Owner(Some(7)))) => true,
            _ => false,
        });
        let mut denied = vec![1];
        denied.extend(&words);
        let packet = signed_at(
            core_with(4, opcode, 0, 70 + opcode as u8, denied, Vec::new()),
            7,
            now(),
            90,
        );
        let before = service.anchor.current().unwrap();
        assert_eq!(
            consume(&mut service, 0, &read_only, &packet),
            Err(WireError::ProductRejected)
        );
        assert_eq!(service.anchor.current().unwrap(), before);
    }
    println!("Historical, Raw, Status, Cache and Owner consumed their exact current grants");
    drop(service);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires source, independent source witness, authority, and authority witness etcd"]
fn reference_source_restore_preserves_first_receiver_receipt() {
    let case = "freshness-receiver";
    let root = std::env::temp_dir().join(format!(
        "oip-source-restore-receiver-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let archive = root.join("archive");
    fs::create_dir(&archive).unwrap();
    let journal = source_writer(case);
    let reader = source_reader(case);
    let restore = EtcdTransport::new(etcd_config("SOURCE_RESTORE", case)).unwrap();
    let empty = restore.current().unwrap();
    let b = binding();
    let a = source_record(b, TerminalKind::Confirmed, 31);
    let b_reversed = source_record(b, TerminalKind::Reversed, 32);
    assert_eq!(journal.record(&a), Ok(true));
    assert_eq!(journal.record(&a), Ok(false));
    let selected = certificate(&reader, b.origin);
    assert_eq!(selected.statement, a.statement);

    let anchor = head_at(
        &archive,
        WitnessWriter {
            generation: 1,
            identity: [24; 32],
        },
        case,
    );
    let attached = attachment(&anchor, source_provider());
    let path = JournalPath::create();
    let prepared = anchor
        .prepare_genesis(
            &mut path.file(),
            genesis(10, 1),
            source_provider(),
            true,
            &attached.proof,
        )
        .unwrap();
    anchor
        .provision_genesis(
            &prepared,
            &attached.proof,
            &key(13)
                .sign(&prepared.authorization_message().unwrap())
                .to_bytes(),
        )
        .unwrap();
    let mut service = PersistentAuthority::open(path.file(), anchor, attached).unwrap();
    let token = SessionIssuer::new(key(8))
        .issue(&source_provider(), 7, 2, 300)
        .unwrap();
    start(&mut service, &token, b, 10);
    let r = cut(&mut service).revision;
    let terminal = call(1, 2, 0, 13, r, b, false, &[1, 31], Some(&selected));
    did(
        consume(&mut service, 0, &token, &terminal).unwrap(),
        Reply::Recorded,
    );
    let r = cut(&mut service).revision;
    let credit = call(1, 3, 2, 14, r, b, true, &[31], None);
    assert_eq!(
        ordinary(consume(&mut service, 2, &token, &credit).unwrap()),
        Collection::Waiting
    );
    let r = cut(&mut service).revision;
    let reconcile = call(3, 6, 0, 15, r, b, true, &[0, 31], Some(&selected));
    did(
        owner_consume(&mut service, &token, &reconcile),
        Reply::Reconciled,
    );
    let r = cut(&mut service).revision;
    let publish = call(1, 5, 0, 16, r, b, false, &[], None);
    did(
        consume(&mut service, 0, &token, &publish).unwrap(),
        Reply::Published,
    );
    let original = decode_packet(&credit, credit.len()).unwrap();
    let receipt_packet = signed_at(
        core_with(4, 8, 2, 70, vec![2], vec![original.core_bytes().to_vec()]),
        7,
        now(),
        90,
    );
    let first = consume(&mut service, 2, &token, &receipt_packet).unwrap();
    assert!(
        matches!(first, WireReply::Receipt(Some(Receipt::Ordinary(Collection::Collected(outcome))))
        if outcome.reply == OutcomeReply::Accepted(Reply::Credited))
    );
    let selected_head = service.anchor.current().unwrap();
    let confirmed = restore.current().unwrap();
    assert_eq!(restore.replace(&confirmed, &empty.bytes), Ok(true));
    assert!(journal.record(&b_reversed).is_err());
    for (id, seed) in [(1, 21), (2, 22)] {
        assert_eq!(
            SourceSigner::new(id, key(seed)).issue(&reader, b.origin),
            Err(WireError::InvalidSource)
        );
    }
    let r = cut(&mut service).revision;
    let forged_terminal = call(1, 2, 0, 17, r, b, false, &[2, 32], Some(&selected));
    let forged_refund = call(1, 4, 0, 18, r, b, true, &[0, 32], Some(&selected));
    assert_eq!(
        consume(&mut service, 0, &token, &forged_terminal),
        Err(WireError::InvalidSource)
    );
    assert_eq!(
        consume(&mut service, 0, &token, &forged_refund),
        Err(WireError::InvalidSource)
    );
    assert_eq!(service.anchor.current().unwrap(), selected_head);
    assert_eq!(cut(&mut service).revision, r);
    assert_eq!(
        consume(&mut service, 2, &token, &receipt_packet).unwrap(),
        first
    );
    assert_eq!(service.anchor.current().unwrap(), selected_head);
    assert_eq!(mass(&mut service, b), (5, 0, 5));
    assert_eq!(journal.repair_selected(), Ok(true));
    assert_eq!(certificate(&reader, b.origin), selected);
    assert!(journal.record(&b_reversed).is_err());
    assert_eq!(service.anchor.current().unwrap(), selected_head);
    println!(
        "Confirmed31 retained exact Credited receipt and mass (5,0,5); source-only empty replay could not produce Reversed32"
    );
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
