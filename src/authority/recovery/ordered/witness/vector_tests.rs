use super::*;
use crate::authority::identity::{ActionReply, Entry, Receipt};
use crate::authority::reads::CheckedExecution;
use crate::authority::recovery::ordered::etcd::EtcdConfig;
use crate::authority::recovery::vector_tests::{DEFAULT_PROFILE, Rules, genesis};
use crate::authority::recovery::wire::schedule::{WireOccurrence, WireScheduleReply};
use crate::authority::recovery::wire::vector_tests::ordered_tests::schedule_tests::{
    ack_channel, ack_credentials, dispatched_fixture, signed_ack, signed_current,
};
use crate::authority::recovery::wire::vector_tests::{
    channel, core_with, debit_core, operation, signed, uint256, wire_auth,
};
use crate::authority::recovery::wire::{DebitResult, DeliveryWindow, WireReply};
use crate::authority::recovery::{Attachment, PersistentAuthority, append_record};
use crate::authority::{Collection, CommitRef, Outcome, OutcomeReply};
use crate::lock_finality::Reply;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fs::{self, OpenOptions};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
const WRITER: WitnessWriter = WitnessWriter {
    generation: 1,
    identity: [1; 32],
};

struct Directory(PathBuf);

impl Directory {
    fn create() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("oip-witness-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn new_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
}

fn reopen(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing isolated witness fixture {name}"))
}

pub(in crate::authority::recovery) fn config(role: &str, case: &str) -> EtcdConfig {
    let field = |name| env(&format!("OIP_WITNESS_{role}_{name}"));
    EtcdConfig {
        executable: PathBuf::from(env("OIP_WITNESS_ETCDCTL")),
        endpoint: field("ENDPOINT").parse().unwrap(),
        cluster_id: field("CLUSTER").parse().unwrap(),
        key: format!("/oraclizer/witness-test/{case}"),
        ca_cert: field("CA"),
        client_cert: field("CERT"),
        client_key: field("KEY"),
        dial_timeout: Duration::from_secs(2),
        rpc_timeout: Duration::from_secs(2),
        process_timeout: Duration::from_secs(5),
        max_control_bytes: 256 * 1024,
    }
}

struct SignedFixture(VerifyingKey);

fn authority_signer() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

fn attachment_message(
    profile: RecoveryProfile,
    authority: [u8; 32],
    witness: [u8; 32],
    writer: WitnessWriter,
    connected: bool,
) -> Vec<u8> {
    let mut bytes = b"oip/witness-fixture-attachment\0".to_vec();
    bytes.extend(encode(&(profile, authority, witness, writer, connected)).unwrap());
    bytes
}

impl WitnessAttachmentVerifier for SignedFixture {
    type Proof = [u8; 64];

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        authority: [u8; 32],
        witness: [u8; 32],
        writer: WitnessWriter,
        connected: bool,
        proof: &Self::Proof,
    ) -> bool {
        self.0
            .verify_strict(
                &attachment_message(profile, authority, witness, writer, connected),
                &Signature::from_bytes(proof),
            )
            .is_ok()
    }

    fn verify_genesis(&self, cut: &WitnessGenesis, _: &Self::Proof, bytes: &[u8]) -> bool {
        Signature::from_slice(bytes).is_ok_and(|sig| {
            self.0
                .verify_strict(&cut.authorization_message().unwrap(), &sig)
                .is_ok()
        })
    }

    fn verify_repair(&self, cut: &WitnessRepair, _: &Self::Proof, bytes: &[u8]) -> bool {
        Signature::from_slice(bytes).is_ok_and(|sig| {
            self.0
                .verify_strict(&cut.authorization_message().unwrap(), &sig)
                .is_ok()
        })
    }
}

fn head(
    role: &str,
    case: &str,
    archive: &Path,
    profile: RecoveryProfile,
    writer: WitnessWriter,
) -> WitnessHead<SignedFixture> {
    WitnessHead::new(
        EtcdTransport::new(config(role, case)).unwrap(),
        EtcdTransport::new(config("SELECTOR", case)).unwrap(),
        JournalArchive::new(archive, profile, 1024 * 1024).unwrap(),
        profile,
        writer,
        4,
        SignedFixture(authority_signer().verifying_key()),
    )
    .unwrap()
}

fn attachment(head: &WitnessHead<SignedFixture>) -> Attachment<Rules, [u8; 64]> {
    let store = &head.ordered.store;
    let proof = authority_signer()
        .sign(&attachment_message(
            store.profile,
            store.authority.attachment_binding(),
            store.witness.attachment_binding(),
            store.writer,
            true,
        ))
        .to_bytes();
    let mut security = Rules::default();
    security.ordered_clock = Some(Arc::new(AtomicU64::new(105)));
    Attachment {
        profile: store.profile,
        security,
        proof,
        source_connected: true,
    }
}

fn genesis_sig(cut: &WitnessGenesis) -> [u8; 64] {
    authority_signer()
        .sign(&cut.authorization_message().unwrap())
        .to_bytes()
}

fn repair_sig(cut: &WitnessRepair) -> [u8; 64] {
    authority_signer()
        .sign(&cut.authorization_message().unwrap())
        .to_bytes()
}

#[test]
#[ignore = "requires separate isolated authority, witness, and restore etcd instances"]
fn witness_live_genesis_debit_faults_and_repair() {
    let archive = Directory::create();
    let work = Directory::create();
    let first_path = work.0.join("first.records");
    let other_path = work.0.join("other.records");
    let mut first = new_file(&first_path);
    let mut other = new_file(&other_path);
    let mut bad = new_file(&work.0.join("bad.records"));
    let root = head("AUTHORITY", "debit", &archive.0, DEFAULT_PROFILE, WRITER);
    let proof = attachment(&root).proof;
    let mut invalid = genesis(10, 1);
    invalid.supply.insert(binding_asset(), 11);
    assert_eq!(
        root.prepare_genesis(&mut bad, invalid, Rules::default(), true, &proof),
        Err(RecoveryError::InvalidBootstrap)
    );
    assert_eq!(bad.metadata().unwrap().len(), 0);

    let left = root
        .prepare_genesis(&mut first, genesis(10, 1), Rules::default(), true, &proof)
        .unwrap();
    let right = root
        .prepare_genesis(&mut other, genesis(11, 1), Rules::default(), true, &proof)
        .unwrap();
    let left_sig = genesis_sig(&left);
    let right_sig = genesis_sig(&right);
    assert_eq!(
        root.provision_genesis(&left, &proof, &right_sig),
        Err(RecoveryError::AttachmentRejected)
    );
    let wrong_profile = RecoveryProfile {
        deployment: 8,
        ..DEFAULT_PROFILE
    };
    let wrong = head("AUTHORITY", "debit", &archive.0, wrong_profile, WRITER);
    assert!(
        wrong
            .provision_genesis(&left, &attachment(&wrong).proof, &left_sig)
            .is_err()
    );

    let (won_left, won_right) = std::thread::scope(|scope| {
        let a = scope.spawn(|| root.provision_genesis(&left, &proof, &left_sig).is_ok());
        let b = scope.spawn(|| root.provision_genesis(&right, &proof, &right_sig).is_ok());
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_ne!(won_left, won_right);
    let (chosen, chosen_sig, path, rejected, rejected_sig) = if won_left {
        (&left, &left_sig, first_path, &right, &right_sig)
    } else {
        (&right, &right_sig, other_path, &left, &left_sig)
    };
    let initial_witness = root.ordered.store.read_witness().unwrap();
    let initial_authority = root.ordered.store.authority.current().unwrap();
    root.provision_genesis(chosen, &proof, chosen_sig).unwrap();
    assert!(root.ordered.store.witness.current().unwrap() == initial_witness.raw);
    assert!(root.ordered.store.authority.current().unwrap() == initial_authority);
    assert!(
        root.provision_genesis(rejected, &proof, rejected_sig)
            .is_err()
    );
    let initial_bytes = fs::read(&path).unwrap();
    println!("invalid genesis held; two signed values competed; exact replay consumed no write");

    let read = signed(core_with(4, 1, 0, 54, vec![2, 0, 2, 0, 17], Vec::new()));
    let readonly = head("AUTHORITY", "debit", &archive.0, DEFAULT_PROFILE, WRITER);
    let attached = attachment(&readonly);
    let mut failed =
        PersistentAuthority::open(File::open(&path).unwrap(), readonly, attached).unwrap();
    assert_eq!(
        failed.receive_wire(
            &channel(0),
            Entry::Normal,
            &read,
            &wire_auth(),
            DeliveryWindow::default()
        ),
        Err(WireError::Recovery(RecoveryError::Io))
    );
    assert!(root.ordered.store.witness.current().unwrap() == initial_witness.raw);
    drop(failed);
    let signed_channel = channel(0);
    let attached = attachment(&root);
    let mut live = PersistentAuthority::open(reopen(&path), root, attached).unwrap();
    let reserve = signed(core_with(
        3,
        1,
        0,
        50,
        vec![10, 10, 2, 0, 9, 0, 17, 17, 7, 2, 3, 0, 1, 17, 0, 20],
        vec![uint256(5)],
    ));
    let mut dispatch_core = debit_core(1);
    let mut words = std::mem::take(&mut operation(&mut dispatch_core).words);
    words[0] = 11;
    words[1] = 11;
    let dispatch = signed(core_with(3, 2, 0, 51, words, vec![uint256(5)]));
    for (packet, effect) in [
        (&reserve, Reply::Reserved),
        (&dispatch, Reply::SourceDispatched),
    ] {
        let received = live
            .receive_wire(
                &signed_channel,
                Entry::Normal,
                packet,
                &wire_auth(),
                DeliveryWindow::default(),
            )
            .unwrap();
        assert!(
            matches!(received.reply, WireReply::Executed(ActionReply::Ordinary(
            CheckedExecution::Forwarded(Collection::Collected(Outcome { reply: OutcomeReply::Accepted(answer), .. }))
        )) if answer == effect)
        );
    }
    let debit = signed(debit_core(2));
    assert_eq!(
        live.receive_wire(
            &signed_channel,
            Entry::Normal,
            &debit,
            &wire_auth(),
            DeliveryWindow {
                response_lost: true,
                ..DeliveryWindow::default()
            },
        ),
        Err(WireError::ResponseLost),
    );
    println!("after-CAS response loss returned no success");
    let receipt = DebitResult::Published(Receipt::Ordinary(Collection::Collected(Outcome {
        reply: OutcomeReply::Accepted(Reply::Debited),
        commit: Some(CommitRef { position: 2 }),
    })));
    assert_eq!(
        live.resolve_wire_debit(&signed_channel, &debit, &wire_auth(), false),
        Ok(receipt)
    );
    let root = &live.anchor;
    let store = &root.ordered.store;
    let selected = store.current_selection().unwrap();
    assert_eq!(selected.envelope.archive.head.sequence, 3);

    // Retain an actual flushed next journal record, then stop after authority
    // prepare. Its archive exists, but the public head remains selected.
    let mut file = reopen(&path);
    let mut proposed_record = exact_image(&mut file, selected.envelope.archive.head).unwrap();
    proposed_record.previous = Some(selected.envelope.archive.head);
    proposed_record.sequence += 1;
    let next = append_record(&mut file, &proposed_record, File::sync_all).unwrap();
    let orphan = store.archive.retain(&mut file, next).unwrap();
    let mut state = selected.state.clone();
    state.head = Some(next);
    let staged = store.propose(&selected, state.encode().unwrap(), orphan, WRITER);
    let pending_bytes = store.prepare_selection(&selected, &staged).unwrap();
    assert_eq!(root.current().unwrap(), selected.state.head);
    assert!(store.witness.current().unwrap() == selected.raw);
    assert!(root.revoke(44).unwrap());
    assert_eq!(
        store.witness.replace(&selected.raw, &pending_bytes),
        Ok(false)
    );

    let current = store.current_selection().unwrap();
    let cancelled = TransportKey::for_core(
        crate::wire::codec::decode_packet(&read, read.len())
            .unwrap()
            .core(),
    )
    .unwrap();
    let staged = store.propose(
        &current,
        current.state.encode().unwrap(),
        current.envelope.archive,
        WRITER,
    );
    let prepared = store.prepare_selection(&current, &staged).unwrap();
    assert!(root.cancel(cancelled).unwrap());
    assert_eq!(store.witness.replace(&current.raw, &prepared), Ok(false));
    let current = store.current_selection().unwrap();
    let staged = store.propose(
        &current,
        current.state.encode().unwrap(),
        current.envelope.archive,
        WRITER,
    );
    let prepared = store.prepare_selection(&current, &staged).unwrap();
    let rotated = WitnessWriter {
        generation: 2,
        identity: [2; 32],
    };
    assert!(root.rotate_writer(rotated).unwrap());
    assert_eq!(store.witness.replace(&current.raw, &prepared), Ok(false));
    assert!(root.observe().is_err());
    drop(live);

    let current = head("AUTHORITY", "debit", &archive.0, DEFAULT_PROFILE, rotated);
    let before_rollback = current.ordered.store.current_selection().unwrap();
    let mirror = current.ordered.store.authority.current().unwrap();
    assert!(
        current
            .ordered
            .store
            .authority
            .replace(&mirror, &initial_authority.bytes)
            .unwrap()
    );
    assert!(current.ordered.store.authority.current().unwrap().revision > mirror.revision);
    assert!(current.current().is_err());
    assert_eq!(
        current.checkpoint_readback().unwrap().0,
        before_rollback.state.head
    );
    let stale_path = work.0.join("stale.records");
    fs::write(&stale_path, &initial_bytes).unwrap();
    let attached = attachment(&current);
    assert!(PersistentAuthority::open(reopen(&stale_path), current, attached).is_err());
    println!(
        "pre-flush and orphan held; revoke/cancel/rotation fenced exact old prepares; witness alone read back the selected head"
    );

    let foreign = EtcdTransport::new(config("RESTORED", "debit")).unwrap();
    let empty = foreign.current().unwrap();
    assert!(foreign.replace(&empty, &initial_authority.bytes).unwrap());
    let mut wrong_cluster = config("RESTORED", "debit");
    wrong_cluster.cluster_id = config("AUTHORITY", "debit").cluster_id;
    assert!(
        EtcdTransport::new(wrong_cluster)
            .unwrap()
            .current()
            .is_err()
    );
    let recovered_writer = WitnessWriter {
        generation: 3,
        identity: [3; 32],
    };
    let recovered = head(
        "RESTORED",
        "debit",
        &archive.0,
        DEFAULT_PROFILE,
        recovered_writer,
    );
    let proof = attachment(&recovered).proof;
    assert!(recovered.current().is_err());
    let wrong_destination = work.0.join("wrong-existing.records");
    fs::write(&wrong_destination, b"do not overwrite").unwrap();
    let wrong_cut = recovered
        .repair_cut(&wrong_destination, true, &proof)
        .unwrap();
    assert!(
        recovered
            .repair_from_archive(&wrong_cut, &proof, &repair_sig(&wrong_cut))
            .is_err()
    );
    assert_eq!(fs::read(&wrong_destination).unwrap(), b"do not overwrite");

    let destination = work.0.join("repaired.records");
    let cut = recovered.repair_cut(&destination, true, &proof).unwrap();
    let sig = repair_sig(&cut);
    let store = &recovered.ordered.store;
    // Simulate interruption after file restoration and authority preparation.
    store.archive.restore(cut.archive, &destination).unwrap();
    let previous = store.read_witness().unwrap();
    let mut state = previous.state.clone();
    state.writer_generation = recovered_writer.generation;
    let mut candidate = store.propose(
        &previous,
        state.encode().unwrap(),
        cut.archive,
        recovered_writer,
    );
    candidate.authorization = Some(Sha256::digest(cut.authorization_message().unwrap()).into());
    let staged = AuthorityPrepare {
        profile: DEFAULT_PROFILE,
        base: cut.selected,
        preparations: vec![encode(&candidate).unwrap()],
    };
    let prior = store.authority.current().unwrap();
    store
        .install_exact_prepare(&prior, cut.restored, &staged)
        .unwrap();
    recovered.repair_from_archive(&cut, &proof, &sig).unwrap();
    let repaired_witness = store.witness.current().unwrap();
    recovered.repair_from_archive(&cut, &proof, &sig).unwrap();
    assert!(store.witness.current().unwrap() == repaired_witness);
    let mut old_nonce = cut.clone();
    old_nonce.destination = work.0.join("nonce-reuse.records");
    assert!(
        recovered
            .repair_from_archive(&old_nonce, &proof, &repair_sig(&old_nonce))
            .is_err()
    );
    assert!(!old_nonce.destination.exists());
    let attached = attachment(&recovered);
    let mut live = PersistentAuthority::open(reopen(&destination), recovered, attached).unwrap();
    assert_eq!(
        live.resolve_wire_debit(&signed_channel, &debit, &wire_auth(), false),
        Ok(receipt)
    );
    println!(
        "new cluster repair resumed exact existing file and preparation; old nonce could not select another path"
    );
}

fn binding_asset() -> u64 {
    crate::authority::recovery::vector_tests::binding().asset
}

#[test]
#[ignore = "requires separate isolated authority and witness etcd instances"]
fn witness_live_schedule_uses_one_archived_selection() {
    let archive = Directory::create();
    let (path, anchor, job, cut) = dispatched_fixture();
    let root = head("AUTHORITY", "schedule", &archive.0, DEFAULT_PROFILE, WRITER);
    let store = &root.ordered.store;
    let mut file = path.file();
    let archived = store.archive.retain(&mut file, anchor.head()).unwrap();
    let control = OrderedHead::<WitnessStore<SignedFixture>>::initial_value(
        DEFAULT_PROFILE,
        Some(anchor.head()),
        WRITER.generation,
    )
    .unwrap();
    // The old published fixture is provisioned for this test only.
    let witness = store.witness.current().unwrap();
    let selected = Selection {
        profile: DEFAULT_PROFILE,
        authority: store.authority.attachment_binding(),
        witness: store.witness.attachment_binding(),
        control,
        archive: archived,
        floor: anchor.head(),
        writer: WRITER,
        previous: None,
        repair_nonce: [42; 32],
        authorization: None,
    };
    assert!(
        store
            .witness
            .replace(&witness, &encode(&selected).unwrap())
            .unwrap()
    );
    let witness = store.witness.current().unwrap();
    let authority = store.authority.current().unwrap();
    let mirror = AuthorityPrepare {
        profile: DEFAULT_PROFILE,
        base: Mark::of(&witness),
        preparations: Vec::new(),
    };
    assert!(
        store
            .authority
            .replace(&authority, &encode(&mirror).unwrap())
            .unwrap()
    );
    let attached = attachment(&root);
    let mut live = PersistentAuthority::open(path.file(), root, attached).unwrap();
    let ack = signed_ack(job, 50);
    let read = signed_current(cut);
    let requests = [
        WireOccurrence {
            label: 501,
            channel: &ack_channel(),
            bytes: &ack,
            credentials: &ack_credentials(),
        },
        WireOccurrence {
            label: 777,
            channel: &channel(2),
            bytes: &read,
            credentials: &wire_auth(),
        },
    ];
    let result = live.schedule_wire(&requests, &[0]).unwrap();
    assert_eq!(
        result.exchanges,
        [crate::authority::recovery::schedule::Exchange::Exchanged]
    );
    assert_eq!(
        result.replies[0].reply.unwrap().reply,
        WireScheduleReply::Acknowledged(true)
    );
    assert_eq!(result.replies[1].label, 777);
    let selected = live.anchor.ordered.store.current_selection().unwrap();
    assert_eq!(selected.raw.revision, witness.revision + 1);
    assert_eq!(
        selected.envelope.archive.head.sequence,
        anchor.head().sequence + 1
    );
    live.schedule_wire(&requests, &[0]).unwrap();
    assert!(live.anchor.ordered.store.witness.current().unwrap() == selected.raw);
    println!(
        "actual signed ACK/read schedule selected one exact archived head; exact retry selected none"
    );
}

#[test]
#[ignore = "requires separate isolated authority and witness TLS identities"]
fn witness_live_rejects_cross_cluster_credentials_and_copied_trust() {
    for (endpoint, wrong_writer) in [("AUTHORITY", "SELECTOR"), ("SELECTOR", "AUTHORITY")] {
        let right = EtcdTransport::new(config(endpoint, "tls")).unwrap();
        let expected = right.current().unwrap();
        let wrong = config(wrong_writer, "tls");
        let mut crossed = config(endpoint, "tls");
        crossed.client_cert = wrong.client_cert;
        crossed.client_key = wrong.client_key;
        let crossed = EtcdTransport::new(crossed).unwrap();
        assert!(crossed.current().is_err());
        assert!(crossed.replace(&expected, b"must never write").is_err());
        assert!(right.current().unwrap() == expected);
    }

    let fixtures = Directory::create();
    let same_ca = fixtures.0.join("copy-ca.pem");
    let same_key = fixtures.0.join("copy-client.key");
    let source = config("AUTHORITY", "tls");
    fs::copy(&source.ca_cert, &same_ca).unwrap();
    fs::copy(&source.client_key, &same_key).unwrap();
    let authority = EtcdTransport::new(source).unwrap();
    let mut copied = config("SELECTOR", "tls");
    copied.ca_cert = same_ca.to_str().unwrap().into();
    assert!(!authority.independent_of(&EtcdTransport::new(copied).unwrap()));
    let mut copied = config("SELECTOR", "tls");
    copied.client_key = same_key.to_str().unwrap().into();
    assert!(!authority.independent_of(&EtcdTransport::new(copied).unwrap()));
    let mut alias = config("SELECTOR", "tls");
    alias.ca_cert = config("AUTHORITY", "tls").ca_cert;
    assert!(!authority.independent_of(&EtcdTransport::new(alias).unwrap()));

    let mut before_config = config("AUTHORITY", "tls");
    before_config.ca_cert = same_ca.to_str().unwrap().into();
    let before = EtcdTransport::new(before_config).unwrap();
    assert!(before.current().is_ok());
    let original_binding = before.attachment_binding();
    let mut changed = fs::read(&same_ca).unwrap();
    changed.extend_from_slice(b"\n# changed trust material\n");
    fs::write(&same_ca, changed).unwrap();
    assert!(before.current().is_err());
    let mut after_config = config("AUTHORITY", "tls");
    after_config.ca_cert = same_ca.to_str().unwrap().into();
    let after = EtcdTransport::new(after_config).unwrap();
    assert_ne!(after.attachment_binding(), original_binding);
    println!(
        "both cross-role clients held; copied or aliased trust failed; changing trust bytes changed the binding"
    );
}
