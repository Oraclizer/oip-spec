use super::*;
use crate::authority::recovery::{
    Attachment, HeadError, ordered::{ControlStore, ControlValue, OrderedHead},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, atomic::{AtomicU64, AtomicUsize, Ordering}, mpsc},
    thread,
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(15);
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct Bridge {
    dir: PathBuf,
    case: &'static str,
}

#[derive(Serialize)]
struct Exchange<'a> {
    operation: &'static str,
    case: &'static str,
    revision: Option<u64>,
    old: Option<&'a [u8]>,
    new: Option<&'a [u8]>,
}

#[derive(Deserialize)]
struct Response {
    revision: Option<u64>,
    bytes: Option<Vec<u8>>,
    changed: Option<bool>,
}

impl Bridge {
    fn exchange(&self, operation: &'static str, old: Option<&ControlValue>, new: Option<&[u8]>) -> Result<Response, HeadError> {
        let id = format!("{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let staged = self.dir.join(format!("{id}.tmp"));
        let request = self.dir.join(format!("{id}.request"));
        let response = self.dir.join(format!("{id}.response"));
        let data = Exchange {
            operation, case: self.case, revision: old.map(|old| old.revision),
            old: old.map(|old| old.bytes.as_slice()), new,
        };
        fs::write(&staged, serde_json::to_vec(&data).map_err(|_| HeadError)?).map_err(|_| HeadError)?;
        fs::rename(staged, request).map_err(|_| HeadError)?;
        let until = Instant::now() + WAIT;
        while Instant::now() < until {
            if let Ok(bytes) = fs::read(&response) {
                fs::remove_file(response).map_err(|_| HeadError)?;
                return serde_json::from_slice(&bytes).map_err(|_| HeadError);
            }
            thread::sleep(Duration::from_millis(5));
        }
        Err(HeadError)
    }
}

impl ControlStore for Bridge {
    type AttachmentProof = (RecoveryProfile, bool);

    fn verify_attachment(&self, profile: RecoveryProfile, connected: bool, proof: &Self::AttachmentProof) -> bool {
        (profile, connected) == *proof
    }

    fn current(&self) -> Result<ControlValue, HeadError> {
        let response = self.exchange("read", None, None)?;
        Ok(ControlValue { revision: response.revision.ok_or(HeadError)?, bytes: response.bytes.ok_or(HeadError)? })
    }

    fn replace(&self, expected: &ControlValue, candidate: &[u8]) -> Result<bool, HeadError> {
        self.exchange("replace", Some(expected), Some(candidate))?.changed.ok_or(HeadError)
    }
}

type Endpoint = PersistentAuthority<Rules, OrderedHead<Bridge>>;

fn open(path: &Path, bridge: Bridge, writer: u64, clock: Option<Arc<AtomicU64>>) -> Endpoint {
    let mut security = Rules::default();
    security.ordered_clock = clock;
    open_with_rules(path, bridge, writer, security)
}

fn open_with_rules(path: &Path, bridge: Bridge, writer: u64, security: Rules) -> Endpoint {
    let attachment = Attachment {
        profile: DEFAULT_PROFILE, proof: (DEFAULT_PROFILE, true), security, source_connected: true,
    };
    PersistentAuthority::open(
        OpenOptions::new().read(true).write(true).open(path).unwrap(),
        OrderedHead::new(bridge, DEFAULT_PROFILE, writer),
        attachment,
    ).unwrap()
}

fn exact<C: ControlStore>(store: &C) -> (AnchorHead, u64) {
    let value = store.current().unwrap();
    let state: serde_json::Value = serde_json::from_slice(&value.bytes).unwrap();
    (serde_json::from_value(state["head"].clone()).unwrap(), value.revision)
}

fn pending<C: ControlStore>(endpoint: &mut PersistentAuthority<Rules, OrderedHead<C>>) -> u64 {
    endpoint.transact(|product| product.reads.authority.state.primary.ledger.pending(binding().origin)).unwrap()
}

fn is_debited(reply: DebitResult) -> bool {
    matches!(reply, DebitResult::Published(Receipt::Ordinary(Collection::Collected(
        Outcome { reply: OutcomeReply::Accepted(Reply::Debited), commit: Some(CommitRef { position: 2 }) }
    ))))
}

#[derive(Clone)]
pub(in crate::authority::recovery) struct MemoryControl(Arc<std::sync::Mutex<ControlValue>>);

pub(in crate::authority::recovery) mod schedule_tests;

impl ControlStore for MemoryControl {
    type AttachmentProof = (RecoveryProfile, bool);

    fn verify_attachment(&self, profile: RecoveryProfile, connected: bool, proof: &Self::AttachmentProof) -> bool {
        (profile, connected) == *proof
    }

    fn current(&self) -> Result<ControlValue, HeadError> {
        self.0.lock().map(|value| value.clone()).map_err(|_| HeadError)
    }

    fn replace(&self, expected: &ControlValue, candidate: &[u8]) -> Result<bool, HeadError> {
        let mut value = self.0.lock().map_err(|_| HeadError)?;
        if *value != *expected {
            return Ok(false);
        }
        value.revision += 1;
        value.bytes = candidate.to_vec();
        Ok(true)
    }
}

type MemoryEndpoint = PersistentAuthority<Rules, OrderedHead<MemoryControl>>;

fn memory_endpoint(path: &JournalPath) -> MemoryEndpoint {
    memory_endpoint_with(path, |_| {})
}

/// A seeded endpoint whose test security the caller adjusts before opening.
fn memory_endpoint_with(path: &JournalPath, configure: impl FnOnce(&mut Rules)) -> MemoryEndpoint {
    let anchor = TestAnchor::new();
    seed_dispatch(&mut path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1));
    memory_endpoint_configured(path, anchor.head(), configure)
}

fn memory_endpoint_at(path: &JournalPath, head: AnchorHead) -> MemoryEndpoint {
    memory_endpoint_configured(path, head, |_| {})
}

impl MemoryControl {
    pub(in crate::authority::recovery) fn with_head(head: Option<AnchorHead>) -> Self {
        let bytes = OrderedHead::<Self>::initial_value(DEFAULT_PROFILE, head, 1).unwrap();
        Self(Arc::new(std::sync::Mutex::new(ControlValue { revision: 1, bytes })))
    }
}

fn memory_control(head: AnchorHead) -> MemoryControl {
    MemoryControl::with_head(Some(head))
}

fn memory_open(file: fs::File, control: MemoryControl, writer: u64, security: Rules) -> MemoryEndpoint {
    let attachment = Attachment {
        profile: DEFAULT_PROFILE, proof: (DEFAULT_PROFILE, true), security, source_connected: true,
    };
    PersistentAuthority::open(file, OrderedHead::new(control, DEFAULT_PROFILE, writer), attachment).unwrap()
}

fn clocked(clock: Arc<AtomicU64>) -> Rules {
    let mut security = Rules::default();
    security.ordered_clock = Some(clock);
    security
}

fn memory_endpoint_configured(
    path: &JournalPath, head: AnchorHead, configure: impl FnOnce(&mut Rules),
) -> MemoryEndpoint {
    let mut security = clocked(Arc::new(AtomicU64::new(105)));
    configure(&mut security);
    memory_open(path.file(), memory_control(head), 1, security)
}

fn revision(service: &mut MemoryEndpoint) -> usize {
    service.transact(|product| product.reads.current_cut().revision).unwrap()
}

#[test]
fn ordered_durable_non_effect_retains_its_receipt_and_allows_fresh_debit() {
    for outcome in [OutcomeReply::Busy, OutcomeReply::Rejected] {
        let path = JournalPath::create();
        let mut service = memory_endpoint(&path);
        let mut original = debit_core(if outcome == OutcomeReply::Busy { 1 } else { 2 });
        if outcome == OutcomeReply::Rejected {
            // The signed lock holder differs from the current caller, while
            // the work's origin and generation still match the valid Debit.
            operation(&mut original).words[15] = 8;
        }
        let original = signed(original);
        if outcome == OutcomeReply::Rejected {
            assert_eq!(
                service.resolve_wire_debit(&channel(0), &original, &wire_auth(), true),
                Err(WireError::ProductRejected),
            );
        }
        let original_reply = service.receive_wire(
            &channel(0), Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
        ).unwrap();
        assert_eq!(
            original_reply.reply,
            WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
                Collection::Collected(Outcome { reply: outcome, commit: None }),
            ))),
        );
        let exact_receipt = DebitResult::Published(Receipt::Ordinary(
            Collection::Collected(Outcome { reply: outcome, commit: None }),
        ));
        assert_eq!(
            service.resolve_wire_debit(&channel(0), &original, &wire_auth(), true),
            Ok(exact_receipt),
        );

        let mut replacement = debit_core(2);
        replacement.uuid.as_mut().unwrap()[0] ^= 1;
        operation(&mut replacement).words[1] += 1;
        let replacement = signed(replacement);
        service.receive_wire(
            &channel(0), Entry::Adapter, &replacement, &wire_auth(), DeliveryWindow::default(),
        ).unwrap();
        assert!(is_debited(service.resolve_wire_debit(
            &channel(0), &replacement, &wire_auth(), false,
        ).unwrap()));
        let original_core = decode_packet(&replacement, replacement.len()).unwrap();
        let mut changed_core = original_core.core().clone();
        changed_core.uuid.as_mut().unwrap()[1] ^= 1;
        let nested_receipt = signed(core_with(
            4, 8, 0, 112, vec![2], vec![encode_core(&changed_core).unwrap()],
        ));
        assert_eq!(
            service.receive_wire(&channel(0), Entry::Adapter, &nested_receipt, &wire_auth(), DeliveryWindow::default()),
            Err(WireError::ProductRejected),
        );
        assert_eq!(
            service.resolve_wire_debit(&channel(0), &original, &wire_auth(), false),
            Ok(exact_receipt),
        );
    }
}

#[test]
fn ordered_wait_uses_the_callers_monotonic_deadline() {
    let (send, reply) = mpsc::channel::<Result<Received, WireError>>();
    send.send(Err(WireError::InvalidSource)).unwrap();
    assert_eq!(
        wait_for_ordered_wire_reply(&reply, Instant::now()),
        Err(WireError::RequestUnresolved),
    );
    assert_eq!(
        wait_for_ordered_wire_reply(&reply, Instant::now() + WAIT),
        Err(WireError::InvalidSource),
    );
    drop(send);
    assert_eq!(
        wait_for_ordered_wire_reply(&reply, Instant::now() + WAIT),
        Err(WireError::RequestUnresolved),
    );
}

#[test]
#[ignore = "requires an isolated mTLS etcd cluster and an external exchange driver"]
fn ordered_signed_debit() {
    let dir = PathBuf::from(std::env::var_os("OIP_ORDERED_NATIVE_DIR").unwrap());
    let phase = std::env::var("OIP_ORDERED_NATIVE_PHASE").unwrap();
    let original = fs::read(dir.join("original-debit.bin")).unwrap();
    let parent: AnchorHead = serde_json::from_slice(&fs::read(dir.join("head-3.json")).unwrap()).unwrap();
    let channel = channel(0);
    let clock = Arc::new(AtomicU64::new(105));
    if phase == "restart" {
        let bridge = Bridge { dir: dir.clone(), case: "late" };
        clock.store(106, Ordering::SeqCst);
        let mut service = open(&dir.join("late.records"), bridge, 1, Some(clock));
        assert_eq!(pending(&mut service), 5);
        assert!(is_debited(service.resolve_wire_debit(&channel, &original, &wire_auth(), true).unwrap()));
        println!("restart: original receipt and five pending units restored from the published head");
        return;
    }

    let cases: &[&'static str] = if phase == "mutation" { &["revoke"] }
        else { &["late", "revoke", "cancel", "writer", "close", "external-only"] };
    for &case in cases {
        clock.store(105, Ordering::SeqCst);
        let bridge = Bridge { dir: dir.clone(), case };
        let path = dir.join(format!("{case}.records"));
        fs::copy(dir.join("through-head-3.records"), &path).unwrap();
        let initial = OrderedHead::<Bridge>::initial_value(DEFAULT_PROFILE, Some(parent), 1).unwrap();
        assert_eq!(bridge.exchange("create", None, Some(&initial)).unwrap().changed, Some(true));
        let mut service = open(&path, bridge.clone(), 1, Some(clock.clone()));
        assert_eq!(pending(&mut service), 0);
        if case == "external-only" {
            let mut mismatched = open(&path, bridge.clone(), 1, None);
            assert_eq!(
                mismatched.receive_wire(&channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default()),
                Err(WireError::InvalidSource),
            );
            assert_eq!(exact(&bridge).0, parent);
            assert_eq!(pending(&mut service), 0);
            println!("external-only: an adapter with no ordered revocation binding refused before effect");
            continue;
        }

        let (prepared, at_cas) = mpsc::channel();
        let (resume, continue_commit) = mpsc::channel();
        let worker_bridge = bridge.clone();
        let worker_path = path.clone();
        let worker_packet = original.clone();
        let worker_channel = channel.clone();
        let worker_clock = clock.clone();
        let start = Instant::now();
        let (reply_tx, reply_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut security = Rules::default();
            security.ordered_clock = Some(worker_clock);
            let calls = AtomicU64::new(0);
            let continue_commit = std::sync::Mutex::new(continue_commit);
            security.ordered_boundary_hook = Some(Arc::new(move || {
                // Two checks run during admission. The next check is after
                // the prepared bytes are synchronized and before any CAS.
                if calls.fetch_add(1, Ordering::SeqCst) == 2 {
                    prepared.send(()).unwrap();
                    continue_commit.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
            }));
            let mut worker = open_with_rules(&worker_path, worker_bridge, 1, security);
            let delivery = DeliveryWindow { deadline: Some(104), ..Default::default() };
            let reply = worker.receive_wire(&worker_channel, Entry::Adapter, &worker_packet, &wire_auth(), delivery);
            reply_tx.send(reply).unwrap();
        });
        at_cas.recv_timeout(WAIT).unwrap();
        assert!(fs::metadata(&path).unwrap().len() > parent.offset + parent.length);
        assert_eq!(exact(&bridge).0, parent);
        assert_eq!(
            service.resolve_wire_debit(&channel, &original, &wire_auth(), false),
            Ok(DebitResult::Unresolved),
        );
        let control = OrderedHead::new(bridge.clone(), DEFAULT_PROFILE, 1);
        let transport = TransportKey::for_core(decode_packet(&original, original.len()).unwrap().core()).unwrap();
        let mut replacement = decode_packet(&original, original.len()).unwrap().core().clone();
        replacement.uuid.as_mut().unwrap()[0] ^= 1;
        operation(&mut replacement).words[1] += 1;
        let replacement = signed(replacement);
        match case {
            "late" => {
                assert_eq!(
                    wait_for_ordered_wire_reply(&reply_rx, Instant::now() + Duration::from_millis(20)),
                    Err(WireError::RequestUnresolved),
                );
                clock.store(106, Ordering::SeqCst);
            }
            "revoke" => assert!(control.revoke(FORMER.principal).unwrap()),
            "cancel" => assert!(control.cancel(transport).unwrap()),
            "writer" => assert!(control.rotate_writer(2).unwrap()),
            "close" => {
                let alternative_path = dir.join("close-competing.records");
                fs::copy(dir.join("through-head-3.records"), &alternative_path).unwrap();
                let mut competing = open(&alternative_path, bridge.clone(), 1, Some(clock.clone()));
                let mut same_uuid = core_with(4, 1, 0, 112, vec![2, 0, 2, 0, 17], vec![]);
                same_uuid.uuid = decode_packet(&original, original.len()).unwrap().core().uuid.clone();
                assert_eq!(
                    competing.receive_wire(&channel, Entry::Adapter, &signed(same_uuid), &wire_auth(), DeliveryWindow::default()),
                    Err(WireError::ReplayConflict),
                );
                assert_eq!(
                    competing.receive_wire(&channel, Entry::Adapter, &replacement, &wire_auth(), DeliveryWindow::default()),
                    Err(WireError::RequestUnresolved),
                );
                let mut changed = decode_packet(&original, original.len()).unwrap().core().clone();
                changed.uuid.as_mut().unwrap()[0] ^= 2;
                assert_eq!(
                    service.resolve_wire_debit(&channel, &signed(changed), &wire_auth(), true),
                    Err(WireError::ReplayConflict),
                );
                assert_eq!(
                    service.resolve_wire_debit(&channel, &original,
                        &WireCredentials { token: &super::super::super::vector_tests::SUCCESSOR, ..wire_auth() }, true),
                    Err(WireError::ProductRejected),
                );
                assert_eq!(service.resolve_wire_debit(&channel, &original, &wire_auth(), true), Ok(DebitResult::Rejected));
            }
            _ => unreachable!(),
        }
        resume.send(()).unwrap();
        let result = reply_rx.recv_timeout(WAIT).unwrap();
        worker.join().unwrap();
        if case == "late" {
            assert!(matches!(
                result.unwrap().reply,
                WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
                    Collection::Collected(Outcome { reply: OutcomeReply::Accepted(Reply::Debited), .. }),
                ))),
            ));
            assert_eq!(pending(&mut service), 5);
            let expected: AnchorHead = serde_json::from_slice(&fs::read(dir.join("produced-head-4.json")).unwrap()).unwrap();
            assert_eq!(exact(&bridge).0, expected);
            assert_eq!(
                service.receive_wire(&channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default()),
                Err(WireError::TtlExpired),
            );
            let readback = service.resolve_wire_debit(&channel, &original, &wire_auth(), false).unwrap();
            assert!(is_debited(readback));
            assert_eq!(service.resolve_wire_debit(&channel, &original, &wire_auth(), true), Ok(readback));
            let mut replacement = decode_packet(&replacement, replacement.len()).unwrap().core().clone();
            replacement.issued_seconds = Some(106);
            assert_eq!(
                service.receive_wire(&channel, Entry::Adapter, &signed(replacement), &wire_auth(), DeliveryWindow::default()),
                Err(WireError::RequestUnresolved),
            );
            println!("late: timeout then late durable Debit, expired admission refused, exact original recovered");
        } else {
            assert_eq!(result, Err(hold()), "{case}: a prior authority event must defeat publication");
            assert_eq!(exact(&bridge).0, parent);
            if case == "writer" {
                service = open(&path, bridge.clone(), 2, Some(clock.clone()));
            }
            assert_eq!(pending(&mut service), 0);
            if case == "revoke" {
                assert_eq!(service.resolve_wire_debit(&channel, &original, &wire_auth(), true), Err(WireError::InvalidSource));
            } else if case == "close" {
                assert_eq!(service.resolve_wire_debit(&channel, &original, &wire_auth(), false), Ok(DebitResult::Rejected));
                let accepted = service.receive_wire(&channel, Entry::Adapter, &replacement, &wire_auth(), DeliveryWindow::default()).unwrap();
                let retry = service.receive_wire(&channel, Entry::Adapter, &replacement, &wire_auth(), DeliveryWindow::default()).unwrap();
                assert_eq!(retry.arrival, Arrival::Identical);
                assert_eq!(retry.reply, accepted.reply);
                assert_eq!(pending(&mut service), 5);
                assert_eq!(exact(&bridge).0.sequence, parent.sequence + 1);
            }
            println!("{case}: prior decision rejected the original publication with no effect");
        }
        println!("{case}: elapsed_ms={}", start.elapsed().as_millis());
    }
}

/// The ordered cases of `ordered_signed_debit` against an in-memory
/// compare-and-set store, so that every default run executes them. Two
/// authorities share one journal and one control value. The worker stops
/// after its prepared bytes are synchronized and before its compare-and-set,
/// and the other side changes the control value in between.
#[test]
fn concurrent_authorities_serialize_on_the_exact_control_head() {
    for case in ["commit", "revoke", "cancel", "writer"] {
        let path = JournalPath::create();
        let anchor = TestAnchor::new();
        seed_dispatch(&mut path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1));
        let parent = anchor.head();
        let control = memory_control(parent);
        let clock = Arc::new(AtomicU64::new(105));
        let original = signed(debit_core(2));
        let mut service = memory_open(path.file(), control.clone(), 1, clocked(clock.clone()));
        assert_eq!(pending(&mut service), 0);

        let (prepared, at_cas) = mpsc::channel();
        let (resume, continue_commit) = mpsc::channel::<()>();
        let (reply_tx, reply_rx) = mpsc::channel();
        let worker_file = path.file();
        let worker_control = control.clone();
        let worker_packet = original.clone();
        let worker_clock = clock.clone();
        let worker = thread::spawn(move || {
            let mut security = clocked(worker_clock);
            let calls = AtomicU64::new(0);
            let continue_commit = std::sync::Mutex::new(continue_commit);
            security.ordered_boundary_hook = Some(Arc::new(move || {
                // As in the external test, the third check is after the
                // prepared bytes are synchronized and before any CAS.
                if calls.fetch_add(1, Ordering::SeqCst) == 2 {
                    prepared.send(()).unwrap();
                    continue_commit.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
            }));
            let mut worker = memory_open(worker_file, worker_control, 1, security);
            let reply = worker.receive_wire(
                &channel(0), Entry::Adapter, &worker_packet, &wire_auth(), DeliveryWindow::default(),
            );
            reply_tx.send(reply).unwrap();
        });
        at_cas.recv_timeout(WAIT).unwrap();
        assert_eq!(exact(&control).0, parent, "{case}");
        assert_eq!(
            service.resolve_wire_debit(&channel(0), &original, &wire_auth(), false),
            Ok(DebitResult::Unresolved),
            "{case}",
        );
        let head = OrderedHead::new(control.clone(), DEFAULT_PROFILE, 1);
        let transport = TransportKey::for_core(decode_packet(&original, original.len()).unwrap().core()).unwrap();
        match case {
            "commit" => (),
            "revoke" => assert!(head.revoke(FORMER.principal).unwrap()),
            "cancel" => assert!(head.cancel(transport).unwrap()),
            "writer" => assert!(head.rotate_writer(2).unwrap()),
            _ => unreachable!(),
        }
        resume.send(()).unwrap();
        let result = reply_rx.recv_timeout(WAIT).unwrap();
        worker.join().unwrap();
        if case == "commit" {
            assert!(matches!(
                result.unwrap().reply,
                WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
                    Collection::Collected(Outcome { reply: OutcomeReply::Accepted(Reply::Debited), .. }),
                ))),
            ));
            assert_eq!(exact(&control).0.sequence, parent.sequence + 1);
            assert_eq!(pending(&mut service), 5);
            assert!(is_debited(service.resolve_wire_debit(&channel(0), &original, &wire_auth(), false).unwrap()));
        } else {
            assert_eq!(result, Err(hold()), "{case}: a prior authority event must defeat publication");
            assert_eq!(exact(&control).0, parent, "{case}");
            if case == "writer" {
                service = memory_open(path.file(), control.clone(), 2, clocked(clock.clone()));
            }
            assert_eq!(pending(&mut service), 0, "{case}");
        }
    }
}

impl response::ResponseSigner for Rules {
    fn parameters(&self, _: &Channel, _: [u8; 32]) -> Option<response::ResponseParameters> {
        let mut uuid = UUID;
        uuid[0] = 212;
        Some(response::ResponseParameters {
            principal: 42,
            key_id: 9,
            authority_epoch: 9,
            issued_seconds: self.ordered_clock.as_ref()?.load(Ordering::SeqCst),
            ttl_seconds: 20,
            uuid,
            route_scope: 1,
        })
    }

    fn sign(&self, preimage: &[u8]) -> Option<[u8; 64]> {
        Some(local_key().sign(preimage).to_bytes())
    }
}

fn response_channel(target: u64, source: u64) -> Channel {
    let local = offer(target, source, &[6]);
    let remote = offer(source, target, &[6]);
    let context = Negotiation {
        deployment: 7,
        local: target,
        remote: source,
        challenge: 3,
        now: 105,
        floor: 6,
        legacy_allowed: false,
        local_key: remote_key().verifying_key().to_bytes(),
        remote_key: local_key().verifying_key().to_bytes(),
    };
    negotiate(&context, SignedOffers {
        local: &local,
        remote: &remote,
        local_signature: &remote_key().sign(&offer_bytes(&local)).to_bytes(),
        remote_signature: &local_key().sign(&offer_bytes(&remote)).to_bytes(),
        confirmation: &local_key().sign(&confirmation_bytes(&local, &remote, &profile())).to_bytes(),
    }).unwrap()
}

fn response_boundary(channel: &Channel) -> Boundary {
    Boundary {
        source: channel.remote(),
        target: channel.local(),
        principal: 42,
        public_key: local_key().verifying_key().to_bytes(),
        ..boundary()
    }
}

fn assert_response(
    original: &[u8],
    outbound: &[u8],
    kind: u64,
    expected: response::ResponseCode,
    position: Option<usize>,
) {
    let expected_packet = decode_packet(original, original.len()).unwrap();
    let original_core = expected_packet.core();
    let reply_channel = response_channel(original_core.source_domain.unwrap(), original_core.target_domain.unwrap());
    let verified = response::admit_response(
        &reply_channel, &response_boundary(&reply_channel), &expected_packet, outbound,
    ).unwrap();
    assert_eq!(verified.id.namespace, original_core.principal.unwrap());
    assert_eq!(verified.code, response::ResponseStatus::Known(expected));
    assert_eq!(verified.commit.map(|commit| commit.position), position);

    let packet = decode_packet(outbound, outbound.len()).unwrap();
    let Body::Ack(operation) = packet.core().body.as_ref().unwrap() else { panic!("ACK Response"); };
    assert_eq!(packet.core().source_domain, original_core.target_domain);
    assert_eq!(packet.core().target_domain, original_core.source_domain);
    assert_eq!(operation.opcode, Some(2));
    assert_eq!(operation.words[2..5], [kind, expected as u64, u64::from(position.is_some())]);
    assert_eq!(operation.words.len(), if position.is_some() { 6 } else { 5 });
    assert_eq!(operation.blobs, [expected_packet.core_bytes()]);
    assert_eq!(operation.appeal_deadline, None);
    assert_eq!(packet.encode().unwrap(), outbound);
}

#[test]
fn reference_response_retains_busy_rejected_and_unavailable() {
    use response::ResponseCode;
    for code in [ResponseCode::Busy, ResponseCode::Rejected, ResponseCode::Unavailable] {
        let path = JournalPath::create();
        let mut service = memory_endpoint(&path);
        if code == ResponseCode::Unavailable {
            service.reconnect((DEFAULT_PROFILE, false), false).unwrap();
        }
        let channel = channel(0);
        let mut core = debit_core(if code == ResponseCode::Busy { 1 } else { 2 });
        if code == ResponseCode::Rejected {
            operation(&mut core).words[15] = 8;
        }
        let original = signed(core);
        let before = service.anchor.current().unwrap().unwrap();
        let frame = service.receive_wire_response(
            &channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
        ).unwrap();
        assert_response(&original, &frame, 1, code, None);
        let after = service.anchor.current().unwrap().unwrap();
        assert_eq!(after.sequence, before.sequence + 1);
        assert_eq!(service.transact(|p| p.reads.current_cut().revision).unwrap(), 2);
        let resolved = service.resolve_wire_debit_response(&channel, &original, &wire_auth(), false).unwrap();
        assert_eq!(resolved, frame);
        assert_eq!(service.anchor.current().unwrap(), Some(after));
    }
}

#[test]
fn reference_response_distinguishes_delivery_and_authentication() {
    use response::ResponseCode;
    let path = JournalPath::create();
    let mut service = memory_endpoint(&path);
    let channel = channel(0);
    let original = signed(debit_core(2));
    let before = service.anchor.current().unwrap().unwrap();

    let unresolved = service.resolve_wire_debit_response(&channel, &original, &wire_auth(), false).unwrap();
    assert_response(&original, &unresolved, 2, ResponseCode::Unresolved, None);
    // A frame whose own signature does not verify receives no signed answer.
    let mut bad_signature = original.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    assert_eq!(service.receive_wire_response(
        &channel, Entry::Adapter, &bad_signature, &wire_auth(), DeliveryWindow::default(),
    ), Err(WireError::InvalidSignature));
    assert_eq!(
        service.resolve_wire_debit_response(&channel, &bad_signature, &wire_auth(), false),
        Err(WireError::InvalidSignature),
    );
    assert_eq!(service.receive_wire_response(
        &channel, Entry::Adapter, &[0], &wire_auth(), DeliveryWindow::default(),
    ), Err(WireError::InvalidFormat));
    assert_eq!(service.anchor.current().unwrap(), Some(before));

    let lost = service.receive_wire_response(
        &channel, Entry::Adapter, &original, &wire_auth(),
        DeliveryWindow { response_lost: true, ..DeliveryWindow::default() },
    ).unwrap();
    assert_response(&original, &lost, 2, ResponseCode::ResponseLost, None);
    let after = service.anchor.current().unwrap().unwrap();
    assert_eq!(after.sequence, before.sequence + 1);

    let other = &super::super::super::vector_tests::SUCCESSOR;
    let refusal = service.resolve_wire_debit_response(
        &channel, &original, &WireCredentials { token: other, ..wire_auth() }, false,
    ).unwrap();
    assert_response(&original, &refusal, 3, ResponseCode::ProductRejected, None);
    let receipt = service.resolve_wire_debit_response(&channel, &original, &wire_auth(), false).unwrap();
    assert_response(&original, &receipt, 1, ResponseCode::Debited, Some(2));
    assert_eq!(service.anchor.current().unwrap(), Some(after));
}

fn sign_response_core(core: Core) -> Vec<u8> {
    let signature = local_key().sign(&signing_bytes(&encode_core(&core).unwrap()).unwrap());
    encode_packet(&Packet { core: Some(core), signature: Some(signature.to_bytes().to_vec()) }).unwrap()
}

#[test]
fn reference_response_rejects_a_changed_binding() {
    use response::ResponseCode;
    let path = JournalPath::create();
    let mut service = memory_endpoint(&path);
    let original = signed(debit_core(2));
    let outbound = service.receive_wire_response(
        &channel(0), Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
    ).unwrap();
    assert_response(&original, &outbound, 1, ResponseCode::Debited, Some(2));

    let original = decode_packet(&original, original.len()).unwrap();
    let core = decode_packet(&outbound, outbound.len()).unwrap().core().clone();
    let channel = response_channel(0, 0);
    let check = |modified| response::admit_response(
        &channel, &response_boundary(&channel), &original, &sign_response_core(modified),
    );
    for (index, value, error) in [
        (0, 8, WireError::InvalidSource),
        (1, 34, WireError::InvalidFormat),
        (2, 2, WireError::InvalidFormat),
        (2, 4, WireError::InvalidFormat),
        (3, ResponseCode::Reserved as u64, WireError::InvalidFormat),
        (3, ResponseCode::Unresolved as u64, WireError::InvalidFormat),
        (5, 3, WireError::InvalidFormat),
    ] {
        let mut modified = core.clone();
        operation(&mut modified).words[index] = value;
        assert_eq!(check(modified), Err(error));
    }

    // A code this version does not define is accepted as its category only.
    let mut unknown = core.clone();
    operation(&mut unknown).words[3] = 999;
    let verified = check(unknown).unwrap();
    assert_eq!(
        verified.code,
        response::ResponseStatus::Unknown { kind: response::ResponseKind::Recorded, code: 999 },
    );
    assert_eq!(verified.code.known(), None);
    assert_eq!(verified.commit.map(|commit| commit.position), Some(2));
    for (kind, code, category) in [
        (2, 57, response::ResponseKind::Delivery),
        (3, 78, response::ResponseKind::Refusal),
    ] {
        let mut unknown = core.clone();
        let words = &mut operation(&mut unknown).words;
        words.truncate(5);
        words[2] = kind;
        words[3] = code;
        words[4] = 0;
        assert_eq!(
            check(unknown).unwrap().code,
            response::ResponseStatus::Unknown { kind: category, code },
        );
    }
    let mut unknown_with_commit = core.clone();
    operation(&mut unknown_with_commit).words[2] = 2;
    operation(&mut unknown_with_commit).words[3] = 57;
    assert_eq!(check(unknown_with_commit), Err(WireError::InvalidFormat));
    let mut unknown_debit_position = core.clone();
    operation(&mut unknown_debit_position).words[3] = 999;
    operation(&mut unknown_debit_position).words[5] = 3;
    assert_eq!(check(unknown_debit_position), Err(WireError::InvalidFormat));

    let mut changed_presence = core.clone();
    operation(&mut changed_presence).words[4] = 0;
    operation(&mut changed_presence).words.pop();
    assert_eq!(check(changed_presence), Err(WireError::InvalidFormat));

    let mut changed_original = original.core().clone();
    changed_original.uuid.as_mut().unwrap()[0] ^= 1;
    let mut modified = core.clone();
    operation(&mut modified).blobs[0] = encode_core(&changed_original).unwrap();
    assert_eq!(check(modified), Err(WireError::ReplayConflict), "the exact submitted Core must survive correlation");

    let mut bad_signature = outbound;
    *bad_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        response::admit_response(&channel, &response_boundary(&channel), &original, &bad_signature),
        Err(WireError::InvalidSignature),
    );
}

#[test]
#[ignore = "requires an external native Debit archive"]
fn reference_response_archived_debit() {
    use response::ResponseCode;
    use std::io::Write;
    let archive = PathBuf::from(std::env::var_os("OIP_ORDERED_NATIVE_DIR").unwrap());
    let original = fs::read(archive.join("original-debit.bin")).unwrap();
    assert_eq!(original.len(), 425);
    assert_eq!(format!("{:x}", Sha256::digest(&original)),
        "98ad90e7a9f2b5fc3f9fb47af5de03d4f288b743d1ecf38be6455ed0e21d0d09");
    let before = serde_json::from_slice(&fs::read(archive.join("head-3.json")).unwrap()).unwrap();
    let after = serde_json::from_slice(&fs::read(archive.join("produced-head-4.json")).unwrap()).unwrap();
    let path = JournalPath::create();
    let mut file = path.file();
    file.write_all(&fs::read(archive.join("through-head-3.records")).unwrap()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut service = memory_endpoint_at(&path, before);
    let channel = channel(0);
    let first = service.receive_wire_response(
        &channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
    ).unwrap();
    assert_response(&original, &first, 1, ResponseCode::Debited, Some(2));
    assert_eq!(service.anchor.current().unwrap(), Some(after));
    let len = path.file().metadata().unwrap().len();
    let retry = service.receive_wire_response(
        &channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
    ).unwrap();
    let resolved = service.resolve_wire_debit_response(&channel, &original, &wire_auth(), false).unwrap();
    assert_eq!(retry, first);
    assert_eq!(resolved, first);
    assert_eq!(service.anchor.current().unwrap(), Some(after));
    assert_eq!(path.file().metadata().unwrap().len(), len);
    println!("original_bytes=425 response_bytes={} response_sha256={:x} commit_position=2", first.len(), Sha256::digest(&first));
}

/// The six reference operations that the reference configuration does not
/// execute. Every other operation of version 6 is accepted.
const REFERENCE_REFUSED: [(u64, u64); 6] = [(3, 7), (3, 8), (5, 2), (6, 1), (6, 2), (7, 2)];

/// A refused frame leaves the anchor head and the committed revision as they were.
fn unchanged(service: &mut MemoryEndpoint, before: Option<AnchorHead>) {
    assert_eq!(service.anchor.current().unwrap(), before);
    assert_eq!(revision(service), 2);
}

#[test]
fn a_frame_whose_signature_fails_receives_no_signed_response() {
    use response::ResponseCode;
    let path = JournalPath::create();
    let mut service = memory_endpoint(&path);
    let channel = channel(0);
    let original = signed(debit_core(2));
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let before = service.anchor.current().unwrap();
    // The credential that the frame names and one that it does not name get
    // the same unsigned error, so the answer reveals no registration.
    for token in [&FORMER, &super::super::super::vector_tests::SUCCESSOR] {
        let credentials = WireCredentials { token, ..wire_auth() };
        assert_eq!(
            service.receive_wire_response(
                &channel, Entry::Adapter, &tampered, &credentials, DeliveryWindow::default(),
            ),
            Err(WireError::InvalidSignature),
        );
        assert_eq!(
            service.resolve_wire_debit_response(&channel, &tampered, &credentials, false),
            Err(WireError::InvalidSignature),
        );
        unchanged(&mut service, before);
    }
    let first = service.receive_wire_response(
        &channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
    ).unwrap();
    assert_response(&original, &first, 1, ResponseCode::Debited, Some(2));
    assert_eq!(revision(&mut service), 3);
    assert_eq!(service.anchor.current().unwrap().unwrap().sequence, before.unwrap().sequence + 1);
}

#[test]
fn a_call_whose_response_cannot_fit_the_frame_limit_is_refused_before_its_effect() {
    use response::ResponseCode;
    let channel = channel(0);
    let original = signed(debit_core(2));
    let measured = {
        let path = JournalPath::create();
        let mut service = memory_endpoint(&path);
        service.receive_wire_response(
            &channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
        ).unwrap().len()
    };
    assert!(measured > original.len());
    let path = JournalPath::create();
    let limit = Arc::new(AtomicUsize::new(original.len()));
    let shared = limit.clone();
    let mut service = memory_endpoint_with(&path, move |rules| rules.frame_limit = Some(shared));
    let before = service.anchor.current().unwrap();
    for size in [original.len(), measured - 1] {
        limit.store(size, Ordering::SeqCst);
        assert_eq!(
            service.receive_wire_response(
                &channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
            ),
            Err(WireError::InvalidFormat),
        );
        assert_eq!(
            service.resolve_wire_debit_response(&channel, &original, &wire_auth(), false),
            Err(WireError::InvalidFormat),
        );
        unchanged(&mut service, before);
    }
    limit.store(measured, Ordering::SeqCst);
    let unresolved = service.resolve_wire_debit_response(&channel, &original, &wire_auth(), false).unwrap();
    assert_response(&original, &unresolved, 2, ResponseCode::Unresolved, None);
    unchanged(&mut service, before);
    let frame = service.receive_wire_response(
        &channel, Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
    ).unwrap();
    assert_eq!(frame.len(), measured);
    assert_response(&original, &frame, 1, ResponseCode::Debited, Some(2));
    assert_eq!(revision(&mut service), 3);
}

#[test]
fn every_wire_entry_refuses_another_declared_version_before_decoding() {
    let path = JournalPath::create();
    let mut service = memory_endpoint(&path);
    let channel = channel(0);
    let core = encode_core(&debit_core(2)).unwrap();
    assert_eq!(raw_frame(&core), signed(debit_core(2)));
    let declared = |version: u8, extension: &[u8]| {
        let mut bytes = core.clone();
        assert_eq!(bytes[..2], [0x08, 6]);
        bytes[1] = version;
        bytes.extend_from_slice(extension);
        raw_frame(&bytes)
    };
    // Core field 26 is not defined by version 6.
    let field_26 = [0xd0, 0x01, 0x01];
    let before = service.anchor.current().unwrap();
    for (frame, expected) in [
        (declared(5, &[]), WireError::UnsupportedVersion),
        (declared(7, &[]), WireError::UnsupportedVersion),
        (declared(7, &field_26), WireError::UnsupportedVersion),
        (declared(6, &field_26), WireError::InvalidFormat),
    ] {
        assert_eq!(
            service.receive_wire(
                &channel, Entry::Adapter, &frame, &wire_auth(), DeliveryWindow::default(),
            ).err(),
            Some(expected),
        );
        assert_eq!(
            service.receive_wire_response(
                &channel, Entry::Adapter, &frame, &wire_auth(), DeliveryWindow::default(),
            ),
            Err(expected),
        );
        assert_eq!(service.resolve_wire_debit(&channel, &frame, &wire_auth(), false), Err(expected));
        assert_eq!(
            service.resolve_wire_debit_response(&channel, &frame, &wire_auth(), false),
            Err(expected),
        );
        unchanged(&mut service, before);
    }
}

#[test]
fn operations_outside_the_selected_profile_are_refused_without_a_signed_response() {
    let path = JournalPath::create();
    let mut service = memory_endpoint_with(&path, |rules| {
        rules.refused_operations = REFERENCE_REFUSED.into_iter().collect();
    });
    let channel = channel(0);
    let before = service.anchor.current().unwrap();
    for (family, opcode) in REFERENCE_REFUSED {
        let frame = signed(core_with(family, opcode, 0, 30, vec![1, 2], Vec::new()));
        let mut tampered = frame.clone();
        *tampered.last_mut().unwrap() ^= 1;
        // The refusal precedes the signature and source checks.
        for bytes in [&frame, &tampered] {
            assert_eq!(
                service.receive_wire(
                    &channel, Entry::Adapter, bytes, &wire_auth(), DeliveryWindow::default(),
                ).err(),
                Some(WireError::UnsupportedVersion),
                "{family}/{opcode}",
            );
            assert_eq!(
                service.receive_wire_response(
                    &channel, Entry::Adapter, bytes, &wire_auth(), DeliveryWindow::default(),
                ),
                Err(WireError::UnsupportedVersion),
                "{family}/{opcode}",
            );
            assert_eq!(
                service.resolve_wire_debit(&channel, bytes, &wire_auth(), false),
                Err(WireError::UnsupportedVersion),
                "{family}/{opcode}",
            );
            assert_eq!(
                service.resolve_wire_debit_response(&channel, bytes, &wire_auth(), false),
                Err(WireError::UnsupportedVersion),
                "{family}/{opcode}",
            );
            unchanged(&mut service, before);
        }
    }
    // An accepted operation still reaches its effect.
    let debit = signed(debit_core(2));
    service.receive_wire(&channel, Entry::Adapter, &debit, &wire_auth(), DeliveryWindow::default()).unwrap();
    assert!(is_debited(service.resolve_wire_debit(&channel, &debit, &wire_auth(), false).unwrap()));
}

#[test]
fn a_configured_delivery_ttl_limit_refuses_a_longer_signed_ttl() {
    let original = signed(debit_core(2));
    for (limit, expected) in [(Some(4), Some(WireError::TtlInvalid)), (Some(5), None), (None, None)] {
        let path = JournalPath::create();
        let mut service = memory_endpoint_with(&path, |rules| rules.max_delivery_ttl = limit);
        let result = service.receive_wire(
            &channel(0), Entry::Adapter, &original, &wire_auth(), DeliveryWindow::default(),
        );
        assert_eq!(result.err(), expected, "{limit:?}");
        assert_eq!(revision(&mut service), if expected.is_some() { 2 } else { 3 });
    }
}
