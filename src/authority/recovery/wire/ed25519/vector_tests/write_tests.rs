use super::reference_execution_trace::channel_for;
use super::*;
use crate::authority::identity::{ActionReply, Entry, Observation, ProductAuthority, Receipt};
use crate::authority::reads::{CheckedExecution, ReadHistory, Value};
use crate::authority::recovery::ordered::OrderedHead;
use crate::authority::recovery::vector_tests::{JournalPath, TestAnchor, attachment, genesis};
use crate::authority::recovery::wire::response::{ResponseCode, ResponseStatus, admit_response};
use crate::authority::recovery::wire::vector_tests::{
    core_with, ordered_tests::MemoryControl, raw_frame, wire_auth,
};
use crate::authority::recovery::wire::{DeliveryWindow, Received, WireCredentials, WireReply};
use crate::authority::recovery::{
    AnchorHead, Attachment, AuthenticatedHead, CommitRecord, PersistentAuthority, RetainedImage,
    commit_guarded, exact_image, validate_retained_transition,
};
use crate::authority::{Collection, Outcome, OutcomeReply};
use crate::lock_finality::{Binding, Credential, Phase, Reply};
use crate::wire::admission::{Arrival, TransportKey};
use crate::wire::generated::Operation as WireOperation;
use crate::wire::legacy::unhex;
use crate::{AuthenticatedCaller, CallId, OriginKey};
use std::fs::File;
use std::sync::Arc;

const CORE_VECTOR: &str = include_str!("../../../../../../tests/vectors/write-core-vectors.tsv");
const OBSERVATIONS: &str =
    include_str!("../../../../../../tests/vectors/write-execution-observations.tsv");
const CUT: CommitCut = CommitCut {
    authority_epoch: 9,
    revision: 0,
};
const ORIGIN: OriginKey = OriginKey {
    domain: 0,
    event: 17,
};
const ID: CallId = CallId {
    namespace: 7,
    sequence: 1,
};
const BINDING: Binding = Binding {
    origin: ORIGIN,
    asset: 17,
    owner: 3,
    destination: 2,
    recipient: 3,
    amount: 5,
};

struct Fixture {
    exact: Vec<u8>,
    core: Core,
    packet: Vec<u8>,
    payload: CallPayload,
}

fn fixture() -> Fixture {
    let fields: Vec<_> = CORE_VECTOR.trim_end().split('\t').collect();
    let ["I", "write-core", hex] = fields.as_slice() else {
        panic!("unexpected Write Core vector");
    };
    let exact = unhex(hex).unwrap();
    assert_eq!(exact.len(), 363);
    let packet = raw_frame(&exact);
    let canonical = decode_packet(&packet, packet.len()).unwrap();
    assert_eq!(canonical.core_bytes(), exact);
    let core = canonical.core().clone();
    assert_eq!(encode_core(&core).unwrap(), exact);
    let Operands::Ordinary {
        id,
        payload,
        proofs,
    } = decode(&core, 4).unwrap()
    else {
        panic!("expected typed Write");
    };
    assert_eq!(id, ID);
    assert_eq!(
        payload,
        CallPayload {
            message_id: 1,
            origin_epoch: 9,
            endpoint: 0,
            caller: 7,
            session: 1,
            cut: CUT,
            binding: BINDING,
            credential: Some(Credential {
                asset: 17,
                origin: ORIGIN,
                holder: 7,
                generation: 0,
                epoch: 9
            }),
            versions: vec![(17, 0)],
            command: Command::Write {
                generation: 0,
                value: 9
            },
        }
    );
    assert!(proofs.is_empty());
    println!(
        "write-input\t{:x}\t{:x}",
        Sha256::digest(&exact),
        Sha256::digest(&packet)
    );
    Fixture {
        exact,
        core,
        packet,
        payload,
    }
}

type Ed25519 = Ed25519Security<FixedClock>;
type Service = PersistentAuthority<Ed25519, OrderedHead<MemoryControl>>;

fn anchor(control: &MemoryControl) -> OrderedHead<MemoryControl> {
    OrderedHead::new(control.clone(), DEFAULT_PROFILE, 1)
}

fn reference_attachment(
    execute: bool,
    receipts: bool,
) -> Attachment<Ed25519, (RecoveryProfile, bool)> {
    let mut profile = config();
    let sessions = &mut profile.peers.get_mut(&7).unwrap().sessions;
    let grant = sessions.get_mut(&1).unwrap().get_mut(&0).unwrap();
    grant.execute = execute.then_some(17).into_iter().collect();
    grant.receipts = receipts.then_some(17).into_iter().collect();
    grant.raw = vec![Query::ApplicationValue(17)];
    Attachment {
        profile: DEFAULT_PROFILE,
        source_connected: true,
        proof: (DEFAULT_PROFILE, true),
        security: Ed25519Security::new(profile, key(6), FixedClock(105)).unwrap(),
    }
}

fn start<S: WireSecurity, H: AuthenticatedHead>(
    mut file: File,
    anchor: H,
    mut attachment: Attachment<S, H::AttachmentProof>,
    fixture: &Fixture,
    value_permission: bool,
    expired: bool,
) -> PersistentAuthority<S, H> {
    let mut initial = genesis(5, 1);
    initial.owners.insert(17, 3);
    initial.identities.push(Identity {
        principal: 3,
        ocid: 103,
        rai: 203,
        ..FORMER
    });
    initial.balances = BTreeMap::from([(BINDING.source(), 5)]);
    initial.regulation = None;
    if !value_permission {
        assert!(
            initial
                .contexts
                .iter_mut()
                .find(|context| context.endpoint == 0)
                .unwrap()
                .write_permissions
                .remove(&(7, 17, 9))
        );
    }
    let mut product = ProductAuthority::bootstrap(initial, attachment.security).unwrap();
    let state = &mut product.reads.authority.state;
    let ledger = &mut state.primary.ledger;
    let reserve = CallPayload {
        credential: None,
        command: Command::Reserve { duration: 20 },
        ..fixture.payload.clone()
    };
    assert_eq!(
        ledger.submit_normal(AuthenticatedCaller(7), reserve.request(), |_, _, _| true),
        Reply::Reserved,
    );
    if expired {
        assert!(ledger.observe_clock(20));
    }
    // The exported fixture starts with a held lock at cut zero. Rebase the
    // setup reservation into that opening image before selecting the record.
    let mut ledger_json = serde_json::to_value(&ledger).unwrap();
    ledger_json["state"]["cut"] = serde_json::to_value(CUT).unwrap();
    *ledger = serde_json::from_value(ledger_json).unwrap();
    assert_eq!(ledger.lock_owner(17), Some(ORIGIN));
    assert_eq!(ledger.phase(ORIGIN), Some(Phase::Held));
    assert_eq!(ledger.generation(ORIGIN), Some(0));
    assert_eq!(ledger.asset_data(17), Some((0, 0)));
    state.read_history = ReadHistory::new(&state.primary);
    let record = CommitRecord {
        profile: DEFAULT_PROFILE,
        sequence: 0,
        previous: None,
        image: RetainedImage::capture(&product),
    };
    assert!(record.image.accepts_security(product.security.as_ref()));
    validate_retained_transition(&record, None).unwrap();
    commit_guarded(
        &mut file,
        &anchor,
        &record,
        File::sync_all,
        anchor.checkpoint_state().unwrap(),
        || Ok(None),
    )
    .unwrap();
    attachment.security = Arc::try_unwrap(product.security).ok().unwrap();
    PersistentAuthority::open(file, anchor, attachment).unwrap()
}

fn credentials<'a>(client: &'a SessionToken, packet: &'a Vec<u8>) -> WireCredentials<'a, Ed25519> {
    WireCredentials {
        token: client,
        signature: packet,
        maintenance: None,
        endorsement: None,
        previous: None,
        successor: None,
    }
}

struct Reference {
    service: Service,
    client: SessionToken,
    path: JournalPath,
    control: MemoryControl,
}

impl Reference {
    fn new(fixture: &Fixture, value_permission: bool, expired: bool) -> Self {
        Self::with_attachment(
            fixture,
            value_permission,
            expired,
            reference_attachment(true, true),
        )
    }

    fn with_attachment(
        fixture: &Fixture,
        value_permission: bool,
        expired: bool,
        attachment: Attachment<Ed25519, (RecoveryProfile, bool)>,
    ) -> Self {
        let path = JournalPath::create();
        let control = MemoryControl::with_head(None);
        let service = start(
            path.file(),
            anchor(&control),
            attachment,
            fixture,
            value_permission,
            expired,
        );
        let client = token(&service.security, 1, 100);
        Self {
            service,
            client,
            path,
            control,
        }
    }

    fn reopen(self, execute: bool, receipts: bool) -> Self {
        let Self {
            service,
            client,
            path,
            control,
        } = self;
        drop(service);
        let service = PersistentAuthority::open(
            path.file(),
            anchor(&control),
            reference_attachment(execute, receipts),
        )
        .unwrap();
        Self {
            service,
            client,
            path,
            control,
        }
    }

    fn receive(&mut self, packet: &Vec<u8>) -> Result<Received, WireError> {
        self.service.receive_wire(
            &channel_for(6, 7),
            Entry::Normal,
            packet,
            &credentials(&self.client, packet),
            DeliveryWindow::default(),
        )
    }

    fn outcome(&mut self, packet: &Vec<u8>, arrival: Arrival) -> Outcome {
        received_outcome(self.receive(packet).unwrap(), arrival)
    }

    fn head(&self) -> AnchorHead {
        self.service.anchor.current().unwrap().unwrap()
    }

    fn image(&mut self) -> RetainedImage {
        let head = self.head();
        exact_image(&mut self.service.file, head).unwrap().image
    }

    fn assert_data(&mut self, data: (u64, u64), cut: CommitCut) {
        let image = self.image();
        assert_eq!(image.authority.primary.ledger.asset_data(17), Some(data));
        assert_eq!(image.authority.primary.ledger.current_cut(), cut);
    }
}

fn received_outcome(received: Received, arrival: Arrival) -> Outcome {
    assert_eq!(received.arrival, arrival);
    let WireReply::Executed(ActionReply::Ordinary(CheckedExecution::Forwarded(
        Collection::Collected(outcome),
    ))) = received.reply
    else {
        panic!("expected retained Write outcome: {:?}", received.reply);
    };
    outcome
}

fn response(
    service: &mut Service,
    client: &SessionToken,
    packet: &Vec<u8>,
) -> (ResponseCode, Option<usize>) {
    let raw = service
        .receive_wire_response(
            &channel_for(6, 7),
            Entry::Normal,
            packet,
            &credentials(client, packet),
            DeliveryWindow::default(),
        )
        .unwrap();
    let boundary = Boundary {
        deployment: 7,
        source: 0,
        target: 0,
        principal: 42,
        key_id: 3,
        epoch: 9,
        route_scope: 1,
        now: 105,
        asset_ttl_floor: 2,
        future_skew: 0,
        max_frame: 1024 * 1024,
        max_nesting: 4,
        version_floor: 6,
        critical_allowed: false,
        public_key: key(6).verifying_key().to_bytes(),
    };
    let original = decode_packet(packet, packet.len()).unwrap();
    let verified = admit_response(&channel_for(7, 6), &boundary, &original, &raw).unwrap();
    let ResponseStatus::Known(code) = verified.code else {
        panic!("expected a known recorded Write code");
    };
    (code, verified.commit.map(|commit| commit.position))
}

fn observe_case(reference: &mut Reference, fixture: &Fixture, case: usize, outcome: Outcome) {
    let head = reference.head();
    let state = reference.image().authority;
    let result = state.primary.calls.get(&ID);
    assert_eq!(
        result.map(|call| (&call.payload, call.outcome)),
        Some((&fixture.payload, outcome))
    );
    assert_eq!(state.primary.owners.get(&17), Some(&3));
    assert_eq!(
        state
            .wire_bindings
            .get(&TransportKey::for_core(&fixture.core).unwrap()),
        Some(&fixture.exact),
    );
    let (value, version) = state.primary.ledger.asset_data(17).unwrap();
    let cut = state.primary.ledger.current_cut();
    assert_eq!(cut.authority_epoch, 9);
    let (code, commit) = response(&mut reference.service, &reference.client, &fixture.packet);
    assert_eq!(commit, outcome.commit.map(|commit| commit.position));
    assert_eq!(reference.head(), head);
    let row = format!(
        "{case}\t{}\t{}\t{}\t{}\t{value}\t{version}\t{}",
        u8::from(result.is_some()),
        code as u64,
        u8::from(commit.is_some()),
        commit.unwrap_or(0),
        cut.revision,
    );
    println!("write-row\t{row}");
    println!(
        "write-head\t{case}\t{}\t{}",
        head.sequence,
        crate::wire::legacy::hex(&head.digest)
    );
    assert_eq!(row, OBSERVATIONS.lines().nth(case).unwrap());
}

fn receipt(original: &Core, tag: u8) -> Vec<u8> {
    signed(core_with(
        4,
        8,
        0,
        tag,
        vec![1],
        vec![encode_core(original).unwrap()],
    ))
}

fn raw_read(tag: u8) -> Vec<u8> {
    signed(core_with(4, 3, 0, tag, vec![1, 1, 17], vec![]))
}

fn write_operation(core: &mut Core) -> &mut WireOperation {
    let Some(Body::LockManagement(operation)) = core.body.as_mut() else {
        panic!("expected LOCK_MANAGEMENT");
    };
    operation
}

#[test]
fn write_reference_signed_execution_and_reopen() {
    let fixture = fixture();
    let mut reference = Reference::new(&fixture, true, false);
    let mut tampered = fixture.packet.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let opening = reference.head();
    assert_eq!(
        reference.receive(&tampered),
        Err(WireError::InvalidSignature)
    );
    assert_eq!(reference.head(), opening);

    let outcome = reference.outcome(&fixture.packet, Arrival::First);
    assert_eq!(outcome.reply, OutcomeReply::Accepted(Reply::DataUpdated));
    let committed = reference.head();
    assert_ne!(committed, opening);
    observe_case(&mut reference, &fixture, 0, outcome);

    let mut reference = reference.reopen(true, true);
    let replay = reference.outcome(&fixture.packet, Arrival::Identical);
    assert_eq!(replay, outcome);
    observe_case(&mut reference, &fixture, 2, replay);
    assert_eq!(reference.head(), committed);
    assert_eq!(
        reference
            .receive(&receipt(&fixture.core, 10))
            .unwrap()
            .reply,
        WireReply::Receipt(Some(Receipt::Ordinary(Collection::Collected(outcome)))),
    );
    assert_eq!(
        reference.receive(&raw_read(11)).unwrap().reply,
        WireReply::Observation(Observation::Raw(Ok(Value::Units(9)))),
    );

    let before_conflicts = reference.head();
    let mut changed = fixture.core.clone();
    changed.issued_seconds = Some(101);
    assert_eq!(
        reference.receive(&signed(changed.clone())),
        Err(WireError::ReplayConflict)
    );
    assert_eq!(
        reference.receive(&receipt(&changed, 12)),
        Err(WireError::ReplayConflict)
    );
    changed = fixture.core.clone();
    changed.uuid.as_mut().unwrap()[0] = 13;
    assert_eq!(decode(&changed, 4), decode(&fixture.core, 4));
    assert_eq!(
        reference.receive(&signed(changed.clone())),
        Err(WireError::ReplayConflict)
    );
    assert_eq!(
        reference.receive(&receipt(&changed, 14)),
        Err(WireError::RequestUnresolved)
    );
    assert_eq!(reference.head(), before_conflicts);

    write_operation(&mut changed).words[1] = 2;
    let fresh = signed(changed);
    let busy = reference.outcome(&fresh, Arrival::First);
    assert_eq!(
        busy,
        Outcome {
            reply: OutcomeReply::Busy,
            commit: None
        }
    );
    assert_eq!(
        response(&mut reference.service, &reference.client, &fresh),
        (ResponseCode::Busy, None)
    );
    reference.assert_data((9, 1), CommitCut { revision: 1, ..CUT });
}

#[test]
fn write_reference_missing_value_permission() {
    let fixture = fixture();
    let mut reference = Reference::new(&fixture, false, false);
    let outcome = reference.outcome(&fixture.packet, Arrival::First);
    observe_case(&mut reference, &fixture, 1, outcome);
    assert_eq!(
        outcome,
        Outcome {
            reply: OutcomeReply::Rejected,
            commit: None
        }
    );
    assert_eq!(
        reference
            .receive(&receipt(&fixture.core, 15))
            .unwrap()
            .reply,
        WireReply::Receipt(Some(Receipt::Ordinary(Collection::Collected(outcome)))),
    );
    assert_eq!(
        reference.receive(&raw_read(16)).unwrap().reply,
        WireReply::Observation(Observation::Raw(Ok(Value::Units(0)))),
    );
}

#[test]
fn write_reference_signed_preconditions_and_timeout() {
    let fixture = fixture();
    let rejected = Outcome {
        reply: OutcomeReply::Rejected,
        commit: None,
    };
    for (word, name) in [
        (17, "credential epoch"),
        (20, "asset version"),
        (21, "lock generation"),
    ] {
        let mut core = fixture.core.clone();
        write_operation(&mut core).words[word] += 1;
        let mut reference = Reference::new(&fixture, true, false);
        assert_eq!(
            reference.outcome(&signed(core), Arrival::First),
            rejected,
            "{name}"
        );
        reference.assert_data((0, 0), CUT);
    }

    let mut reference = Reference::new(&fixture, true, true);
    let opening = reference.head();
    let mut timeout = fixture.core.clone();
    let operation = write_operation(&mut timeout);
    operation.opcode = Some(8);
    operation.words.pop();
    *operation.words.last_mut().unwrap() = 1;
    assert!(matches!(
        decode(&timeout, 4),
        Ok(Operands::Ordinary {
            payload: CallPayload {
                command: Command::Timeout { elapsed: 1 },
                ..
            },
            ..
        })
    ));
    let mut wrong_epoch = fixture.core.clone();
    wrong_epoch.authority_epoch = Some(8);
    assert_eq!(
        reference.receive(&signed(wrong_epoch)),
        Err(WireError::InvalidSource)
    );
    assert_eq!(
        reference.receive(&signed(timeout)),
        Err(WireError::UnsupportedVersion)
    );
    assert_eq!(reference.head(), opening);
    assert_eq!(reference.outcome(&fixture.packet, Arrival::First), rejected);
    reference.assert_data((0, 0), CUT);
}

#[test]
fn write_reference_requires_current_session_grants() {
    let fixture = fixture();
    let mut reference =
        Reference::with_attachment(&fixture, true, false, reference_attachment(false, true));
    let opening = reference.head();
    assert_eq!(
        reference.receive(&fixture.packet),
        Err(WireError::ProductRejected)
    );
    assert_eq!(reference.head(), opening);

    let mut reference =
        Reference::with_attachment(&fixture, true, false, reference_attachment(true, false));
    let outcome = reference.outcome(&fixture.packet, Arrival::First);
    assert_eq!(outcome.reply, OutcomeReply::Accepted(Reply::DataUpdated));
    let committed = reference.head();
    let mut reference = reference.reopen(true, false);
    assert_eq!(
        reference.receive(&fixture.packet),
        Err(WireError::ProductRejected)
    );
    assert_eq!(
        reference.receive(&receipt(&fixture.core, 17)),
        Err(WireError::ProductRejected)
    );
    assert_eq!(reference.head(), committed);
}

#[test]
fn write_nonordered_signed_receipt_requires_exact_original() {
    let fixture = fixture();
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = start(
        path.file(),
        anchor.clone(),
        attachment(DEFAULT_PROFILE, true),
        &fixture,
        true,
        false,
    );
    let mut receive = |packet: &[u8]| {
        service.receive_wire(
            &channel_for(6, 7),
            Entry::Normal,
            packet,
            &wire_auth(),
            DeliveryWindow::default(),
        )
    };
    let outcome = received_outcome(receive(&fixture.packet).unwrap(), Arrival::First);
    assert_eq!(outcome.reply, OutcomeReply::Accepted(Reply::DataUpdated));
    let exact = receipt(&fixture.core, 18);
    let mut tampered = exact.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(receive(&tampered), Err(WireError::InvalidSignature));
    assert_eq!(
        receive(&exact).unwrap().reply,
        WireReply::Receipt(Some(Receipt::Ordinary(Collection::Collected(outcome))))
    );
    let before = anchor.head();
    let mut changed = fixture.core.clone();
    changed.issued_seconds = Some(101);
    assert_eq!(
        receive(&receipt(&changed, 19)),
        Err(WireError::ReplayConflict)
    );
    changed = fixture.core.clone();
    changed.uuid.as_mut().unwrap()[0] = 20;
    assert_eq!(
        receive(&receipt(&changed, 21)),
        Err(WireError::RequestUnresolved)
    );
    assert_eq!(anchor.head(), before);
}
