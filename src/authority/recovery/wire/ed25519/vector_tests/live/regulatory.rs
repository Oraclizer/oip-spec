use super::terminal::{
    call, certificate, consume, cut, did, ordinary, owner_consume, rules, source_reader,
    source_record, source_writer, start,
};
use super::*;
use crate::OriginKey;
use crate::authority::identity::ActionReply;
use crate::authority::reads::Value;
use crate::authority::recovery::vector_tests::binding;
use crate::authority::recovery::wire::ed25519::{
    ack::{AckIssuer, ReceiverJournal},
    legal::{EnforcementAuthority, EnforcementIssuer, LegalAuthority, LegalIssuer},
    maintenance::{
        MaintenanceAuthority, MaintenanceIntent, MaintenanceReply, MaintenanceSigner,
        future_time_signature,
    },
};
use crate::authority::regulation::{
    Action as LegalAction, LegalGrant, LegalReply, Mode, Refusal, RegulatoryRoute, SpendGrant,
    SpendKind, SpendReply, SpendScope,
};
use crate::authority::{Collection, CommitRef, OutcomeReply};
use crate::lock_finality::{Binding, Reply, TerminalKind};
use crate::wire::generated::operation::AppealDeadline;
use crate::wire::operands::decode;
use std::fs::File;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

type Head = WitnessHead<Ed25519WitnessAuthority>;
type Service = PersistentAuthority<Ed25519Security<ClockProbe>, Head>;
const ACK_PEER: Identity = Identity {
    principal: 99,
    domain: 99,
    ocid: 199,
    rai: 299,
};

#[derive(Clone, Default)]
struct ClockProbe {
    fixed: Arc<AtomicU64>,
    revoke_after_flush: Arc<Mutex<Option<(File, u64, Head)>>>,
}

impl AuthorityClock for ClockProbe {
    fn unix_seconds(&self) -> Option<u64> {
        let mut watch = self.revoke_after_flush.lock().unwrap();
        let revoke = if watch
            .as_ref()
            .is_some_and(|(file, length, _)| file.metadata().unwrap().len() > *length)
        {
            watch.take()
        } else {
            None
        };
        drop(watch);
        if let Some((_, _, head)) = revoke {
            assert!(head.revoke(7).unwrap());
        }
        let fixed = self.fixed.load(Ordering::SeqCst);
        if fixed == 0 {
            SystemClock.unix_seconds()
        } else {
            Some(fixed)
        }
    }
}

pub(super) fn regulated_config() -> Ed25519Profile {
    let mut config = actual_config();
    config.sources = rules();
    config.other_endpoints.insert(2);
    config.maintenance_authorities.insert(
        7,
        MaintenanceAuthority {
            time: Some(key(32).verifying_key().to_bytes()),
            queue: Some(key(33).verifying_key().to_bytes()),
        },
    );
    config.legal_authorities.insert(
        7,
        LegalAuthority {
            key: key(30).verifying_key().to_bytes(),
            jurisdiction: 1,
            legal_basis: 1,
            assets: BTreeSet::from([17]),
            actions: vec![
                LegalAction::Freeze,
                LegalAction::Seize,
                LegalAction::Confiscate,
            ],
        },
    );
    config.enforcement_authorities.insert(
        7,
        EnforcementAuthority {
            key: key(31).verifying_key().to_bytes(),
            jurisdiction: 1,
            legal_basis: 1,
            assets: BTreeSet::from([17]),
        },
    );
    config.peers.insert(
        99,
        PeerRegistration {
            identity: ACK_PEER,
            key_id: 11,
            public_key: key(34).verifying_key().to_bytes(),
            sessions: BTreeMap::from([(1, BTreeMap::from([(2, EndpointGrant::default())]))]),
        },
    );
    config.acknowledgers.insert(99, 99);
    let grant = EndpointGrant {
        execute: BTreeSet::from([17]),
        receipts: BTreeSet::from([17]),
        recovery: BTreeSet::from([17]),
        legal: BTreeSet::from([17]),
        spend: BTreeSet::from([17]),
        current: vec![Query::RegulatoryState(2, 17), Query::SourcePool(0, 17)],
        ..EndpointGrant::default()
    };
    config
        .peers
        .get_mut(&7)
        .unwrap()
        .sessions
        .insert(2, BTreeMap::from([(0, grant.clone()), (2, grant)]));
    config
}

fn provider(clock: &ClockProbe) -> Ed25519Security<ClockProbe> {
    Ed25519Security::new(regulated_config(), key(6), clock.clone()).unwrap()
}

fn maintenance(
    service: &mut Service,
    security: &Ed25519Security<ClockProbe>,
    token: &MaintenanceToken,
    intent: MaintenanceIntent,
    seed: u8,
) -> MaintenanceReply {
    let request = service
        .prepare_reference_maintenance(token, intent)
        .unwrap();
    let signature = MaintenanceSigner::new(key(seed))
        .sign(security, &request)
        .unwrap();
    service
        .execute_reference_maintenance(token, &signature)
        .unwrap()
}

fn prefix(id: u8, revision: usize, b: Binding) -> Vec<u64> {
    vec![
        u64::from(id),
        u64::from(id),
        2,
        revision as u64,
        9,
        b.origin.domain,
        b.origin.event,
        b.asset,
        b.owner,
        b.destination,
        b.recipient,
    ]
}

fn legal_packet(
    security: &Ed25519Security<ClockProbe>,
    stage: LegalStage,
    tag: u8,
    revision: usize,
    order: &crate::authority::regulation::Order,
) -> (u64, Vec<u8>) {
    let b = order.binding;
    let (opcode, target) = match stage {
        LegalStage::SourceEmission => (1, b.origin.domain),
        LegalStage::ReceivingCommit => (2, b.destination),
    };
    let mut words = prefix(tag, revision, b);
    let action = match order.action {
        LegalAction::Freeze => 1,
        LegalAction::Seize => 3,
        LegalAction::Confiscate => 4,
        _ => unreachable!(),
    };
    words.extend([action, 7, 1, 1, 9, 1, b.asset]);
    if let Some(previous) = order.predecessor {
        words.extend([1, previous.domain, previous.event]);
    } else {
        words.push(0);
    }
    if let Some(destination) = order.destination {
        words.extend([1, destination]);
    } else {
        words.push(0);
    }
    let mut core = core_with(
        2,
        opcode,
        target,
        tag,
        words,
        vec![uint256(b.amount), vec![1]],
    );
    let Body::RegulatoryAction(op) = core.body.as_mut().unwrap() else {
        unreachable!()
    };
    op.appeal_deadline = order
        .appeal_deadline
        .map(AppealDeadline::AppealDeadlineUtcSeconds);
    let Operands::Legal {
        id,
        payload,
        order: decoded,
        ..
    } = decode(&core, 4).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(decoded, *order);
    let certificate = LegalIssuer::new(key(30))
        .issue(security, target, stage, id, &payload, order)
        .unwrap();
    let Body::RegulatoryAction(op) = core.body.as_mut().unwrap() else {
        unreachable!()
    };
    op.blobs[1] = certificate;
    (target, signed_at(core, 7, now(), 180))
}

fn legal(
    service: &mut Service,
    security: &Ed25519Security<ClockProbe>,
    token: &SessionToken,
    stage: LegalStage,
    tag: u8,
    order: &crate::authority::regulation::Order,
) -> LegalReply {
    let revision = cut(service).revision;
    let (target, packet) = legal_packet(security, stage, tag, revision, order);
    let WireReply::Executed(ActionReply::Legal(reply)) =
        consume(service, target, token, &packet).unwrap()
    else {
        unreachable!()
    };
    reply
}

fn order(
    event: u64,
    action: LegalAction,
    predecessor: Option<OriginKey>,
    deadline: Option<u64>,
) -> crate::authority::regulation::Order {
    let b = Binding {
        origin: OriginKey { domain: 0, event },
        amount: 0,
        ..binding()
    };
    crate::authority::regulation::Order {
        binding: b,
        action,
        officer: 7,
        jurisdiction: 1,
        legal_basis: 1,
        scope: BTreeSet::from([17]),
        issuance_epoch: 9,
        predecessor,
        appeal_deadline: deadline,
        destination: (action == LegalAction::Confiscate).then_some(b.recipient),
    }
}

pub(super) fn spend_packet<C: AuthorityClock>(
    security: &Ed25519Security<C>,
    tag: u8,
    revision: usize,
    reference: CommitRef,
    ordinary: bool,
) -> Vec<u8> {
    let b = binding();
    let mut words = prefix(tag, revision, b);
    words.extend([reference.position as u64, 3, 4, u64::from(!ordinary)]);
    let mut blobs = vec![uint256(5), uint256(1)];
    if !ordinary {
        words.extend([7, 1, 1, 1, 17, 0]);
        blobs.push(vec![1]);
    }
    let mut core = core_with(
        if ordinary { 1 } else { 2 },
        if ordinary { 6 } else { 3 },
        2,
        tag,
        words,
        blobs,
    );
    if !ordinary {
        let Operands::Spend {
            id,
            payload,
            authorization: Some(order),
            ..
        } = decode(&core, 4).unwrap()
        else {
            unreachable!()
        };
        let certificate = EnforcementIssuer::new(key(31))
            .issue(security, 2, id, &payload, &order)
            .unwrap();
        let Body::RegulatoryAction(op) = core.body.as_mut().unwrap() else {
            unreachable!()
        };
        op.blobs[2] = certificate;
    }
    signed_at(core, 7, now(), 180)
}

fn channel_atomicity(
    local: u8,
    remote: u8,
    local_domain: u64,
    remote_domain: u64,
    atomicity: u64,
) -> Channel {
    let offer = |sender, receiver| Offer {
        deployment: 7,
        sender,
        receiver,
        challenge: 82,
        expires: now() + 300,
        versions: BTreeSet::from([6]),
        families: (1..=7).collect(),
        atomicities: BTreeSet::from([atomicity, 3]),
        schemes: BTreeSet::from([1]),
    };
    let a = offer(local_domain, remote_domain);
    let b = offer(remote_domain, local_domain);
    let profile = select_profile(&a, &b, 6, false).unwrap();
    negotiate(
        &Negotiation {
            deployment: 7,
            local: local_domain,
            remote: remote_domain,
            challenge: 82,
            now: now(),
            floor: 6,
            legacy_allowed: false,
            local_key: key(local).verifying_key().to_bytes(),
            remote_key: key(remote).verifying_key().to_bytes(),
        },
        SignedOffers {
            local: &a,
            remote: &b,
            local_signature: &key(local).sign(&offer_bytes(&a)).to_bytes(),
            remote_signature: &key(remote).sign(&offer_bytes(&b)).to_bytes(),
            confirmation: &key(remote)
                .sign(&confirmation_bytes(&a, &b, &profile))
                .to_bytes(),
        },
    )
    .unwrap()
}

#[test]
#[ignore = "requires isolated Linux authority, witness, source, and receiver stores"]
fn reference_regulatory_live_time_spend_and_receiver_ack() {
    let root = std::env::temp_dir().join(format!("oip-regulatory-live-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let archive = root.join("archive");
    fs::create_dir(&archive).unwrap();
    let clock = ClockProbe::default();
    let writer = WitnessWriter {
        generation: 1,
        identity: [24; 32],
    };
    let anchor = head_at(&archive, writer, "regulatory");
    let security = provider(&clock);
    let session = SessionIssuer::new(key(8));
    let token = session.issue(&security, 7, 2, 600).unwrap();
    let receiver_token = session.issue(&security, 99, 1, 600).unwrap();
    let operator = MaintenanceIssuer::new(key(9))
        .issue(&security, 7, 600)
        .unwrap();
    let proof = WitnessAttachmentIssuer::new(key(12))
        .issue(&anchor, true)
        .unwrap();
    let path = JournalPath::create();
    let mut initial = genesis(10, 1);
    initial.identities.push(ACK_PEER);
    let policy = initial.regulation.as_mut().unwrap();
    for action in [LegalAction::Seize, LegalAction::Confiscate] {
        for stage in [LegalStage::SourceEmission, LegalStage::ReceivingCommit] {
            policy.legal.push(LegalGrant {
                stage,
                route: RegulatoryRoute::Normal,
                officer: 7,
                jurisdiction: 1,
                legal_basis: 1,
                asset: 17,
                action,
                epoch: 9,
            });
        }
    }
    policy.spend.push(SpendGrant {
        route: RegulatoryRoute::Normal,
        actor: 7,
        epoch: 9,
        scope: SpendScope {
            root: binding(),
            sender: 3,
            recipient: 4,
            amount: 1,
            kind: SpendKind::Ordinary,
        },
        jurisdiction: 0,
        legal_basis: 0,
    });
    let genesis_cut = anchor
        .prepare_genesis(&mut path.file(), initial, provider(&clock), true, &proof)
        .unwrap();
    anchor
        .provision_genesis(
            &genesis_cut,
            &proof,
            &key(13)
                .sign(&genesis_cut.authorization_message().unwrap())
                .to_bytes(),
        )
        .unwrap();
    let mut service = PersistentAuthority::open(
        path.file(),
        anchor,
        Attachment {
            profile: DEFAULT_PROFILE,
            source_connected: true,
            proof,
            security: provider(&clock),
        },
    )
    .unwrap();

    let reserve = call(3, 1, 0, 5, 0, binding(), false, &[20], None);
    let genesis_head = service.anchor.current().unwrap();
    assert_eq!(
        consume(&mut service, 0, &token, &reserve),
        Err(WireError::ProductRejected)
    );
    let first = service
        .prepare_reference_maintenance(&operator, MaintenanceIntent::ObserveTime { session: 2 })
        .unwrap();
    assert!(
        MaintenanceSigner::new(key(33))
            .sign(&security, &first)
            .is_err()
    );
    let future = future_time_signature(first.clone(), now() + 1000, &key(32));
    assert!(
        service
            .execute_reference_maintenance(&operator, &future)
            .is_err()
    );
    assert_eq!(service.anchor.current().unwrap(), genesis_head);
    assert_eq!(
        service
            .execute_reference_maintenance(
                &operator,
                &MaintenanceSigner::new(key(32))
                    .sign(&security, &first)
                    .unwrap()
            )
            .unwrap(),
        MaintenanceReply::Observed(true)
    );
    let first_clock = service
        .transact(|p| p.reads.authority.state.primary.ledger.clock())
        .unwrap();
    assert!(first_clock > 0 && first_clock <= now());
    let b = binding();
    assert_eq!(
        maintenance(
            &mut service,
            &security,
            &operator,
            MaintenanceIntent::Enqueue { origin: b.origin },
            33
        ),
        MaintenanceReply::Enqueued(None)
    );
    start(&mut service, &token, b, 10);
    assert_eq!(super::terminal::mass(&mut service, b), (5, 5, 0));
    assert_eq!(
        maintenance(
            &mut service,
            &security,
            &operator,
            MaintenanceIntent::ObserveTime { session: 2 },
            32
        ),
        MaintenanceReply::Observed(true)
    );
    assert_eq!(super::terminal::mass(&mut service, b), (5, 5, 0));
    let pending_clock = service
        .transact(|p| p.reads.authority.state.primary.ledger.clock())
        .unwrap();

    let source = source_writer("regulatory");
    let reader = source_reader("regulatory");
    assert_eq!(
        source.record(&source_record(b, TerminalKind::Confirmed, 61)),
        Ok(true)
    );
    let certificate = certificate(&reader, b.origin);
    let r = cut(&mut service).revision;
    let terminal = call(1, 2, 0, 13, r, b, false, &[1, 61], Some(&certificate));
    let Collection::Collected(recorded) =
        ordinary(consume(&mut service, 0, &token, &terminal).unwrap())
    else {
        unreachable!()
    };
    assert_eq!(recorded.reply, OutcomeReply::Accepted(Reply::Recorded));
    let reference = recorded.commit.unwrap();
    let r = cut(&mut service).revision;
    let credit = call(1, 3, 2, 14, r, b, true, &[61], None);
    assert_eq!(
        ordinary(consume(&mut service, 2, &token, &credit).unwrap()),
        Collection::Waiting
    );
    let r = cut(&mut service).revision;
    let reconcile = call(3, 6, 0, 15, r, b, true, &[0, 61], Some(&certificate));
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

    let pre_freeze = order(
        38,
        LegalAction::Confiscate,
        Some(OriginKey {
            domain: 0,
            event: 41,
        }),
        Some(now() + 5),
    );
    assert_eq!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::SourceEmission,
            38,
            &pre_freeze
        ),
        LegalReply::Refused(Refusal::MissingPriorSeizure)
    );
    let freeze = order(40, LegalAction::Freeze, None, None);
    assert!(matches!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::SourceEmission,
            40,
            &freeze
        ),
        LegalReply::Emitted(_)
    ));
    assert!(matches!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::ReceivingCommit,
            41,
            &freeze
        ),
        LegalReply::Applied(_)
    ));
    let freeze_revision = cut(&mut service).revision;
    let freeze_publication = call(
        1,
        5,
        0,
        52,
        freeze_revision,
        freeze.binding,
        false,
        &[],
        None,
    );
    did(
        consume(&mut service, 0, &token, &freeze_publication).unwrap(),
        Reply::Published,
    );
    let r = cut(&mut service).revision;
    let ordinary = spend_packet(&security, 42, r, reference, true);
    assert_eq!(
        consume(&mut service, 2, &token, &ordinary).unwrap(),
        WireReply::Executed(ActionReply::Spend(SpendReply::Rejected))
    );
    let r = cut(&mut service).revision;
    let enforced = spend_packet(&security, 43, r, reference, false);
    assert!(
        matches!(consume(&mut service,2,&token,&enforced).unwrap(),WireReply::Executed(ActionReply::Spend(SpendReply::Executed{root,..})) if root==b.origin)
    );
    let r = cut(&mut service).revision;
    let read = signed_at(
        core_with(4, 1, 2, 44, vec![2, r as u64, 5, 2, 17], Vec::new()),
        7,
        now(),
        180,
    );
    assert!(
        matches!(consume(&mut service,2,&token,&read).unwrap(),WireReply::Observation(Observation::Current(Ok(value))) if value.value==Value::Regulatory(Some(Mode::Frozen)))
    );

    let appeal = now() + 1;
    let seize = order(
        45,
        LegalAction::Seize,
        Some(freeze.binding.origin),
        Some(appeal),
    );
    assert!(matches!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::SourceEmission,
            45,
            &seize
        ),
        LegalReply::Emitted(_)
    ));
    assert!(matches!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::ReceivingCommit,
            46,
            &seize
        ),
        LegalReply::Applied(_)
    ));
    let confiscate = order(
        47,
        LegalAction::Confiscate,
        Some(seize.binding.origin),
        Some(appeal),
    );
    let r = cut(&mut service).revision;
    let elapsed = call(3, 8, 0, 47, r, b, false, &[u64::MAX / 2], None);
    assert_eq!(
        consume(&mut service, 0, &token, &elapsed),
        Err(WireError::UnsupportedVersion)
    );
    assert_eq!(
        service
            .transact(|p| p.reads.authority.state.primary.ledger.clock())
            .unwrap(),
        pending_clock
    );
    assert_eq!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::SourceEmission,
            48,
            &confiscate
        ),
        LegalReply::Refused(Refusal::AppealStillOpen)
    );
    while now() < appeal {
        std::thread::sleep(Duration::from_millis(100));
    }
    let mass = super::terminal::mass(&mut service, b);
    assert_eq!(
        maintenance(
            &mut service,
            &security,
            &operator,
            MaintenanceIntent::ObserveTime { session: 2 },
            32
        ),
        MaintenanceReply::Observed(true)
    );
    assert_eq!(super::terminal::mass(&mut service, b), mass);
    assert!(matches!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::SourceEmission,
            49,
            &confiscate
        ),
        LegalReply::Emitted(_)
    ));
    assert!(matches!(
        legal(
            &mut service,
            &security,
            &token,
            LegalStage::ReceivingCommit,
            50,
            &confiscate
        ),
        LegalReply::Applied(_)
    ));
    println!(
        "first trusted time preceded leases; future raw elapsed held; actual legal preconditions and observed appeal cut supplied"
    );

    let MaintenanceReply::Enqueued(Some(slot)) = maintenance(
        &mut service,
        &security,
        &operator,
        MaintenanceIntent::Enqueue { origin: b.origin },
        33,
    ) else {
        unreachable!()
    };
    let MaintenanceReply::Dispatched(Some(first)) = maintenance(
        &mut service,
        &security,
        &operator,
        MaintenanceIntent::Dispatch { key: slot },
        33,
    ) else {
        unreachable!()
    };
    assert_eq!(first.job().attempts, 1);
    assert_eq!(
        maintenance(
            &mut service,
            &security,
            &operator,
            MaintenanceIntent::Fail { key: slot },
            33
        ),
        MaintenanceReply::Failed(true)
    );
    let MaintenanceReply::Dispatched(Some(second)) = maintenance(
        &mut service,
        &security,
        &operator,
        MaintenanceIntent::Dispatch { key: slot },
        33,
    ) else {
        unreachable!()
    };
    assert_eq!(second.job().attempts, 2);
    assert_eq!(first.job().commitment, second.job().commitment);
    let receiver = ReceiverJournal::new(
        EtcdTransport::new(etcd_config("RECEIVER", "regulatory")).unwrap(),
        DEFAULT_PROFILE,
        99,
    );
    let config = regulated_config();
    let receiver_channel = channel_atomicity(34, 6, 99, 2, 1);
    let ack_issuer = AckIssuer::new(key(34));
    assert!(
        ack_issuer
            .issue(&config, &clock, &receiver_channel, &receiver, slot)
            .is_err()
    );
    assert_eq!(receiver.record(&first), Ok(true));
    assert_eq!(receiver.record(&second), Ok(false));
    let observed = now();
    let fixed = FixedClock(observed);
    let ack = ack_issuer
        .issue(&config, &fixed, &receiver_channel, &receiver, slot)
        .unwrap();
    assert_eq!(
        ack_issuer
            .issue(&config, &fixed, &receiver_channel, &receiver, slot)
            .unwrap(),
        ack
    );
    let other_ack = ack_issuer
        .issue(
            &config,
            &fixed,
            &channel_atomicity(34, 6, 99, 2, 2),
            &receiver,
            slot,
        )
        .unwrap();
    assert_ne!(
        decode_packet(&ack, ack.len()).unwrap().core().uuid,
        decode_packet(&other_ack, other_ack.len())
            .unwrap()
            .core()
            .uuid
    );
    assert!(
        AckIssuer::new(key(7))
            .issue(&config, &fixed, &receiver_channel, &receiver, slot)
            .is_err()
    );
    let mut changed = decode_packet(&ack, ack.len()).unwrap().core().clone();
    let Body::Ack(op) = changed.body.as_mut().unwrap() else {
        unreachable!()
    };
    op.words[2] += 1;
    changed.uuid.as_mut().unwrap()[0] ^= 1;
    let wrong = signed_at(changed, 34, observed, 30);
    let mut wrong_target = decode_packet(&ack, ack.len()).unwrap().core().clone();
    let Body::Ack(op) = wrong_target.body.as_mut().unwrap() else {
        unreachable!()
    };
    op.words[3] = 98;
    wrong_target.uuid.as_mut().unwrap()[0] ^= 2;
    let wrong_target = signed_at(wrong_target, 34, observed, 30);
    let inbound = channel_at(6, 34, 2, 99);
    let before = service.anchor.current().unwrap();
    assert_eq!(
        service.receive_wire(
            &inbound,
            Entry::Adapter,
            &wrong_target,
            &WireCredentials {
                maintenance: Some(&operator),
                ..credentials(&receiver_token, &wrong_target)
            },
            DeliveryWindow::default()
        ),
        Err(WireError::InvalidSource)
    );
    assert_eq!(service.anchor.current().unwrap(), before);
    let ack_call = |service: &mut Service, packet: &Vec<u8>| {
        service
            .receive_wire(
                &inbound,
                Entry::Adapter,
                packet,
                &WireCredentials {
                    maintenance: Some(&operator),
                    ..credentials(&receiver_token, packet)
                },
                DeliveryWindow::default(),
            )
            .unwrap()
            .reply
    };
    assert_eq!(
        ack_call(&mut service, &wrong),
        WireReply::Acknowledged(false)
    );
    assert_eq!(ack_call(&mut service, &ack), WireReply::Acknowledged(true));
    assert_eq!(ack_call(&mut service, &ack), WireReply::Acknowledged(true));
    let MaintenanceReply::Dispatched(None) = maintenance(
        &mut service,
        &security,
        &operator,
        MaintenanceIntent::Dispatch { key: slot },
        33,
    ) else {
        unreachable!()
    };
    assert_eq!(
        service
            .transact(|p| p
                .reads
                .authority
                .state
                .primary
                .origins
                .get(&b.origin)
                .unwrap()
                .decision
                .unwrap()
                .commit)
            .unwrap(),
        reference
    );
    println!(
        "durable exact receiver ACK completed only the matching retry and preserved first primary"
    );

    // Same actual retained response in two negotiated atomicity profiles.
    let root_receipt = publish;
    let frozen = now();
    clock.fixed.store(frozen, Ordering::SeqCst);
    let creds = credentials(&token, &root_receipt);
    let first = service
        .receive_wire_response(
            &channel_atomicity(6, 7, 0, 0, 1),
            Entry::Normal,
            &root_receipt,
            &creds,
            DeliveryWindow::default(),
        )
        .unwrap();
    let retry = service
        .receive_wire_response(
            &channel_atomicity(6, 7, 0, 0, 1),
            Entry::Normal,
            &root_receipt,
            &creds,
            DeliveryWindow::default(),
        )
        .unwrap();
    let other = service
        .receive_wire_response(
            &channel_atomicity(6, 7, 0, 0, 2),
            Entry::Normal,
            &root_receipt,
            &creds,
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(first, retry);
    assert_ne!(
        decode_packet(&first, first.len()).unwrap().core().uuid,
        decode_packet(&other, other.len()).unwrap().core().uuid
    );
    clock.fixed.store(0, Ordering::SeqCst);

    let before = service.anchor.current().unwrap();
    let request = service
        .prepare_reference_maintenance(&operator, MaintenanceIntent::ObserveTime { session: 2 })
        .unwrap();
    let signature = MaintenanceSigner::new(key(32))
        .sign(&security, &request)
        .unwrap();
    let file = path.file();
    let length = file.metadata().unwrap().len();
    *clock.revoke_after_flush.lock().unwrap() =
        Some((file, length, head_at(&archive, writer, "regulatory")));
    assert_eq!(
        service.execute_reference_maintenance(&operator, &signature),
        Err(RecoveryError::Hold)
    );
    assert_eq!(service.anchor.current().unwrap(), before);
    println!("authority revocation after flush defeated signed time maintenance");
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
