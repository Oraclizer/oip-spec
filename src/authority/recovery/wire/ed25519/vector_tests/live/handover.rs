use super::regulatory::{regulated_config, spend_packet};
use super::terminal::{
    call, certificate, cut, did, mass, ordinary, source_reader, source_record, source_writer,
};
use super::*;
use crate::authority::identity::{Consent, Credentials, Receipt};
use crate::authority::recovery::vector_tests::{binding, contexts};
use crate::authority::recovery::wire::ed25519::{
    dispatch::OrderedDispatcher,
    maintenance::{MaintenanceIntent, MaintenanceReply, MaintenanceSigner},
};
use crate::authority::{Collection, CommitRef, OutcomeReply};
use crate::lock_finality::{Binding, Reply, TerminalKind};
use std::fs::File;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;

type Service<C = SystemClock> =
    PersistentAuthority<Ed25519Security<C>, WitnessHead<Ed25519WitnessAuthority>>;

type PublicationPause = (File, u64, mpsc::Sender<()>, mpsc::Receiver<()>);

#[derive(Clone, Default)]
struct PauseClock(Arc<Mutex<Option<PublicationPause>>>);

impl AuthorityClock for PauseClock {
    fn unix_seconds(&self) -> Option<u64> {
        let pause = {
            let mut wait = self.0.lock().unwrap();
            if wait
                .as_ref()
                .is_some_and(|(file, length, _, _)| file.metadata().unwrap().len() > *length)
            {
                wait.take()
            } else {
                None
            }
        };
        if let Some((_, _, reached, release)) = pause {
            reached.send(()).unwrap();
            release.recv_timeout(Duration::from_secs(45)).unwrap();
        }
        SystemClock.unix_seconds()
    }
}

fn configurations() -> (Ed25519Profile, Ed25519Profile) {
    let mut old = regulated_config();
    old.handover_maintainers.insert(7);
    let former = old.peers.get_mut(&7).unwrap();
    former
        .sessions
        .get_mut(&1)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .transfer_owner
        .insert(17);
    former
        .sessions
        .get_mut(&2)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .recovery
        .insert(17);
    former
        .sessions
        .get_mut(&2)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .owner
        .insert(17);
    let mut next = old.clone();
    next.authority_epoch = 10;
    next.response_key = key(11).verifying_key().to_bytes();
    next.session_issuer = key(23).verifying_key().to_bytes();
    next.peers.get_mut(&7).unwrap().sessions.remove(&1);
    next.peers.get_mut(&8).unwrap().sessions = BTreeMap::from([(
        3,
        BTreeMap::from([(
            0,
            EndpointGrant {
                recovery: BTreeSet::from([17]),
                owner: BTreeSet::from([17]),
                ..EndpointGrant::default()
            },
        )]),
    )]);
    (old, next)
}

fn current<C: AuthorityClock>(
    old: &Ed25519Profile,
    next: &Ed25519Profile,
    clock: C,
) -> Ed25519Security<C> {
    let provider = Ed25519Security::new(old.clone(), key(6), clock).unwrap();
    let endpoints = contexts(10);
    let preimage = provider
        .successor_readiness_signing_bytes(next, &endpoints)
        .unwrap();
    provider
        .with_successor(next.clone(), endpoints, &key(11).sign(&preimage).to_bytes())
        .unwrap()
}

fn attach<C: AuthorityClock>(
    anchor: &WitnessHead<Ed25519WitnessAuthority>,
    security: Ed25519Security<C>,
) -> Attachment<Ed25519Security<C>, [u8; 64]> {
    let proof = WitnessAttachmentIssuer::new(key(12))
        .issue(anchor, true)
        .unwrap();
    Attachment {
        profile: DEFAULT_PROFILE,
        proof,
        source_connected: true,
        security,
    }
}

fn receive<C: AuthorityClock>(
    service: &mut Service<C>,
    channel: &Channel,
    token: &SessionToken,
    packet: &Vec<u8>,
    endorsement: Option<&Credentials<'_, Ed25519Security<C>>>,
) -> Result<WireReply, WireError> {
    service
        .receive_wire(
            channel,
            Entry::Normal,
            packet,
            &WireCredentials {
                endorsement,
                ..credentials(token, packet)
            },
            DeliveryWindow::default(),
        )
        .map(|result| result.reply)
}

fn proposal_packet(proposal: &Handover, label: u8, left: &[u8], right: &[u8]) -> Vec<u8> {
    signed_at(
        core_with(
            7,
            1,
            0,
            label,
            vec![
                proposal.old_session,
                proposal.expected.revision as u64,
                proposal.asset,
                proposal.previous,
                proposal.successor,
                proposal.old_session,
                proposal.new_session,
                proposal.epoch,
            ],
            vec![
                serde_json::to_vec(&proposal.contexts).unwrap(),
                left.to_vec(),
                right.to_vec(),
            ],
        ),
        7,
        now(),
        180,
    )
}

fn current_core(packet: &[u8], replace_credential_epoch: bool) -> Core {
    let mut core = decode_packet(packet, packet.len()).unwrap().core().clone();
    core.authority_epoch = Some(10);
    if replace_credential_epoch {
        let op = match core.body.as_mut().unwrap() {
            Body::StateSync(op) | Body::LockManagement(op) => op,
            _ => panic!("current lock operation"),
        };
        op.words[17] = 10;
    }
    core
}

fn recovery_proof(core: &Core, identity: Identity, session: u64, seed: u8) -> Vec<u8> {
    let Operands::Ordinary { id, payload, .. } = decode(core, 4).unwrap() else {
        panic!("ordinary");
    };
    key(seed)
        .sign(
            &claim_recovery_signing_bytes(
                DEFAULT_PROFILE,
                identity,
                SessionProof {
                    session,
                    epoch: payload.cut.authority_epoch,
                },
                payload.endpoint,
                payload.binding.origin,
                id,
                &payload,
            )
            .unwrap(),
        )
        .to_bytes()
        .to_vec()
}

fn lock_core(epoch: u64, revision: usize, b: Binding, generation: u64, label: u8) -> Core {
    let mut core = core_with(
        3,
        4,
        0,
        label,
        vec![
            u64::from(label),
            u64::from(label),
            2,
            revision as u64,
            9,
            b.origin.domain,
            b.origin.event,
            b.asset,
            b.owner,
            b.destination,
            b.recipient,
            1,
            b.asset,
            b.origin.domain,
            b.origin.event,
            7,
            0,
            epoch,
            1,
            b.asset,
            0,
            generation,
        ],
        vec![uint256(b.amount), vec![1; 64]],
    );
    core.authority_epoch = Some(epoch);
    core
}

fn fence<C: AuthorityClock>(
    service: &mut Service<C>,
    link: &Channel,
    worker: &SessionToken,
    owner: &SessionToken,
    mut core: Core,
    identity: Identity,
    seed: u8,
    change_embedded_proof: bool,
) -> Result<WireReply, WireError> {
    let session = owner.claims.session;
    let epoch = owner.claims.epoch;
    let signature = recovery_proof(&core, identity, session, seed);
    let Body::LockManagement(op) = core.body.as_mut().unwrap() else {
        panic!("lock");
    };
    op.blobs[1] = signature.clone();
    if change_embedded_proof {
        op.blobs[1][0] ^= 1;
    }
    let packet = signed_at(core, 7, now(), 180);
    let endorsement = Credentials {
        token: owner,
        proof: SessionProof { session, epoch },
        signature: &signature,
    };
    receive(service, link, worker, &packet, Some(&endorsement))
}

#[test]
#[ignore = "requires isolated Linux source, authority and witness etcd"]
fn reference_handover_live_wait_and_current_owner() {
    let root = std::env::temp_dir().join(format!("oip-handover-live-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let archive = root.join("archive");
    fs::create_dir(&archive).unwrap();
    let writer = WitnessWriter {
        generation: 1,
        identity: [31; 32],
    };
    let make_head = || head_at(&archive, writer, "handover");
    let (old, next) = configurations();
    let signing = Ed25519Security::new(old.clone(), key(6), SystemClock).unwrap();
    let mut invalid = next.clone();
    invalid.maintenance_issuer = invalid.response_key;
    assert!(
        signing
            .successor_readiness_signing_bytes(&invalid, &contexts(10))
            .is_err()
    );
    let message = signing
        .successor_readiness_signing_bytes(&next, &contexts(10))
        .unwrap();
    assert!(
        signing
            .with_successor(
                next.clone(),
                contexts(10),
                &key(6).sign(&message).to_bytes()
            )
            .is_err()
    );
    let clock = PauseClock::default();
    let old_provider = current(&old, &next, SystemClock);
    let old_issuer = SessionIssuer::new(key(8));
    let worker = || old_issuer.issue(&old_provider, 7, 2, 300).unwrap();
    let former = old_issuer.issue(&old_provider, 7, 1, 300).unwrap();
    let candidate = old_issuer.issue(&old_provider, 8, 1, 300).unwrap();
    let maintenance = MaintenanceIssuer::new(key(9))
        .issue(&old_provider, 7, 300)
        .unwrap();
    let next_provider = || Ed25519Security::new(next.clone(), key(11), SystemClock).unwrap();
    let next_issuer = SessionIssuer::new(key(23));
    let new_worker = || next_issuer.issue(&next_provider(), 7, 2, 300).unwrap();
    let new_owner = || next_issuer.issue(&next_provider(), 8, 3, 300).unwrap();
    let path = JournalPath::create();
    let anchor = make_head();
    let attached = attach(&anchor, current(&old, &next, clock.clone()));
    let prepared = anchor
        .prepare_genesis(
            &mut path.file(),
            genesis(10, 1),
            current(&old, &next, clock.clone()),
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
    let old_link = channel(6, 7);
    let new_link = channel(11, 7);
    let b = binding();
    let observation = service
        .prepare_reference_maintenance(&maintenance, MaintenanceIntent::ObserveTime { session: 2 })
        .unwrap();
    let observation = MaintenanceSigner::new(key(32))
        .sign(&old_provider, &observation)
        .unwrap();
    assert!(matches!(
        service
            .execute_reference_maintenance(&maintenance, &observation)
            .unwrap(),
        MaintenanceReply::Observed(true),
    ));
    let revision = cut(&mut service).revision;
    let reserve = call(3, 1, 0, 10, revision, b, false, &[300], None);
    did(
        receive(&mut service, &old_link, &worker(), &reserve, None).unwrap(),
        Reply::Reserved,
    );
    let dispatch = call(3, 2, 0, 11, revision + 1, b, true, &[0], None);
    did(
        receive(&mut service, &old_link, &worker(), &dispatch, None).unwrap(),
        Reply::SourceDispatched,
    );
    let position = revision + 2;
    let debit = call(1, 1, 0, 12, position, b, true, &[0], None);
    let before = service.anchor.current().unwrap();
    let future = signed_at(current_core(&debit, true), 7, now(), 180);
    assert_eq!(
        receive(&mut service, &new_link, &new_worker(), &future, None),
        Err(WireError::InvalidSource)
    );
    assert_eq!(service.anchor.current().unwrap(), before);

    let (reached, waiting) = mpsc::channel();
    let (release, paused) = mpsc::channel();
    let file = path.file();
    let length = file.metadata().unwrap().len();
    *clock.0.lock().unwrap() = Some((file, length, reached, paused));
    let dispatcher = OrderedDispatcher::start(
        service,
        NonZeroUsize::new(1).unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
    std::thread::scope(|scope| {
        let reply = scope.spawn(|| {
            dispatcher.receive(
                old_link.clone(),
                worker(),
                debit.clone(),
                Instant::now() + Duration::from_secs(25),
            )
        });
        waiting.recv_timeout(Duration::from_secs(20)).unwrap();
        assert_eq!(reply.join().unwrap(), Err(WireError::RequestUnresolved));
        assert_eq!(make_head().current().unwrap(), before);
        release.send(()).unwrap();
    });
    let exact = dispatcher
        .resolve_debit(
            old_link.clone(),
            worker(),
            debit.clone(),
            Instant::now() + Duration::from_secs(25),
        )
        .unwrap();
    response(&debit, &exact, ResponseCode::Debited, Some(position));
    let after_debit = make_head().current().unwrap().unwrap();
    assert_eq!(after_debit.sequence, before.unwrap().sequence + 1);
    let retry = dispatcher
        .receive(
            old_link.clone(),
            worker(),
            debit.clone(),
            Instant::now() + Duration::from_secs(25),
        )
        .unwrap();
    response(&debit, &retry, ResponseCode::Debited, Some(position));
    assert_eq!(make_head().current().unwrap(), Some(after_debit));
    dispatcher.shutdown().unwrap();
    println!(
        "bounded worker timeout left old head; exact resolution and retry selected one Debit at position {position}"
    );

    let anchor = make_head();
    let attached = attach(&anchor, current(&old, &next, SystemClock));
    let mut service = PersistentAuthority::open(path.file(), anchor, attached).unwrap();
    assert_eq!(mass(&mut service, b), (5, 5, 0));
    let proposal = Handover {
        asset: 17,
        previous: 7,
        successor: 8,
        expected: cut(&mut service),
        old_session: 1,
        new_session: 3,
        epoch: 10,
        contexts: contexts(10),
    };
    let left = key(7)
        .sign(
            &old_provider
                .handover_consent_signing_bytes(FORMER, &proposal)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let right = key(10)
        .sign(
            &old_provider
                .handover_consent_signing_bytes(SUCCESSOR, &proposal)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let consume = |service: &mut Service,
                   packet: &Vec<u8>,
                   right: Option<&Consent<'_, Ed25519Security<SystemClock>>>| {
        service
            .receive_wire(
                &old_link,
                Entry::Normal,
                packet,
                &WireCredentials {
                    maintenance: Some(&maintenance),
                    previous: Some(&Consent {
                        token: &former,
                        signature: &left,
                    }),
                    successor: right,
                    ..credentials(&former, packet)
                },
                DeliveryWindow::default(),
            )
            .map(|value| value.reply)
    };
    let handover = proposal_packet(&proposal, 51, &left, &right);
    assert_eq!(
        consume(&mut service, &handover, None),
        Err(WireError::ProductRejected)
    );
    let consent = Consent {
        token: &candidate,
        signature: &right,
    };
    let mut changed = proposal.clone();
    changed.contexts[0].grants.clear();
    let changed = proposal_packet(&changed, 52, &left, &right);
    assert_eq!(
        consume(&mut service, &changed, Some(&consent)),
        Err(WireError::InvalidSource)
    );
    let altered = proposal_packet(&proposal, 53, &left, &left);
    assert_eq!(
        consume(&mut service, &altered, Some(&consent)),
        Err(WireError::InvalidSource)
    );
    assert_eq!(service.anchor.current().unwrap(), Some(after_debit));
    assert_eq!(
        consume(&mut service, &handover, Some(&consent)),
        Ok(WireReply::Changed(true))
    );
    let selected = service.anchor.current().unwrap().unwrap();
    assert_eq!(selected.sequence, after_debit.sequence + 1);
    assert_eq!(
        consume(&mut service, &handover, Some(&consent)),
        Err(WireError::Recovery(RecoveryError::AttachmentRejected))
    );
    drop(service);

    let anchor = make_head();
    let mut substituted = next.clone();
    substituted.response_ttl_seconds += 1;
    let wrong = Ed25519Security::new(substituted, key(11), SystemClock).unwrap();
    assert!(matches!(
        PersistentAuthority::open(path.file(), make_head(), attach(&anchor, wrong)),
        Err(RecoveryError::AttachmentRejected)
    ));
    let attached = attach(&anchor, next_provider());
    let mut service = PersistentAuthority::open(path.file(), anchor, attached).unwrap();
    assert_eq!(cut(&mut service).authority_epoch, 10);
    assert_eq!(mass(&mut service, b), (5, 5, 0));
    assert_eq!(
        service
            .transact(|p| p.reads.authority.state.primary.owners[&17])
            .unwrap(),
        8
    );
    let mut cancel = lock_core(9, proposal.expected.revision, b, 0, 66);
    let Body::LockManagement(op) = cancel.body.as_mut().unwrap() else {
        panic!("lock");
    };
    op.opcode = Some(3);
    let signature = recovery_proof(&cancel, FORMER, 2, 7);
    let Body::LockManagement(op) = cancel.body.as_mut().unwrap() else {
        panic!("lock");
    };
    op.blobs[1] = signature;
    let cancel = signed_at(cancel, 7, now(), 180);
    let old_enforcement = spend_packet(
        &old_provider,
        67,
        proposal.expected.revision,
        CommitRef { position },
        false,
    );
    for route in [
        Entry::Normal,
        Entry::Administrative,
        Entry::ForceInclusion,
        Entry::Upgrade,
        Entry::Adapter,
    ] {
        for (packet, local) in [(&debit, 0), (&cancel, 0), (&old_enforcement, 2)] {
            assert_eq!(
                service.receive_wire(
                    &channel_at(6, 7, local, 0),
                    route,
                    packet,
                    &credentials(&worker(), packet),
                    DeliveryWindow::default(),
                ),
                Err(WireError::InvalidSource)
            );
        }
    }
    assert_eq!(service.anchor.current().unwrap(), Some(selected));

    let mut owner_read = core_with(4, 7, 0, 65, vec![3, 17], Vec::new());
    owner_read.principal = Some(8);
    owner_read.key_id = Some(12);
    owner_read.authority_epoch = Some(10);
    let owner_read = signed_at(owner_read, 10, now(), 180);
    assert_eq!(
        receive(
            &mut service,
            &channel(11, 10),
            &new_owner(),
            &owner_read,
            None
        ),
        Ok(WireReply::Observation(Observation::Owner(Some(8)))),
    );

    let generation = 0;
    let pending = lock_core(10, cut(&mut service).revision, b, generation, 54);
    let denied = fence(
        &mut service,
        &new_link,
        &new_worker(),
        &new_owner(),
        pending,
        SUCCESSOR,
        10,
        false,
    )
    .unwrap();
    assert!(
        matches!(ordinary(denied), Collection::Collected(outcome) if outcome.reply == OutcomeReply::Rejected)
    );
    assert_eq!(mass(&mut service, b), (5, 5, 0));

    let journal = source_writer("handover");
    let stored = source_record(b, TerminalKind::Reversed, 42);
    assert!(journal.record(&stored).unwrap());
    let reader = source_reader("handover");
    let evidence = certificate(&reader, b.origin);
    assert_eq!(evidence.statement.origin_epoch, 9);
    let before = service.anchor.current().unwrap();
    let old_refund = call(
        1,
        4,
        0,
        68,
        proposal.expected.revision,
        b,
        true,
        &[0, 42],
        Some(&evidence),
    );
    for route in [
        Entry::Normal,
        Entry::Administrative,
        Entry::ForceInclusion,
        Entry::Upgrade,
        Entry::Adapter,
    ] {
        assert_eq!(
            service.receive_wire(
                &old_link,
                route,
                &old_refund,
                &credentials(&worker(), &old_refund),
                DeliveryWindow::default(),
            ),
            Err(WireError::InvalidSource)
        );
    }
    assert_eq!(service.anchor.current().unwrap(), before);
    let revision = cut(&mut service).revision;
    let record = call(1, 2, 0, 55, revision, b, false, &[2, 42], Some(&evidence));
    let record = signed_at(current_core(&record, false), 7, now(), 180);
    did(
        receive(&mut service, &new_link, &new_worker(), &record, None).unwrap(),
        Reply::Recorded,
    );
    let refund = call(
        1,
        4,
        0,
        56,
        cut(&mut service).revision,
        b,
        true,
        &[0, 42],
        Some(&evidence),
    );
    let refund = current_core(&refund, true);
    let worker_token = new_worker();
    let owner_token = new_owner();
    let packet = signed_at(refund.clone(), 7, now(), 180);
    let wrong_signature = recovery_proof(&refund, FORMER, 2, 7);
    let wrong = Credentials {
        token: &worker_token,
        proof: SessionProof {
            session: 2,
            epoch: 10,
        },
        signature: &wrong_signature,
    };
    assert_eq!(
        receive(
            &mut service,
            &new_link,
            &worker_token,
            &packet,
            Some(&wrong)
        ),
        Err(WireError::ProductRejected)
    );
    let signature = recovery_proof(&refund, SUCCESSOR, 3, 10);
    let owner = Credentials {
        token: &owner_token,
        proof: SessionProof {
            session: 3,
            epoch: 10,
        },
        signature: &signature,
    };
    let apply = |service: &mut Service| {
        receive(service, &new_link, &worker_token, &packet, Some(&owner)).unwrap()
    };
    assert_eq!(ordinary(apply(&mut service)), Collection::Waiting);
    assert_eq!(mass(&mut service, b), (10, 0, 0));
    let publish = call(1, 5, 0, 63, cut(&mut service).revision, b, false, &[], None);
    let publish = signed_at(current_core(&publish, false), 7, now(), 180);
    did(
        receive(&mut service, &new_link, &worker_token, &publish, None).unwrap(),
        Reply::Published,
    );
    let exact = ordinary(apply(&mut service));
    assert!(
        matches!(exact, Collection::Collected(outcome) if outcome.reply == OutcomeReply::Accepted(Reply::Refunded))
    );
    let original = decode_packet(&packet, packet.len()).unwrap();
    let mut receipt = core_with(4, 8, 0, 64, vec![2], vec![original.core_bytes().to_vec()]);
    receipt.authority_epoch = Some(10);
    let receipt = signed_at(receipt, 7, now(), 180);
    assert_eq!(
        receive(&mut service, &new_link, &worker_token, &receipt, None).unwrap(),
        WireReply::Receipt(Some(Receipt::Ordinary(exact))),
    );
    assert_eq!(mass(&mut service, b), (10, 0, 0));

    let other = Binding {
        origin: crate::OriginKey {
            event: 19,
            ..b.origin
        },
        ..b
    };
    let revision = cut(&mut service).revision;
    let reserve = call(3, 1, 0, 57, revision, other, false, &[30], None);
    let reserve = signed_at(current_core(&reserve, false), 7, now(), 180);
    did(
        receive(&mut service, &new_link, &worker_token, &reserve, None).unwrap(),
        Reply::Reserved,
    );
    let dispatch = call(3, 2, 0, 58, revision + 1, other, true, &[0], None);
    let dispatch = signed_at(current_core(&dispatch, true), 7, now(), 180);
    did(
        receive(&mut service, &new_link, &worker_token, &dispatch, None).unwrap(),
        Reply::SourceDispatched,
    );
    let revision = cut(&mut service).revision;
    let expired_session = lock_core(9, revision, other, 0, 59);
    assert_eq!(
        fence(
            &mut service,
            &old_link,
            &worker(),
            &former,
            expired_session,
            FORMER,
            7,
            false
        ),
        Err(WireError::InvalidSource)
    );
    let wrong_embedded = lock_core(10, revision, other, 0, 60);
    assert_eq!(
        fence(
            &mut service,
            &new_link,
            &worker_token,
            &owner_token,
            wrong_embedded,
            SUCCESSOR,
            10,
            true
        ),
        Err(WireError::ProductRejected)
    );
    let stale_gen = lock_core(10, revision, other, 1, 61);
    let denied = fence(
        &mut service,
        &new_link,
        &worker_token,
        &owner_token,
        stale_gen,
        SUCCESSOR,
        10,
        false,
    )
    .unwrap();
    assert!(
        matches!(ordinary(denied), Collection::Collected(outcome) if outcome.reply == OutcomeReply::Rejected)
    );
    let exact = lock_core(10, cut(&mut service).revision, other, 0, 62);
    did(
        fence(
            &mut service,
            &new_link,
            &worker_token,
            &owner_token,
            exact,
            SUCCESSOR,
            10,
            false,
        )
        .unwrap(),
        Reply::Closed,
    );
    println!(
        "dual handover selected epoch 10, owner 8, sessions 2 and 3; old epoch 9 origin resolved once; only exact current owner Fence closed the dispatched lock"
    );
}

#[test]
#[ignore = "requires isolated Linux authority and witness etcd"]
fn reference_handover_live_successor_revoked_after_prepare() {
    let root = std::env::temp_dir().join(format!("oip-handover-revoke-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let writer = WitnessWriter {
        generation: 1,
        identity: [32; 32],
    };
    let make_head = || head_at(&root, writer, "handover-revoked");
    let (old, next) = configurations();
    let clock = PauseClock::default();
    let provider = current(&old, &next, SystemClock);
    let issuer = SessionIssuer::new(key(8));
    let former = issuer.issue(&provider, 7, 1, 300).unwrap();
    let incoming = issuer.issue(&provider, 8, 1, 300).unwrap();
    let maintainer = MaintenanceIssuer::new(key(9))
        .issue(&provider, 7, 300)
        .unwrap();
    let path = JournalPath::create();
    let anchor = make_head();
    let attached = attach(&anchor, current(&old, &next, clock.clone()));
    let prepared = anchor
        .prepare_genesis(
            &mut path.file(),
            genesis(10, 1),
            current(&old, &next, clock.clone()),
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
    let previous = service.anchor.current().unwrap();
    let proposal = Handover {
        asset: 17,
        previous: 7,
        successor: 8,
        expected: cut(&mut service),
        old_session: 1,
        new_session: 3,
        epoch: 10,
        contexts: contexts(10),
    };
    let left = key(7)
        .sign(
            &provider
                .handover_consent_signing_bytes(FORMER, &proposal)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let right = key(10)
        .sign(
            &provider
                .handover_consent_signing_bytes(SUCCESSOR, &proposal)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let packet = proposal_packet(&proposal, 51, &left, &right);
    let (reached, waiting) = mpsc::channel();
    let (release, paused) = mpsc::channel();
    let file = path.file();
    let length = file.metadata().unwrap().len();
    *clock.0.lock().unwrap() = Some((file, length, reached, paused));
    let handover = |service: &mut Service<PauseClock>| {
        service.receive_wire(
            &channel(6, 7),
            Entry::Normal,
            &packet,
            &WireCredentials {
                maintenance: Some(&maintainer),
                previous: Some(&Consent {
                    token: &former,
                    signature: &left,
                }),
                successor: Some(&Consent {
                    token: &incoming,
                    signature: &right,
                }),
                ..credentials(&former, &packet)
            },
            DeliveryWindow::default(),
        )
    };
    std::thread::scope(|scope| {
        let result = scope.spawn(|| handover(&mut service));
        waiting.recv_timeout(Duration::from_secs(20)).unwrap();
        assert!(make_head().revoke(8).unwrap());
        release.send(()).unwrap();
        assert_eq!(
            result.join().unwrap(),
            Err(WireError::Recovery(RecoveryError::Hold))
        );
    });
    assert_eq!(handover(&mut service), Err(WireError::InvalidSource));
    assert_eq!(service.anchor.current().unwrap(), previous);
    assert_eq!(cut(&mut service), proposal.expected);
    assert_eq!(
        service
            .transact(|p| p.reads.authority.state.primary.owners[&17])
            .unwrap(),
        7
    );
    println!(
        "successor revocation after sync kept the previous witness head and owner; exact retry denied"
    );
}
