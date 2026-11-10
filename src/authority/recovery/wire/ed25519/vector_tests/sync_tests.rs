use super::reference_execution_trace::channel_for;
use super::*;
use crate::SessionBinding;
use crate::authority::CommitRef;
use crate::authority::identity::{ActionReply, Consent, Entry, Observation, Receipt};
use crate::authority::reads::{CurrentRead, ReadError, Value};
use crate::authority::recovery::ordered::OrderedHead;
use crate::authority::recovery::vector_tests::{JournalPath, SUCCESSOR, contexts, genesis};
use crate::authority::recovery::wire::response::{ResponseCode, ResponseStatus, admit_response};
use crate::authority::recovery::wire::vector_tests::ordered_tests::MemoryControl;
use crate::authority::recovery::wire::vector_tests::{core_with, operation, signed, uint256};
use crate::authority::recovery::wire::{DeliveryWindow, Received, WireCredentials, WireReply};
use crate::authority::recovery::{
    AnchorHead, Attachment, AuthenticatedHead, PersistentAuthority, exact_image,
};
use crate::authority::sync::{Commitment, Outcome, Stream};
use crate::wire::admission::Arrival;
use crate::wire::operands::SyncMode;
use crate::wire::source_attestation::{self, SourceSignature, SourceStatement};
use std::io::Write;

pub(super) const STREAM: Stream = Stream {
    asset: 17,
    origin_domain: 30,
};
const OTHER: Stream = Stream {
    asset: 17,
    origin_domain: 31,
};
type Service = PersistentAuthority<Ed25519Security<FixedClock>, OrderedHead<MemoryControl>>;

fn roster(epoch: u64, roster_id: u64) -> source::SyncRoster {
    source::SyncRoster {
        origin_epoch: epoch,
        roster_id,
        quorum: 2,
        signers: BTreeMap::from([
            (101, key(21).verifying_key().to_bytes()),
            (102, key(22).verifying_key().to_bytes()),
        ]),
    }
}

pub(super) fn enabled() -> Ed25519Profile {
    let mut policy = config();
    policy.sync = source::SyncPolicy {
        accept_sync: true,
        accept_current: true,
        rosters: BTreeMap::from([(30, roster(6, 11)), (31, roster(6, 12))]),
    };
    let sessions = &mut policy.peers.get_mut(&7).unwrap().sessions;
    let grant = sessions.get_mut(&2).unwrap().get_mut(&0).unwrap();
    grant
        .current
        .extend([Query::Commitment(STREAM), Query::Commitment(OTHER)]);
    let mut recovery = grant.clone();
    recovery.full_resync.insert(STREAM);
    sessions.insert(3, BTreeMap::from([(0, recovery)]));
    policy
}

fn anchor(control: &MemoryControl) -> OrderedHead<MemoryControl> {
    OrderedHead::new(control.clone(), DEFAULT_PROFILE, 1)
}

fn attach(
    security: Ed25519Security<FixedClock>,
) -> Attachment<Ed25519Security<FixedClock>, (RecoveryProfile, bool)> {
    Attachment {
        profile: DEFAULT_PROFILE,
        source_connected: true,
        proof: (DEFAULT_PROFILE, true),
        security,
    }
}

fn security(policy: Ed25519Profile) -> Ed25519Security<FixedClock> {
    Ed25519Security::new(policy, key(6), FixedClock(105)).unwrap()
}

pub(super) fn initial() -> crate::authority::identity::Bootstrap {
    let mut initial = genesis(10, 1);
    initial.sessions.insert(
        3,
        SessionBinding {
            principal: 7,
            authority_epoch: 9,
        },
    );
    initial
}

fn credentials<'a>(
    client: &'a SessionToken,
    bytes: &'a Vec<u8>,
) -> WireCredentials<'a, Ed25519Security<FixedClock>> {
    WireCredentials {
        token: client,
        signature: bytes,
        maintenance: None,
        endorsement: None,
        previous: None,
        successor: None,
    }
}

fn receive(
    service: &mut Service,
    client: &SessionToken,
    bytes: &Vec<u8>,
) -> Result<Received, WireError> {
    service.receive_wire(
        &channel_for(6, 7),
        Entry::Normal,
        bytes,
        &credentials(client, bytes),
        DeliveryWindow::default(),
    )
}

fn recorded(
    service: &mut Service,
    client: &SessionToken,
    bytes: &Vec<u8>,
    expected: ResponseCode,
    commit: Option<usize>,
) {
    let response = service
        .receive_wire_response(
            &channel_for(6, 7),
            Entry::Normal,
            bytes,
            &credentials(client, bytes),
            DeliveryWindow::default(),
        )
        .unwrap();
    let result = verified_response(bytes, &response);
    assert_eq!(result.code, ResponseStatus::Known(expected));
    assert_eq!(result.commit, commit.map(|position| CommitRef { position }));
    let head = selected(service);
    let image = exact_image(&mut service.file, head).unwrap().image;
    let cut = image.authority.primary.ledger.current_cut();
    let original = decode_packet(bytes, bytes.len()).unwrap();
    println!(
        "sync-response\t{}\t{}\t{:?}\t{}\t{}\t{:x}",
        result.id.sequence,
        result.code.known().unwrap() as u64,
        result.commit.map(|commit| commit.position),
        cut.authority_epoch,
        cut.revision,
        Sha256::digest(original.core_bytes())
    );
}

pub(super) fn verified_response(
    bytes: &[u8],
    response: &[u8],
) -> crate::authority::recovery::wire::response::VerifiedResponse {
    let original = decode_packet(bytes, bytes.len()).unwrap();
    let boundary = Boundary {
        deployment: 7,
        source: 0,
        target: 0,
        principal: 42,
        key_id: 3,
        epoch: original.core().authority_epoch.unwrap(),
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
    admit_response(&channel_for(7, 6), &boundary, &original, response).unwrap()
}

pub(super) fn statement(
    stream: Stream,
    event: u64,
    position: u64,
    value: u8,
    predecessor: Option<[u8; 32]>,
) -> SourceStatement {
    SourceStatement {
        deployment: 7,
        origin_domain: stream.origin_domain,
        origin_epoch: 6,
        roster_id: stream.origin_domain - 19,
        asset: stream.asset,
        origin_event: event,
        source_position: position,
        commitment: [value; 32],
        predecessor,
    }
}

fn vote(statement: &SourceStatement, signer_id: u64, seed: u8) -> SourceSignature {
    SourceSignature {
        signer_id,
        signature: key(seed).sign(&statement.signing_bytes()).to_bytes(),
    }
}

fn proof(statement: &SourceStatement) -> Vec<u8> {
    proof_with_keys(statement, [21, 22])
}

fn proof_with_keys(statement: &SourceStatement, keys: [u8; 2]) -> Vec<u8> {
    source_attestation::encode(
        statement,
        &[vote(statement, 101, keys[0]), vote(statement, 102, keys[1])],
    )
    .unwrap()
}

pub(super) fn call(
    statement: &SourceStatement,
    mode: SyncMode,
    session: u64,
    revision: u64,
    tag: u8,
    attestation: Vec<u8>,
) -> Core {
    let id = u64::from(tag);
    core_with(
        1,
        7,
        0,
        tag,
        vec![
            id + 500,
            id,
            session,
            revision,
            statement.origin_epoch,
            statement.origin_domain,
            statement.origin_event,
            statement.asset,
            statement.source_position,
            mode as u64,
        ],
        vec![
            statement.commitment.to_vec(),
            statement
                .predecessor
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default(),
            attestation,
        ],
    )
}

fn packet(
    statement: &SourceStatement,
    mode: SyncMode,
    session: u64,
    revision: u64,
    tag: u8,
) -> Vec<u8> {
    signed(call(
        statement,
        mode,
        session,
        revision,
        tag,
        proof(statement),
    ))
}

fn current(session: u64, revision: u64, stream: Stream, tag: u8) -> Vec<u8> {
    signed(core_with(
        4,
        9,
        0,
        tag,
        vec![session, revision, stream.asset, stream.origin_domain],
        vec![],
    ))
}

fn receipt(original: &[u8], session: u64, tag: u8) -> Vec<u8> {
    let decoded = decode_packet(original, original.len()).unwrap();
    signed(core_with(
        4,
        8,
        0,
        tag,
        vec![session],
        vec![decoded.core_bytes().to_vec()],
    ))
}

fn current_reply(revision: usize, entry: Option<Commitment>) -> WireReply {
    WireReply::Observation(Observation::Current(Ok(CurrentRead {
        cut: CommitCut {
            authority_epoch: 9,
            revision,
        },
        value: Value::Commitment(entry),
    })))
}

pub(super) fn entry(statement: SourceStatement) -> Commitment {
    Commitment {
        commitment: statement.commitment,
        source_position: statement.source_position,
        origin_epoch: statement.origin_epoch,
        origin_event: statement.origin_event,
    }
}

fn selected(service: &Service) -> AnchorHead {
    service.anchor.current().unwrap().unwrap()
}

#[test]
fn sync_product_reopens_exact_bytes_from_the_previous_authority() {
    let policy_bytes = include_bytes!("prior-policy.json");
    let policy: Ed25519Profile = serde_json::from_slice(policy_bytes).unwrap();
    assert!(policy.sync.is_empty());
    assert!(
        policy
            .peers
            .values()
            .flat_map(|peer| peer.sessions.values())
            .all(|grants| { grants.values().all(|grant| grant.full_resync.is_empty()) })
    );
    assert_eq!(serde_json::to_vec(&policy).unwrap(), policy_bytes);

    let image_bytes = include_bytes!("prior-authority-record.json");
    let head = AnchorHead {
        profile: DEFAULT_PROFILE,
        sequence: 0,
        offset: 0,
        length: image_bytes.len() as u64,
        digest: Sha256::digest(image_bytes).into(),
    };
    let path = JournalPath::create();
    let mut file = path.file();
    file.write_all(image_bytes).unwrap();
    file.sync_all().unwrap();
    let control = MemoryControl::with_head(Some(head));
    let mut service =
        PersistentAuthority::open(file, anchor(&control), attach(security(policy))).unwrap();
    let opened = exact_image(&mut service.file, head).unwrap();
    assert_eq!(serde_json::to_vec(&opened).unwrap(), image_bytes);
    assert_eq!(selected(&service), head);
    println!(
        "sync-prior-bytes\t{:x}\t{:x}",
        Sha256::digest(policy_bytes),
        Sha256::digest(image_bytes)
    );
}

#[test]
fn sync_product_handover_selects_new_roster_and_explicit_active_session_grants() {
    let mut old = enabled();
    old.handover_maintainers.insert(7);
    old.peers
        .get_mut(&7)
        .unwrap()
        .sessions
        .get_mut(&1)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .transfer_owner
        .insert(STREAM.asset);
    old.peers.insert(
        8,
        PeerRegistration {
            identity: SUCCESSOR,
            key_id: 12,
            public_key: key(10).verifying_key().to_bytes(),
            sessions: BTreeMap::from([(4, BTreeMap::from([(0, EndpointGrant::default())]))]),
        },
    );
    let mut next = old.clone();
    next.authority_epoch = 10;
    let grants = &mut next.peers.get_mut(&7).unwrap().sessions;
    grants.remove(&1);
    grants
        .get_mut(&3)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .full_resync
        .clear();
    grants
        .get_mut(&2)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .current
        .retain(|query| *query != Query::Commitment(STREAM));
    let roster = next.sync.rosters.get_mut(&STREAM.origin_domain).unwrap();
    roster.origin_epoch = 7;
    roster.roster_id = 14;
    roster.signers = BTreeMap::from([
        (101, key(25).verifying_key().to_bytes()),
        (102, key(26).verifying_key().to_bytes()),
    ]);
    let old = security(old);
    let next_contexts = contexts(10);
    let ready = old
        .successor_readiness_signing_bytes(&next, &next_contexts)
        .unwrap();
    let old = old
        .with_successor(
            next.clone(),
            next_contexts.clone(),
            &key(6).sign(&ready).to_bytes(),
        )
        .unwrap();
    let path = JournalPath::create();
    let control = MemoryControl::with_head(None);
    let mut service =
        PersistentAuthority::initialize(path.file(), anchor(&control), attach(old), initial())
            .unwrap();
    let old_client = token(&service.security, 3, 100);
    let first = statement(STREAM, 70, 90, 3, None);
    let original = packet(&first, SyncMode::Initial, 3, 0, 70);
    recorded(
        &mut service,
        &old_client,
        &original,
        ResponseCode::StateCommitmentSynced,
        Some(0),
    );

    let proposal = Handover {
        asset: STREAM.asset,
        previous: 7,
        successor: 8,
        old_session: 1,
        new_session: 4,
        expected: CommitCut {
            authority_epoch: 9,
            revision: 1,
        },
        epoch: 10,
        contexts: next_contexts,
    };
    let previous = key(7)
        .sign(
            &service
                .security
                .handover_consent_signing_bytes(FORMER, &proposal)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let successor = key(10)
        .sign(
            &service
                .security
                .handover_consent_signing_bytes(SUCCESSOR, &proposal)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let signed_proposal = signed(core_with(
        7,
        1,
        0,
        71,
        vec![1, 1, STREAM.asset, 7, 8, 1, 4, 10],
        vec![
            serde_json::to_vec(&proposal.contexts).unwrap(),
            previous.clone(),
            successor.clone(),
        ],
    ));
    let issuer = SessionIssuer::new(key(8));
    let previous_token = issuer.issue(&service.security, 7, 1, 300).unwrap();
    let successor_token = issuer.issue(&service.security, 8, 4, 300).unwrap();
    let maintenance = MaintenanceIssuer::new(key(9))
        .issue(&service.security, 7, 300)
        .unwrap();
    let credentials = WireCredentials {
        previous: Some(&Consent {
            token: &previous_token,
            signature: &previous,
        }),
        successor: Some(&Consent {
            token: &successor_token,
            signature: &successor,
        }),
        maintenance: Some(&maintenance),
        ..credentials(&previous_token, &signed_proposal)
    };
    let handover = service
        .receive_wire(
            &channel_for(6, 7),
            Entry::Normal,
            &signed_proposal,
            &credentials,
            DeliveryWindow::default(),
        )
        .unwrap();
    assert_eq!(handover.reply, WireReply::Changed(true));
    drop(service);
    let mut service =
        PersistentAuthority::open(path.file(), anchor(&control), attach(security(next))).unwrap();
    let current_head = selected(&service);
    let image = exact_image(&mut service.file, current_head).unwrap().image;
    let cut = image.authority.primary.ledger.current_cut();
    assert_eq!(cut.authority_epoch, 10);
    assert_eq!(
        image.authority.primary.sync.entries.get(&STREAM),
        Some(&entry(first))
    );
    assert_eq!(
        receive(&mut service, &old_client, &original),
        Err(WireError::InvalidSource)
    );
    let client = token(&service.security, 3, 100);
    let no_read = token(&service.security, 2, 100);
    let current_packet = |session, revision, tag| {
        let mut core = core_with(
            4,
            9,
            0,
            tag,
            vec![session, revision, STREAM.asset, STREAM.origin_domain],
            vec![],
        );
        core.authority_epoch = Some(10);
        signed(core)
    };
    let revision = cut.revision as u64;
    assert_eq!(
        receive(&mut service, &no_read, &current_packet(2, revision, 72)),
        Err(WireError::ProductRejected)
    );
    let query = receive(&mut service, &client, &current_packet(3, revision, 73)).unwrap();
    assert_eq!(
        query.reply,
        WireReply::Observation(Observation::Current(Ok(CurrentRead {
            cut,
            value: Value::Commitment(Some(entry(first))),
        })))
    );

    let current = SourceStatement {
        origin_epoch: 7,
        roster_id: 14,
        origin_event: 71,
        source_position: 91,
        ..first
    };
    let after_handover = |statement: &SourceStatement, mode, label, keys| {
        let mut core = call(
            statement,
            mode,
            3,
            revision,
            label,
            proof_with_keys(statement, keys),
        );
        core.authority_epoch = Some(10);
        signed(core)
    };
    let old_roster = SourceStatement {
        origin_epoch: 6,
        roster_id: 11,
        ..current
    };
    recorded(
        &mut service,
        &client,
        &after_handover(&old_roster, SyncMode::FullResync, 74, [21, 22]),
        ResponseCode::SourceAttestationRejected,
        None,
    );
    recorded(
        &mut service,
        &client,
        &after_handover(&current, SyncMode::FullResync, 75, [25, 26]),
        ResponseCode::StateCommitmentMismatch,
        None,
    );
    let incremental = SourceStatement {
        predecessor: Some(first.commitment),
        ..current
    };
    let stale = SourceStatement {
        source_position: first.source_position,
        ..incremental
    };
    recorded(
        &mut service,
        &client,
        &after_handover(&stale, SyncMode::Incremental, 76, [25, 26]),
        ResponseCode::StateCommitmentStale,
        None,
    );
    recorded(
        &mut service,
        &client,
        &after_handover(&incremental, SyncMode::Incremental, 77, [25, 26]),
        ResponseCode::StateCommitmentSynced,
        Some(cut.revision),
    );
    println!(
        "sync-product\thandover-roster-and-grants\t9\t10\t{}\t{}",
        cut.revision,
        cut.revision + 1
    );
}

#[test]
fn sync_product_records_exact_outcomes_and_recovers_the_selected_value() {
    let path = JournalPath::create();
    let control = MemoryControl::with_head(None);
    let mut service = PersistentAuthority::initialize(
        path.file(),
        anchor(&control),
        attach(security(enabled())),
        initial(),
    )
    .unwrap();
    let client = token(&service.security, 2, 100);
    let restricted = token(&service.security, 1, 100);
    let recovery = token(&service.security, 3, 100);
    let absence = current(2, 0, STREAM, 1);
    assert_eq!(
        receive(&mut service, &client, &absence).unwrap().reply,
        current_reply(0, None)
    );
    let unauthorized = current(1, 0, STREAM, 2);
    assert_eq!(
        receive(&mut service, &restricted, &unauthorized),
        Err(WireError::ProductRejected)
    );

    let zero = statement(STREAM, 10, 40, 0, None);
    let initial = packet(&zero, SyncMode::Initial, 2, 0, 3);
    let before = selected(&service);
    assert_eq!(
        service.receive_wire(
            &channel_for(6, 7),
            Entry::Normal,
            &initial,
            &credentials(&client, &initial),
            DeliveryWindow {
                response_lost: true,
                ..DeliveryWindow::default()
            },
        ),
        Err(WireError::ResponseLost)
    );
    let after = selected(&service);
    assert_ne!(before, after);
    let record = exact_image(&mut service.file, after).unwrap();
    assert_eq!(
        record.image.authority.primary.sync.entries.get(&STREAM),
        Some(&entry(zero))
    );
    assert_eq!(
        record.image.authority.primary.ledger.current_cut().revision,
        1
    );
    println!(
        "sync-selected\t{}\t{}\t{:x}",
        after.sequence,
        after.offset,
        Sha256::digest(&initial)
    );
    drop(service);
    let mut service =
        PersistentAuthority::open(path.file(), anchor(&control), attach(security(enabled())))
            .unwrap();
    assert_eq!(
        receive(&mut service, &client, &initial).unwrap(),
        Received {
            arrival: Arrival::Identical,
            reply: WireReply::Executed(ActionReply::SyncCommitment(Outcome::Synced(CommitRef {
                position: 0
            }))),
        }
    );
    assert_eq!(selected(&service), after);
    recorded(
        &mut service,
        &client,
        &initial,
        ResponseCode::StateCommitmentSynced,
        Some(0),
    );
    let exact = receipt(&initial, 2, 4);
    assert_eq!(
        receive(&mut service, &client, &exact).unwrap().reply,
        WireReply::Receipt(Some(Receipt::SyncCommitment(Outcome::Synced(CommitRef {
            position: 0
        }))))
    );
    assert_eq!(
        receive(&mut service, &client, &absence).unwrap().reply,
        WireReply::Observation(Observation::Current(Err(ReadError::Busy)))
    );
    assert_eq!(
        receive(&mut service, &client, &current(2, 1, STREAM, 5))
            .unwrap()
            .reply,
        current_reply(1, Some(entry(zero)))
    );
    let wrong_scope = current(
        2,
        1,
        Stream {
            asset: 17,
            origin_domain: 99,
        },
        6,
    );
    assert_eq!(
        receive(&mut service, &client, &wrong_scope),
        Err(WireError::ProductRejected)
    );

    let mut changed = decode_packet(&initial, initial.len())
        .unwrap()
        .core()
        .clone();
    operation(&mut changed).words[0] += 1;
    assert_eq!(
        receive(&mut service, &client, &signed(changed.clone())),
        Err(WireError::ReplayConflict)
    );
    changed.uuid.as_mut().unwrap()[0] = 7;
    let changed = signed(changed);
    assert_eq!(
        receive(&mut service, &client, &changed),
        Err(WireError::ProductRejected)
    );
    assert!(receive(&mut service, &client, &receipt(&changed, 2, 8)).is_err());

    let incremental = statement(STREAM, 11, 42, 9, Some([0; 32]));
    let stale_cut = signed(call(&incremental, SyncMode::Incremental, 2, 0, 9, vec![]));
    recorded(&mut service, &client, &stale_cut, ResponseCode::Busy, None);
    let invalid_proof = signed(call(&incremental, SyncMode::Incremental, 2, 1, 10, vec![]));
    recorded(
        &mut service,
        &client,
        &invalid_proof,
        ResponseCode::SourceAttestationRejected,
        None,
    );
    let valid = packet(&incremental, SyncMode::Incremental, 2, 1, 11);
    recorded(
        &mut service,
        &client,
        &valid,
        ResponseCode::StateCommitmentSynced,
        Some(1),
    );
    recorded(
        &mut service,
        &client,
        &invalid_proof,
        ResponseCode::SourceAttestationRejected,
        None,
    );
    recorded(&mut service, &client, &stale_cut, ResponseCode::Busy, None);

    let wrong_predecessor = statement(STREAM, 12, 43, 10, Some([0; 32]));
    recorded(
        &mut service,
        &client,
        &packet(&wrong_predecessor, SyncMode::Incremental, 2, 2, 12),
        ResponseCode::StateCommitmentMismatch,
        None,
    );
    let changed_event = statement(STREAM, 11, 43, 10, Some([9; 32]));
    recorded(
        &mut service,
        &client,
        &packet(&changed_event, SyncMode::Incremental, 2, 2, 13),
        ResponseCode::StateCommitmentStale,
        None,
    );
    let stale_position = statement(STREAM, 12, 42, 10, Some([9; 32]));
    recorded(
        &mut service,
        &client,
        &packet(&stale_position, SyncMode::Incremental, 2, 2, 14),
        ResponseCode::StateCommitmentStale,
        None,
    );

    let independent = statement(OTHER, 10, 1, 17, None);
    recorded(
        &mut service,
        &client,
        &packet(&independent, SyncMode::Initial, 2, 2, 15),
        ResponseCode::StateCommitmentSynced,
        Some(2),
    );
    let snapshot = statement(STREAM, 12, 43, 10, None);
    recorded(
        &mut service,
        &client,
        &packet(&snapshot, SyncMode::FullResync, 2, 3, 16),
        ResponseCode::StateCommitmentMismatch,
        None,
    );
    let bad_proof = signed(call(&snapshot, SyncMode::FullResync, 2, 3, 17, vec![]));
    recorded(
        &mut service,
        &client,
        &bad_proof,
        ResponseCode::SourceAttestationRejected,
        None,
    );
    recorded(
        &mut service,
        &recovery,
        &packet(&snapshot, SyncMode::FullResync, 3, 3, 18),
        ResponseCode::StateCommitmentSynced,
        Some(3),
    );
    assert_eq!(
        receive(&mut service, &client, &current(2, 4, STREAM, 19))
            .unwrap()
            .reply,
        current_reply(4, Some(entry(snapshot)))
    );
    assert_eq!(
        receive(&mut service, &client, &current(2, 4, OTHER, 20))
            .unwrap()
            .reply,
        current_reply(4, Some(entry(independent)))
    );
    let final_head = selected(&service);
    assert_eq!(service.anchor.revoke(7), Ok(true));
    assert_eq!(
        receive(&mut service, &client, &initial),
        Err(WireError::InvalidSource)
    );
    assert_eq!(
        receive(&mut service, &client, &exact),
        Err(WireError::InvalidSource)
    );
    assert_eq!(
        receive(&mut service, &client, &current(2, 4, STREAM, 21)),
        Err(WireError::InvalidSource)
    );
    assert_eq!(selected(&service), final_head);
}

#[test]
fn sync_product_checks_operation_scope_and_all_votes_before_recording() {
    let path = JournalPath::create();
    let control = MemoryControl::with_head(None);
    let mut disabled = PersistentAuthority::initialize(
        path.file(),
        anchor(&control),
        attach(security(config())),
        genesis(10, 1),
    )
    .unwrap();
    let origin = statement(STREAM, 30, 50, 1, None);
    let mut bytes = packet(&origin, SyncMode::Initial, 2, 0, 30);
    let client = token(&disabled.security, 2, 100);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        receive(&mut disabled, &client, &bytes),
        Err(WireError::UnsupportedVersion)
    );
    assert_eq!(
        receive(&mut disabled, &client, &current(2, 0, STREAM, 31)),
        Err(WireError::UnsupportedVersion)
    );
    assert_eq!(selected(&disabled).sequence, 0);
    drop(disabled);

    let path = JournalPath::create();
    let control = MemoryControl::with_head(None);
    let mut service = PersistentAuthority::initialize(
        path.file(),
        anchor(&control),
        attach(security(enabled())),
        initial(),
    )
    .unwrap();
    let client = token(&service.security, 2, 100);
    let readonly = token(&service.security, 1, 100);
    let unauthorized = packet(&origin, SyncMode::Initial, 1, 0, 32);
    assert_eq!(
        receive(&mut service, &readonly, &unauthorized),
        Err(WireError::ProductRejected)
    );
    let mut invalid = call(&origin, SyncMode::Initial, 2, 0, 33, proof(&origin));
    operation(&mut invalid).blobs[0].pop();
    assert_eq!(
        receive(&mut service, &client, &signed(invalid)),
        Err(WireError::InvalidFormat)
    );
    assert_eq!(selected(&service).sequence, 0);

    let no_extra_key = source_attestation::encode(
        &origin,
        &[
            vote(&origin, 101, 21),
            vote(&origin, 102, 22),
            vote(&origin, 103, 23),
        ],
    )
    .unwrap();
    let one = source_attestation::encode(&origin, &[vote(&origin, 101, 21)]).unwrap();
    let wrong_roster = proof(&SourceStatement {
        roster_id: 12,
        ..origin
    });
    let wrong_deployment = proof(&SourceStatement {
        deployment: 8,
        ..origin
    });
    let wrong_commitment = proof(&SourceStatement {
        commitment: [4; 32],
        ..origin
    });
    let wrong_epoch = proof(&SourceStatement {
        origin_epoch: 5,
        ..origin
    });
    let wrong_key =
        source_attestation::encode(&origin, &[vote(&origin, 101, 21), vote(&origin, 102, 21)])
            .unwrap();
    let mut malformed = proof(&origin);
    malformed.push(0);
    for (tag, evidence) in (40..).zip([
        no_extra_key,
        one,
        wrong_roster,
        wrong_deployment,
        wrong_commitment,
        wrong_epoch,
        wrong_key,
        malformed,
    ]) {
        let rejected = signed(call(&origin, SyncMode::Initial, 2, 0, tag, evidence));
        recorded(
            &mut service,
            &client,
            &rejected,
            ResponseCode::SourceAttestationRejected,
            None,
        );
    }
    service.reconnect((DEFAULT_PROFILE, false), false).unwrap();
    let unavailable = packet(&origin, SyncMode::Initial, 2, 0, 48);
    recorded(
        &mut service,
        &client,
        &unavailable,
        ResponseCode::Unavailable,
        None,
    );
    service.reconnect((DEFAULT_PROFILE, true), true).unwrap();
    recorded(
        &mut service,
        &client,
        &unavailable,
        ResponseCode::Unavailable,
        None,
    );

    let consumed = packet(&origin, SyncMode::Initial, 2, 0, 40);
    assert_eq!(
        receive(&mut service, &client, &consumed),
        Err(WireError::ReplayConflict)
    );
    recorded(
        &mut service,
        &client,
        &packet(&origin, SyncMode::Initial, 2, 0, 49),
        ResponseCode::StateCommitmentSynced,
        Some(0),
    );
    let reserve = |id, tag| {
        signed(core_with(
            3,
            1,
            0,
            tag,
            vec![id, id, 2, 1, 9, 0, 17, 17, 7, 2, 3, 0, 1, 17, 0, 20],
            vec![uint256(5)],
        ))
    };
    assert_eq!(
        receive(&mut service, &client, &reserve(49, 50)),
        Err(WireError::ProductRejected)
    );
    recorded(
        &mut service,
        &client,
        &reserve(60, 60),
        ResponseCode::Reserved,
        Some(1),
    );
    let later = statement(STREAM, 31, 51, 2, Some(origin.commitment));
    let mut collision = call(&later, SyncMode::Incremental, 2, 2, 61, proof(&later));
    operation(&mut collision).words[1] = 60;
    assert_eq!(
        receive(&mut service, &client, &signed(collision)),
        Err(WireError::ProductRejected)
    );
    assert_eq!(
        receive(&mut service, &client, &current(2, 2, STREAM, 62))
            .unwrap()
            .reply,
        current_reply(2, Some(entry(origin)))
    );
    println!("sync-product\tcross-operation-id-collision\t77\t77\t2");

    let mut duplicate_key = enabled();
    duplicate_key
        .sync
        .rosters
        .get_mut(&30)
        .unwrap()
        .signers
        .insert(103, key(21).verifying_key().to_bytes());
    assert!(Ed25519Security::new(duplicate_key, key(6), FixedClock(105)).is_err());
    let mut zero_quorum = enabled();
    zero_quorum.sync.rosters.get_mut(&30).unwrap().quorum = 0;
    assert!(Ed25519Security::new(zero_quorum, key(6), FixedClock(105)).is_err());
}
