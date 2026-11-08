use super::super::RetainedImage;
use super::super::vector_tests::{
    Cas, DEFAULT_PROFILE, EPOCH, FORMER, HOST, JournalPath, ROOT, Rules, Service, TestAnchor, YES,
    accepted, attachment, auth, binding, contexts, cut, genesis, payload, request, sessions,
    submit,
};
use super::*;
use crate::CallId;
use crate::authority::identity::Observation;
use crate::authority::reads::{CheckedExecution, ReadError, Value};
use crate::authority::{CallPayload, Collection, CommitRef, Outcome, OutcomeReply};
use crate::lock_finality::{Account, Binding, Command, Reply, TerminalEvidence, TerminalKind};
use crate::vector_tests::{Vector, parse_vectors};

const VECTORS: &str = include_str!("../../../../tests/vectors/parallel-composition.tsv");
const OTHER: OriginKey = OriginKey {
    domain: 0,
    event: 22,
};

fn origin(event: u64) -> OriginKey {
    OriginKey { domain: 0, event }
}

fn second() -> Binding {
    Binding {
        origin: OTHER,
        asset: 22,
        ..binding()
    }
}

fn service(path: &JournalPath, anchor: &TestAnchor) -> Service {
    let b = second();
    let mut initial = genesis(10, 1);
    initial.supply.insert(b.asset, 10);
    initial.owners.insert(b.asset, FORMER.principal);
    initial.balances.insert(b.source(), 10);
    PersistentAuthority::initialize(
        path.file(),
        anchor.clone(),
        attachment(DEFAULT_PROFILE, true),
        initial,
    )
    .unwrap()
}

fn fork(path: &JournalPath, anchor: &TestAnchor) -> (JournalPath, TestAnchor, Service) {
    let (other_path, other_anchor) = path.fork(anchor);
    let other = other_path
        .reopen(&other_anchor, DEFAULT_PROFILE, true)
        .unwrap();
    (other_path, other_anchor, other)
}

fn image(service: &mut Service) -> RetainedImage {
    service
        .transact(|product| RetainedImage::capture(product))
        .unwrap()
}

fn fund(service: &mut Service, b: Binding, first: u64, publish: bool) -> SettlementKey {
    let commands = [
        (Command::Reserve { duration: 20 }, Reply::Reserved),
        (Command::Dispatch { generation: 0 }, Reply::SourceDispatched),
        (Command::Debit { generation: 0 }, Reply::Debited),
        (
            Command::RecordTerminal(TerminalEvidence {
                binding: b,
                kind: TerminalKind::Confirmed,
                reference: first,
            }),
            Reply::Recorded,
        ),
        (Command::Credit { reference: first }, Reply::Credited),
        (
            Command::Reconcile {
                generation: 0,
                reference: first,
            },
            Reply::Reconciled,
        ),
    ];
    let mut decision = None;
    for (offset, (command, expected)) in commands.into_iter().enumerate() {
        let sequence = first + offset as u64;
        let call = payload(service, b, sequence, command);
        let reply = submit(service, &call, sequence);
        if matches!(command, Command::Credit { .. }) {
            assert_eq!(
                reply,
                Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(
                    Collection::Waiting
                )))
            );
        } else {
            let commit = accepted(reply, expected);
            if matches!(command, Command::RecordTerminal(_)) {
                decision = Some(commit);
            }
        }
    }
    if publish {
        let sequence = first + 6;
        let call = payload(service, b, sequence, Command::PublishPrimary);
        accepted(submit(service, &call, sequence), Reply::Published);
    }
    SettlementKey {
        origin: b.origin,
        commit: decision.unwrap(),
    }
}

fn queue<'a>(label: u64, operation: &str, key: SettlementKey) -> Occurrence<'a, Rules> {
    Occurrence {
        label,
        action: match operation {
            "enqueue" => ServiceAction::Enqueue {
                maintenance: &HOST,
                origin: key.origin,
            },
            "dispatch" => ServiceAction::Dispatch {
                maintenance: &HOST,
                key,
            },
            "fail" => ServiceAction::Fail {
                maintenance: &HOST,
                key,
            },
            _ => panic!("unknown queue operation {operation}"),
        },
    }
}

fn exact_key(keys: &[SettlementKey], row: &Vector<'_>, letter: &str) -> SettlementKey {
    let key = keys[row.number(&format!("commit_{letter}")) as usize];
    assert_eq!(key.origin, origin(row.number(&format!("origin_{letter}"))));
    key
}

fn reply(report: &ScheduleReport, label: u64) -> &Result<ServiceReply, RecoveryError> {
    &report
        .replies
        .iter()
        .find(|entry| entry.label == label)
        .unwrap()
        .reply
}

fn attempt(report: &ScheduleReport, label: u64) -> Option<u64> {
    let Ok(ServiceReply::Dispatched(job)) = reply(report, label) else {
        panic!("expected dispatch reply")
    };
    job.map(|job| job.attempts)
}

fn schedule_name(value: Exchange) -> &'static str {
    match value {
        Exchange::Exchanged => "exchange",
        Exchange::Serialized => "serial",
    }
}

fn pair_jobs(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut left = service(&path, &anchor);
    let first = fund(&mut left, binding(), 10, true);
    let second = fund(&mut left, second(), 30, true);
    let keys = [first, second];
    let a = exact_key(&keys, row, "a");
    let b = exact_key(&keys, row, "b");
    let op_a = row.field("operation_a");
    let op_b = row.field("operation_b");
    if op_a != "enqueue" {
        assert_eq!(left.enqueue_secondary(&HOST, a.origin).unwrap(), Some(a));
        if row.input.contains_key("attempt_a") {
            assert_eq!(row.number("attempt_a"), 0);
        }
    } else {
        assert_eq!(row.field("job_a"), "absent");
    }
    if a != b {
        assert_eq!(left.enqueue_secondary(&HOST, b.origin).unwrap(), Some(b));
        if row.input.contains_key("attempt_b") {
            assert_eq!(row.number("attempt_b"), 0);
        }
    }

    let (_other_path, _other_anchor, mut right) = fork(&path, &anchor);
    let chosen = if row.field("request_exchange") == "true" {
        &[0][..]
    } else {
        &[]
    };
    let selected = left
        .schedule(&[queue(1, op_a, a), queue(2, op_b, b)], chosen)
        .unwrap();
    let mode = schedule_name(selected.exchanges[0]);
    match row.id {
        "independent-actual-dispatches" | "publication-derived-enqueue-and-other-dispatch" => {
            let baseline = right
                .schedule(&[queue(1, op_a, a), queue(2, op_b, b)], &[])
                .unwrap();
            assert_eq!(selected.replies, baseline.replies, "{}", row.id);
            let equal = image(&mut left) == image(&mut right);
            if op_a == "enqueue" {
                assert_eq!(row.field("publication_a"), "committed");
                assert_eq!(row.field("job_b"), "waiting");
                assert_eq!(reply(&selected, 1), &Ok(ServiceReply::Enqueued(Some(a))));
                format!(
                    "schedule={mode};enqueue_key_a={};reply_b_attempt={};retained_state_equal={equal}",
                    a.origin.event,
                    attempt(&selected, 2).unwrap()
                )
            } else {
                format!(
                    "schedule={mode};reply_a_attempt={};reply_b_attempt={};retained_state_equal={equal}",
                    attempt(&selected, 1).unwrap(),
                    attempt(&selected, 2).unwrap()
                )
            }
        }
        "same-slot-enqueue-dispatch-conflict" => {
            let reverse = right
                .schedule(&[queue(2, op_b, b), queue(1, op_a, a)], &[])
                .unwrap();
            let earlier = attempt(&reverse, 2).map_or("none".to_owned(), |value| value.to_string());
            let actual = attempt(&selected, 2).map_or("none".to_owned(), |value| value.to_string());
            format!("schedule={mode};reply_b_attempt={actual};unsafe_reverse_reply_b={earlier}")
        }
        "same-slot-labeled-attempts" => {
            let reverse = right
                .schedule(&[queue(2, op_b, b), queue(1, op_a, a)], &[])
                .unwrap();
            let changed = reply(&selected, 1) != reply(&reverse, 1)
                || reply(&selected, 2) != reply(&reverse, 2);
            format!(
                "schedule={mode};reply_a_attempt={};reply_b_attempt={};unsafe_reverse_changes_replies={changed}",
                attempt(&selected, 1).unwrap(),
                attempt(&selected, 2).unwrap()
            )
        }
        "same-slot-failure-conflict" => {
            assert_eq!(
                reply(&selected, 2),
                &Ok(ServiceReply::Changed(mode == "serial")),
                "{}",
                row.id
            );
            format!("schedule={mode}")
        }
        other => panic!("unknown queue vector {other}"),
    }
}

fn observation<'a>(
    label: u64,
    auth: &'a Credentials<'a, Rules>,
    target: EndpointId,
    request: ReadRequest,
) -> Occurrence<'a, Rules> {
    Occurrence {
        label,
        action: ServiceAction::Read {
            auth,
            target,
            request,
            cache: None,
        },
    }
}

fn balance_query(row: &Vector<'_>) -> ReadRequest {
    ReadRequest::Raw(Query::AccountBalance(Account {
        endpoint: row.number("domain"),
        asset: row.number("asset"),
        owner: row.number("recipient"),
    }))
}

fn read_and_dispatch(row: &Vector<'_>) -> String {
    assert_eq!(row.field("operation_a"), "raw_read");
    assert_eq!(row.field("operation_b"), "dispatch");
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut left = service(&path, &anchor);
    let key = fund(&mut left, binding(), 10, true);
    assert_eq!(key.origin, origin(row.number("origin_b")));
    left.enqueue_secondary(&HOST, key.origin).unwrap().unwrap();
    let (_other_path, _other_anchor, mut right) = fork(&path, &anchor);
    let credentials = auth(&FORMER, 1, row.number("epoch"));
    let actions = [
        observation(1, &credentials, row.number("domain"), balance_query(row)),
        queue(2, "dispatch", key),
    ];
    assert_eq!(row.field("request_exchange"), "true");
    let exchanged = left.schedule(&actions, &[0]).unwrap();
    let input = right.schedule(&actions, &[]).unwrap();
    assert_eq!(exchanged.replies, input.replies, "{}", row.id);
    let Ok(ServiceReply::Observation(Observation::Raw(Ok(Value::Units(units))))) =
        reply(&exchanged, 1)
    else {
        panic!("missing actual published units");
    };
    assert_eq!(*units, row.number("amount"));
    format!(
        "schedule={};reply_a={units};reply_b_attempt={};retained_state_equal={}",
        schedule_name(exchanged.exchanges[0]),
        attempt(&exchanged, 2).unwrap(),
        image(&mut left) == image(&mut right)
    )
}

fn execute<'a>(
    label: u64,
    auth: &'a Credentials<'a, Rules>,
    call: &'a CallPayload,
    id: u64,
    endorsement: Option<&'a Credentials<'a, Rules>>,
) -> Occurrence<'a, Rules> {
    Occurrence {
        label,
        action: ServiceAction::Execute {
            auth,
            request: request(call, id),
            endorsement,
        },
    }
}

fn busy(reply: &Result<ServiceReply, RecoveryError>) -> bool {
    matches!(
        reply,
        Ok(ServiceReply::Executed(ActionReply::Ordinary(
            CheckedExecution::Forwarded(Collection::Collected(Outcome {
                reply: OutcomeReply::Busy,
                ..
            }))
        )))
    )
}

fn shared_cut(row: &Vector<'_>) -> String {
    assert_eq!(row.field("same_initial_cut"), "true");
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let first = payload(
        &mut service,
        Binding {
            asset: row.number("asset_a"),
            ..binding()
        },
        1,
        Command::Reserve { duration: 20 },
    );
    let second = payload(
        &mut service,
        Binding {
            asset: row.number("asset_b"),
            ..second()
        },
        2,
        Command::Reserve { duration: 20 },
    );
    assert_eq!(first.cut, second.cut);
    let credentials = auth(&FORMER, 2, row.number("epoch"));
    let schedule = service
        .schedule(
            &[
                execute(1, &credentials, &first, 1, None),
                execute(2, &credentials, &second, 2, None),
            ],
            &[0],
        )
        .unwrap();
    let second_effect = service
        .transact(|product| {
            product
                .reads
                .authority
                .state
                .primary
                .ledger
                .lock_owner(second.binding.asset)
                .is_some()
        })
        .unwrap();
    format!(
        "schedule={};second_fresh_result={};second_effect={second_effect}",
        schedule_name(schedule.exchanges[0]),
        if busy(reply(&schedule, 2)) {
            "busy"
        } else {
            "other"
        }
    )
}

fn read_after_primary(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let b = Binding {
        asset: row.number("asset"),
        origin: origin(18),
        ..binding()
    };
    let query = Query::ApplicationValue(b.asset);
    let old = CommitCut {
        authority_epoch: EPOCH,
        revision: row.number("old_revision") as usize,
    };
    let credentials = auth(&FORMER, 2, EPOCH);
    let owner = auth(&FORMER, 1, EPOCH);
    let initial = service
        .read(
            Entry::Normal,
            &credentials,
            0,
            ReadRequest::Current {
                query,
                expected: old,
            },
            None,
        )
        .unwrap();
    let Observation::Current(Ok(initial)) = initial else {
        panic!("missing actual initial value")
    };
    assert_eq!(initial.value, Value::Units(row.number("old_value")));
    let reserve = payload(&mut service, b, 1, Command::Reserve { duration: 20 });
    let write = CallPayload {
        cut: CommitCut {
            revision: old.revision + 1,
            ..old
        },
        ..payload(
            &mut service,
            b,
            2,
            Command::Write {
                generation: 0,
                value: row.number("new_value"),
            },
        )
    };
    let cancel = CallPayload {
        cut: CommitCut {
            revision: old.revision + 2,
            ..old
        },
        ..payload(&mut service, b, 3, Command::Cancel { generation: 0 })
    };
    let report = service
        .schedule(
            &[
                execute(1, &credentials, &reserve, 1, None),
                execute(2, &credentials, &write, 2, None),
                execute(3, &credentials, &cancel, 3, Some(&owner)),
                observation(
                    4,
                    &credentials,
                    0,
                    ReadRequest::Current {
                        query,
                        expected: old,
                    },
                ),
            ],
            &[2],
        )
        .unwrap();
    let old_busy = matches!(
        reply(&report, 4),
        Ok(ServiceReply::Observation(Observation::Current(Err(
            ReadError::Busy
        ))))
    );
    let new = CommitCut {
        authority_epoch: EPOCH,
        revision: row.number("new_revision") as usize,
    };
    let result = service
        .read(
            Entry::Normal,
            &credentials,
            0,
            ReadRequest::Current {
                query,
                expected: new,
            },
            None,
        )
        .unwrap();
    let Observation::Current(Ok(actual)) = result else {
        panic!("missing released value: {}", row.id)
    };
    let Value::Units(value) = actual.value else {
        panic!("expected application value")
    };
    format!(
        "schedule={};old_expected_read={};new_expected_read={value}",
        schedule_name(report.exchanges[0]),
        if old_busy { "busy" } else { "other" }
    )
}

fn shared_policy(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let old_epoch = row.number("old_epoch");
    let new_epoch = row.number("new_epoch");
    let credentials = auth(&FORMER, 1, old_epoch);
    let replacement = contexts(new_epoch);
    let sessions = sessions(new_epoch);
    let install = Occurrence {
        label: 1,
        action: ServiceAction::InstallEpoch {
            maintenance: &HOST,
            epoch: new_epoch,
            contexts: &replacement,
            sessions: &sessions,
        },
    };
    let read = observation(
        2,
        &credentials,
        0,
        ReadRequest::Historical {
            query: Query::ApplicationValue(row.number("asset")),
            revision: row.number("revision") as usize,
        },
    );
    let schedule = service.schedule(&[install, read], &[0]).unwrap();
    assert_eq!(reply(&schedule, 1), &Ok(ServiceReply::Changed(true)));
    let rejected = reply(&schedule, 2) == &Err(RecoveryError::Endpoint(EndpointError::Rejected));
    format!(
        "schedule={};old_proof_result={}",
        schedule_name(schedule.exchanges[0]),
        if rejected { "rejected" } else { "visible" }
    )
}

fn missing_publication(row: &Vector<'_>) -> String {
    assert_eq!(row.field("publication_before"), "absent");
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let key = fund(&mut service, binding(), 10, false);
    assert_eq!(key.origin, origin(row.number("origin_a")));
    assert_eq!(key.origin, origin(row.number("origin_b")));
    let earlier = service.schedule(&[queue(1, "enqueue", key)], &[]).unwrap();
    let earlier = if reply(&earlier, 1) == &Ok(ServiceReply::Enqueued(None)) {
        "none"
    } else {
        "present"
    };
    let publication = payload(&mut service, binding(), 16, Command::PublishPrimary);
    let credentials = auth(&FORMER, 2, EPOCH);
    let report = service
        .schedule(
            &[
                execute(1, &credentials, &publication, 16, None),
                queue(2, "enqueue", key),
            ],
            &[0],
        )
        .unwrap();
    let later = if reply(&report, 2) == &Ok(ServiceReply::Enqueued(Some(key))) {
        "exact_key"
    } else {
        "other"
    };
    format!(
        "schedule={};earlier_enqueue={earlier};later_enqueue={later}",
        schedule_name(report.exchanges[0])
    )
}

fn caller_collision(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let b = binding();
    let id = row.number("same_sequence");
    let first = payload(&mut service, b, id, Command::Reserve { duration: 20 });
    let second = payload(
        &mut service,
        second(),
        id,
        Command::Reserve { duration: 20 },
    );
    let credentials = auth(&FORMER, 2, EPOCH);
    assert_eq!(credentials.token.principal, row.number("actual_caller"));
    let forged = Occurrence {
        label: 2,
        action: ServiceAction::Execute {
            auth: &credentials,
            request: Request {
                id: CallId {
                    namespace: row.number("foreign_namespace"),
                    sequence: id,
                },
                ..request(&second, id)
            },
            endorsement: None,
        },
    };
    let report = service
        .schedule(&[execute(1, &credentials, &first, id, None), forged], &[0])
        .unwrap();
    let rejected = reply(&report, 2) == &Err(RecoveryError::Endpoint(EndpointError::Rejected));
    format!(
        "schedule={};forged_request={}",
        schedule_name(report.exchanges[0]),
        if rejected { "rejected" } else { "visible" }
    )
}

fn finite(row: &Vector<'_>) -> String {
    assert_eq!(row.field("read_c"), "authorized");
    assert_eq!(row.field("all_adjacent_pairs_compatible"), "true");
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut left = service(&path, &anchor);
    let a = fund(&mut left, binding(), 10, true);
    let b = fund(&mut left, second(), 30, true);
    assert_eq!(a.origin, origin(row.number("origin_a")));
    assert_eq!(b.origin, origin(row.number("origin_b")));
    for key in [a, b] {
        assert_eq!(
            left.enqueue_secondary(&HOST, key.origin).unwrap(),
            Some(key)
        );
    }
    let (_other_path, _other_anchor, mut right) = fork(&path, &anchor);
    let credentials = auth(&FORMER, 1, EPOCH);
    let occurrences = [
        queue(row.number("occurrence_a"), "dispatch", a),
        queue(row.number("occurrence_b"), "dispatch", b),
        observation(
            row.number("occurrence_c"),
            &credentials,
            2,
            ReadRequest::Raw(Query::AccountBalance(binding().destination())),
        ),
    ];
    let shuffled = left.schedule(&occurrences, &[0, 1]).unwrap();
    assert_eq!(
        shuffled.exchanges,
        [Exchange::Exchanged, Exchange::Exchanged],
        "{}",
        row.id
    );
    let baseline = right.schedule(&occurrences, &[]).unwrap();
    format!(
        "same_occurrence_replies={};retained_state_equal={}",
        shuffled.replies == baseline.replies,
        image(&mut left) == image(&mut right)
    )
}

fn bounded(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let key = fund(&mut service, binding(), 10, true);
    assert_eq!(key.origin, origin(row.number("origin")));
    assert_eq!(
        service.enqueue_secondary(&HOST, key.origin).unwrap(),
        Some(key)
    );
    // The frozen upper-bound case starts at the representable counter limit.
    service
        .transact(|product| {
            product
                .reads
                .authority
                .state
                .secondary
                .jobs
                .get_mut(&key)
                .unwrap()
                .attempts = row.number("attempt");
        })
        .unwrap();
    let before = anchor.head();
    let report = service.schedule(&[queue(1, "dispatch", key)], &[]).unwrap();
    format!(
        "reply={};attempt_unchanged={}",
        if attempt(&report, 1).is_none() {
            "none"
        } else {
            "job"
        },
        anchor.head() == before
    )
}

#[test]
fn proof_derived_parallel_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        let observed = match row.id {
            "independent-actual-dispatches"
            | "publication-derived-enqueue-and-other-dispatch"
            | "same-slot-enqueue-dispatch-conflict"
            | "same-slot-labeled-attempts"
            | "same-slot-failure-conflict" => pair_jobs(&row),
            "actual-credit-read-and-queue-write" => read_and_dispatch(&row),
            "distinct-assets-share-the-authority-cut" => shared_cut(&row),
            "current-read-after-shared-cut-writes" => read_after_primary(&row),
            "current-policy-also-gates-a-historical-read" => shared_policy(&row),
            "missing-publication-is-a-read-dependency" => missing_publication(&row),
            "caller-namespace-collision-in-scheduled-execution" => caller_collision(&row),
            "finite-adjacent-occurrence-exchanges" => finite(&row),
            "bounded-dispatch-attempts" => bounded(&row),
            other => panic!("unknown composition vector {other}"),
        };
        assert_eq!(observed, row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 13);
}

#[test]
fn same_slot_is_classified_even_when_it_does_not_exist() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let absent = SettlementKey {
        origin: ROOT,
        commit: CommitRef { position: 100 },
    };
    let before = anchor.head();
    let report = service
        .schedule(
            &[queue(1, "dispatch", absent), queue(2, "fail", absent)],
            &[0],
        )
        .unwrap();
    assert_eq!(report.exchanges, [Exchange::Serialized]);
    assert_eq!(reply(&report, 1), &Ok(ServiceReply::Dispatched(None)));
    assert_eq!(reply(&report, 2), &Ok(ServiceReply::Changed(false)));
    assert_eq!(anchor.head(), before);
}

#[test]
fn duplicate_ack_is_true_and_completed_dispatch_is_none() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let key = fund(&mut service, binding(), 10, true);
    service
        .enqueue_secondary(&HOST, key.origin)
        .unwrap()
        .unwrap();
    let job = service.dispatch_secondary(&HOST, key).unwrap().unwrap();
    let acknowledgement = Acknowledgement {
        key,
        commitment: job.commitment,
        target: job.target,
    };
    let ack = |label| Occurrence {
        label,
        action: ServiceAction::Acknowledge {
            maintenance: &HOST,
            acknowledgement,
            signature: &YES,
        },
    };
    let report = service
        .schedule(&[ack(1), queue(2, "dispatch", key)], &[0])
        .unwrap();
    assert_eq!(report.exchanges, [Exchange::Serialized]);
    assert_eq!(reply(&report, 1), &Ok(ServiceReply::Changed(true)));
    assert_eq!(reply(&report, 2), &Ok(ServiceReply::Dispatched(None)));
    let before = anchor.head();
    let duplicate = service.schedule(&[ack(3)], &[]).unwrap();
    assert_eq!(reply(&duplicate, 3), &Ok(ServiceReply::Changed(true)));
    assert_eq!(anchor.head(), before);
}

#[test]
fn scheduled_cache_rechecks_its_provider_in_the_actual_consumer() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let key = fund(&mut service, binding(), 10, true);
    service
        .enqueue_secondary(&HOST, key.origin)
        .unwrap()
        .unwrap();
    let credentials = auth(&FORMER, 1, EPOCH);
    let query = Query::ApplicationValue(17);
    let captured = service
        .read(
            Entry::Normal,
            &credentials,
            0,
            ReadRequest::CaptureCache(query),
            None,
        )
        .unwrap();
    let Observation::Cache(Ok(cache)) = captured else {
        panic!("expected real authority cache")
    };
    let claim = cache.claim().unwrap();
    let wrong = CacheClaim {
        provider: claim.provider + 1,
        ..claim
    };
    let expected = cut(&mut service);
    let report = service
        .schedule(
            &[
                Occurrence {
                    label: 1,
                    action: ServiceAction::Read {
                        auth: &credentials,
                        target: 0,
                        request: ReadRequest::Current { query, expected },
                        cache: Some(&wrong),
                    },
                },
                queue(2, "dispatch", key),
            ],
            &[0],
        )
        .unwrap();
    assert_eq!(report.exchanges, [Exchange::Exchanged]);
    assert_eq!(
        reply(&report, 1),
        &Ok(ServiceReply::Observation(Observation::Current(Err(
            ReadError::Busy
        )))),
        "scheduled-wrong-cache-provider"
    );
    assert_eq!(attempt(&report, 2), Some(1));
}

#[test]
fn labels_cannot_authorize_and_batch_jobs_wait_for_the_confirmed_head() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let key = fund(&mut service, binding(), 10, true);
    service
        .enqueue_secondary(&HOST, key.origin)
        .unwrap()
        .unwrap();
    let before = anchor.head();
    let duplicate = service.schedule(
        &[queue(1, "dispatch", key), queue(1, "dispatch", key)],
        &[0],
    );
    assert_eq!(duplicate, Err(ScheduleError::InvalidPlan));
    assert_eq!(anchor.head(), before);
    let invalid_host = 0;
    let denied = service
        .schedule(
            &[
                Occurrence {
                    label: HOST,
                    action: ServiceAction::Enqueue {
                        maintenance: &invalid_host,
                        origin: key.origin,
                    },
                },
                queue(2, "dispatch", key),
            ],
            &[0],
        )
        .unwrap();
    assert_eq!(denied.exchanges, [Exchange::Serialized]);
    assert_eq!(
        reply(&denied, HOST),
        &Err(RecoveryError::Endpoint(EndpointError::Rejected))
    );
    assert_eq!(attempt(&denied, 2), Some(1));
    let before = anchor.head();
    anchor.mode(Cas::LostBefore);
    assert_eq!(
        service.schedule(&[queue(2, "dispatch", key)], &[]),
        Err(ScheduleError::Recovery(RecoveryError::Hold)),
        "scheduled-head-confirms-job"
    );
    assert_eq!(anchor.head(), before);
    anchor.mode(Cas::Normal);
    assert_eq!(
        attempt(
            &service.schedule(&[queue(2, "dispatch", key)], &[]).unwrap(),
            2
        ),
        Some(2)
    );
}

#[test]
fn receipt_capture_and_source_probe_keep_their_exact_labels_through_two_swaps() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut first = service(&path, &anchor);
    let key = fund(&mut first, binding(), 10, true);
    let held_binding = second();
    let held = super::super::vector_tests::reserve(&mut first, held_binding, 80);
    let dispatch = payload(
        &mut first,
        held_binding,
        81,
        Command::Dispatch { generation: 0 },
    );
    accepted(submit(&mut first, &dispatch, 81), Reply::SourceDispatched);
    let debit = payload(
        &mut first,
        held_binding,
        82,
        Command::Debit { generation: 0 },
    );
    accepted(submit(&mut first, &debit, 82), Reply::Debited);
    first.enqueue_secondary(&HOST, key.origin).unwrap().unwrap();
    let (_path, _anchor, mut second) = fork(&path, &anchor);
    let credentials = auth(&FORMER, 2, EPOCH);
    let occurrences = [
        Occurrence {
            label: 3,
            action: ServiceAction::Receipt {
                auth: &credentials,
                request: request(&held, 80),
            },
        },
        queue(1, "dispatch", key),
        observation(
            8,
            &credentials,
            0,
            ReadRequest::CaptureCache(Query::AccountBalance(binding().source())),
        ),
        Occurrence {
            label: 5,
            action: ServiceAction::SourceProbe {
                maintenance: &HOST,
                origin: held_binding.origin,
                evidence: None,
            },
        },
    ];
    let exchanged = first.schedule(&occurrences, &[0, 1]).unwrap();
    assert_eq!(
        exchanged.exchanges,
        [Exchange::Exchanged, Exchange::Exchanged]
    );
    let ordered = second.schedule(&occurrences, &[]).unwrap();
    assert_eq!(exchanged.replies, ordered.replies);
    assert_eq!(
        reply(&exchanged, 5),
        &Ok(ServiceReply::Source(SourceAction::Query(held_binding)))
    );
    assert_eq!(image(&mut first), image(&mut second));
}

#[test]
fn enqueue_resolves_the_newly_published_slot_after_a_serial_step() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = service(&path, &anchor);
    let key = fund(&mut service, binding(), 10, false);
    let publish = payload(&mut service, binding(), 16, Command::PublishPrimary);
    let credentials = auth(&FORMER, 2, EPOCH);
    let report = service
        .schedule(
            &[
                execute(1, &credentials, &publish, 16, None),
                queue(2, "enqueue", key),
                queue(3, "dispatch", key),
            ],
            &[1],
        )
        .unwrap();
    assert_eq!(
        report.exchanges,
        [Exchange::Serialized],
        "late-publication-slot"
    );
    assert_eq!(reply(&report, 2), &Ok(ServiceReply::Enqueued(Some(key))));
    assert_eq!(attempt(&report, 3), Some(1));
}
