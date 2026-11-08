use super::*;
use crate::lock_finality::Permission;
use crate::vector_tests::{Vector, parse_vectors};

const VECTORS: &str = include_str!("../../tests/vectors/authoritative-outcomes.tsv");
const PERMISSIONS: [Permission; 13] = [
    Permission::Reserve,
    Permission::Dispatch,
    Permission::Debit,
    Permission::Cancel,
    Permission::Fence,
    Permission::Preempt,
    Permission::ObserveTime,
    Permission::Attest,
    Permission::Credit,
    Permission::Refund,
    Permission::Reconcile,
    Permission::Write,
    Permission::PublishPrimary,
];

#[derive(Clone, Copy)]
struct Case {
    caller: AuthenticatedCaller,
    session: SessionId,
    epoch: u64,
    origin_epoch: u64,
    binding: Binding,
    initial: u64,
    target: EndpointId,
}

fn optional(row: &Vector<'_>, key: &str, default: u64) -> u64 {
    row.input
        .get(key)
        .map_or(default, |value| value.parse().unwrap())
}

impl Case {
    fn from_vector(row: &Vector<'_>) -> Self {
        Self {
            caller: AuthenticatedCaller(row.number("caller")),
            session: row.number("session"),
            epoch: optional(row, "epoch", optional(row, "authority_epoch", 9)),
            origin_epoch: row.number("origin_epoch"),
            binding: Binding {
                origin: OriginKey {
                    domain: row.number("source_domain"),
                    event: row.number("event"),
                },
                asset: row.number("asset"),
                owner: row.number("caller"),
                destination: optional(row, "destination_domain", 2),
                recipient: optional(row, "recipient", 3),
                amount: optional(row, "amount", 5),
            },
            initial: optional(row, "initial", 10),
            target: optional(row, "target", 99),
        }
    }

    fn sessions(self, epoch: u64) -> BTreeMap<SessionId, SessionBinding> {
        BTreeMap::from([(
            self.session,
            SessionBinding {
                principal: self.caller.0,
                authority_epoch: epoch,
            },
        )])
    }

    fn contexts(
        self,
        epoch: u64,
        deny_admin: bool,
        conflict: Option<Binding>,
    ) -> Vec<EndpointContext> {
        [self.binding.origin.domain, self.binding.destination]
            .map(|endpoint| {
                let mut grants = BTreeSet::new();
                for route in [Route::Normal, Route::Administrative, Route::Adapter] {
                    for permission in PERMISSIONS {
                        if !(deny_admin
                            && route == Route::Administrative
                            && permission == Permission::Dispatch)
                        {
                            grants.insert((self.caller.0, route, permission));
                        }
                    }
                }
                let dependencies = match conflict {
                    Some(other) if endpoint == self.binding.origin.domain => BTreeMap::from([
                        (self.binding.asset, BTreeSet::from([other.asset])),
                        (other.asset, BTreeSet::from([self.binding.asset])),
                    ]),
                    _ => BTreeMap::new(),
                };
                EndpointContext {
                    endpoint,
                    epoch,
                    grants,
                    dependencies,
                    write_permissions: BTreeSet::new(),
                }
            })
            .into()
    }

    fn authority(self, deny_admin: bool, conflict: Option<Binding>) -> Authority {
        let mut supply = BTreeMap::from([(self.binding.asset, u128::from(self.initial))]);
        if let Some(other) = conflict {
            supply.insert(other.asset, 0);
        }
        let ledger = Ledger::new(
            self.epoch,
            self.contexts(self.epoch, deny_admin, conflict),
            self.sessions(self.epoch),
            BTreeSet::from([self.caller.0]),
            BTreeMap::from([(self.binding.source(), self.initial)]),
            &supply,
        )
        .unwrap();
        Authority::new(ledger, self.target).unwrap()
    }

    fn id(self, sequence: u64) -> CallId {
        CallId {
            namespace: self.caller.0,
            sequence,
        }
    }

    fn payload(self, authority: &Authority, message_id: u64, command: Command) -> CallPayload {
        let cut = authority.current_cut();
        let credential = match command {
            Command::Dispatch { generation }
            | Command::Debit { generation }
            | Command::Cancel { generation }
            | Command::Refund { generation, .. }
            | Command::Reconcile { generation, .. } => Some(generation),
            Command::Credit { .. } => Some(0),
            _ => None,
        }
        .map(|generation| Credential {
            asset: self.binding.asset,
            origin: self.binding.origin,
            holder: self.caller.0,
            generation,
            epoch: cut.authority_epoch,
        });
        CallPayload {
            message_id,
            origin_epoch: self.origin_epoch,
            endpoint: if matches!(command, Command::Credit { .. }) {
                self.binding.destination
            } else {
                self.binding.origin.domain
            },
            caller: self.caller.0,
            session: self.session,
            cut,
            binding: self.binding,
            credential,
            versions: Vec::new(),
            command,
        }
    }

    fn send(
        self,
        authority: &mut Authority,
        sequence: u64,
        route: Route,
        command: Command,
    ) -> Collection {
        let payload = self.payload(authority, sequence, command);
        authority.submit(
            route,
            self.caller,
            self.id(sequence),
            &payload,
            |_, _, _| true,
        )
    }

    fn reserve(self, authority: &mut Authority) {
        assert!(matches!(
            self.send(
                authority,
                100,
                Route::Normal,
                Command::Reserve { duration: 10 }
            ),
            Collection::Collected(Outcome {
                reply: OutcomeReply::Accepted(Reply::Reserved),
                ..
            })
        ));
    }

    fn pending(self, authority: &mut Authority) {
        self.reserve(authority);
        assert!(matches!(
            self.send(
                authority,
                101,
                Route::Normal,
                Command::Dispatch { generation: 0 }
            ),
            Collection::Collected(Outcome {
                reply: OutcomeReply::Accepted(Reply::SourceDispatched),
                ..
            })
        ));
        let debit = authority.current_cut().revision;
        assert!(matches!(
            self.send(
                authority,
                102,
                Route::Normal,
                Command::Debit { generation: 0 }
            ),
            Collection::Collected(Outcome {
                reply: OutcomeReply::Accepted(Reply::Debited),
                ..
            })
        ));
        assert_eq!(
            authority.origin_debit(self.binding.origin),
            Some(CommitRef { position: debit })
        );
    }

    fn record(self, authority: &mut Authority, kind: TerminalKind) -> OriginDecision {
        let position = authority.current_cut().revision;
        let evidence = TerminalEvidence {
            binding: self.binding,
            kind,
            reference: 0,
        };
        let reply = self.send(
            authority,
            103,
            Route::Adapter,
            Command::RecordTerminal(evidence),
        );
        assert_eq!(
            reply,
            Collection::Collected(Outcome::committed(
                OutcomeReply::Accepted(Reply::Recorded),
                CommitRef { position }
            ))
        );
        authority.origin_decision(self.binding.origin).unwrap()
    }

    fn publish(self, authority: &mut Authority) {
        assert!(matches!(
            self.send(authority, 105, Route::Normal, Command::PublishPrimary),
            Collection::Collected(Outcome {
                reply: OutcomeReply::Accepted(Reply::Published),
                ..
            })
        ));
    }

    fn release(self, authority: &mut Authority) {
        assert!(matches!(
            self.send(
                authority,
                106,
                Route::Normal,
                Command::Reconcile {
                    generation: 0,
                    reference: 0
                }
            ),
            Collection::Collected(Outcome {
                reply: OutcomeReply::Accepted(Reply::Reconciled),
                ..
            })
        ));
    }
}

fn route(value: &str) -> Route {
    match value {
        "normal" => Route::Normal,
        "administrative" => Route::Administrative,
        "adapter" => Route::Adapter,
        _ => panic!("unknown route {value}"),
    }
}

fn kind(value: &str) -> TerminalKind {
    match value {
        "confirmed" => TerminalKind::Confirmed,
        "reversed" => TerminalKind::Reversed,
        _ => panic!("unknown terminal kind {value}"),
    }
}

fn name(reply: Collection) -> &'static str {
    match reply {
        Collection::Rejected => "rejected",
        Collection::Waiting => "waiting",
        Collection::Collected(outcome) => match outcome.reply {
            OutcomeReply::Rejected => "rejected",
            OutcomeReply::Busy => "busy",
            OutcomeReply::Unavailable => "unavailable",
            OutcomeReply::Accepted(Reply::SourceDispatched) => "source_dispatched",
            OutcomeReply::Accepted(Reply::Credited) => "credited",
            _ => panic!("unexpected observed result {outcome:?}"),
        },
    }
}

fn call_vectors(case: Case, row: &Vector<'_>) -> String {
    let id = CallId {
        namespace: row.number("namespace"),
        sequence: row.number("sequence"),
    };
    let message = row.number("message");
    if row.operation == "busy-retry" {
        assert_eq!(row.number("first_asset"), case.binding.asset);
        let conflict = Case {
            binding: Binding {
                asset: row.number("conflicting_asset"),
                origin: OriginKey {
                    event: row.number("conflicting_event"),
                    ..case.binding.origin
                },
                ..case.binding
            },
            ..case
        };
        let mut authority = case.authority(false, Some(conflict.binding));
        case.reserve(&mut authority);
        let request = conflict.payload(&authority, message, Command::Reserve { duration: 10 });
        let before = authority.ledger_snapshot();
        let first = authority.submit(Route::Normal, case.caller, id, &request, |_, _, _| true);
        assert_eq!(name(first), "busy");
        assert_eq!(authority.ledger_snapshot(), before);
        assert!(matches!(
            case.send(
                &mut authority,
                108,
                Route::Normal,
                Command::Cancel { generation: 0 }
            ),
            Collection::Collected(Outcome {
                reply: OutcomeReply::Accepted(Reply::Closed),
                ..
            })
        ));
        let next = authority.submit(Route::Adapter, case.caller, id, &request, |_, _, _| true);
        return format!(
            "reply={};new_reservations={}",
            name(next),
            usize::from(authority.lock_owner(conflict.binding.asset).is_some())
        );
    }

    let denied = row.operation == "denied-retry";
    let unavailable = row.operation == "unavailable-retry";
    let mut authority = case.authority(denied, None);
    case.reserve(&mut authority);
    let revision = authority.current_cut().revision;
    let request = case.payload(&authority, message, Command::Dispatch { generation: 0 });
    if unavailable {
        authority.driver_connection(false);
    }
    let entry = if denied {
        route(row.field("first_route"))
    } else {
        Route::Normal
    };
    let first = authority.submit(entry, case.caller, id, &request, |_, _, _| true);
    let observed = match row.operation {
        "first-dispatch" => {
            assert_eq!(
                first,
                Collection::Collected(Outcome::committed(
                    OutcomeReply::Accepted(Reply::SourceDispatched),
                    CommitRef { position: revision }
                ))
            );
            first
        }
        "restart-retry" => {
            let committed = authority.snapshot();
            authority.crash();
            assert_eq!(authority.snapshot(), committed);
            assert_eq!(
                authority.submit(Route::Normal, case.caller, id, &request, |_, _, _| true),
                Collection::Waiting
            );
            assert!(authority.recover(Some(&committed)));
            authority.submit(Route::Adapter, case.caller, id, &request, |_, _, _| true)
        }
        "conflicting-call" => {
            let changed = CallPayload {
                message_id: row.number("retry_message"),
                ..request
            };
            authority.submit(Route::Normal, case.caller, id, &changed, |_, _, _| true)
        }
        "denied-retry" => {
            assert_eq!(name(first), "rejected");
            authority.submit(
                route(row.field("retry_route")),
                case.caller,
                id,
                &request,
                |_, _, _| true,
            )
        }
        "unavailable-retry" => {
            assert_eq!(name(first), "unavailable");
            authority.driver_connection(true);
            authority.submit(Route::Normal, case.caller, id, &request, |_, _, _| true)
        }
        other => panic!("unknown call vector {other}"),
    };
    format!(
        "reply={};authority_effects={}",
        name(observed),
        authority.current_cut().revision - revision
    )
}

fn completion_vector(case: Case, row: &Vector<'_>) -> String {
    let mut authority = case.authority(false, None);
    case.pending(&mut authority);
    case.record(&mut authority, TerminalKind::Confirmed);
    let payload = case.payload(&authority, 1, Command::Credit { reference: 0 });
    let id = case.id(1);
    assert_eq!(
        authority.submit(Route::Adapter, case.caller, id, &payload, |_, _, _| true),
        Collection::Waiting
    );
    if row.field("published") == "true" {
        case.publish(&mut authority);
    }
    if row.field("released") == "true" {
        case.release(&mut authority);
    }
    let before = authority.completed_count();
    assert!(!authority.is_completed(id));
    let reply = authority.collect(case.caller, id, &payload, |_, _, _| true);
    assert_eq!(
        authority.collect(case.caller, id, &payload, |_, _, _| true),
        reply
    );
    if reply == Collection::Waiting {
        assert!(!authority.is_completed(id));
        assert_eq!(authority.completed_count(), before);
        return "reply=waiting".to_owned();
    }
    assert!(authority.is_completed(id));
    format!(
        "reply={};completions={}",
        name(reply),
        authority.completed_count() - before
    )
}

fn credit_once(case: Case, authority: &mut Authority, id: u64, message: u64, route: Route) -> u64 {
    let before = authority.balance(case.binding.destination());
    let payload = case.payload(authority, message, Command::Credit { reference: 0 });
    authority.submit(route, case.caller, case.id(id), &payload, |_, _, _| true);
    (authority.balance(case.binding.destination()) - before) / case.binding.amount
}

fn origin_vectors(case: Case, row: &Vector<'_>) -> String {
    let mut authority = case.authority(false, None);
    case.pending(&mut authority);
    let initial_kind = if row.operation == "conflicting-terminal-kind" {
        kind(row.field("first_kind"))
    } else {
        TerminalKind::Confirmed
    };
    let decision = case.record(&mut authority, initial_kind);
    match row.operation {
        "conflicting-origin-epoch" => {
            let changed = Case {
                origin_epoch: row.number("retry_origin_epoch"),
                ..case
            };
            let reply = changed.send(
                &mut authority,
                1,
                Route::Adapter,
                Command::Credit { reference: 0 },
            );
            format!(
                "reply={};new_credits={}",
                name(reply),
                authority.balance(case.binding.destination()) / case.binding.amount
            )
        }
        "conflicting-terminal-kind" => {
            assert_eq!(credit_once(case, &mut authority, 3, 3, Route::Normal), 1);
            let other = TerminalEvidence {
                binding: case.binding,
                kind: kind(row.field("retry_kind")),
                reference: 1,
            };
            assert_eq!(
                name(case.send(
                    &mut authority,
                    1,
                    Route::Administrative,
                    Command::RecordTerminal(other)
                )),
                "rejected"
            );
            assert_eq!(
                name(case.send(
                    &mut authority,
                    2,
                    Route::Adapter,
                    Command::Refund {
                        generation: 0,
                        reference: 1
                    }
                )),
                "rejected"
            );
            assert_eq!(
                authority.origin_decision(case.binding.origin),
                Some(decision)
            );
            let decision_name = match decision.kind {
                TerminalKind::Confirmed => "confirmed",
                TerminalKind::Reversed => "reversed",
            };
            let refunds = (authority.balance(case.binding.source()) + case.binding.amount
                - case.initial)
                / case.binding.amount;
            format!("decision={decision_name};refunds={refunds}")
        }
        "reroute-original-credit" => {
            let a = credit_once(
                case,
                &mut authority,
                1,
                row.number("first_message"),
                route(row.field("first_route")),
            );
            let b = credit_once(
                case,
                &mut authority,
                2,
                row.number("retry_message"),
                route(row.field("retry_route")),
            );
            format!(
                "credits={};destination={}",
                a + b,
                authority.balance(case.binding.destination())
            )
        }
        "split-authority-control" => {
            let first_route = route(row.field("first_route"));
            let second_route = route(row.field("second_route"));
            let mut isolated = case.authority(false, None);
            case.pending(&mut isolated);
            case.record(&mut isolated, initial_kind);
            let first = credit_once(case, &mut authority, 1, 1, first_route);
            let shared_second = credit_once(case, &mut authority, 2, 2, second_route);
            let isolated_second = credit_once(case, &mut isolated, 2, 2, second_route);
            format!(
                "shared_new_credits={};isolated_new_credits={}",
                first + shared_second,
                first + isolated_second
            )
        }
        other => panic!("unknown origin vector {other}"),
    }
}

fn status(value: SettlementStatus) -> &'static str {
    match value {
        SettlementStatus::Waiting => "waiting",
        SettlementStatus::InFlight => "in_flight",
        SettlementStatus::Completed => "completed",
    }
}

fn queue_vectors(case: Case, row: &Vector<'_>) -> String {
    let mut authority = case.authority(false, None);
    case.pending(&mut authority);
    let terminal = case.record(&mut authority, TerminalKind::Confirmed);
    let position = terminal.commit.position + row.number("primary_position") as usize;
    assert_eq!(
        position, terminal.commit.position,
        "primary anchor vector must name the committed position"
    );
    assert_eq!(credit_once(case, &mut authority, 1, 1, Route::Normal), 1);
    if row.operation == "early-enqueue" {
        authority.enqueue_secondary(case.binding.origin);
        return format!("jobs={}", authority.secondary_job_count());
    }
    case.publish(&mut authority);
    let published = authority.primary_publication(case.binding.origin).unwrap();
    assert_eq!(published.decision, terminal);
    let before = authority.primary_snapshot();
    let key = authority.enqueue_secondary(case.binding.origin).unwrap();
    assert_eq!(key.commit.position, position);
    let first = authority.dispatch_secondary(key).unwrap();
    assert_eq!(first.target, case.target);
    let mut ack = Acknowledgement {
        key,
        target: case.target,
        commitment: published,
    };
    match row.operation {
        "wrong-ack" | "retry-ack" => {
            ack.commitment.decision.commit.position =
                position + row.number("ack_position") as usize;
            if row.operation == "retry-ack" {
                assert!(authority.fail_secondary(key));
                let retried = authority.dispatch_secondary(key).unwrap();
                assert_eq!(retried.commitment, first.commitment);
                assert_eq!(retried.commitment.key(), key);
            }
            authority.acknowledge_secondary(ack, |provided| provided.target == case.target);
        }
        "secondary-fail" => assert!(authority.fail_secondary(key)),
        other => panic!("unknown queue vector {other}"),
    }
    let job = authority.secondary_job(key).unwrap();
    let unchanged = authority.primary_snapshot() == before;
    let fields = format!(
        "status={};primary_unchanged={unchanged}",
        status(job.status)
    );
    match row.operation {
        "retry-ack" => format!("attempts={};{fields}", job.attempts),
        "secondary-fail" => {
            let refunds = (authority.balance(case.binding.source()) + case.binding.amount
                - case.initial)
                / case.binding.amount;
            format!("{fields};refunds={refunds}")
        }
        _ => fields,
    }
}

#[test]
fn proof_derived_outcome_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        let case = Case::from_vector(&row);
        let observed = match row.operation {
            "first-dispatch" | "restart-retry" | "conflicting-call" | "denied-retry"
            | "unavailable-retry" | "busy-retry" => call_vectors(case, &row),
            "completion" => completion_vector(case, &row),
            "conflicting-origin-epoch"
            | "conflicting-terminal-kind"
            | "reroute-original-credit"
            | "split-authority-control" => origin_vectors(case, &row),
            _ => queue_vectors(case, &row),
        };
        assert_eq!(observed, row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 17);
}

fn standard_case() -> Case {
    let row = parse_vectors(VECTORS).next().unwrap();
    Case::from_vector(&row)
}

#[test]
fn foreign_and_unverified_calls_cannot_poison_a_valid_id() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.reserve(&mut authority);
    let payload = case.payload(&authority, 1, Command::Dispatch { generation: 0 });
    let id = case.id(1);
    let before = authority.snapshot();
    let foreign = CallId {
        namespace: id.namespace + 1,
        ..id
    };
    assert_eq!(
        authority.submit(Route::Normal, case.caller, foreign, &payload, |_, _, _| {
            true
        }),
        Collection::Rejected
    );
    assert_eq!(
        authority.submit(Route::Normal, case.caller, id, &payload, |_, _, _| false),
        Collection::Rejected
    );
    assert_eq!(authority.snapshot(), before);
    assert_eq!(
        name(authority.submit(Route::Normal, case.caller, id, &payload, |_, _, _| true)),
        "source_dispatched"
    );
}

#[test]
fn exact_old_request_requires_a_current_session_even_after_recovery() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.reserve(&mut authority);
    let stale = authority.snapshot();
    let payload = case.payload(&authority, 1, Command::Dispatch { generation: 0 });
    let id = case.id(1);
    let old = authority.submit(Route::Normal, case.caller, id, &payload, |_, _, _| true);
    authority.crash();
    assert!(!authority.recover(Some(&stale)));
    let current = authority.snapshot();
    assert!(authority.recover(Some(&current)));
    assert!(authority.install_epoch(
        case.caller,
        case.epoch + 1,
        case.contexts(case.epoch + 1, false, None),
        BTreeMap::new()
    ));
    assert_eq!(
        authority.collect(case.caller, id, &payload, |_, _, _| true),
        Collection::Rejected
    );
    assert!(authority.install_epoch(
        case.caller,
        case.epoch + 2,
        case.contexts(case.epoch + 2, false, None),
        case.sessions(case.epoch + 2)
    ));
    assert_eq!(
        authority.submit(
            Route::Administrative,
            case.caller,
            id,
            &payload,
            |_, _, _| true
        ),
        old
    );
    assert_eq!(
        authority.collect(case.caller, id, &payload, |_, _, _| true),
        old
    );
    assert!(authority.is_completed(id));
}

#[test]
fn exact_reversal_waits_for_publication_and_keeps_commit_on_evidence_refresh() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.pending(&mut authority);
    let decision = case.record(&mut authority, TerminalKind::Reversed);
    let refreshed = TerminalEvidence {
        binding: case.binding,
        kind: TerminalKind::Reversed,
        reference: 4,
    };
    assert!(matches!(
        case.send(
            &mut authority,
            104,
            Route::Adapter,
            Command::RecordTerminal(refreshed)
        ),
        Collection::Collected(Outcome {
            reply: OutcomeReply::Accepted(Reply::EvidenceRefreshed),
            ..
        })
    ));
    assert_eq!(
        authority.origin_decision(case.binding.origin),
        Some(decision)
    );
    let payload = case.payload(
        &authority,
        1,
        Command::Refund {
            generation: 0,
            reference: 4,
        },
    );
    let id = case.id(1);
    let position = authority.current_cut().revision;
    assert_eq!(
        authority.submit(Route::Normal, case.caller, id, &payload, |_, _, _| true),
        Collection::Waiting
    );
    assert_eq!(authority.balance(case.binding.source()), case.initial);
    assert_eq!(authority.lock_owner(case.binding.asset), None);
    assert_eq!(
        authority.collect(case.caller, id, &payload, |_, _, _| true),
        Collection::Waiting
    );
    case.publish(&mut authority);
    let done = Collection::Collected(Outcome::committed(
        OutcomeReply::Accepted(Reply::Refunded),
        CommitRef { position },
    ));
    assert_eq!(
        authority.collect(case.caller, id, &payload, |_, _, _| true),
        done
    );
    assert_eq!(
        authority.collect(case.caller, id, &payload, |_, _, _| true),
        done
    );
    assert!(authority.is_completed(id));
    assert_eq!(
        authority
            .primary_publication(case.binding.origin)
            .unwrap()
            .decision,
        decision
    );
}

#[test]
fn acknowledgement_requires_an_authenticated_target_and_prior_dispatch() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.pending(&mut authority);
    case.record(&mut authority, TerminalKind::Confirmed);
    assert_eq!(credit_once(case, &mut authority, 1, 1, Route::Normal), 1);
    case.publish(&mut authority);
    let commitment = authority.primary_publication(case.binding.origin).unwrap();
    let key = authority.enqueue_secondary(case.binding.origin).unwrap();
    let ack = Acknowledgement {
        key,
        commitment,
        target: case.target,
    };
    assert!(!authority.acknowledge_secondary(ack, |_| true));
    assert_eq!(
        authority.secondary_job(key).unwrap().status,
        SettlementStatus::Waiting
    );
    authority.dispatch_secondary(key).unwrap();
    assert!(!authority.acknowledge_secondary(
        Acknowledgement {
            target: case.binding.destination,
            ..ack
        },
        |_| true
    ));
    assert!(!authority.acknowledge_secondary(ack, |_| false));
    assert_eq!(
        authority.secondary_job(key).unwrap().status,
        SettlementStatus::InFlight
    );
    assert!(authority.acknowledge_secondary(ack, |_| true));
    assert_eq!(
        authority.secondary_job(key).unwrap().status,
        SettlementStatus::Completed
    );
}

#[test]
fn original_epoch_is_separate_from_current_authority_and_duplicate_has_no_new_effect() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.pending(&mut authority);
    let terminal = case.record(&mut authority, TerminalKind::Confirmed);
    let current = case.epoch + 1;
    assert!(authority.install_epoch(
        case.caller,
        current,
        case.contexts(current, false, None),
        case.sessions(current)
    ));
    let first = case.payload(&authority, 1, Command::Credit { reference: 0 });
    assert_eq!(first.origin_epoch, case.epoch);
    assert_eq!(first.credential.unwrap().epoch, current);
    let first_position = authority.current_cut().revision;
    assert_eq!(
        authority.submit(Route::Normal, case.caller, case.id(1), &first, |_, _, _| {
            true
        }),
        Collection::Waiting
    );
    case.release(&mut authority);
    case.publish(&mut authority);

    let mut duplicate = case.payload(&authority, 2, Command::Credit { reference: 0 });
    let valid = duplicate.credential.unwrap();
    duplicate.credential = Some(Credential {
        holder: case.caller.0 + 1,
        ..valid
    });
    assert_eq!(
        name(authority.submit(
            Route::Adapter,
            case.caller,
            case.id(2),
            &duplicate,
            |_, _, _| true
        )),
        "rejected"
    );
    duplicate.message_id = 3;
    duplicate.credential = Some(valid);
    let before = authority.ledger_snapshot();
    assert_eq!(
        authority.submit(
            Route::Adapter,
            case.caller,
            case.id(3),
            &duplicate,
            |_, _, _| true
        ),
        Collection::Collected(Outcome::committed(
            OutcomeReply::DuplicateSettlement(TerminalKind::Confirmed),
            CommitRef {
                position: first_position
            }
        ))
    );
    assert_eq!(authority.ledger_snapshot(), before);
    assert_eq!(
        authority
            .primary_publication(case.binding.origin)
            .unwrap()
            .decision,
        terminal
    );
}

#[test]
fn replay_payload_keeps_the_original_credential_version_vector_and_origin_epoch() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.reserve(&mut authority);
    let payload = case.payload(&authority, 1, Command::Dispatch { generation: 0 });
    let id = case.id(1);
    assert_eq!(
        name(authority.submit(Route::Normal, case.caller, id, &payload, |_, _, _| true)),
        "source_dispatched"
    );
    let before = authority.snapshot();
    let credential = Credential {
        generation: 1,
        ..payload.credential.unwrap()
    };
    for changed in [
        CallPayload {
            credential: Some(credential),
            ..payload.clone()
        },
        CallPayload {
            versions: vec![(case.binding.asset, 0)],
            ..payload.clone()
        },
        CallPayload {
            origin_epoch: case.epoch + 1,
            ..payload.clone()
        },
    ] {
        assert_eq!(
            authority.submit(Route::Adapter, case.caller, id, &changed, |_, _, _| true),
            Collection::Rejected
        );
        assert_eq!(authority.snapshot(), before);
    }
}

#[test]
fn direct_submission_completes_once_before_replay_or_collection() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.reserve(&mut authority);
    let id = case.id(1);
    let payload = case.payload(&authority, 1, Command::Dispatch { generation: 0 });
    let before = authority.completed_count();
    let reply = authority.submit(Route::Normal, case.caller, id, &payload, |_, _, _| true);
    assert_eq!(name(reply), "source_dispatched");
    assert!(authority.is_completed(id));
    assert_eq!(authority.completed_count(), before + 1);
    let completed = authority.snapshot();
    assert_eq!(
        authority.submit(Route::Adapter, case.caller, id, &payload, |_, _, _| true),
        reply
    );
    assert_eq!(
        authority.collect(case.caller, id, &payload, |_, _, _| true),
        reply
    );
    assert_eq!(authority.snapshot(), completed);
}

#[test]
fn a_duplicate_decision_and_a_duplicate_reversal_return_the_original_commit() {
    let case = standard_case();
    let mut authority = case.authority(false, None);
    case.pending(&mut authority);
    let decision = case.record(&mut authority, TerminalKind::Reversed);
    let evidence = TerminalEvidence {
        binding: case.binding,
        kind: TerminalKind::Reversed,
        reference: 0,
    };
    let before = authority.ledger_snapshot();
    assert_eq!(
        case.send(
            &mut authority,
            107,
            Route::Adapter,
            Command::RecordTerminal(evidence)
        ),
        Collection::Collected(Outcome::committed(
            OutcomeReply::DuplicateDecision,
            decision.commit
        ))
    );
    assert_eq!(authority.ledger_snapshot(), before);
    assert_eq!(
        authority.origin_decision(case.binding.origin),
        Some(decision)
    );

    let refund = Command::Refund {
        generation: 0,
        reference: 0,
    };
    let payload = case.payload(&authority, 1, refund);
    let position = authority.current_cut().revision;
    assert_eq!(
        authority.submit(Route::Normal, case.caller, case.id(1), &payload, |_, _, _| true),
        Collection::Waiting
    );
    case.publish(&mut authority);
    assert_eq!(
        authority.collect(case.caller, case.id(1), &payload, |_, _, _| true),
        Collection::Collected(Outcome::committed(
            OutcomeReply::Accepted(Reply::Refunded),
            CommitRef { position }
        ))
    );

    // A second Refund call for the same reversal returns the original commit
    // and changes nothing.
    let duplicate = case.payload(&authority, 2, refund);
    let before = authority.ledger_snapshot();
    assert_eq!(
        authority.submit(
            Route::Normal,
            case.caller,
            case.id(2),
            &duplicate,
            |_, _, _| true
        ),
        Collection::Collected(Outcome::committed(
            OutcomeReply::DuplicateSettlement(TerminalKind::Reversed),
            CommitRef { position }
        ))
    );
    assert_eq!(authority.ledger_snapshot(), before);
    assert_eq!(authority.balance(case.binding.source()), case.initial);
}
