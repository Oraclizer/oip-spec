use super::*;
use crate::SessionBinding;
use crate::authority::reads::{CheckedExecution, Query, ReadError, ReadKind, Reader, Value};
use crate::authority::{Authority, Collection};
use crate::lock_finality::{
    Account, Command, Credential, EndpointContext, Permission, Route, TerminalEvidence,
};
use crate::vector_tests::{Vector, parse_vectors};

const VECTORS: &str = include_str!("../../../tests/vectors/regulatory-execution.tsv");
const ROUTES: [RegulatoryRoute; 4] = [
    RegulatoryRoute::Normal,
    RegulatoryRoute::Administrative,
    RegulatoryRoute::Adapter,
    RegulatoryRoute::ForceInclusion,
];
const STAGES: [LegalStage; 2] = [LegalStage::SourceEmission, LegalStage::ReceivingCommit];
const ACTIONS: [Action; 7] = [
    Action::Freeze,
    Action::Restrict,
    Action::Seize,
    Action::Confiscate,
    Action::Unfreeze,
    Action::Unrestrict,
    Action::Release,
];
const ALLOWED: fn(AuthenticatedCaller, ReadKind, Query) -> bool = |_, _, _| true;
const SESSION: SessionId = 1;

#[derive(Clone, Copy)]
struct Case {
    actor: AuthenticatedCaller,
    epoch: u64,
    binding: Binding,
    initial: u64,
    jurisdiction: u64,
    basis: u64,
    sender: Principal,
    recipient: Principal,
    amount: u64,
}

fn number(row: &Vector<'_>, field: &str, default: u64) -> u64 {
    row.input
        .get(field)
        .map_or(default, |value| value.parse().unwrap())
}

impl Case {
    fn from_vector(row: &Vector<'_>) -> Self {
        let actor = AuthenticatedCaller(row.number("actor"));
        Self {
            actor,
            epoch: row.number("epoch"),
            binding: Binding {
                origin: OriginKey {
                    domain: row.number("source"),
                    event: number(row, "root_event", number(row, "event", 17)),
                },
                asset: row.number("asset"),
                owner: actor.0,
                destination: row.number("receiver"),
                recipient: number(row, "sender", number(row, "destination", 3)),
                amount: number(row, "root_amount", 5),
            },
            initial: number(row, "initial", 10),
            jurisdiction: number(row, "jurisdiction", 1),
            basis: number(row, "legal_basis", 1),
            sender: number(row, "sender", 3),
            recipient: number(row, "recipient", 4),
            amount: number(row, "amount", 1),
        }
    }

    fn key(self, event: u64) -> OriginKey {
        OriginKey {
            event,
            ..self.binding.origin
        }
    }

    fn id(self, sequence: u64) -> CallId {
        CallId {
            namespace: self.actor.0,
            sequence,
        }
    }

    fn reader(self) -> Reader {
        Reader {
            actor: self.actor,
            session: SESSION,
        }
    }

    fn scope(self, kind: SpendKind) -> SpendScope {
        SpendScope {
            root: self.binding,
            sender: self.sender,
            recipient: self.recipient,
            amount: self.amount,
            kind,
        }
    }

    fn endpoint(self, allow_confiscate: bool, allow_enforcement: bool) -> ReadAuthority {
        self.endpoint_with_enrollments(allow_confiscate, allow_enforcement, &[])
    }

    fn endpoint_with_enrollments(
        self,
        allow_confiscate: bool,
        allow_enforcement: bool,
        extra: &[Enrollment],
    ) -> ReadAuthority {
        let b = self.binding;
        let mut enrollments = vec![Enrollment {
            asset: b.asset,
            source: b.origin.domain,
            receiver: b.destination,
        }];
        enrollments.extend_from_slice(extra);
        let domains: BTreeSet<_> = enrollments
            .iter()
            .flat_map(|link| [link.source, link.receiver])
            .collect();
        let mut supply = BTreeMap::from([(b.asset, u128::from(self.initial))]);
        for link in extra {
            supply.entry(link.asset).or_default();
        }
        let permissions = [
            Permission::Reserve,
            Permission::Dispatch,
            Permission::Debit,
            Permission::Cancel,
            Permission::Attest,
            Permission::Credit,
            Permission::Reconcile,
            Permission::PublishPrimary,
        ];
        let contexts = domains.into_iter().map(|endpoint| EndpointContext {
            endpoint,
            epoch: self.epoch,
            grants: [Route::Normal, Route::Administrative, Route::Adapter]
                .into_iter()
                .flat_map(|route| {
                    permissions
                        .into_iter()
                        .map(move |permission| (self.actor.0, route, permission))
                })
                .collect(),
            dependencies: BTreeMap::new(),
            write_permissions: BTreeSet::new(),
        });
        let ledger = Ledger::new(
            self.epoch,
            contexts.collect(),
            BTreeMap::from([(
                SESSION,
                SessionBinding {
                    principal: self.actor.0,
                    authority_epoch: self.epoch,
                },
            )]),
            BTreeSet::from([self.actor.0]),
            BTreeMap::from([(b.source(), self.initial)]),
            &supply,
        )
        .unwrap();
        let mut legal = Vec::new();
        let mut spend = Vec::new();
        for route in ROUTES {
            for stage in STAGES {
                for action in ACTIONS {
                    if allow_confiscate || action != Action::Confiscate {
                        legal.push(LegalGrant {
                            stage,
                            route,
                            officer: self.actor.0,
                            jurisdiction: self.jurisdiction,
                            legal_basis: self.basis,
                            asset: b.asset,
                            action,
                            epoch: self.epoch,
                        });
                    }
                }
            }
            spend.push(SpendGrant {
                route,
                actor: self.actor.0,
                epoch: self.epoch,
                scope: self.scope(SpendKind::Ordinary),
                jurisdiction: 0,
                legal_basis: 0,
            });
            if allow_enforcement {
                for kind in [SpendKind::Recover, SpendKind::Confiscate] {
                    spend.push(SpendGrant {
                        route,
                        actor: self.actor.0,
                        epoch: self.epoch,
                        scope: self.scope(kind),
                        jurisdiction: self.jurisdiction,
                        legal_basis: self.basis,
                    });
                }
            }
        }
        ReadAuthority::new_regulated(
            Authority::new(ledger, 99).unwrap(),
            100,
            Policy {
                enrollments,
                legal,
                spend,
                clock_observers: BTreeSet::from([(self.actor.0, self.epoch)]),
            },
        )
        .unwrap()
    }

    fn ordinary_call(
        self,
        endpoint: &mut ReadAuthority,
        id: u64,
        binding: Binding,
        command: Command,
    ) -> CheckedExecution {
        let cut = endpoint.current_cut();
        let credential = match command {
            Command::Dispatch { generation }
            | Command::Debit { generation }
            | Command::Reconcile { generation, .. } => Some(generation),
            Command::Credit { .. } => Some(0),
            _ => None,
        }
        .map(|generation| Credential {
            asset: binding.asset,
            origin: binding.origin,
            holder: self.actor.0,
            generation,
            epoch: cut.authority_epoch,
        });
        let payload = CallPayload {
            message_id: id,
            origin_epoch: self.epoch,
            endpoint: if matches!(command, Command::Credit { .. }) {
                binding.destination
            } else {
                binding.origin.domain
            },
            caller: self.actor.0,
            session: SESSION,
            cut,
            binding,
            credential,
            versions: Vec::new(),
            command,
        };
        endpoint.execute_at_checked_cut(
            Route::Normal,
            self.actor,
            cut,
            self.id(id),
            &payload,
            |_, _, _| true,
        )
    }

    fn order(
        self,
        action: Action,
        event: u64,
        predecessor: Option<u64>,
        deadline: Option<u64>,
        destination: Option<u64>,
    ) -> Order {
        let b = self.binding;
        Order {
            binding: Binding {
                origin: self.key(event),
                recipient: destination.unwrap_or(b.recipient),
                amount: 0,
                ..b
            },
            action,
            officer: self.actor.0,
            jurisdiction: self.jurisdiction,
            legal_basis: self.basis,
            scope: BTreeSet::from([b.asset]),
            issuance_epoch: self.epoch,
            predecessor: predecessor.map(|prior| self.key(prior)),
            appeal_deadline: deadline,
            destination,
        }
    }

    fn order_call<'a>(
        self,
        endpoint: &ReadAuthority,
        stage: LegalStage,
        route: RegulatoryRoute,
        id: CallId,
        order: &'a Order,
    ) -> LegalCall<'a> {
        let cut = endpoint.current_cut();
        LegalCall {
            stage,
            route,
            actor: self.actor,
            id,
            expected: cut,
            order,
            payload: LegalPayload {
                message_id: id.sequence,
                caller: self.actor.0,
                session: SESSION,
                cut,
                binding: order.binding,
                action: order.action,
                origin_epoch: order.issuance_epoch,
            },
        }
    }

    fn submit_order(
        self,
        endpoint: &mut ReadAuthority,
        stage: LegalStage,
        route: RegulatoryRoute,
        sequence: u64,
        order: &Order,
    ) -> LegalReply {
        let call = self.order_call(endpoint, stage, route, self.id(sequence), order);
        endpoint.submit_order(call, |_| true)
    }

    fn complete_order(self, endpoint: &mut ReadAuthority, order: &Order, sequence: u64) {
        let route = RegulatoryRoute::Normal;
        assert!(matches!(
            self.submit_order(endpoint, LegalStage::SourceEmission, route, sequence, order),
            LegalReply::Emitted(_)
        ));
        assert!(matches!(
            self.submit_order(
                endpoint,
                LegalStage::ReceivingCommit,
                route,
                sequence + 1,
                order
            ),
            LegalReply::Applied(_)
        ));
        assert!(accepted(
            self.ordinary_call(
                endpoint,
                sequence + 2,
                order.binding,
                Command::PublishPrimary
            ),
            Reply::Published
        ));
    }

    fn clock(self, endpoint: &mut ReadAuthority, now: u64) {
        assert!(endpoint.observe_regulatory_time(
            self.actor,
            SESSION,
            endpoint.current_cut(),
            now,
            |_, _, _| true
        ));
    }

    fn read(self, endpoint: &ReadAuthority, query: Query) -> Value {
        endpoint
            .current(self.reader(), query, endpoint.current_cut(), None, ALLOWED)
            .unwrap()
            .value
    }

    fn mode(self, endpoint: &ReadAuthority, domain: EndpointId) -> Mode {
        let Value::Regulatory(Some(mode)) =
            self.read(endpoint, Query::RegulatoryState(domain, self.binding.asset))
        else {
            panic!("missing registered mode");
        };
        mode
    }

    fn fund_root(self, endpoint: &mut ReadAuthority) -> CommitRef {
        let b = self.binding;
        assert!(accepted(
            self.ordinary_call(endpoint, 100, b, Command::Reserve { duration: 20 }),
            Reply::Reserved
        ));
        assert!(accepted(
            self.ordinary_call(endpoint, 101, b, Command::Dispatch { generation: 0 }),
            Reply::SourceDispatched
        ));
        assert!(accepted(
            self.ordinary_call(endpoint, 102, b, Command::Debit { generation: 0 }),
            Reply::Debited
        ));
        let record = self.ordinary_call(
            endpoint,
            103,
            b,
            Command::RecordTerminal(TerminalEvidence {
                binding: b,
                kind: TerminalKind::Confirmed,
                reference: 0,
            }),
        );
        let CheckedExecution::Forwarded(Collection::Collected(Outcome {
            reply: OutcomeReply::Accepted(Reply::Recorded),
            commit: Some(commit),
        })) = record
        else {
            panic!("missing committed root")
        };
        assert_eq!(
            self.ordinary_call(endpoint, 104, b, Command::Credit { reference: 0 }),
            CheckedExecution::Forwarded(Collection::Waiting)
        );
        assert!(accepted(
            self.ordinary_call(
                endpoint,
                105,
                b,
                Command::Reconcile {
                    generation: 0,
                    reference: 0
                }
            ),
            Reply::Reconciled
        ));
        assert!(accepted(
            self.ordinary_call(endpoint, 106, b, Command::PublishPrimary),
            Reply::Published
        ));
        commit
    }

    fn spend_call<'a>(
        self,
        endpoint: &ReadAuthority,
        sequence: u64,
        reference: CommitRef,
        kind: SpendKind,
        enforcement: Option<&'a EnforcementOrder>,
    ) -> SpendCall<'a> {
        let cut = endpoint.current_cut();
        SpendCall {
            route: RegulatoryRoute::ForceInclusion,
            actor: self.actor,
            id: self.id(sequence),
            expected: cut,
            payload: SpendPayload {
                message_id: sequence,
                caller: self.actor.0,
                session: SESSION,
                cut,
                origin_epoch: self.epoch,
                reference,
                scope: self.scope(kind),
            },
            enforcement,
        }
    }

    fn order_for_spend(self, kind: SpendKind) -> EnforcementOrder {
        EnforcementOrder {
            scope: self.scope(kind),
            officer: self.actor.0,
            jurisdiction: self.jurisdiction,
            legal_basis: self.basis,
            assets: BTreeSet::from([self.binding.asset]),
            prior_seizure: None,
            appeal_deadline: None,
        }
    }

    fn balance(self, endpoint: &ReadAuthority, holder: Principal) -> u64 {
        let account = Account {
            owner: holder,
            ..self.binding.destination()
        };
        let Value::Units(units) =
            self.read(endpoint, Query::RootBalance(self.binding.origin, account))
        else {
            panic!("missing root units")
        };
        units
    }
}

fn accepted(value: CheckedExecution, reply: Reply) -> bool {
    matches!(value, CheckedExecution::Forwarded(Collection::Collected(Outcome {
        reply: OutcomeReply::Accepted(actual), commit: Some(_)
    })) if actual == reply)
}

fn effects(endpoint: &ReadAuthority) -> PrimarySnapshot {
    let mut snapshot = endpoint.authority.primary_snapshot();
    snapshot.regulation.legal_receipts.clear();
    snapshot.regulation.spend_receipts.clear();
    snapshot
}

fn refusal_name(reply: LegalReply) -> &'static str {
    match reply {
        LegalReply::Emitted(_) => "emitted",
        LegalReply::Applied(_) => "applied",
        LegalReply::Refused(Refusal::MissingPriorFreeze) => "missing_prior_freeze",
        LegalReply::Refused(Refusal::MissingPriorSeizure) => "missing_prior_seizure",
        LegalReply::Refused(Refusal::AppealStillOpen) => "appeal_still_open",
        LegalReply::Refused(Refusal::AppealDeadlineMismatch) => "appeal_deadline_mismatch",
        LegalReply::Refused(Refusal::InvalidAuthority) => "invalid_authority",
        LegalReply::Refused(_) => "other_refusal",
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Active => "active",
        Mode::Restricted => "restricted",
        Mode::Frozen => "frozen",
        Mode::Seized => "seized",
        Mode::Confiscated => "confiscated",
    }
}

fn route(value: &str) -> RegulatoryRoute {
    match value {
        "normal" => RegulatoryRoute::Normal,
        "administrative" => RegulatoryRoute::Administrative,
        "adapter" => RegulatoryRoute::Adapter,
        "force_inclusion" => RegulatoryRoute::ForceInclusion,
        _ => panic!("unknown route {value}"),
    }
}

fn setup_mode(case: Case, endpoint: &mut ReadAuthority, row: &Vector<'_>) {
    let mode = row.field("mode");
    if row.input.get("predecessor_kind") == Some(&"restrict") {
        let other = row.number("supplied_predecessor");
        case.complete_order(
            endpoint,
            &case.order(Action::Restrict, other, None, None, None),
            100,
        );
        case.complete_order(
            endpoint,
            &case.order(Action::Unrestrict, other + 1, None, None, None),
            110,
        );
    }
    if matches!(mode, "frozen" | "seized") {
        case.complete_order(
            endpoint,
            &case.order(Action::Freeze, row.number("freeze"), None, None, None),
            120,
        );
    }
    if mode == "restricted" {
        case.complete_order(
            endpoint,
            &case.order(Action::Restrict, 44, None, None, None),
            120,
        );
    }
    if mode == "seized" {
        case.complete_order(
            endpoint,
            &case.order(
                Action::Seize,
                row.number("seizure"),
                Some(row.number("freeze")),
                Some(number(row, "recorded_deadline", row.number("deadline"))),
                None,
            ),
            130,
        );
    }
    assert_eq!(
        mode_name(case.mode(endpoint, case.binding.origin.domain)),
        mode
    );
}

fn legal_vector(case: Case, row: &Vector<'_>) -> String {
    let action = if row.operation == "seize" {
        Action::Seize
    } else {
        Action::Confiscate
    };
    let exact = if action == Action::Seize {
        row.number("freeze")
    } else {
        row.number("seizure")
    };
    let order = case.order(
        action,
        row.number("event"),
        Some(number(row, "supplied_predecessor", exact)),
        Some(row.number("deadline")),
        (action == Action::Confiscate).then(|| row.number("destination")),
    );
    let routes = row.input.get("routes").map_or_else(
        || ROUTES.to_vec(),
        |routes| routes.split(',').map(route).collect(),
    );
    let mut observed = None;
    for route in routes {
        let mut endpoint = case.endpoint(row.input.get("grant") != Some(&"false"), true);
        setup_mode(case, &mut endpoint, row);
        case.clock(&mut endpoint, number(row, "now", 5));
        let before = effects(&endpoint);
        let first = case.submit_order(&mut endpoint, LegalStage::SourceEmission, route, 1, &order);
        let source_unchanged = effects(&endpoint) == before;
        let second =
            case.submit_order(&mut endpoint, LegalStage::ReceivingCommit, route, 2, &order);
        let text = if matches!(second, LegalReply::Applied(_)) {
            assert!(matches!(first, LegalReply::Emitted(_)), "{}", row.id);
            assert!(accepted(
                case.ordinary_call(&mut endpoint, 3, order.binding, Command::PublishPrimary),
                Reply::Published
            ));
            format!(
                "reply=applied;source_mode={};receiver_mode={}",
                mode_name(case.mode(&endpoint, case.binding.origin.domain)),
                mode_name(case.mode(&endpoint, case.binding.destination))
            )
        } else {
            assert_eq!(first, second, "{}", row.id);
            format!(
                "reply={};authority_unchanged={}",
                refusal_name(first),
                source_unchanged && effects(&endpoint) == before
            )
        };
        if let Some(previous) = observed.as_ref() {
            assert_eq!(&text, previous, "{}", row.id);
        }
        observed = Some(text);
    }
    observed.unwrap()
}

fn legal_retry(case: Case, row: &Vector<'_>) -> String {
    let mut endpoint = case.endpoint(true, true);
    setup_mode(case, &mut endpoint, row);
    case.clock(&mut endpoint, row.number("first_now"));
    let order = case.order(
        Action::Confiscate,
        row.number("event"),
        Some(row.number("seizure")),
        Some(row.number("deadline")),
        Some(row.number("destination")),
    );
    let id = CallId {
        namespace: row.number("call_namespace"),
        sequence: row.number("call_sequence"),
    };
    let call = case.order_call(
        &endpoint,
        LegalStage::SourceEmission,
        RegulatoryRoute::Normal,
        id,
        &order,
    );
    let first = endpoint.submit_order(call, |_| true);
    assert_eq!(first, LegalReply::Refused(Refusal::AppealStillOpen));
    case.clock(&mut endpoint, row.number("retry_now"));
    let before = endpoint.snapshot();
    let reply = endpoint.submit_order(call, |_| true);
    format!(
        "reply={};authority_unchanged={}",
        refusal_name(reply),
        endpoint.snapshot() == before
    )
}

fn restrict_held(case: Case, row: &Vector<'_>) -> String {
    let mut endpoint = case.endpoint(true, true);
    let binding = Binding {
        origin: case.key(row.number("reservation_event")),
        ..case.binding
    };
    assert!(accepted(
        case.ordinary_call(&mut endpoint, 1, binding, Command::Reserve { duration: 10 }),
        Reply::Reserved
    ));
    let order = case.order(
        Action::Restrict,
        row.number("restrict_event"),
        None,
        None,
        None,
    );
    case.complete_order(&mut endpoint, &order, 10);
    let ledger = &endpoint.authority.state.primary.ledger;
    let kept = ledger.lock_owner(binding.asset) == Some(binding.origin)
        && ledger.generation(binding.origin) == Some(0);
    format!(
        "reply=applied;mode={};reservation_preserved={kept}",
        mode_name(case.mode(&endpoint, binding.origin.domain))
    )
}

fn freeze_vector(case: Case, row: &Vector<'_>) -> String {
    let allowed = row.input.get("authorized") != Some(&"false");
    let mut endpoint = case.endpoint(true, allowed);
    let freeze = case.order(Action::Freeze, row.number("freeze_event"), None, None, None);
    if row.operation == "protected-debit" {
        assert_eq!(row.field("source_intent"), "dispatched");
        let b = Binding {
            amount: case.amount,
            ..case.binding
        };
        assert!(accepted(
            case.ordinary_call(&mut endpoint, 1, b, Command::Reserve { duration: 10 }),
            Reply::Reserved
        ));
        assert!(accepted(
            case.ordinary_call(&mut endpoint, 2, b, Command::Dispatch { generation: 0 }),
            Reply::SourceDispatched
        ));
        case.complete_order(&mut endpoint, &freeze, 10);
        let reply = case.ordinary_call(&mut endpoint, 3, b, Command::Debit { generation: 0 });
        let ledger = &endpoint.authority.state.primary.ledger;
        let reply = if accepted(reply, Reply::Debited) {
            "debited"
        } else {
            "rejected"
        };
        return format!(
            "reply={reply};source_balance={};new_pending={}",
            ledger.balance(b.source()),
            ledger.pending(b.origin)
        );
    }
    let reference = case.fund_root(&mut endpoint);
    case.complete_order(&mut endpoint, &freeze, 10);
    if row.operation == "frozen-read" {
        return format!(
            "mode={};kind=current",
            mode_name(case.mode(&endpoint, case.binding.destination))
        );
    }
    let kind = if row.operation == "enforcement-spend" {
        assert_eq!(row.field("kind"), "recover");
        SpendKind::Recover
    } else {
        SpendKind::Ordinary
    };
    let enforcement = (kind != SpendKind::Ordinary).then(|| case.order_for_spend(kind));
    let call = case.spend_call(&endpoint, 1, reference, kind, enforcement.as_ref());
    let reply = endpoint.submit_spend(call, |_| true);
    let sender = case.balance(&endpoint, case.sender);
    let recipient = case.balance(&endpoint, case.recipient);
    match reply {
        SpendReply::Executed { root, .. } if kind != SpendKind::Ordinary => format!(
            "reply=executed;sender_balance={sender};recipient_balance={recipient};root_consumed={};mode={}",
            root.event,
            mode_name(case.mode(&endpoint, case.binding.destination))
        ),
        SpendReply::Executed { .. } => {
            format!("reply=executed;sender_balance={sender};recipient_balance={recipient}")
        }
        _ => format!("reply=rejected;sender_balance={sender};recipient_balance={recipient}"),
    }
}

#[test]
fn proof_derived_regulatory_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        let case = Case::from_vector(&row);
        let result = match row.operation {
            "confiscate" | "seize" => legal_vector(case, &row),
            "legal-retry" => legal_retry(case, &row),
            "restrict-held" => restrict_held(case, &row),
            _ => freeze_vector(case, &row),
        };
        assert_eq!(result, row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 15);
}

fn standard_case() -> Case {
    Case::from_vector(
        &parse_vectors(VECTORS)
            .find(|row| row.id == "lawful-recovery-spend-after-freeze")
            .unwrap(),
    )
}

#[test]
fn thaw_paths_consume_the_current_exact_provenance() {
    let case = standard_case();
    let mut endpoint = case.endpoint(true, true);
    let freeze = case.order(Action::Freeze, 40, None, None, None);
    case.complete_order(&mut endpoint, &freeze, 100);
    let wrong = case.order(Action::Unfreeze, 41, Some(99), None, None);
    assert_eq!(
        case.submit_order(
            &mut endpoint,
            LegalStage::SourceEmission,
            RegulatoryRoute::Normal,
            1,
            &wrong
        ),
        LegalReply::Refused(Refusal::InvalidState)
    );
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Unfreeze, 42, Some(40), None, None),
        110,
    );
    assert_eq!(case.mode(&endpoint, case.binding.destination), Mode::Active);
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Restrict, 43, None, None, None),
        120,
    );
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Unrestrict, 44, None, None, None),
        130,
    );
    assert_eq!(case.mode(&endpoint, case.binding.destination), Mode::Active);
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Freeze, 45, None, None, None),
        140,
    );
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Seize, 46, Some(45), Some(5), None),
        150,
    );
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Release, 47, Some(46), None, None),
        160,
    );
    assert_eq!(
        case.mode(&endpoint, case.binding.origin.domain),
        Mode::Active
    );
    assert_eq!(case.mode(&endpoint, case.binding.destination), Mode::Active);
}

#[test]
fn receiving_requires_the_exact_emitted_order_and_payload() {
    let case = standard_case();
    let mut endpoint = case.endpoint(true, true);
    let order = case.order(Action::Freeze, 40, None, None, None);
    let before = effects(&endpoint);
    let call = case.order_call(
        &endpoint,
        LegalStage::SourceEmission,
        RegulatoryRoute::Normal,
        case.id(1),
        &order,
    );
    let changed = LegalCall {
        payload: LegalPayload {
            binding: Binding {
                recipient: order.binding.recipient + 1,
                ..order.binding
            },
            ..call.payload
        },
        ..call
    };
    assert_eq!(
        endpoint.submit_order(changed, |_| true),
        LegalReply::Refused(Refusal::InvalidBinding),
        "exact-legal-payload"
    );
    assert_eq!(effects(&endpoint), before);
    assert_eq!(
        case.submit_order(
            &mut endpoint,
            LegalStage::ReceivingCommit,
            RegulatoryRoute::ForceInclusion,
            2,
            &order
        ),
        LegalReply::Refused(Refusal::ConflictingOrder)
    );
    assert!(matches!(
        case.submit_order(
            &mut endpoint,
            LegalStage::SourceEmission,
            RegulatoryRoute::Adapter,
            3,
            &order
        ),
        LegalReply::Emitted(_)
    ));
    let altered = Order {
        legal_basis: order.legal_basis + 1,
        ..order.clone()
    };
    assert_eq!(
        case.submit_order(
            &mut endpoint,
            LegalStage::ReceivingCommit,
            RegulatoryRoute::Administrative,
            4,
            &altered
        ),
        LegalReply::Refused(Refusal::InvalidAuthority)
    );
    assert!(matches!(
        case.submit_order(
            &mut endpoint,
            LegalStage::ReceivingCommit,
            RegulatoryRoute::ForceInclusion,
            5,
            &order
        ),
        LegalReply::Applied(_)
    ));
    let query = Query::RegulatoryState(case.binding.destination, case.binding.asset);
    let unpublished = endpoint.current_cut();
    assert_eq!(
        endpoint.current(case.reader(), query, unpublished, None, ALLOWED),
        Err(ReadError::Busy)
    );
    assert!(accepted(
        case.ordinary_call(&mut endpoint, 6, order.binding, Command::PublishPrimary),
        Reply::Published
    ));
    assert_eq!(case.mode(&endpoint, case.binding.destination), Mode::Frozen);
    assert_eq!(
        endpoint.historical(case.reader(), query, unpublished.revision, ALLOWED),
        Err(ReadError::Busy)
    );
}

#[test]
fn lawful_enforcement_requires_exact_committed_root_and_bound_parties() {
    let case = standard_case();
    let mut endpoint = case.endpoint(true, true);
    let reference = case.fund_root(&mut endpoint);
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Freeze, 20, None, None, None),
        10,
    );
    let exact = case.order_for_spend(SpendKind::Recover);
    let before = effects(&endpoint);
    let bad_reference = case.spend_call(
        &endpoint,
        1,
        CommitRef {
            position: reference.position + 1,
        },
        SpendKind::Recover,
        Some(&exact),
    );
    assert_eq!(
        endpoint.submit_spend(bad_reference, |_| true),
        SpendReply::Rejected,
        "exact-root-reference"
    );
    let wrong = EnforcementOrder {
        scope: SpendScope {
            recipient: case.recipient + 1,
            ..exact.scope
        },
        ..exact.clone()
    };
    let wrong_parties = case.spend_call(&endpoint, 2, reference, SpendKind::Recover, Some(&wrong));
    assert_eq!(
        endpoint.submit_spend(wrong_parties, |_| true),
        SpendReply::Rejected,
        "exact-enforcement-payload"
    );
    assert_eq!(effects(&endpoint), before);
    let valid = case.spend_call(&endpoint, 3, reference, SpendKind::Recover, Some(&exact));
    let reply = endpoint.submit_spend(valid, |_| true);
    assert!(matches!(reply, SpendReply::Executed { root, .. } if root == case.binding.origin));
    let settled = endpoint.snapshot();
    assert_eq!(endpoint.submit_spend(valid, |_| true), reply);
    assert_eq!(endpoint.snapshot(), settled);
}

#[test]
fn confiscation_spend_uses_the_same_preserved_appeal_deadline() {
    let case = standard_case();
    let mut endpoint = case.endpoint(true, true);
    let reference = case.fund_root(&mut endpoint);
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Freeze, 20, None, None, None),
        10,
    );
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Seize, 21, Some(20), Some(5), None),
        20,
    );
    case.clock(&mut endpoint, 4);
    let mut order = case.order_for_spend(SpendKind::Confiscate);
    order.prior_seizure = Some(case.key(21));
    order.appeal_deadline = Some(4);
    let short = case.spend_call(&endpoint, 1, reference, SpendKind::Confiscate, Some(&order));
    assert_eq!(endpoint.submit_spend(short, |_| true), SpendReply::Rejected);
    assert_eq!(case.balance(&endpoint, case.sender), 5);
    case.clock(&mut endpoint, 5);
    order.appeal_deadline = Some(5);
    let live = case.spend_call(&endpoint, 2, reference, SpendKind::Confiscate, Some(&order));
    assert!(matches!(
        endpoint.submit_spend(live, |_| true),
        SpendReply::Executed { .. }
    ));
    assert_eq!(case.balance(&endpoint, case.sender), 4);
}

#[test]
fn freeze_updates_all_enrolled_domains_and_blocks_the_other_receiver_spend() {
    let base = standard_case();
    let case = Case {
        binding: Binding {
            destination: 3,
            ..base.binding
        },
        ..base
    };
    let another_asset = case.binding.asset + 1;
    let mut endpoint = case.endpoint_with_enrollments(
        true,
        true,
        &[
            Enrollment {
                asset: case.binding.asset,
                source: case.binding.origin.domain,
                receiver: 2,
            },
            Enrollment {
                asset: another_asset,
                source: case.binding.origin.domain,
                receiver: 3,
            },
        ],
    );
    let reference = case.fund_root(&mut endpoint);
    let order = base.order(Action::Freeze, 20, None, None, None);
    base.complete_order(&mut endpoint, &order, 10);
    for domain in [case.binding.origin.domain, 2, 3] {
        assert_eq!(
            case.mode(&endpoint, domain),
            Mode::Frozen,
            "freeze-all-enrolled-domains"
        );
    }
    assert_eq!(
        case.read(&endpoint, Query::RegulatoryState(3, another_asset)),
        Value::Regulatory(Some(Mode::Active))
    );
    let call = case.spend_call(&endpoint, 1, reference, SpendKind::Ordinary, None);
    assert_eq!(
        endpoint.submit_spend(call, |_| true),
        SpendReply::Rejected,
        "frozen-other-receiver-spend"
    );
    assert_eq!(case.balance(&endpoint, case.sender), 5);
    assert_eq!(case.balance(&endpoint, case.recipient), 0);

    // The SEIZE is received at 3, using the completed FREEZE received at 2.
    case.complete_order(
        &mut endpoint,
        &case.order(Action::Seize, 21, Some(20), Some(5), None),
        20,
    );
    assert_eq!(case.mode(&endpoint, 2), Mode::Seized);
    assert_eq!(case.mode(&endpoint, 3), Mode::Seized);
    base.complete_order(
        &mut endpoint,
        &base.order(Action::Release, 22, Some(21), None, None),
        30,
    );
    assert_eq!(case.mode(&endpoint, 3), Mode::Active);
    let call = case.spend_call(&endpoint, 2, reference, SpendKind::Ordinary, None);
    assert!(matches!(
        endpoint.submit_spend(call, |_| true),
        SpendReply::Executed { .. }
    ));

    let authority = &endpoint.authority.state.primary;
    let mut duplicated = authority.regulation.policy.clone();
    duplicated.enrollments.push(duplicated.enrollments[0]);
    assert!(RegulationState::configured(duplicated, &authority.ledger).is_none());
}

#[test]
fn a_confiscation_without_a_destination_is_refused_on_every_route() {
    let case = standard_case();
    for route in ROUTES {
        let mut endpoint = case.endpoint(true, true);
        case.complete_order(
            &mut endpoint,
            &case.order(Action::Freeze, 40, None, None, None),
            120,
        );
        case.complete_order(
            &mut endpoint,
            &case.order(Action::Seize, 41, Some(40), Some(5), None),
            130,
        );
        case.clock(&mut endpoint, 5);
        let missing = case.order(Action::Confiscate, 42, Some(41), Some(5), None);
        let before = effects(&endpoint);
        let first = case.submit_order(&mut endpoint, LegalStage::SourceEmission, route, 1, &missing);
        assert_eq!(
            first,
            LegalReply::Refused(Refusal::MissingDestination),
            "{route:?}"
        );
        assert_eq!(
            case.submit_order(&mut endpoint, LegalStage::ReceivingCommit, route, 2, &missing),
            first,
            "{route:?}"
        );
        assert_eq!(effects(&endpoint), before, "{route:?}");
        assert_eq!(
            case.mode(&endpoint, case.binding.origin.domain),
            Mode::Seized
        );

        // The same order with its destination is applied.
        let exact = case.order(
            Action::Confiscate,
            42,
            Some(41),
            Some(5),
            Some(case.binding.recipient),
        );
        assert!(
            matches!(
                case.submit_order(&mut endpoint, LegalStage::SourceEmission, route, 3, &exact),
                LegalReply::Emitted(_)
            ),
            "{route:?}"
        );
        assert!(
            matches!(
                case.submit_order(&mut endpoint, LegalStage::ReceivingCommit, route, 4, &exact),
                LegalReply::Applied(_)
            ),
            "{route:?}"
        );
    }
}
