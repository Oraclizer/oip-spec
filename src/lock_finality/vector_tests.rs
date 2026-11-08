use super::*;
use crate::vector_tests::{Vector, parse_vectors};

const VECTORS: &str = include_str!("../../tests/vectors/lock-finality.tsv");
const CALLER: Principal = 7;
const SESSION: SessionId = 1;
const INITIAL_EPOCH: u64 = 9;
const LEASE: u64 = 5;
const ROUTES: [Route; 3] = [Route::Normal, Route::Administrative, Route::Adapter];
const PERMISSIONS: [Permission; 12] = [
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
];

fn context(endpoint: EndpointId, epoch: u64) -> EndpointContext {
    EndpointContext {
        endpoint,
        epoch,
        dependencies: BTreeMap::new(),
        write_permissions: BTreeSet::new(),
        grants: [CALLER, CALLER + 1]
            .into_iter()
            .flat_map(|caller| {
                ROUTES.into_iter().flat_map(move |route| {
                    PERMISSIONS
                        .into_iter()
                        .map(move |permission| (caller, route, permission))
                })
            })
            .collect(),
    }
}

fn sessions(epoch: u64) -> BTreeMap<SessionId, SessionBinding> {
    BTreeMap::from([
        (
            SESSION,
            SessionBinding {
                principal: CALLER,
                authority_epoch: epoch,
            },
        ),
        (
            SESSION + 1,
            SessionBinding {
                principal: CALLER + 1,
                authority_epoch: epoch,
            },
        ),
    ])
}

fn standard_binding() -> Binding {
    Binding {
        origin: OriginKey {
            domain: 0,
            event: 17,
        },
        asset: 17,
        owner: CALLER,
        destination: 2,
        recipient: 3,
        amount: 5,
    }
}

fn initialize(binding: Binding, epoch: u64, initial: u64) -> Ledger {
    Ledger::new(
        epoch,
        vec![
            context(binding.origin.domain, epoch),
            context(binding.destination, epoch),
        ],
        sessions(epoch),
        BTreeSet::from([CALLER]),
        BTreeMap::from([(binding.source(), initial)]),
        &BTreeMap::from([(binding.asset, u128::from(initial))]),
    )
    .unwrap()
}

fn credential(binding: Binding, holder: Principal, generation: u64, epoch: u64) -> Credential {
    Credential {
        asset: binding.asset,
        origin: binding.origin,
        holder,
        generation,
        epoch,
    }
}

fn request(
    ledger: &Ledger,
    binding: Binding,
    command: Command,
    supplied: Option<Credential>,
) -> Request<'static> {
    Request {
        endpoint: match command {
            Command::Credit { .. } => binding.destination,
            _ => binding.origin.domain,
        },
        caller: CALLER,
        session: SESSION,
        cut: ledger.current_cut(),
        binding,
        credential: supplied,
        versions: &[],
        command,
    }
}

fn submit(ledger: &mut Ledger, route: Route, req: Request<'_>) -> Reply {
    let actor = AuthenticatedCaller(req.caller);
    match route {
        Route::Normal => ledger.submit_normal(actor, req, |_, _, _| true),
        Route::Administrative => ledger.submit_administrative(actor, req, |_, _, _| true),
        Route::Adapter => ledger.submit_adapter(actor, req, |_, _, _| true),
    }
}

fn act(
    ledger: &mut Ledger,
    route: Route,
    binding: Binding,
    command: Command,
    supplied: Option<Credential>,
) -> Reply {
    let req = request(ledger, binding, command, supplied);
    submit(ledger, route, req)
}

fn mass(ledger: &Ledger, binding: Binding) -> String {
    format!(
        "source={};pending={};destination={}",
        ledger.balance(binding.source()),
        ledger.pending(binding.origin),
        ledger.balance(binding.destination())
    )
}

fn reply_name(reply: Reply) -> &'static str {
    match reply {
        Reply::SourceDispatched => "source_dispatched",
        Reply::Rejected => "rejected",
        Reply::Busy => "busy",
        Reply::Credited => "credited",
        Reply::Refunded => "refunded",
        unexpected => panic!("unexpected vector reply {unexpected:?}"),
    }
}

fn version_entries(input: &str) -> Vec<(AssetId, u64)> {
    input
        .split(',')
        .map(|entry| {
            let (asset, version) = entry.split_once(':').unwrap();
            (asset.parse().unwrap(), version.parse().unwrap())
        })
        .collect()
}

fn with_footprint(
    first: Binding,
    second: Binding,
    epoch: u64,
    second_balance: u64,
    dependencies: BTreeMap<AssetId, BTreeSet<AssetId>>,
    writes: BTreeSet<(Principal, AssetId, u64)>,
) -> Ledger {
    let mut source = context(first.origin.domain, epoch);
    source.dependencies = dependencies;
    source.write_permissions = writes;
    Ledger::new(
        epoch,
        vec![source, context(first.destination, epoch)],
        sessions(epoch),
        BTreeSet::from([CALLER]),
        BTreeMap::from([(first.source(), 10), (second.source(), second_balance)]),
        &BTreeMap::from([
            (first.asset, 10),
            (second.asset, u128::from(second_balance)),
        ]),
    )
    .unwrap()
}

fn run_footprint(row: &Vector<'_>) -> String {
    let caller = row.number("caller");
    let epoch = row.number("epoch");
    let domain = row.number("source_domain");
    let versions = version_entries(row.field("versions"));
    let opposite = row.operation == "opposite-locks";
    let (asset, event, other_asset, other_event) = if opposite {
        (
            row.number("first_asset"),
            row.number("first_event"),
            row.number("second_asset"),
            row.number("second_event"),
        )
    } else {
        let dependency = row.number("dependency");
        (
            row.number("asset"),
            row.number("event"),
            dependency,
            dependency,
        )
    };
    let first = Binding {
        owner: caller,
        asset,
        origin: OriginKey { domain, event },
        ..standard_binding()
    };
    let second = Binding {
        owner: caller,
        asset: other_asset,
        origin: OriginKey {
            domain,
            event: other_event,
        },
        ..standard_binding()
    };
    let dependencies = if opposite {
        let mut dependencies = BTreeMap::<AssetId, BTreeSet<AssetId>>::new();
        for (asset, dependency) in version_entries(row.field("dependencies")) {
            dependencies.entry(asset).or_default().insert(dependency);
        }
        dependencies
    } else {
        BTreeMap::from([(asset, BTreeSet::from([other_asset]))])
    };
    let other_balance = if opposite {
        row.number("second_source_balance")
    } else {
        0
    };
    let mut ledger = with_footprint(
        first,
        second,
        epoch,
        other_balance,
        dependencies,
        BTreeSet::new(),
    );
    let reserve = Command::Reserve { duration: LEASE };
    let initial_versions = if opposite { versions.as_slice() } else { &[] };
    let first_reserve = Request {
        caller,
        versions: initial_versions,
        ..request(&ledger, first, reserve, None)
    };
    assert_eq!(
        submit(&mut ledger, Route::Normal, first_reserve),
        Reply::Reserved
    );
    let before = ledger.snapshot();
    if opposite {
        let second_reserve = Request {
            caller,
            versions: &versions,
            ..request(&ledger, second, reserve, None)
        };
        let reply = submit(&mut ledger, Route::Normal, second_reserve);
        if reply == Reply::Busy {
            assert_eq!(ledger.snapshot(), before, "{}", row.id);
        }
        let first_owner = ledger
            .lock_owner(asset)
            .map(|origin| origin.event.to_string())
            .unwrap_or_else(|| "none".to_owned());
        let second_owner = ledger
            .lock_owner(other_asset)
            .map(|origin| origin.event.to_string())
            .unwrap_or_else(|| "none".to_owned());
        return format!(
            "reply={};owner_{asset}={first_owner};owner_{other_asset}={second_owner};second_reserved={}",
            reply_name(reply),
            ledger.generation(second.origin).is_some()
        );
    }

    let generation = row.number("generation");
    let token = Some(credential(first, caller, generation, epoch));
    let dispatch = Request {
        caller,
        versions: &versions,
        ..request(&ledger, first, Command::Dispatch { generation }, token)
    };
    let reply = submit(&mut ledger, Route::Normal, dispatch);
    let observed = format!("reply={}", reply_name(reply));
    if row.expected.contains("unchanged") {
        return format!("{observed};unchanged={}", ledger.snapshot() == before);
    }
    observed
}
fn run(row: &Vector<'_>) -> String {
    if matches!(row.operation, "opposite-locks" | "pair-dispatch") {
        return run_footprint(row);
    }
    let epoch = row.number("epoch");
    let caller = row.number("caller");
    let binding = Binding {
        origin: OriginKey {
            domain: row.number("source_domain"),
            event: row.number("event"),
        },
        asset: row.number("asset"),
        owner: caller,
        destination: row
            .input
            .get("destination_domain")
            .map_or(2, |n| n.parse().unwrap()),
        recipient: row.input.get("recipient").map_or(3, |n| n.parse().unwrap()),
        amount: row.input.get("amount").map_or(5, |n| n.parse().unwrap()),
    };
    let mut ledger = initialize(
        binding,
        epoch,
        row.input.get("initial").map_or(10, |n| n.parse().unwrap()),
    );
    let reserve = request(&ledger, binding, Command::Reserve { duration: LEASE }, None);
    assert_eq!(
        submit(&mut ledger, Route::Normal, Request { caller, ..reserve }),
        Reply::Reserved
    );
    let generation = row.number("generation");
    if matches!(row.operation, "dispatch" | "rotate-and-dispatch") {
        let route = match row.field("route") {
            "normal" => Route::Normal,
            "administrative" => Route::Administrative,
            "adapter" => Route::Adapter,
            other => panic!("unknown route {other}"),
        };
        let rotated = row.operation == "rotate-and-dispatch";
        if rotated {
            let new_epoch = row.number("new_epoch");
            let contexts = row
                .field("registered")
                .split(',')
                .map(|value| context(value.parse().unwrap(), new_epoch))
                .collect();
            assert!(ledger.install_epoch(
                AuthenticatedCaller(caller),
                new_epoch,
                contexts,
                sessions(new_epoch)
            ));
        }
        let supplied = Credential {
            origin: OriginKey {
                event: row.number("token_event"),
                ..binding.origin
            },
            ..credential(
                binding,
                row.number("holder"),
                generation,
                row.number("token_epoch"),
            )
        };
        let before = ledger.snapshot();
        let dispatch = request(
            &ledger,
            binding,
            Command::Dispatch { generation: 0 },
            Some(supplied),
        );
        let reply = submit(&mut ledger, route, Request { caller, ..dispatch });
        let observed = format!("reply={}", reply_name(reply));
        if rotated {
            return format!(
                "epoch={};{observed};unchanged_after_install={}",
                ledger.current_cut().authority_epoch,
                ledger.snapshot() == before
            );
        }
        if row.expected.contains("unchanged") {
            return format!("{observed};unchanged={}", ledger.snapshot() == before);
        }
        return observed;
    }
    let token = Some(credential(binding, caller, generation, epoch));
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Dispatch { generation },
            token
        ),
        Reply::SourceDispatched
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Debit { generation },
            token
        ),
        Reply::Debited
    );

    match row.operation {
        "debit" => mass(&ledger, binding),
        "timeout" => {
            assert_eq!(
                act(
                    &mut ledger,
                    Route::Normal,
                    binding,
                    Command::Timeout {
                        elapsed: row.number("elapsed")
                    },
                    None
                ),
                Reply::TimeObserved
            );
            mass(&ledger, binding)
        }
        "cancel" | "fence" => {
            let command = if row.operation == "cancel" {
                Command::Cancel { generation }
            } else {
                Command::Fence { generation }
            };
            let before = ledger.snapshot();
            let reply = act(&mut ledger, Route::Normal, binding, command, token);
            assert_eq!(ledger.snapshot(), before, "{}", row.id);
            format!("reply={};{}", reply_name(reply), mass(&ledger, binding))
        }
        "retry-debit" => {
            let before = ledger.snapshot();
            act(
                &mut ledger,
                Route::Normal,
                binding,
                Command::Debit { generation },
                token,
            );
            let observed = mass(&ledger, binding);
            assert_eq!(observed, row.expected, "{}", row.id);
            assert_eq!(ledger.snapshot(), before, "{}", row.id);
            observed
        }
        "driver-loss" => {
            let before = ledger.snapshot();
            ledger.driver_connection(false);
            assert_eq!(ledger.snapshot(), before);
            assert_eq!(
                act(
                    &mut ledger,
                    Route::Adapter,
                    binding,
                    Command::Debit { generation },
                    token
                ),
                Reply::Rejected
            );
            mass(&ledger, binding)
        }
        "preempt" => {
            assert_eq!(
                act(
                    &mut ledger,
                    Route::Normal,
                    binding,
                    Command::Timeout {
                        elapsed: row.number("elapsed")
                    },
                    None
                ),
                Reply::TimeObserved
            );
            assert_eq!(
                act(
                    &mut ledger,
                    Route::Administrative,
                    binding,
                    Command::Preempt {
                        duration: row.number("duration")
                    },
                    None
                ),
                Reply::Preempted
            );
            format!(
                "generation={};{}",
                ledger.generation(binding.origin).unwrap(),
                mass(&ledger, binding)
            )
        }
        "credit" | "refund" | "timeout-and-credit" => {
            if row.operation == "timeout-and-credit" {
                assert_eq!(
                    act(
                        &mut ledger,
                        Route::Normal,
                        binding,
                        Command::Timeout {
                            elapsed: row.number("elapsed")
                        },
                        None
                    ),
                    Reply::TimeObserved
                );
            }
            let kind = match row.field("evidence") {
                "confirmed" => TerminalKind::Confirmed,
                "reversed" => TerminalKind::Reversed,
                other => panic!("unknown evidence kind {other}"),
            };
            let evidence = TerminalEvidence {
                binding,
                kind,
                reference: row.number("record_index"),
            };
            assert_eq!(
                act(
                    &mut ledger,
                    Route::Adapter,
                    binding,
                    Command::RecordTerminal(evidence),
                    None
                ),
                Reply::Recorded
            );
            let reference = row.number("request_index");
            let command = if row.operation == "refund" {
                Command::Refund {
                    generation,
                    reference,
                }
            } else {
                Command::Credit { reference }
            };
            let reply = act(&mut ledger, Route::Adapter, binding, command, token);
            format!("reply={};{}", reply_name(reply), mass(&ledger, binding))
        }
        operation => panic!("{}: unknown operation {operation}", row.id),
    }
}

#[test]
fn proof_derived_lock_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        assert_eq!(run(&row), row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 23);
}

fn pending_ledger(binding: Binding) -> (Ledger, Credential) {
    let mut ledger = initialize(binding, INITIAL_EPOCH, 10);
    let token = make_pending(&mut ledger, binding);
    (ledger, token)
}

fn make_pending(ledger: &mut Ledger, binding: Binding) -> Credential {
    let token = credential(binding, CALLER, 0, INITIAL_EPOCH);
    assert_eq!(
        act(
            ledger,
            Route::Normal,
            binding,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Reserved
    );
    assert_eq!(
        act(
            ledger,
            Route::Normal,
            binding,
            Command::Dispatch { generation: 0 },
            Some(token)
        ),
        Reply::SourceDispatched
    );
    assert_eq!(
        act(
            ledger,
            Route::Normal,
            binding,
            Command::Debit { generation: 0 },
            Some(token)
        ),
        Reply::Debited
    );
    token
}

#[test]
fn genesis_requires_expected_supply_and_overdraw_is_rejected_after_reserve() {
    let binding = standard_binding();
    let bad = Ledger::new(
        INITIAL_EPOCH,
        vec![context(0, INITIAL_EPOCH), context(2, INITIAL_EPOCH)],
        sessions(INITIAL_EPOCH),
        BTreeSet::new(),
        BTreeMap::from([(binding.source(), 11)]),
        &BTreeMap::from([(binding.asset, 10)]),
    );
    assert!(matches!(bad, Err(GenesisError::InvalidSupply)));
    let mut ledger = initialize(binding, INITIAL_EPOCH, 0);
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Reserved
    );
    let before = ledger.snapshot();
    let token = Some(credential(binding, CALLER, 0, INITIAL_EPOCH));
    for command in [
        Command::Dispatch { generation: 0 },
        Command::Debit { generation: 0 },
    ] {
        assert_eq!(
            act(&mut ledger, Route::Normal, binding, command, token),
            Reply::Rejected
        );
        assert_eq!(ledger.snapshot(), before);
    }
}

#[test]
fn role_route_identity_and_current_cut_are_independent_checks() {
    let binding = standard_binding();
    let epoch = INITIAL_EPOCH;
    let mut source = context(0, epoch);
    source
        .grants
        .remove(&(CALLER, Route::Normal, Permission::Fence));
    let mut ledger = Ledger::new(
        epoch,
        vec![source, context(2, epoch)],
        sessions(epoch),
        BTreeSet::from([CALLER]),
        BTreeMap::from([(binding.source(), 10)]),
        &BTreeMap::from([(binding.asset, 10)]),
    )
    .unwrap();
    let reserve = request(&ledger, binding, Command::Reserve { duration: LEASE }, None);
    let before = ledger.snapshot();
    assert_eq!(
        ledger.submit_normal(AuthenticatedCaller(CALLER + 1), reserve, |_, _, _| true),
        Reply::Rejected
    );
    assert_eq!(
        ledger.submit_normal(AuthenticatedCaller(CALLER), reserve, |_, _, _| false),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(submit(&mut ledger, Route::Normal, reserve), Reply::Reserved);
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Dispatch { generation: 0 },
            Some(credential(binding, CALLER, 0, epoch))
        ),
        Reply::SourceDispatched
    );
    let fence = request(
        &ledger,
        binding,
        Command::Fence { generation: 0 },
        Some(credential(binding, CALLER, 0, epoch)),
    );
    let before = ledger.snapshot();
    assert_eq!(submit(&mut ledger, Route::Normal, fence), Reply::Rejected);
    let stale = Request {
        cut: reserve.cut,
        ..fence
    };
    assert_eq!(
        submit(&mut ledger, Route::Administrative, stale),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        submit(&mut ledger, Route::Administrative, fence),
        Reply::Closed
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Rejected
    );
}

#[test]
fn epoch_install_is_complete_unique_newer_and_maintainer_only() {
    let binding = standard_binding();
    let old = INITIAL_EPOCH;
    let new = old + 1;
    let mut ledger = initialize(binding, old, 10);
    let before = ledger.snapshot();
    for (caller, epoch, batch) in [
        (CALLER, new, vec![context(0, new)]),
        (
            CALLER,
            new,
            vec![context(0, new), context(0, new), context(2, new)],
        ),
        (CALLER, new, vec![context(0, new), context(2, old)]),
        (CALLER + 1, new, vec![context(0, new), context(2, new)]),
        (CALLER, old, vec![context(0, old), context(2, old)]),
    ] {
        assert!(!ledger.install_epoch(AuthenticatedCaller(caller), epoch, batch, sessions(epoch)));
        assert_eq!(ledger.snapshot(), before);
    }
    assert!(ledger.install_epoch(
        AuthenticatedCaller(CALLER),
        new,
        vec![context(0, new), context(2, new)],
        sessions(new)
    ));
    assert_eq!(ledger.current_cut().authority_epoch, new);
}

#[test]
fn terminal_binding_and_pending_preemption_preserve_single_resolution() {
    let binding = standard_binding();
    let (mut ledger, old_token) = pending_ledger(binding);
    let evidence = TerminalEvidence {
        binding,
        kind: TerminalKind::Confirmed,
        reference: 3,
    };
    let wrong = TerminalEvidence {
        binding: Binding {
            amount: 1,
            ..binding
        },
        ..evidence
    };
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::RecordTerminal(wrong),
            None
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::RecordTerminal(evidence),
            None
        ),
        Reply::Recorded
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Timeout { elapsed: LEASE },
            None
        ),
        Reply::TimeObserved
    );
    let preempt = Request {
        caller: CALLER + 1,
        session: SESSION + 1,
        ..request(&ledger, binding, Command::Preempt { duration: LEASE }, None)
    };
    assert_eq!(
        submit(&mut ledger, Route::Administrative, preempt),
        Reply::Preempted
    );
    assert_eq!(ledger.evidence(3), Some(evidence));
    assert_eq!(ledger.pending(binding.origin), 5);
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::Credit { reference: 3 },
            Some(old_token)
        ),
        Reply::Rejected
    );
    let token = credential(binding, CALLER + 1, 1, INITIAL_EPOCH);
    let credit = Request {
        caller: CALLER + 1,
        session: SESSION + 1,
        ..request(
            &ledger,
            binding,
            Command::Credit { reference: 3 },
            Some(token),
        )
    };
    assert_eq!(submit(&mut ledger, Route::Adapter, credit), Reply::Credited);
    let before = ledger.snapshot();
    let replay = Request {
        cut: ledger.current_cut(),
        ..credit
    };
    assert_eq!(submit(&mut ledger, Route::Adapter, replay), Reply::Rejected);
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::RecordTerminal(TerminalEvidence {
                kind: TerminalKind::Reversed,
                reference: 4,
                ..evidence
            }),
            None
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(mass(&ledger, binding), "source=5;pending=0;destination=5");
}

#[test]
fn verified_worker_reserves_and_debits_the_distinct_bound_owner() {
    let binding = Binding {
        owner: 3,
        ..standard_binding()
    };
    let mut ledger = initialize(binding, INITIAL_EPOCH, 10);
    let token = Some(credential(binding, CALLER, 0, INITIAL_EPOCH));
    let verify = |who: AuthenticatedCaller, route, signed: &Request| {
        who.0 == CALLER && route == Route::Normal && signed.binding == binding
    };
    let before = ledger.snapshot();
    let modified = request(
        &ledger,
        Binding {
            recipient: 8,
            ..binding
        },
        Command::Reserve { duration: LEASE },
        None,
    );
    assert_eq!(
        ledger.submit_normal(AuthenticatedCaller(CALLER), modified, verify),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    for (command, supplied, reply) in [
        (Command::Reserve { duration: LEASE }, None, Reply::Reserved),
        (
            Command::Dispatch { generation: 0 },
            token,
            Reply::SourceDispatched,
        ),
        (Command::Debit { generation: 0 }, token, Reply::Debited),
    ] {
        let req = request(&ledger, binding, command, supplied);
        assert_eq!(
            ledger.submit_normal(AuthenticatedCaller(CALLER), req, verify),
            reply
        );
    }
    assert_eq!(ledger.balance(binding.source()), 5);
    assert_eq!(
        ledger.balance(Account {
            owner: CALLER,
            ..binding.source()
        }),
        0
    );
    assert_eq!(ledger.pending(binding.origin), 5);
}

#[test]
fn held_cancel_and_dispatched_fence_are_distinct() {
    let binding = standard_binding();
    let mut ledger = initialize(binding, INITIAL_EPOCH, 10);
    let held = Some(credential(binding, CALLER, 0, INITIAL_EPOCH));
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Reserved
    );
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Administrative,
            binding,
            Command::Fence { generation: 0 },
            held
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Cancel { generation: 0 },
            held
        ),
        Reply::Closed
    );

    let next = Binding {
        origin: OriginKey {
            event: binding.origin.event + 1,
            ..binding.origin
        },
        ..binding
    };
    let dispatched = Some(credential(next, CALLER, 0, INITIAL_EPOCH));
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            next,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Reserved
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            next,
            Command::Dispatch { generation: 0 },
            dispatched
        ),
        Reply::SourceDispatched
    );
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            next,
            Command::Cancel { generation: 0 },
            dispatched
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(
            &mut ledger,
            Route::Administrative,
            next,
            Command::Fence { generation: 0 },
            dispatched
        ),
        Reply::Closed
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            next,
            Command::Debit { generation: 0 },
            dispatched
        ),
        Reply::Rejected
    );
    assert_eq!(mass(&ledger, next), "source=10;pending=0;destination=0");
}

#[test]
fn exact_reconcile_releases_a_credited_lock_without_moving_money() {
    let binding = standard_binding();
    let (mut ledger, token) = pending_ledger(binding);
    let reference = 4;
    let evidence = TerminalEvidence {
        binding,
        kind: TerminalKind::Confirmed,
        reference,
    };
    let reconcile = Command::Reconcile {
        generation: 0,
        reference,
    };
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::RecordTerminal(evidence),
            None
        ),
        Reply::Recorded
    );
    let before = ledger.snapshot();
    assert_eq!(
        act(&mut ledger, Route::Normal, binding, reconcile, Some(token)),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::Credit { reference },
            Some(token)
        ),
        Reply::Credited
    );

    let next = Binding {
        origin: OriginKey {
            event: binding.origin.event + 1,
            ..binding.origin
        },
        ..binding
    };
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            next,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Busy
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            Command::Reconcile {
                generation: 0,
                reference: reference + 1
            },
            Some(token)
        ),
        Reply::Rejected
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            reconcile,
            Some(Credential {
                epoch: INITIAL_EPOCH - 1,
                ..token
            })
        ),
        Reply::Rejected
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            binding,
            reconcile,
            Some(Credential {
                generation: 1,
                ..token
            })
        ),
        Reply::Rejected
    );
    let other = Request {
        caller: CALLER + 1,
        session: SESSION + 1,
        ..request(&ledger, binding, reconcile, Some(token))
    };
    assert_eq!(submit(&mut ledger, Route::Normal, other), Reply::Rejected);
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(&mut ledger, Route::Normal, binding, reconcile, Some(token)),
        Reply::Reconciled
    );
    assert_eq!(mass(&ledger, binding), "source=5;pending=0;destination=5");
    let before = ledger.snapshot();
    assert_eq!(
        act(&mut ledger, Route::Normal, binding, reconcile, Some(token)),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            next,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Reserved
    );
}

#[test]
fn expired_lease_requires_reassignment_before_return_or_reconcile() {
    for kind in [TerminalKind::Confirmed, TerminalKind::Reversed] {
        let binding = standard_binding();
        let dependency = Binding {
            asset: 30,
            origin: OriginKey {
                event: 30,
                ..binding.origin
            },
            ..binding
        };
        let dependencies = BTreeMap::from([(binding.asset, BTreeSet::from([dependency.asset]))]);
        let mut ledger = with_footprint(
            binding,
            dependency,
            INITIAL_EPOCH,
            0,
            dependencies,
            BTreeSet::new(),
        );
        let token = make_pending(&mut ledger, binding);
        let reference = 2;
        let evidence = TerminalEvidence {
            binding,
            kind,
            reference,
        };
        assert_eq!(
            act(
                &mut ledger,
                Route::Adapter,
                binding,
                Command::RecordTerminal(evidence),
                None
            ),
            Reply::Recorded
        );
        assert_eq!(
            act(
                &mut ledger,
                Route::Normal,
                binding,
                Command::Timeout { elapsed: LEASE },
                None
            ),
            Reply::TimeObserved
        );
        let (resolution, done) = match kind {
            TerminalKind::Confirmed => {
                assert_eq!(
                    act(
                        &mut ledger,
                        Route::Adapter,
                        binding,
                        Command::Credit { reference },
                        Some(token)
                    ),
                    Reply::Credited
                );
                (
                    Command::Reconcile {
                        generation: 0,
                        reference,
                    },
                    Reply::Reconciled,
                )
            }
            TerminalKind::Reversed => (
                Command::Refund {
                    generation: 0,
                    reference,
                },
                Reply::Refunded,
            ),
        };
        let before = ledger.snapshot();
        assert_eq!(
            act(&mut ledger, Route::Normal, binding, resolution, Some(token)),
            Reply::Rejected
        );
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(
            act(
                &mut ledger,
                Route::Administrative,
                binding,
                Command::Preempt { duration: LEASE },
                None
            ),
            Reply::Preempted
        );
        assert_eq!(ledger.evidence(reference), Some(evidence));
        assert_eq!(ledger.lock_owner(binding.asset), Some(binding.origin));
        assert_eq!(ledger.lock_owner(dependency.asset), Some(binding.origin));
        let fresh = Some(Credential {
            generation: 1,
            ..token
        });
        let resolution = match kind {
            TerminalKind::Confirmed => Command::Reconcile {
                generation: 1,
                reference,
            },
            TerminalKind::Reversed => Command::Refund {
                generation: 1,
                reference,
            },
        };
        assert_eq!(
            act(&mut ledger, Route::Normal, binding, resolution, fresh),
            done
        );
        let expected = match kind {
            TerminalKind::Confirmed => "source=5;pending=0;destination=5",
            TerminalKind::Reversed => "source=10;pending=0;destination=0",
        };
        assert_eq!(mass(&ledger, binding), expected);
        assert_eq!(ledger.lock_owner(binding.asset), None);
        assert_eq!(ledger.lock_owner(dependency.asset), None);
        let before = ledger.snapshot();
        assert_eq!(
            act(&mut ledger, Route::Normal, binding, resolution, fresh),
            Reply::Rejected
        );
        assert_eq!(ledger.snapshot(), before);
    }
}

#[test]
fn write_advances_one_asset_version_and_stale_release_cannot_free_any_member() {
    let first = standard_binding();
    let dependency = Binding {
        asset: 30,
        origin: OriginKey {
            event: 30,
            ..first.origin
        },
        ..first
    };
    let contexts = BTreeMap::from([(first.asset, BTreeSet::from([dependency.asset]))]);
    let mut ledger = with_footprint(
        first,
        dependency,
        INITIAL_EPOCH,
        0,
        contexts,
        BTreeSet::from([(CALLER, dependency.asset, 9)]),
    );
    let reserve = Command::Reserve { duration: LEASE };
    assert_eq!(
        act(&mut ledger, Route::Normal, dependency, reserve, None),
        Reply::Reserved
    );
    let dependency_token = Some(credential(dependency, CALLER, 0, INITIAL_EPOCH));
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            dependency,
            Command::Write {
                generation: 0,
                value: 8
            },
            dependency_token
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            dependency,
            Command::Write {
                generation: 0,
                value: 9
            },
            dependency_token
        ),
        Reply::DataUpdated
    );
    assert_eq!(ledger.asset_data(dependency.asset), Some((9, 1)));
    assert_eq!(ledger.asset_data(first.asset), Some((0, 0)));
    let cancel = Command::Cancel { generation: 0 };
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            dependency,
            cancel,
            dependency_token
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    let current = [(dependency.asset, 1)];
    let release = Request {
        versions: &current,
        ..request(&ledger, dependency, cancel, dependency_token)
    };
    assert_eq!(submit(&mut ledger, Route::Normal, release), Reply::Closed);

    assert_eq!(
        act(&mut ledger, Route::Normal, first, reserve, None),
        Reply::Rejected
    );
    let acquire = Request {
        versions: &current,
        ..request(&ledger, first, reserve, None)
    };
    assert_eq!(submit(&mut ledger, Route::Normal, acquire), Reply::Reserved);
    let token = Some(credential(first, CALLER, 0, INITIAL_EPOCH));
    let before = ledger.snapshot();
    assert_eq!(
        act(&mut ledger, Route::Administrative, first, cancel, token),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    let release = Request {
        versions: &current,
        ..request(&ledger, first, cancel, token)
    };
    assert_eq!(
        submit(&mut ledger, Route::Administrative, release),
        Reply::Closed
    );
    assert_eq!(ledger.lock_owner(first.asset), None);
    assert_eq!(ledger.lock_owner(dependency.asset), None);
}

#[test]
fn context_change_distinguishes_current_and_recorded_footprints() {
    let first = standard_binding();
    let dependency = Binding {
        asset: 30,
        origin: OriginKey {
            event: 30,
            ..first.origin
        },
        ..first
    };
    let contexts = BTreeMap::from([(first.asset, BTreeSet::from([dependency.asset]))]);
    let mut ledger = with_footprint(
        first,
        dependency,
        INITIAL_EPOCH,
        0,
        contexts,
        BTreeSet::new(),
    );
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            first,
            Command::Reserve { duration: LEASE },
            None
        ),
        Reply::Reserved
    );
    let epoch = INITIAL_EPOCH + 1;
    assert!(ledger.install_epoch(
        AuthenticatedCaller(CALLER),
        epoch,
        vec![context(0, epoch), context(2, epoch)],
        sessions(epoch)
    ));
    let token = Some(credential(first, CALLER, 0, epoch));
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            first,
            Command::Dispatch { generation: 0 },
            token
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(ledger.lock_owner(dependency.asset), Some(first.origin));
    assert_eq!(
        act(
            &mut ledger,
            Route::Normal,
            first,
            Command::Cancel { generation: 0 },
            token
        ),
        Reply::Closed
    );
    assert_eq!(ledger.lock_owner(first.asset), None);
    assert_eq!(ledger.lock_owner(dependency.asset), None);
}

#[test]
fn acceptance_refuses_a_binding_with_another_owner_or_destination() {
    let binding = standard_binding();
    let (mut ledger, token) = pending_ledger(binding);
    let evidence = TerminalEvidence {
        binding,
        kind: TerminalKind::Confirmed,
        reference: 3,
    };
    let changed = [
        Binding {
            owner: CALLER + 1,
            ..binding
        },
        Binding {
            destination: binding.destination + 1,
            ..binding
        },
    ];
    for other in changed {
        let before = ledger.snapshot();
        // Evidence for another binding is refused for this reservation, and a
        // call that names another binding does not reach the reservation.
        for (named, recorded) in [(binding, other), (other, other)] {
            assert_eq!(
                act(
                    &mut ledger,
                    Route::Adapter,
                    named,
                    Command::RecordTerminal(TerminalEvidence {
                        binding: recorded,
                        ..evidence
                    }),
                    None
                ),
                Reply::Rejected
            );
        }
        assert_eq!(ledger.snapshot(), before);
    }
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::RecordTerminal(evidence),
            None
        ),
        Reply::Recorded
    );
    let before = ledger.snapshot();
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            changed[0],
            Command::Credit { reference: 3 },
            Some(token)
        ),
        Reply::Rejected
    );
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        act(
            &mut ledger,
            Route::Adapter,
            binding,
            Command::Credit { reference: 3 },
            Some(token)
        ),
        Reply::Credited
    );
}
