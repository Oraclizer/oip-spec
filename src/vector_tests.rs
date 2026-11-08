use super::*;
use crate::interleaving::{Action, State, compare_orders};

const VECTORS: &str = include_str!("../tests/vectors/product-model.tsv");

pub(crate) struct Vector<'a> {
    pub(crate) id: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) input: BTreeMap<&'a str, &'a str>,
    pub(crate) expected: &'a str,
}

impl Vector<'_> {
    pub(crate) fn field(&self, field: &str) -> &str {
        self.input
            .get(field)
            .unwrap_or_else(|| panic!("{} has no {field}", self.id))
    }

    pub(crate) fn number(&self, field: &str) -> u64 {
        self.field(field).parse().unwrap()
    }

    fn flag(&self, field: &str) -> bool {
        self.field(field).parse().unwrap()
    }

    fn request(&self) -> (Product, AuthenticatedCaller, CallId, Envelope) {
        let asset = self.number("asset");
        let session = self.number("session");
        let authority_epoch = self.number("authority_epoch");
        let owner = self.number("session_owner");
        let caller = self.number("claimed");
        (
            Product::new(
                authority_epoch,
                BTreeMap::from([(
                    session,
                    SessionBinding {
                        principal: owner,
                        authority_epoch: self.number("session_epoch"),
                    },
                )]),
                BTreeMap::from([(
                    asset,
                    Asset {
                        owner,
                        credits: 0,
                        active_lock: None,
                    },
                )]),
            ),
            AuthenticatedCaller(self.number("authenticated")),
            CallId {
                namespace: self.number("namespace"),
                sequence: self.number("sequence"),
            },
            Envelope {
                message_id: self.number("message"),
                origin: OriginKey {
                    domain: self.number("origin_domain"),
                    event: self.number("origin_event"),
                },
                asset,
                caller,
                session,
                cut: CommitCut {
                    authority_epoch: self.number("request_epoch"),
                    revision: self.field("request_revision").parse().unwrap(),
                },
                command: Credit {
                    caller,
                    amount: 1,
                    lock: None,
                },
            },
        )
    }
}

fn vectors() -> impl Iterator<Item = Vector<'static>> {
    parse_vectors(VECTORS)
}

pub(crate) fn parse_vectors(tsv: &'static str) -> impl Iterator<Item = Vector<'static>> {
    let mut lines = tsv.lines();
    assert_eq!(
        lines.next(),
        Some("id\toperation\tinputs\texpected\tevidence")
    );
    lines.map(|line| {
        let [id, operation, fields, expected, evidence]: [&str; 5] =
            line.split('\t').collect::<Vec<_>>().try_into().unwrap();
        assert!(!evidence.is_empty(), "{id} lacks proof evidence");
        let mut input = BTreeMap::new();
        for (key, value) in fields.split(';').map(|pair| pair.split_once('=').unwrap()) {
            assert!(input.insert(key, value).is_none(), "{id} repeats {key}");
        }
        Vector {
            id,
            operation,
            input,
            expected,
        }
    })
}

fn proof_request(id: &str) -> (Product, AuthenticatedCaller, CallId, Envelope) {
    vectors().find(|row| row.id == id).unwrap().request()
}

fn submission_name(submission: Submission) -> &'static str {
    match submission {
        Submission::Dispatched => "dispatched",
        Submission::Rejected => "rejected",
        Submission::Waiting => "waiting",
        Submission::Completed(Receipt::Executed) => "executed",
    }
}

fn verdict(accepted: bool) -> &'static str {
    if accepted { "accepted" } else { "rejected" }
}

fn run(row: &Vector<'_>) -> String {
    match row.operation {
        "submit" | "retry" => {
            let (mut product, caller, id, envelope) = row.request();
            let verify = |_, supplied_id, supplied_envelope: &Envelope| {
                row.flag("verified") && supplied_id == id && *supplied_envelope == envelope
            };
            let revision = row.field("revision").parse::<usize>().unwrap();
            if row.operation == "submit" {
                assert_eq!(product.current_cut().revision, revision, "{}", row.id);
                let before = product.snapshot();
                let result = product.submit(caller, id, envelope, verify);
                if result == Submission::Rejected {
                    assert_eq!(product.snapshot(), before, "{}", row.id);
                }
                return submission_name(result).to_owned();
            }

            assert_eq!(
                product.submit(caller, id, envelope, verify),
                Submission::Dispatched,
                "{}",
                row.id
            );
            assert_eq!(product.current_cut().revision, revision, "{}", row.id);
            assert_eq!(
                product.credits(envelope.asset),
                Some(row.number("effect_count")),
                "{}",
                row.id
            );
            match row.field("durable_outcome") {
                "executed" => (),
                // Corrupt only the test fixture. Production has no setter for
                // durable outcomes and cannot fall back to the credit count.
                "absent" => product.durable.calls.get_mut(&id).unwrap().outcome = None,
                value => panic!("{} has unknown durable outcome {value}", row.id),
            }
            let snapshot = product.snapshot();
            product.crash();
            product.restart(Some(&snapshot));
            let result = product.submit(caller, id, envelope, verify);
            assert_eq!(product.current_cut().revision, revision, "{}", row.id);
            format!(
                "{},effect_count={}",
                submission_name(result),
                product.credits(envelope.asset).unwrap()
            )
        }
        "restart" => {
            let (mut product, caller, id, envelope) = proof_request("bound-fresh-call");
            let stale = product.snapshot();
            assert_eq!(
                product.submit(caller, id, envelope, |_, _, _| true),
                Submission::Dispatched
            );
            let durable = product.snapshot();
            product.crash();
            let checked = row.flag("available").then_some(if row.flag("current") {
                &durable
            } else {
                &stale
            });
            product.restart(checked);
            assert_eq!(product.snapshot(), durable);
            match product.endpoint() {
                Endpoint::Up => "up".to_owned(),
                Endpoint::Down => "down".to_owned(),
            }
        }
        "exchange-rotate" | "exchange-write" => {
            let left_asset = row.number("left_asset");
            let right_asset = row.number("right_asset");
            assert_ne!(left_asset, right_asset, "{}", row.id);
            let left = Action::Write {
                asset: left_asset,
                expected_epoch: row.number("left_expected_epoch"),
                value: row.number("left_value"),
            };
            let right = if row.operation == "exchange-rotate" {
                Action::RotateAuthority { asset: right_asset }
            } else {
                Action::Write {
                    asset: right_asset,
                    expected_epoch: row.number("right_expected_epoch"),
                    value: row.number("right_value"),
                }
            };
            let [forward, reverse] = compare_orders(&State::new(row.number("epoch")), left, right);
            if row.operation == "exchange-rotate" {
                format!(
                    "left_then_right={},{};right_then_left={},{}",
                    verdict(forward.left_accepted),
                    forward.state.value(left_asset),
                    verdict(reverse.left_accepted),
                    reverse.state.value(left_asset),
                )
            } else {
                format!(
                    "left={},{};right={},{};exchange={}",
                    verdict(forward.left_accepted),
                    forward.state.value(left_asset),
                    verdict(forward.right_accepted),
                    forward.state.value(right_asset),
                    forward == reverse
                )
            }
        }
        operation => panic!("{} has unknown operation {operation}", row.id),
    }
}

#[test]
fn proof_derived_vectors() {
    let mut seen = std::collections::BTreeSet::new();
    for row in vectors() {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        assert_eq!(run(&row), row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn retry_binds_full_envelope_and_ignores_stale_cut_without_applying_effect() {
    let (mut product, caller, id, envelope) = proof_request("bound-fresh-call");
    assert_eq!(
        product.submit(caller, id, envelope, |_, _, _| true),
        Submission::Dispatched
    );
    assert_ne!(product.current_cut(), envelope.cut);
    let fresh_id = CallId { sequence: 2, ..id };
    assert_eq!(
        product.submit(caller, fresh_id, envelope, |_, _, _| true),
        Submission::Rejected
    );
    let changed = Envelope {
        message_id: 2,
        ..envelope
    };
    assert_eq!(
        product.submit(caller, id, changed, |_, _, _| true),
        Submission::Rejected
    );
    assert_eq!(
        product.submit(caller, id, envelope, |_, _, _| true),
        Submission::Completed(Receipt::Executed)
    );
    assert_eq!(product.cached_reply(id), Some(Receipt::Executed));
    let before_crash = product.snapshot();
    product.crash();
    assert_eq!(product.cached_reply(id), None);
    assert_eq!(product.snapshot(), before_crash);
    assert_eq!(product.credits(envelope.asset), Some(1));
}

#[test]
fn locked_credit_checks_asset_holder_and_generation_before_effect() {
    let (mut product, caller, id, envelope) = proof_request("bound-fresh-call");
    product
        .durable
        .assets
        .get_mut(&envelope.asset)
        .unwrap()
        .active_lock = Some(ActiveLock {
        holder: caller.0,
        generation: 2,
    });
    let token = LockToken {
        asset: envelope.asset,
        owner: caller.0,
        generation: 2,
    };
    assert!(product.current_lock_token(token));
    let with_lock = |lock| Envelope {
        command: Credit {
            lock,
            ..envelope.command
        },
        ..envelope
    };
    for bad_token in [
        None,
        Some(LockToken { asset: 5, ..token }),
        Some(LockToken { owner: 8, ..token }),
        Some(LockToken {
            generation: 1,
            ..token
        }),
    ] {
        assert_eq!(
            product.submit(caller, id, with_lock(bad_token), |_, _, _| true),
            Submission::Rejected
        );
        assert_eq!(product.credits(envelope.asset), Some(0));
    }
    assert_eq!(
        product.submit(caller, id, with_lock(Some(token)), |_, _, _| true),
        Submission::Dispatched
    );
    assert_eq!(product.credits(envelope.asset), Some(1));
}

#[test]
fn recovery_fails_closed_on_stale_snapshot_and_disconnection() {
    let (mut product, caller, id, envelope) = proof_request("bound-fresh-call");
    let stale = product.snapshot();
    assert_eq!(
        product.submit(caller, id, envelope, |_, _, _| true),
        Submission::Dispatched
    );
    let current = product.snapshot();
    product.crash();
    product.restart(Some(&stale));
    assert_eq!(product.endpoint(), Endpoint::Down);
    product.set_authority_connected(false);
    product.restart(Some(&current));
    assert_eq!(product.endpoint(), Endpoint::Down);
    assert_eq!(
        product.submit(caller, id, envelope, |_, _, _| true),
        Submission::Waiting
    );
    product.set_authority_connected(true);
    product.restart(Some(&current));
    assert_eq!(product.endpoint(), Endpoint::Up);
}

#[test]
fn asset_owner_cannot_substitute_for_a_distinct_lock_holder() {
    let (_, holder, holder_call, mut holder_envelope) = proof_request("bound-fresh-call");
    let owner = AuthenticatedCaller(holder.0 + 1);
    let owner_session = holder_envelope.session + 1;
    let authority_epoch = holder_envelope.cut.authority_epoch;
    let mut product = Product::new(
        authority_epoch,
        BTreeMap::from([
            (
                holder_envelope.session,
                SessionBinding {
                    principal: holder.0,
                    authority_epoch,
                },
            ),
            (
                owner_session,
                SessionBinding {
                    principal: owner.0,
                    authority_epoch,
                },
            ),
        ]),
        BTreeMap::from([(
            holder_envelope.asset,
            Asset {
                owner: owner.0,
                active_lock: Some(ActiveLock {
                    holder: holder.0,
                    generation: 2,
                }),
                credits: 0,
            },
        )]),
    );
    let token = LockToken {
        asset: holder_envelope.asset,
        owner: holder.0,
        generation: 2,
    };
    let substitute = LockToken {
        owner: owner.0,
        ..token
    };
    assert!(product.current_lock_token(token));
    assert!(!product.current_lock_token(substitute));
    let owner_call = CallId {
        namespace: owner.0,
        ..holder_call
    };
    let before = product.snapshot();
    for attempted_token in [token, substitute] {
        let owner_envelope = Envelope {
            caller: owner.0,
            session: owner_session,
            command: Credit {
                caller: owner.0,
                lock: Some(attempted_token),
                ..holder_envelope.command
            },
            ..holder_envelope
        };
        assert_eq!(
            product.submit(owner, owner_call, owner_envelope, |_, _, _| true),
            Submission::Rejected
        );
        assert_eq!(product.snapshot(), before);
    }
    holder_envelope.command.lock = Some(token);
    assert_eq!(
        product.submit(holder, holder_call, holder_envelope, |_, _, _| true),
        Submission::Dispatched
    );
    assert_eq!(product.credits(holder_envelope.asset), Some(1));
}
