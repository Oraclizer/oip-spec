use super::*;
use crate::authority::{Outcome, OutcomeReply};
use crate::lock_finality::{
    Binding, Command, Credential, Ledger, Permission, Reply, TerminalEvidence, TerminalKind,
};
use crate::vector_tests::{Vector, parse_vectors};
use std::collections::BTreeSet;

const VECTORS: &str = include_str!("../../../tests/vectors/current-and-historical-reads.tsv");
const READ_ALLOWED: fn(AuthenticatedCaller, ReadKind, Query) -> bool = |_, _, _| true;
const VERIFIED: fn(AuthenticatedCaller, CallId, &CallPayload) -> bool = |_, _, _| true;
const PERMISSIONS: [Permission; 8] = [
    Permission::Reserve,
    Permission::Write,
    Permission::Cancel,
    Permission::Dispatch,
    Permission::Debit,
    Permission::Attest,
    Permission::Credit,
    Permission::PublishPrimary,
];

#[derive(Clone, Copy)]
struct Fixture {
    reader: Reader,
    provider: u64,
    epoch: u64,
    binding: Binding,
    initial: u64,
    written: u64,
}

impl Fixture {
    fn from_vector(row: &Vector<'_>) -> Self {
        Self {
            reader: Reader {
                actor: AuthenticatedCaller(row.number("caller")),
                session: row.number("session"),
            },
            provider: row.number("provider"),
            epoch: row.number("epoch"),
            binding: Binding {
                origin: OriginKey {
                    domain: row.number("source_domain"),
                    event: row.number("event"),
                },
                asset: row.number("asset"),
                owner: row.number("caller"),
                destination: 2,
                recipient: 3,
                amount: 5,
            },
            initial: row.number("initial_value"),
            written: row.number("written_value"),
        }
    }

    fn query(self) -> Query {
        Query::ApplicationValue(self.binding.asset)
    }

    fn contexts(self, epoch: u64) -> Vec<EndpointContext> {
        [self.binding.origin.domain, self.binding.destination]
            .map(|endpoint| EndpointContext {
                endpoint,
                epoch,
                grants: PERMISSIONS
                    .into_iter()
                    .map(|permission| (self.reader.actor.0, Route::Normal, permission))
                    .collect(),
                dependencies: BTreeMap::new(),
                write_permissions: BTreeSet::from([(
                    self.reader.actor.0,
                    self.binding.asset,
                    self.written,
                )]),
            })
            .into()
    }

    fn endpoint(self) -> ReadAuthority {
        let ledger = Ledger::new(
            self.epoch,
            self.contexts(self.epoch),
            BTreeMap::from([(
                self.reader.session,
                SessionBinding {
                    principal: self.reader.actor.0,
                    authority_epoch: self.epoch,
                },
            )]),
            BTreeSet::from([self.reader.actor.0]),
            BTreeMap::from([(self.binding.source(), 10)]),
            &BTreeMap::from([(self.binding.asset, 10)]),
        )
        .unwrap();
        let authority = Authority::new(ledger, 99).unwrap();
        let endpoint = ReadAuthority::new(authority, self.provider);
        assert_eq!(
            self.current(&endpoint).unwrap().value,
            Value::Units(self.initial)
        );
        endpoint
    }

    fn id(self, sequence: u64) -> CallId {
        CallId {
            namespace: self.reader.actor.0,
            sequence,
        }
    }

    fn payload(self, endpoint: &ReadAuthority, sequence: u64, command: Command) -> CallPayload {
        let cut = endpoint.current_cut();
        let credential = match command {
            Command::Write { .. }
            | Command::Cancel { .. }
            | Command::Dispatch { .. }
            | Command::Debit { .. }
            | Command::Credit { .. } => Some(Credential {
                asset: self.binding.asset,
                origin: self.binding.origin,
                holder: self.reader.actor.0,
                generation: 0,
                epoch: cut.authority_epoch,
            }),
            _ => None,
        };
        CallPayload {
            message_id: sequence,
            origin_epoch: self.epoch,
            endpoint: if matches!(command, Command::Credit { .. }) {
                self.binding.destination
            } else {
                self.binding.origin.domain
            },
            caller: self.reader.actor.0,
            session: self.reader.session,
            cut,
            binding: self.binding,
            credential,
            versions: if matches!(command, Command::Cancel { .. }) {
                vec![(self.binding.asset, 1)]
            } else {
                Vec::new()
            },
            command,
        }
    }

    fn submit(
        self,
        endpoint: &mut ReadAuthority,
        sequence: u64,
        command: Command,
    ) -> CheckedExecution {
        let payload = self.payload(endpoint, sequence, command);
        endpoint.execute_at_checked_cut(
            Route::Normal,
            self.reader.actor,
            payload.cut,
            self.id(sequence),
            &payload,
            VERIFIED,
        )
    }

    fn reserve(self, endpoint: &mut ReadAuthority) {
        assert!(accepted(
            self.submit(endpoint, 1, Command::Reserve { duration: 10 }),
            Reply::Reserved
        ));
    }

    fn write(self, endpoint: &mut ReadAuthority) -> CheckedExecution {
        self.submit(
            endpoint,
            2,
            Command::Write {
                generation: 0,
                value: self.written,
            },
        )
    }

    fn release(self, endpoint: &mut ReadAuthority) {
        assert!(accepted(
            self.submit(endpoint, 3, Command::Cancel { generation: 0 }),
            Reply::Closed
        ));
    }

    fn advance(self, endpoint: &mut ReadAuthority) {
        self.reserve(endpoint);
        assert!(accepted(self.write(endpoint), Reply::DataUpdated));
        self.release(endpoint);
    }

    fn current(self, endpoint: &ReadAuthority) -> Result<CurrentRead, ReadError> {
        endpoint.current(
            self.reader,
            self.query(),
            endpoint.current_cut(),
            None,
            READ_ALLOWED,
        )
    }
}

fn accepted(reply: CheckedExecution, expected: Reply) -> bool {
    matches!(reply, CheckedExecution::Forwarded(Collection::Collected(Outcome {
        reply: OutcomeReply::Accepted(actual), commit: Some(_)
    })) if actual == expected)
}

fn error_name(error: ReadError) -> &'static str {
    match error {
        ReadError::Busy => "busy",
        ReadError::Rejected => "rejected",
        ReadError::Unavailable => "unavailable",
    }
}

fn execution_name(reply: CheckedExecution) -> &'static str {
    match reply {
        CheckedExecution::Busy => "busy",
        CheckedExecution::Unavailable => "unavailable",
        CheckedExecution::Rejected => "rejected",
        CheckedExecution::Forwarded(_) => "forwarded",
    }
}

fn units(value: Value) -> u64 {
    let Value::Units(units) = value else {
        panic!("expected units")
    };
    units
}

fn current_observation(result: Result<CurrentRead, ReadError>) -> String {
    match result {
        Ok(value) => format!(
            "kind=current;revision={};epoch={};value={}",
            value.cut.revision,
            value.cut.authority_epoch,
            units(value.value)
        ),
        Err(error) => format!("kind={}", error_name(error)),
    }
}

fn revision(row: &Vector<'_>, field: &str) -> usize {
    row.field(field).parse().unwrap()
}

fn run(row: &Vector<'_>) -> String {
    let fixture = Fixture::from_vector(row);
    let mut endpoint = fixture.endpoint();
    if matches!(row.operation, "held-read" | "held-write") {
        fixture.reserve(&mut endpoint);
        let held = endpoint.current_cut();
        let expected = CommitCut {
            revision: held.revision + revision(row, "expected_revision_offset"),
            ..held
        };
        let before = endpoint.snapshot();
        let read = endpoint.current(
            fixture.reader,
            fixture.query(),
            expected,
            None,
            READ_ALLOWED,
        );
        if row.operation == "held-read" {
            return format!(
                "{};authority_unchanged={}",
                current_observation(read),
                endpoint.snapshot() == before
            );
        }
        let write = fixture.write(&mut endpoint);
        let read_after = fixture.current(&endpoint);
        assert_eq!(read_after, read);
        fixture.release(&mut endpoint);
        return format!(
            "write={};held_read={};released_value={}",
            if accepted(write, Reply::DataUpdated) {
                "accepted"
            } else {
                "rejected"
            },
            match read_after {
                Ok(_) => "current",
                Err(error) => error_name(error),
            },
            units(fixture.current(&endpoint).unwrap().value)
        );
    }

    let stale_cache = (row.operation == "stale-cache").then(|| {
        assert_eq!(
            endpoint.current_cut().revision,
            revision(row, "cached_revision")
        );
        endpoint
            .capture_cache(fixture.reader, fixture.query(), READ_ALLOWED)
            .unwrap()
    });
    fixture.advance(&mut endpoint);
    match row.operation {
        "historical" => match endpoint.historical(
            fixture.reader,
            fixture.query(),
            revision(row, "requested_revision"),
            READ_ALLOWED,
        ) {
            Ok(observation) => format!(
                "kind=historical;revision={};value={}",
                observation.revision,
                units(observation.value)
            ),
            Err(error) => format!("kind={}", error_name(error)),
        },
        "current-direct" | "stale-cache" | "current-cache" => {
            let cache = if row.operation == "current-cache" {
                assert_eq!(
                    endpoint.current_cut().revision,
                    revision(row, "cached_revision")
                );
                Some(
                    endpoint
                        .capture_cache(fixture.reader, fixture.query(), READ_ALLOWED)
                        .unwrap(),
                )
            } else {
                stale_cache
            };
            let expected = CommitCut {
                revision: revision(row, "expected_revision"),
                authority_epoch: fixture.epoch,
            };
            let before = endpoint.snapshot();
            let answer = endpoint.current(
                fixture.reader,
                fixture.query(),
                expected,
                cache.as_ref(),
                READ_ALLOWED,
            );
            if row.operation == "current-cache" {
                assert_eq!(answer, fixture.current(&endpoint));
            }
            let observation = current_observation(answer);
            if row.operation == "stale-cache" {
                format!(
                    "{observation};authority_unchanged={}",
                    endpoint.snapshot() == before
                )
            } else {
                observation
            }
        }
        "stale-execute" | "stale-epoch" => {
            let cut = endpoint.current_cut();
            assert_eq!(cut.revision, revision(row, "actual_revision"));
            let expected = CommitCut {
                revision: revision(row, "expected_revision"),
                authority_epoch: if row.operation == "stale-epoch" {
                    row.number("expected_epoch")
                } else {
                    fixture.epoch
                },
            };
            let before = endpoint.snapshot();
            let payload = CallPayload {
                binding: Binding {
                    origin: OriginKey {
                        event: fixture.binding.origin.event + 1,
                        ..fixture.binding.origin
                    },
                    ..fixture.binding
                },
                versions: vec![(fixture.binding.asset, 1)],
                ..fixture.payload(&endpoint, 4, Command::Reserve { duration: 10 })
            };
            let result = endpoint.execute_at_checked_cut(
                Route::Normal,
                fixture.reader.actor,
                expected,
                fixture.id(4),
                &payload,
                VERIFIED,
            );
            let unchanged = endpoint.snapshot() == before;
            let mut observed = format!(
                "kind={};authority_unchanged={unchanged}",
                execution_name(result)
            );
            if row.operation == "stale-execute" {
                let value = fixture.current(&endpoint).map_or_else(
                    |error| error_name(error).to_owned(),
                    |observation| units(observation.value).to_string(),
                );
                observed.push_str(&format!(";value={value}"));
            }
            // Confirm the payload is genuinely live. Only the wrapper's
            // expected cut differs from this successful control.
            if result == CheckedExecution::Busy {
                let live = endpoint.execute_at_checked_cut(
                    Route::Normal,
                    fixture.reader.actor,
                    cut,
                    fixture.id(4),
                    &payload,
                    VERIFIED,
                );
                assert!(accepted(live, Reply::Reserved));
            }
            observed
        }
        other => panic!("unknown observation vector {other}"),
    }
}

#[test]
fn proof_derived_read_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        assert_eq!(run(&row), row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 9);
}

fn fixture() -> Fixture {
    Fixture::from_vector(&parse_vectors(VECTORS).next().unwrap())
}

#[test]
fn cache_requires_the_same_provider_instance_and_query() {
    let fixture = fixture();
    let mut endpoint = fixture.endpoint();
    fixture.advance(&mut endpoint);
    let other_fixture = Fixture {
        written: fixture.written - 1,
        ..fixture
    };
    let mut same_numeric_provider = other_fixture.endpoint();
    other_fixture.advance(&mut same_numeric_provider);
    assert_eq!(
        other_fixture.current(&same_numeric_provider).unwrap().value,
        Value::Units(8)
    );
    let entry = endpoint
        .capture_cache(fixture.reader, fixture.query(), READ_ALLOWED)
        .unwrap();
    assert_eq!(
        same_numeric_provider.current(
            fixture.reader,
            fixture.query(),
            endpoint.current_cut(),
            Some(&entry),
            READ_ALLOWED
        ),
        Err(ReadError::Busy),
        "cache-source-instance"
    );
    assert_eq!(
        endpoint.current(
            fixture.reader,
            Query::AccountBalance(fixture.binding.source()),
            endpoint.current_cut(),
            Some(&entry),
            READ_ALLOWED
        ),
        Err(ReadError::Busy),
        "cache-query-identity"
    );
    assert_eq!(
        endpoint.current(
            fixture.reader,
            fixture.query(),
            endpoint.current_cut(),
            Some(&entry),
            READ_ALLOWED
        ),
        fixture.current(&endpoint)
    );
}

#[test]
fn historical_prefixes_keep_their_visibility_and_use_current_read_policy() {
    let fixture = fixture();
    let mut endpoint = fixture.endpoint();
    fixture.advance(&mut endpoint);
    let query = fixture.query();
    for revision in [1, 2] {
        assert_eq!(
            endpoint.historical(fixture.reader, query, revision, READ_ALLOWED),
            Err(ReadError::Busy)
        );
    }
    assert_eq!(
        endpoint.historical(fixture.reader, query, 3, READ_ALLOWED),
        Ok(HistoricalRead {
            revision: 3,
            value: Value::Units(9)
        })
    );
    assert_eq!(
        endpoint.historical(fixture.reader, query, 0, |_, kind, _| kind
            == ReadKind::Current),
        Err(ReadError::Rejected)
    );
    let next = fixture.epoch + 1;
    assert!(endpoint.install_epoch(
        fixture.reader.actor,
        next,
        fixture.contexts(next),
        BTreeMap::new()
    ));
    assert_eq!(
        endpoint.historical(fixture.reader, query, 0, READ_ALLOWED),
        Err(ReadError::Rejected)
    );
}

#[test]
fn signed_stale_cut_cannot_store_a_result_through_the_checked_wrapper() {
    let fixture = fixture();
    let mut endpoint = fixture.endpoint();
    let payload = fixture.payload(&endpoint, 1, Command::Reserve { duration: 10 });
    fixture.advance(&mut endpoint);
    let before = endpoint.snapshot();
    let expected = endpoint.current_cut();
    let reply = endpoint.execute_at_checked_cut(
        Route::Normal,
        fixture.reader.actor,
        expected,
        fixture.id(5),
        &payload,
        VERIFIED,
    );
    assert_eq!(reply, CheckedExecution::Busy, "signed-cut-not-forwarded");
    assert_eq!(endpoint.snapshot(), before);
}

#[test]
fn related_reads_wait_for_publication_at_the_requested_prefix() {
    let fixture = fixture();
    let mut endpoint = fixture.endpoint();
    fixture.reserve(&mut endpoint);
    assert!(accepted(
        fixture.submit(&mut endpoint, 2, Command::Dispatch { generation: 0 }),
        Reply::SourceDispatched
    ));
    assert!(accepted(
        fixture.submit(&mut endpoint, 3, Command::Debit { generation: 0 }),
        Reply::Debited
    ));
    let debit_revision = endpoint.current_cut().revision;
    let source = Query::AccountBalance(fixture.binding.source());
    let destination = Query::AccountBalance(fixture.binding.destination());
    let receipt = Query::TerminalReceipt(fixture.binding.origin);
    for query in [source, destination, receipt] {
        assert_eq!(
            endpoint.current(
                fixture.reader,
                query,
                endpoint.current_cut(),
                None,
                READ_ALLOWED
            ),
            Err(ReadError::Busy),
            "unpublished-related-query"
        );
    }
    let terminal = fixture.submit(
        &mut endpoint,
        4,
        Command::RecordTerminal(TerminalEvidence {
            binding: fixture.binding,
            kind: TerminalKind::Confirmed,
            reference: 0,
        }),
    );
    let CheckedExecution::Forwarded(Collection::Collected(Outcome {
        reply: OutcomeReply::Accepted(Reply::Recorded),
        commit: Some(commit),
    })) = terminal
    else {
        panic!("expected committed terminal record")
    };
    assert_eq!(
        fixture.submit(&mut endpoint, 5, Command::Credit { reference: 0 }),
        CheckedExecution::Forwarded(Collection::Waiting)
    );
    assert!(accepted(
        fixture.submit(&mut endpoint, 6, Command::PublishPrimary),
        Reply::Published
    ));
    let decision = OriginDecision {
        binding: fixture.binding,
        kind: TerminalKind::Confirmed,
        origin_epoch: fixture.epoch,
        commit,
    };
    for (query, value) in [
        (source, Value::Units(5)),
        (destination, Value::Units(5)),
        (receipt, Value::Receipt(Some(decision))),
    ] {
        assert_eq!(
            endpoint.historical(fixture.reader, query, debit_revision, READ_ALLOWED),
            Err(ReadError::Busy)
        );
        let cut = endpoint.current_cut();
        assert_eq!(
            endpoint.current(fixture.reader, query, cut, None, READ_ALLOWED),
            Ok(CurrentRead { cut, value })
        );
    }
    assert_eq!(fixture.current(&endpoint), Err(ReadError::Busy));
}

#[test]
fn advanced_revision_blocks_execution_but_allows_exact_receipt_collection() {
    let fixture = fixture();
    let mut endpoint = fixture.endpoint();
    let id = fixture.id(1);
    let payload = fixture.payload(&endpoint, 1, Command::Reserve { duration: 10 });
    let admitted = endpoint.execute_at_checked_cut(
        Route::Normal,
        fixture.reader.actor,
        payload.cut,
        id,
        &payload,
        VERIFIED,
    );
    let CheckedExecution::Forwarded(original) = admitted else {
        panic!("expected a forwarded reservation")
    };
    assert!(accepted(admitted, Reply::Reserved));
    assert!(accepted(fixture.write(&mut endpoint), Reply::DataUpdated));
    fixture.release(&mut endpoint);
    assert_eq!(endpoint.current_cut().revision, 3);
    let before = endpoint.snapshot();

    assert_eq!(
        endpoint.execute_at_checked_cut(
            Route::Normal,
            fixture.reader.actor,
            payload.cut,
            id,
            &payload,
            VERIFIED,
        ),
        CheckedExecution::Busy
    );
    assert_eq!(
        endpoint.collect(fixture.reader.actor, id, &payload, VERIFIED),
        original
    );
    assert_eq!(
        endpoint.collect(fixture.reader.actor, id, &payload, VERIFIED),
        original
    );
    assert_eq!(
        endpoint.collect(fixture.reader.actor, id, &payload, |_, _, _| false),
        Collection::Rejected
    );
    assert_eq!(endpoint.snapshot(), before);
    assert_eq!(fixture.current(&endpoint).unwrap().value, Value::Units(9));
}
