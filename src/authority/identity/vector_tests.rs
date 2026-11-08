use super::super::regulation::{
    Action as LegalAction, Enrollment, LegalGrant, SpendKind, SpendScope,
};
use super::super::{Outcome, OutcomeReply};
use super::*;
use crate::lock_finality::{Binding, Credential, Permission, Reply, TerminalKind};
use crate::vector_tests::{Vector, parse_vectors};

const VECTORS: &str = include_str!("../../../tests/vectors/identity-handover.tsv");
const MAINTENANCE: u64 = 99;
const PERMISSIONS: [Permission; 8] = [
    Permission::Reserve,
    Permission::Dispatch,
    Permission::Debit,
    Permission::Cancel,
    Permission::Refund,
    Permission::Attest,
    Permission::ObserveTime,
    Permission::PublishPrimary,
];

#[derive(Clone)]
enum Signature {
    Valid,
    Invalid,
    Call {
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        id: CallId,
        payload: Box<CallPayload>,
    },
    Approval {
        signer: Identity,
        proposal: Handover,
    },
    Read {
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        request: ReadRequest,
    },
}

struct Rules {
    execute: bool,
    read: bool,
    signer: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            execute: true,
            read: true,
            signer: true,
        }
    }
}

impl Security for Rules {
    type Token = Identity;
    type Signature = Signature;
    type MaintenanceToken = u64;

    fn authenticate(&self, token: &Identity) -> Option<Identity> {
        Some(*token)
    }
    fn authenticate_maintenance(&self, token: &u64) -> Option<Principal> {
        (*token == MAINTENANCE).then_some(7)
    }
    fn permit(&self, _: Identity, _: EndpointId, op: Operation, _: Scope, _: u64) -> bool {
        match op {
            Operation::Execute => self.execute,
            Operation::Current
            | Operation::Historical
            | Operation::Raw
            | Operation::Status
            | Operation::Journal
            | Operation::ReadOwner => self.read,
            _ => true,
        }
    }
    fn verify(
        &self,
        identity: Identity,
        proof: SessionProof,
        target: EndpointId,
        _: Operation,
        signed: Signed<'_>,
        sig: &Signature,
    ) -> bool {
        match sig {
            Signature::Valid => true,
            Signature::Invalid | Signature::Approval { .. } => false,
            Signature::Call {
                identity: signer,
                proof: signed_proof,
                target: signed_target,
                id,
                payload,
            } => {
                *signer == identity
                    && *signed_proof == proof
                    && *signed_target == target
                    && matches!(signed, Signed::Call { id: supplied, action: Action::Ordinary(value) }
                        if supplied == *id && value == payload.as_ref())
            }
            Signature::Read {
                identity: signer,
                proof: signed_proof,
                target: signed_target,
                request,
            } => {
                *signer == identity
                    && *signed_proof == proof
                    && *signed_target == target
                    && matches!(signed, Signed::Read(value) if value == *request)
            }
        }
    }
    fn verify_terminal(
        &self,
        _: Identity,
        _: SessionProof,
        _: EndpointId,
        _: TerminalEvidence,
    ) -> bool {
        self.signer
    }
    fn verify_order(
        &self,
        _: Identity,
        _: SessionProof,
        _: EndpointId,
        _: LegalStage,
        _: &Order,
    ) -> bool {
        true
    }
    fn verify_enforcement(
        &self,
        _: Identity,
        _: SessionProof,
        _: EndpointId,
        _: &EnforcementOrder,
    ) -> bool {
        true
    }
    fn verify_time(&self, _: Principal, _: CommitCut, _: u64, sig: &Signature) -> bool {
        matches!(sig, Signature::Valid)
    }
    fn verify_ack(&self, _: &super::super::Acknowledgement, sig: &Signature) -> bool {
        matches!(sig, Signature::Valid)
    }
    fn approve(&self, identity: Identity, proposal: &Handover, signature: &Signature) -> bool {
        match signature {
            Signature::Valid => true,
            Signature::Approval {
                signer,
                proposal: signed,
            } => *signer == identity && *signed == *proposal,
            _ => false,
        }
    }
}

fn number(row: &Vector<'_>, key: &str, default: u64) -> u64 {
    row.input
        .get(key)
        .map_or(default, |value| value.parse().unwrap())
}

#[derive(Clone, Copy)]
struct Case {
    previous: Identity,
    successor: Identity,
    worker: Identity,
    binding: Binding,
    old_session: SessionId,
    new_session: SessionId,
    worker_session: SessionId,
    old_epoch: u64,
    new_epoch: u64,
}

fn user(principal: Principal, domain: EndpointId) -> Identity {
    Identity {
        principal,
        domain,
        ocid: 100 + principal,
        rai: 200 + principal,
    }
}

impl Case {
    fn from_vector(row: &Vector<'_>) -> Self {
        let previous = number(row, "former", number(row, "actor", 7));
        let successor = number(row, "successor", number(row, "foreign_namespace", 8));
        let source = number(row, "source", number(row, "domain", 0));
        let old_epoch = number(
            row,
            "old_epoch",
            number(row, "signed_epoch", number(row, "epoch", 9)),
        );
        let old_epoch = if row.operation == "owner-recovery" {
            9
        } else {
            old_epoch
        };
        Self {
            previous: Identity {
                ocid: number(row, "ocid", 100 + previous),
                rai: number(row, "registered_rai", 200 + previous),
                ..user(previous, source)
            },
            successor: user(successor, source),
            worker: user(number(row, "worker", previous), source),
            binding: Binding {
                origin: OriginKey {
                    domain: source,
                    event: number(row, "event", 17),
                },
                asset: number(row, "asset", 17),
                owner: previous,
                destination: number(row, "receiver", 2),
                recipient: 3,
                amount: number(row, "pending", 5),
            },
            old_session: number(
                row,
                "old_session",
                if row.operation == "owner-recovery" {
                    1
                } else {
                    number(row, "session", 1)
                },
            ),
            new_session: number(row, "new_session", 3),
            worker_session: number(row, "worker_session", 2),
            old_epoch,
            new_epoch: number(
                row,
                "new_epoch",
                number(row, "current_epoch", number(row, "epoch", 10)),
            ),
        }
    }

    fn contexts(self, epoch: u64) -> Vec<EndpointContext> {
        [self.binding.origin.domain, self.binding.destination]
            .map(|endpoint| EndpointContext {
                endpoint,
                epoch,
                grants: [
                    self.previous.principal,
                    self.successor.principal,
                    self.worker.principal,
                ]
                .into_iter()
                .flat_map(|actor| {
                    PERMISSIONS
                        .into_iter()
                        .map(move |op| (actor, Route::Normal, op))
                })
                .collect(),
                dependencies: BTreeMap::new(),
                write_permissions: BTreeSet::new(),
            })
            .into()
    }

    fn sessions(self, epoch: u64) -> BTreeMap<SessionId, SessionBinding> {
        BTreeMap::from([
            (
                self.old_session,
                SessionBinding {
                    principal: self.previous.principal,
                    authority_epoch: epoch,
                },
            ),
            (
                self.worker_session,
                SessionBinding {
                    principal: self.worker.principal,
                    authority_epoch: epoch,
                },
            ),
            (
                4,
                SessionBinding {
                    principal: self.successor.principal,
                    authority_epoch: epoch,
                },
            ),
        ])
    }

    fn service(self, balance: u64, security: Rules) -> ProductAuthority<Rules> {
        let mut identities = vec![self.previous, self.successor];
        if self.worker.principal != self.previous.principal
            && self.worker.principal != self.successor.principal
        {
            identities.push(self.worker);
        }
        let regulation = Policy {
            enrollments: vec![Enrollment {
                asset: self.binding.asset,
                source: self.binding.origin.domain,
                receiver: self.binding.destination,
            }],
            legal: [LegalStage::SourceEmission, LegalStage::ReceivingCommit]
                .map(|stage| LegalGrant {
                    stage,
                    route: RegulatoryRoute::Normal,
                    officer: self.previous.principal,
                    jurisdiction: 1,
                    legal_basis: 1,
                    asset: self.binding.asset,
                    action: LegalAction::Freeze,
                    epoch: self.old_epoch,
                })
                .into(),
            spend: Vec::new(),
            clock_observers: BTreeSet::new(),
        };
        ProductAuthority::bootstrap(
            Bootstrap {
                epoch: self.old_epoch,
                provider: 100,
                settlement_target: 99,
                contexts: self.contexts(self.old_epoch),
                sessions: self.sessions(self.old_epoch),
                maintainers: BTreeSet::from([self.previous.principal]),
                balances: BTreeMap::from([(self.binding.source(), balance)]),
                supply: BTreeMap::from([(self.binding.asset, u128::from(balance))]),
                identities,
                owners: BTreeMap::from([(self.binding.asset, self.previous.principal)]),
                regulation: Some(regulation),
            },
            security,
        )
        .unwrap()
    }

    fn payload(
        self,
        service: &ProductAuthority<Rules>,
        caller: Identity,
        session: SessionId,
        sequence: u64,
        command: Command,
    ) -> CallPayload {
        let cut = service.reads.current_cut();
        let credential = match command {
            Command::Dispatch { generation }
            | Command::Debit { generation }
            | Command::Cancel { generation }
            | Command::Refund { generation, .. } => Some(Credential {
                asset: self.binding.asset,
                origin: self.binding.origin,
                holder: self.worker.principal,
                generation,
                epoch: cut.authority_epoch,
            }),
            _ => None,
        };
        CallPayload {
            message_id: sequence,
            origin_epoch: self.old_epoch,
            endpoint: self.binding.origin.domain,
            caller: caller.principal,
            session,
            cut,
            binding: self.binding,
            credential,
            versions: Vec::new(),
            command,
        }
    }

    fn ordinary(
        self,
        service: &mut ProductAuthority<Rules>,
        caller: &Identity,
        session: SessionId,
        sequence: u64,
        command: Command,
    ) -> Result<ActionReply, EndpointError> {
        let payload = self.payload(service, *caller, session, sequence, command);
        service.execute(
            Entry::Normal,
            &auth(caller, session, payload.cut.authority_epoch),
            ordinary(&payload, caller.principal, sequence),
            None,
        )
    }

    fn pending(self, service: &mut ProductAuthority<Rules>) -> CallPayload {
        let reserve = self.payload(
            service,
            self.previous,
            self.old_session,
            1,
            Command::Reserve { duration: 10 },
        );
        assert!(accepted(
            service.execute(
                Entry::Normal,
                &auth(&self.previous, self.old_session, self.old_epoch),
                ordinary(&reserve, self.previous.principal, 1),
                None
            ),
            Reply::Reserved
        ));
        assert!(accepted(
            self.ordinary(
                service,
                &self.worker,
                self.worker_session,
                2,
                Command::Dispatch { generation: 0 }
            ),
            Reply::SourceDispatched
        ));
        assert!(accepted(
            self.ordinary(
                service,
                &self.worker,
                self.worker_session,
                3,
                Command::Debit { generation: 0 }
            ),
            Reply::Debited
        ));
        reserve
    }

    fn proposal(self, service: &ProductAuthority<Rules>) -> Handover {
        Handover {
            asset: self.binding.asset,
            previous: self.previous.principal,
            successor: self.successor.principal,
            expected: service.reads.current_cut(),
            old_session: self.old_session,
            new_session: self.new_session,
            epoch: self.new_epoch,
            contexts: self.contexts(self.new_epoch),
        }
    }

    fn handover(
        self,
        service: &mut ProductAuthority<Rules>,
        previous: &Signature,
        successor: &Signature,
    ) -> bool {
        let proposal = self.proposal(service);
        service.maintenance(&MAINTENANCE).unwrap().handover(
            &proposal,
            Consent {
                token: &self.previous,
                signature: previous,
            },
            Consent {
                token: &self.successor,
                signature: successor,
            },
        )
    }

    fn read(
        self,
        service: &ProductAuthority<Rules>,
        who: &Identity,
        session: SessionId,
        epoch: u64,
        request: ReadRequest,
    ) -> Result<Observation, EndpointError> {
        service.read(
            Entry::Normal,
            &auth(who, session, epoch),
            self.binding.origin.domain,
            request,
            None,
        )
    }

    fn status(
        self,
        service: &ProductAuthority<Rules>,
        who: &Identity,
        session: SessionId,
        epoch: u64,
    ) -> OperationStatus {
        let Ok(Observation::Status(status)) = self.read(
            service,
            who,
            session,
            epoch,
            ReadRequest::Status(self.binding.origin),
        ) else {
            panic!("missing authorized status");
        };
        status
    }

    fn owner(
        self,
        service: &ProductAuthority<Rules>,
        who: &Identity,
        session: SessionId,
        epoch: u64,
    ) -> Principal {
        let Ok(Observation::Owner(Some(owner))) = self.read(
            service,
            who,
            session,
            epoch,
            ReadRequest::Owner(self.binding.asset),
        ) else {
            panic!("missing authorized owner");
        };
        owner
    }
}

fn auth(who: &Identity, session: SessionId, epoch: u64) -> Credentials<'_, Rules> {
    Credentials {
        token: who,
        proof: SessionProof { session, epoch },
        signature: &Signature::Valid,
    }
}

fn ordinary(payload: &CallPayload, namespace: Principal, sequence: u64) -> Request<'_> {
    Request {
        target: payload.endpoint,
        id: CallId {
            namespace,
            sequence,
        },
        expected: payload.cut,
        action: Action::Ordinary(payload),
    }
}

fn accepted(reply: Result<ActionReply, EndpointError>, expected: Reply) -> bool {
    matches!(reply, Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(Collection::Collected(Outcome {
        reply: OutcomeReply::Accepted(actual), commit: Some(_)
    })))) if actual == expected)
}

fn routes(row: &Vector<'_>) -> Vec<Entry> {
    row.input.get("routes").map_or_else(
        || vec![Entry::Normal],
        |routes| {
            routes
                .split(',')
                .map(|route| match route {
                    "normal" => Entry::Normal,
                    "administrative" => Entry::Administrative,
                    "force_inclusion" => Entry::ForceInclusion,
                    "upgrade" => Entry::Upgrade,
                    "adapter" => Entry::Adapter,
                    _ => panic!("unknown route {route}"),
                })
                .collect()
        },
    )
}

fn submission(case: Case, row: &Vector<'_>) -> String {
    let namespace = row.number("namespace");
    let sequence = row.number("sequence");
    let token = Identity {
        rai: number(row, "rai", case.previous.rai),
        ..case.previous
    };
    let valid = row.input.get("signature_valid") != Some(&"false");
    let signature = if valid {
        Signature::Valid
    } else {
        Signature::Invalid
    };
    let mut observation = None;
    for entry in routes(row) {
        let mut service = case.service(
            10,
            Rules {
                execute: row.input.get("granted") != Some(&"read_receipt"),
                ..Rules::default()
            },
        );
        let payload = case.payload(
            &service,
            case.previous,
            case.old_session,
            sequence,
            Command::Reserve { duration: 10 },
        );
        let before = service.reads.snapshot();
        let reply = service.execute(
            entry,
            &Credentials {
                signature: &signature,
                ..auth(&token, case.old_session, case.old_epoch)
            },
            ordinary(&payload, namespace, sequence),
            None,
        );
        if row.id == "forged-call-namespace" {
            assert_eq!(reply, Err(EndpointError::Rejected), "forged-call-namespace");
        }
        let actual = if accepted(reply, Reply::Reserved) {
            "admission=allowed".to_owned()
        } else {
            format!(
                "admission=rejected;authority_unchanged={}",
                service.reads.snapshot() == before
            )
        };
        if let Some(ref previous) = observation {
            assert_eq!(previous, &actual, "{}", row.id);
        }
        observation = Some(actual);
    }
    observation.unwrap()
}

fn reads(case: Case, row: &Vector<'_>) -> String {
    let balance = number(row, "source_balance", 5);
    let service = case.service(
        balance,
        Rules {
            read: row.input.get("grant") == Some(&"true"),
            ..Rules::default()
        },
    );
    let query = Query::AccountBalance(case.binding.source());
    if row.operation == "raw-read" {
        assert_eq!(
            service.reads.current_cut().revision,
            row.number("revision") as usize
        );
        return match case.read(
            &service,
            &case.previous,
            case.old_session,
            case.old_epoch,
            ReadRequest::Raw(query),
        ) {
            Ok(Observation::Raw(Ok(Value::Units(value)))) => format!("reply=raw;value={value}"),
            Err(EndpointError::Rejected) => "reply=rejected;value_exposed=false".to_owned(),
            _ => panic!("unexpected raw response"),
        };
    }
    let mut exposed = false;
    for kind in row.field("kinds").split(',') {
        let request = match kind {
            "current" => ReadRequest::Current {
                query,
                expected: service.reads.current_cut(),
            },
            "historical" => ReadRequest::Historical { query, revision: 0 },
            "raw" => ReadRequest::Raw(query),
            "operation_status" => ReadRequest::Status(case.binding.origin),
            "journal" => ReadRequest::Journal,
            "cache" => ReadRequest::CaptureCache(query),
            _ => panic!("unknown read {kind}"),
        };
        exposed |= case
            .read(
                &service,
                &case.previous,
                case.old_session,
                case.old_epoch,
                request,
            )
            .is_ok();
    }
    format!(
        "reply={};value_exposed={exposed}",
        if exposed { "visible" } else { "rejected" }
    )
}

fn journal(case: Case, row: &Vector<'_>) -> String {
    let mut service = case.service(
        10,
        Rules {
            read: row.field("grant") == "true",
            ..Rules::default()
        },
    );
    assert!(accepted(
        case.ordinary(
            &mut service,
            &case.previous,
            case.old_session,
            1,
            Command::Reserve { duration: 10 }
        ),
        Reply::Reserved
    ));
    assert!(accepted(
        case.ordinary(
            &mut service,
            &case.successor,
            4,
            2,
            Command::Timeout { elapsed: 1 }
        ),
        Reply::TimeObserved
    ));
    assert_eq!(service.reads.authority.state.primary.journal.len(), 2);
    let Ok(Observation::Journal(ids)) = case.read(
        &service,
        &case.previous,
        case.old_session,
        case.old_epoch,
        ReadRequest::Journal,
    ) else {
        panic!("missing own journal");
    };
    let own = row.number("own_namespace");
    assert!(ids.iter().any(|id| id.namespace == own));
    format!(
        "foreign_visible={}",
        ids.iter()
            .any(|id| id.namespace == row.number("foreign_namespace"))
    )
}

fn retry(case: Case, row: &Vector<'_>) -> String {
    let mut service = case.service(10, Rules::default());
    let sequence = row.number("sequence");
    let payload = case.payload(
        &service,
        case.previous,
        case.old_session,
        sequence,
        Command::Reserve { duration: 10 },
    );
    let call = ordinary(&payload, row.number("namespace"), sequence);
    let original = service.execute(
        Entry::Normal,
        &auth(&case.previous, case.old_session, case.old_epoch),
        call,
        None,
    );
    assert!(accepted(original, Reply::Reserved));
    assert_eq!(row.field("receipt_exists"), "true");
    let active = row.number("current_epoch");
    if active != case.old_epoch {
        assert!(service.maintenance(&MAINTENANCE).unwrap().install_epoch(
            active,
            case.contexts(active),
            case.sessions(active)
        ));
        let answer = service.receipt(
            Entry::Adapter,
            &auth(&case.previous, case.old_session, active),
            call,
        );
        let exposed = matches!(
            answer,
            Ok(Some(Receipt::Ordinary(Collection::Collected(_))))
        );
        return format!(
            "reply={};receipt_exposed={exposed}",
            if answer.is_err() {
                "rejected"
            } else {
                "retained"
            }
        );
    }
    assert_eq!(row.field("exact_payload"), "true");
    assert_eq!(
        payload.cut.revision,
        row.number("original_revision") as usize
    );
    assert!(accepted(
        case.ordinary(
            &mut service,
            &case.worker,
            case.worker_session,
            2,
            Command::Dispatch { generation: 0 }
        ),
        Reply::SourceDispatched
    ));
    assert_eq!(
        service.reads.current_cut().revision,
        row.number("current_revision") as usize
    );
    let before = service.reads.snapshot();
    let answer = service.receipt(
        Entry::Upgrade,
        &auth(&case.previous, case.old_session, active),
        call,
    );
    let Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(expected))) = original else {
        panic!("missing original")
    };
    let retained = answer == Ok(Some(Receipt::Ordinary(expected)));
    format!(
        "reply={};new_effects={}",
        if retained { "retained" } else { "rejected" },
        usize::from(service.reads.snapshot() != before)
    )
}

fn unknown_receipt(case: Case, row: &Vector<'_>) -> String {
    assert_eq!(row.field("receipt_exists"), "false");
    let service = case.service(10, Rules::default());
    let binding = Binding {
        amount: 0,
        ..case.binding
    };
    let order = Order {
        binding,
        action: LegalAction::Freeze,
        officer: case.previous.principal,
        jurisdiction: 1,
        legal_basis: 1,
        scope: BTreeSet::from([binding.asset]),
        issuance_epoch: case.old_epoch,
        predecessor: None,
        appeal_deadline: None,
        destination: None,
    };
    let cut = service.reads.current_cut();
    let sequence = row.number("sequence");
    let action = Action::Legal {
        stage: LegalStage::SourceEmission,
        order: &order,
        payload: LegalPayload {
            message_id: sequence,
            caller: case.previous.principal,
            session: case.old_session,
            cut,
            binding,
            action: order.action,
            origin_epoch: case.old_epoch,
        },
    };
    let before = service.reads.snapshot();
    let reply = service.receipt(
        Entry::ForceInclusion,
        &auth(&case.previous, case.old_session, case.old_epoch),
        Request {
            target: binding.origin.domain,
            id: CallId {
                namespace: row.number("namespace"),
                sequence,
            },
            expected: cut,
            action,
        },
    );
    format!(
        "receipt_exposed={};authority_unchanged={}",
        matches!(reply, Ok(Some(_))),
        service.reads.snapshot() == before
    )
}

fn handover(case: Case, row: &Vector<'_>) -> String {
    let mut service = case.service(10, Rules::default());
    case.pending(&mut service);
    let before = service.reads.snapshot();
    let previous = if row.input.get("owner_consents") == Some(&"false") {
        Signature::Invalid
    } else {
        Signature::Valid
    };
    let successor = if row.input.get("successor_consents") == Some(&"false") {
        Signature::Invalid
    } else {
        Signature::Valid
    };
    let applied = case.handover(&mut service, &previous, &successor);
    if !applied {
        return format!(
            "reply=rejected;owner={};pending={};authority_unchanged={}",
            case.owner(&service, &case.previous, case.old_session, case.old_epoch),
            case.status(&service, &case.previous, case.old_session, case.old_epoch)
                .pending,
            service.reads.snapshot() == before
        );
    }
    let owner = case.owner(&service, &case.successor, case.new_session, case.new_epoch);
    let pending = case
        .status(&service, &case.successor, case.new_session, case.new_epoch)
        .pending;
    let old_closed = case
        .read(
            &service,
            &case.previous,
            case.old_session,
            case.new_epoch,
            ReadRequest::Owner(case.binding.asset),
        )
        .is_err();
    let new_open = case
        .read(
            &service,
            &case.successor,
            case.new_session,
            case.new_epoch,
            ReadRequest::Owner(case.binding.asset),
        )
        .is_ok();
    let ledger = &service.reads.authority.state.primary.ledger;
    format!(
        "reply=applied;owner={owner};old_session_closed={old_closed};new_session_open={new_open};pending={pending};source_balance={};receiver_balance={}",
        ledger.balance(case.binding.source()),
        ledger.balance(case.binding.destination())
    )
}

fn owner_recovery(case: Case, row: &Vector<'_>) -> String {
    let mut service = case.service(10, Rules::default());
    case.pending(&mut service);
    assert!(case.handover(&mut service, &Signature::Valid, &Signature::Valid));
    let session = row.number("session");
    let owner = if session == case.new_session {
        &case.successor
    } else {
        &case.previous
    };
    let endorsement = auth(owner, session, case.new_epoch);
    let payload = case.payload(
        &service,
        case.worker,
        case.worker_session,
        10,
        Command::Refund {
            generation: 0,
            reference: 0,
        },
    );
    let reply = service.execute(
        Entry::Administrative,
        &auth(&case.worker, case.worker_session, case.new_epoch),
        ordinary(&payload, case.worker.principal, 10),
        Some(&endorsement),
    );
    let status = case.status(&service, &case.successor, case.new_session, case.new_epoch);
    assert!(status.terminal.is_none());
    format!(
        "endorsement={};controller={};pending={}",
        if reply.is_ok() { "allowed" } else { "rejected" },
        case.owner(&service, &case.successor, case.new_session, case.new_epoch),
        status.pending
    )
}

fn old_session(case: Case, row: &Vector<'_>) -> String {
    let mut service = case.service(10, Rules::default());
    let old = case.pending(&mut service);
    assert!(case.handover(&mut service, &Signature::Valid, &Signature::Valid));
    let before = service.reads.snapshot();
    let credentials = auth(&case.previous, case.old_session, case.old_epoch);
    let mut all_rejected = true;
    for entry in routes(row) {
        for operation in row.field("operations").split(',') {
            all_rejected &= match operation {
                "retry" => service
                    .receipt(
                        entry,
                        &credentials,
                        ordinary(&old, case.previous.principal, 1),
                    )
                    .is_err(),
                "cancel" | "recovery" => {
                    let command = if operation == "cancel" {
                        Command::Cancel { generation: 0 }
                    } else {
                        Command::Refund {
                            generation: 0,
                            reference: 0,
                        }
                    };
                    let payload = CallPayload {
                        command,
                        ..old.clone()
                    };
                    service
                        .execute(
                            entry,
                            &credentials,
                            ordinary(&payload, case.previous.principal, 10),
                            None,
                        )
                        .is_err()
                }
                "enforcement" => {
                    let payload = SpendPayload {
                        message_id: 10,
                        caller: case.previous.principal,
                        session: case.old_session,
                        cut: old.cut,
                        origin_epoch: old.origin_epoch,
                        reference: super::super::CommitRef { position: 0 },
                        scope: SpendScope {
                            root: case.binding,
                            sender: 3,
                            recipient: 4,
                            amount: 1,
                            kind: SpendKind::Recover,
                        },
                    };
                    service
                        .execute(
                            entry,
                            &credentials,
                            Request {
                                target: case.binding.destination,
                                id: CallId {
                                    namespace: case.previous.principal,
                                    sequence: 10,
                                },
                                expected: old.cut,
                                action: Action::Spend {
                                    payload,
                                    enforcement: None,
                                },
                            },
                            None,
                        )
                        .is_err()
                }
                _ => panic!("unknown old operation {operation}"),
            };
        }
    }
    format!(
        "reply={};authority_unchanged={}",
        if all_rejected { "rejected" } else { "visible" },
        service.reads.snapshot() == before
    )
}

#[test]
fn proof_derived_identity_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        let case = Case::from_vector(&row);
        let actual = match row.operation {
            "ordinary-submit" => submission(case, &row),
            "raw-read" | "read" => reads(case, &row),
            "journal" => journal(case, &row),
            "retry" => retry(case, &row),
            "receipt" => unknown_receipt(case, &row),
            "handover" => handover(case, &row),
            "owner-recovery" => owner_recovery(case, &row),
            "old-session" => old_session(case, &row),
            _ => panic!("unknown vector {}", row.operation),
        };
        assert_eq!(actual, row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 16);
}

fn standard_case() -> Case {
    Case::from_vector(
        &parse_vectors(VECTORS)
            .find(|row| row.id == "atomic-handover-keeps-pending")
            .unwrap(),
    )
}

#[test]
fn query_signature_binds_full_request_target_and_live_proof() {
    let case = standard_case();
    let service = case.service(5, Rules::default());
    let request = ReadRequest::Raw(Query::ApplicationValue(case.binding.asset));
    let target = case.binding.origin.domain;
    let proof = SessionProof {
        session: case.old_session,
        epoch: case.old_epoch,
    };
    let signature = Signature::Read {
        identity: case.previous,
        proof,
        target,
        request,
    };
    let credentials = Credentials {
        token: &case.previous,
        proof,
        signature: &signature,
    };
    assert!(matches!(
        service.read(Entry::Normal, &credentials, target, request, None),
        Ok(Observation::Raw(Ok(Value::Units(0))))
    ));
    assert!(
        matches!(
            service.read(
                Entry::Adapter,
                &credentials,
                case.binding.destination,
                request,
                None
            ),
            Err(EndpointError::Rejected)
        ),
        "signed-read-target"
    );
    let changed = ReadRequest::Raw(Query::AccountBalance(case.binding.source()));
    assert!(
        matches!(
            service.read(Entry::Administrative, &credentials, target, changed, None),
            Err(EndpointError::Rejected)
        ),
        "signed-read-query"
    );
    let alternate = Credentials {
        proof: SessionProof {
            session: case.worker_session,
            ..proof
        },
        ..credentials
    };
    assert!(
        matches!(
            service.read(Entry::Upgrade, &alternate, target, request, None),
            Err(EndpointError::Rejected)
        ),
        "signed-read-session"
    );
}

#[test]
fn dual_approval_and_context_batch_are_atomic() {
    let case = standard_case();
    let mut service = case.service(10, Rules::default());
    case.pending(&mut service);
    assert!(service.maintenance(&case.previous.principal).is_none());
    let before = service.reads.snapshot();
    let proposal = case.proposal(&service);
    let former = Signature::Approval {
        signer: case.previous,
        proposal: proposal.clone(),
    };
    let mut modified = proposal.clone();
    modified.new_session += 1;
    let wrong = Signature::Approval {
        signer: case.successor,
        proposal: modified,
    };
    assert!(!case.handover(&mut service, &former, &wrong));
    assert_eq!(service.reads.snapshot(), before);
    let successor = Signature::Approval {
        signer: case.successor,
        proposal: proposal.clone(),
    };
    assert!(
        !case.handover(&mut service, &Signature::Invalid, &successor),
        "missing-former-consent"
    );
    assert_eq!(service.reads.snapshot(), before);
    let mut partial = proposal;
    partial.contexts.pop();
    let former = Signature::Approval {
        signer: case.previous,
        proposal: partial.clone(),
    };
    let successor = Signature::Approval {
        signer: case.successor,
        proposal: partial.clone(),
    };
    assert!(!service.maintenance(&MAINTENANCE).unwrap().handover(
        &partial,
        Consent {
            token: &case.previous,
            signature: &former
        },
        Consent {
            token: &case.successor,
            signature: &successor
        }
    ));
    assert_eq!(service.reads.snapshot(), before);
}

#[test]
fn successor_endorsement_and_worker_fence_release_five_with_real_reversal() {
    let case = standard_case();
    let mut service = case.service(10, Rules::default());
    case.pending(&mut service);
    assert!(case.handover(&mut service, &Signature::Valid, &Signature::Valid));
    let record = Command::RecordTerminal(TerminalEvidence {
        binding: case.binding,
        kind: TerminalKind::Reversed,
        reference: 1,
    });
    assert!(accepted(
        case.ordinary(&mut service, &case.worker, case.worker_session, 10, record),
        Reply::Recorded
    ));
    let endorser = auth(&case.successor, case.new_session, case.new_epoch);
    let refund = Command::Refund {
        generation: 0,
        reference: 1,
    };
    let owner_payload = case.payload(&service, case.successor, case.new_session, 11, refund);
    let reply = service.execute(
        Entry::Normal,
        &endorser,
        ordinary(&owner_payload, case.successor.principal, 11),
        Some(&endorser),
    );
    assert_eq!(
        reply,
        Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(
            Collection::Collected(Outcome {
                reply: OutcomeReply::Rejected,
                commit: None,
            })
        ))),
        "owner-cannot-substitute-for-worker"
    );
    assert_eq!(
        case.status(&service, &case.successor, case.new_session, case.new_epoch)
            .pending,
        5
    );

    let worker_payload = case.payload(&service, case.worker, case.worker_session, 12, refund);
    let worker = auth(&case.worker, case.worker_session, case.new_epoch);
    let request = ordinary(&worker_payload, case.worker.principal, 12);
    let former = auth(&case.previous, case.worker_session, case.new_epoch);
    assert_eq!(
        service.execute(Entry::Adapter, &worker, request, Some(&former)),
        Err(EndpointError::Rejected),
        "former-owner-cannot-release-funded-claim"
    );
    assert_eq!(
        service.execute(Entry::Adapter, &worker, request, None),
        Err(EndpointError::Rejected)
    );
    let mut wrong_generation = worker_payload.clone();
    wrong_generation.credential.as_mut().unwrap().generation += 1;
    let wrong = ordinary(&wrong_generation, case.worker.principal, 13);
    assert!(!accepted(
        service.execute(Entry::Adapter, &worker, wrong, Some(&endorser)),
        Reply::Refunded
    ));
    assert_eq!(
        case.status(&service, &case.successor, case.new_session, case.new_epoch)
            .pending,
        5
    );

    assert_eq!(
        service.execute(Entry::ForceInclusion, &worker, request, Some(&endorser)),
        Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(
            Collection::Waiting
        )))
    );
    let source = case.binding.source();
    assert!(matches!(
        case.read(
            &service,
            &case.successor,
            case.new_session,
            case.new_epoch,
            ReadRequest::Raw(Query::AccountBalance(source))
        ),
        Ok(Observation::Raw(Ok(Value::Units(10))))
    ));
    let status = case.status(&service, &case.successor, case.new_session, case.new_epoch);
    assert_eq!(status.pending, 0);
    assert_eq!(status.phase, Some(Phase::Refunded));
    assert!(!status.published);
    assert!(accepted(
        case.ordinary(
            &mut service,
            &case.worker,
            case.worker_session,
            14,
            Command::PublishPrimary
        ),
        Reply::Published
    ));
    assert!(matches!(
        service.receipt(Entry::Upgrade, &worker, request),
        Ok(Some(Receipt::Ordinary(Collection::Collected(Outcome {
            reply: OutcomeReply::Accepted(Reply::Refunded),
            ..
        }))))
    ));
    assert!(
        case.status(&service, &case.successor, case.new_session, case.new_epoch)
            .published
    );
}

#[test]
fn caller_capability_does_not_substitute_for_signer_evidence() {
    let case = standard_case();
    let mut service = case.service(
        10,
        Rules {
            signer: false,
            ..Rules::default()
        },
    );
    case.pending(&mut service);
    let before = service.reads.snapshot();
    let record = Command::RecordTerminal(TerminalEvidence {
        binding: case.binding,
        kind: TerminalKind::Reversed,
        reference: 1,
    });
    assert_eq!(
        case.ordinary(&mut service, &case.worker, case.worker_session, 10, record),
        Err(EndpointError::Rejected),
        "independent-signer-evidence"
    );
    assert_eq!(service.reads.snapshot(), before);
}

#[test]
fn verified_call_signature_binds_message_and_the_entire_payload() {
    let case = standard_case();
    let mut service = case.service(10, Rules::default());
    let original = case.payload(
        &service,
        case.previous,
        case.old_session,
        1,
        Command::Reserve { duration: 10 },
    );
    let call = ordinary(&original, case.previous.principal, 1);
    let proof = SessionProof {
        session: case.old_session,
        epoch: case.old_epoch,
    };
    let signature = Signature::Call {
        identity: case.previous,
        proof,
        target: call.target,
        id: call.id,
        payload: Box::new(original.clone()),
    };
    let credentials = Credentials {
        token: &case.previous,
        proof,
        signature: &signature,
    };
    let before = service.reads.snapshot();
    let changed = CallPayload {
        message_id: 2,
        ..original.clone()
    };
    assert_eq!(
        service.execute(
            Entry::Adapter,
            &credentials,
            ordinary(&changed, call.id.namespace, call.id.sequence),
            None
        ),
        Err(EndpointError::Rejected),
        "signed-call-message"
    );
    let changed = CallPayload {
        binding: Binding {
            recipient: 4,
            ..original.binding
        },
        ..original.clone()
    };
    assert_eq!(
        service.execute(
            Entry::Upgrade,
            &credentials,
            ordinary(&changed, call.id.namespace, call.id.sequence),
            None
        ),
        Err(EndpointError::Rejected),
        "signed-call-binding"
    );
    assert_eq!(service.reads.snapshot(), before);
    assert!(accepted(
        service.execute(Entry::ForceInclusion, &credentials, call, None),
        Reply::Reserved
    ));
}
