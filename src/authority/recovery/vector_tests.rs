use super::*;
use crate::CallId;
use crate::authority::identity::{Action as ClientAction, Operation, SessionProof, Signed};
use crate::authority::reads::{CheckedExecution, Query, ReadError, Value};
use crate::authority::regulation::{
    Action as LegalAction, EnforcementOrder, Enrollment, LegalGrant, LegalPayload, LegalReply,
    LegalStage, Policy, RegulatoryRoute, SpendGrant, SpendKind, SpendPayload, SpendScope,
};
use crate::authority::{CallPayload, Collection, CommitRef, Outcome, OutcomeReply};
use crate::lock_finality::{Account, Command, Credential, Permission, Reply, Route};
use crate::vector_tests::{Vector, parse_vectors};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

const VECTORS: &str = include_str!("../../../tests/vectors/persistent-recovery.tsv");
pub(super) const ROOT: OriginKey = OriginKey {
    domain: 0,
    event: 17,
};
pub(super) const EPOCH: u64 = 9;
pub(super) const HOST: u64 = 99;
pub(super) const YES: bool = true;
pub(super) const DEFAULT_PROFILE: RecoveryProfile = RecoveryProfile {
    deployment: 7,
    format: 1,
    authority_profile: 99,
};

#[derive(Clone, Copy)]
pub(super) enum Cas {
    Normal,
    LostBefore,
    LostAfter,
    Competing(AnchorHead),
}

struct AnchorState {
    head: Option<AnchorHead>,
    cas: Cas,
    attempts: u64,
}

#[derive(Clone)]
pub(super) struct TestAnchor(Arc<Mutex<AnchorState>>);

impl TestAnchor {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(AnchorState {
            head: None,
            cas: Cas::Normal,
            attempts: 0,
        })))
    }

    pub(super) fn mode(&self, cas: Cas) {
        self.0.lock().unwrap().cas = cas;
    }

    pub(super) fn head(&self) -> AnchorHead {
        self.current().unwrap().unwrap()
    }

    fn attempts(&self) -> u64 {
        self.0.lock().unwrap().attempts
    }
}

impl AuthenticatedHead for TestAnchor {
    // The deterministic wire fixture supplies its own publication CAS.
    fn supports_wire_publication(&self) -> bool {
        true
    }

    fn compare_and_set_at_publication(
        &self,
        expected: Option<AnchorHead>,
        candidate: AnchorHead,
        guard: &super::WirePublication,
    ) -> Result<Result<(), super::PublicationRefusal>, HeadError> {
        assert_eq!(guard.wire_expiry, 105);
        assert_eq!(guard.service_deadline, None);
        Ok(if self.compare_and_set(expected, candidate)? {
            Ok(())
        } else {
            Err(super::PublicationRefusal::CheckpointChanged)
        })
    }
    type AttachmentProof = (RecoveryProfile, bool);

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &Self::AttachmentProof,
    ) -> bool {
        (profile, connected) == *proof
    }

    fn current(&self) -> Result<Option<AnchorHead>, HeadError> {
        Ok(self.0.lock().map_err(|_| HeadError)?.head)
    }

    fn compare_and_set(
        &self,
        expected: Option<AnchorHead>,
        candidate: AnchorHead,
    ) -> Result<bool, HeadError> {
        let mut state = self.0.lock().map_err(|_| HeadError)?;
        state.attempts += 1;
        if state.head != expected {
            return Ok(false);
        }
        if expected.map_or(candidate.sequence != 0, |head| {
            head.profile != candidate.profile
                || head.sequence.checked_add(1) != Some(candidate.sequence)
        }) {
            return Ok(false);
        }
        match state.cas {
            Cas::LostBefore => Err(HeadError),
            Cas::LostAfter => {
                state.head = Some(candidate);
                Err(HeadError)
            }
            Cas::Competing(head) => {
                state.head = Some(head);
                Ok(false)
            }
            Cas::Normal => {
                state.head = Some(candidate);
                Ok(true)
            }
        }
    }
}

#[derive(Default)]
pub(super) struct Rules {
    evidence_denied: bool,
    pub(super) ordered_clock: Option<Arc<AtomicU64>>,
    pub(super) ordered_boundary_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(super) ordered_read_allowed: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Replaces the wire frame limit while set.
    pub(super) frame_limit: Option<Arc<std::sync::atomic::AtomicUsize>>,
    pub(super) max_delivery_ttl: Option<u64>,
    /// Family and opcode pairs that this configuration does not accept.
    pub(super) refused_operations: BTreeSet<(u64, u64)>,
}

impl Security for Rules {
    type Token = Identity;
    type Signature = bool;
    type MaintenanceToken = u64;
    fn ordered_revocation_profile(&self) -> Option<RecoveryProfile> {
        self.ordered_clock.as_ref().map(|_| DEFAULT_PROFILE)
    }
    fn authenticate(&self, token: &Identity) -> Option<Identity> {
        Some(*token)
    }
    fn authenticate_maintenance(&self, token: &u64) -> Option<Principal> {
        (*token == HOST).then_some(7)
    }
    fn permit(
        &self,
        _: Identity,
        _: u64,
        operation: Operation,
        _: super::super::identity::Scope,
        _: u64,
    ) -> bool {
        operation != Operation::Current
            || self.ordered_read_allowed.as_ref().is_none_or(|allow| allow.load(Ordering::SeqCst))
    }
    fn verify(
        &self,
        _: Identity,
        _: SessionProof,
        _: u64,
        _: Operation,
        _: Signed<'_>,
        signature: &bool,
    ) -> bool {
        *signature
    }
    fn verify_recovery_evidence(&self, _: TerminalEvidence) -> bool {
        !self.evidence_denied
    }
    fn verify_terminal(&self, _: Identity, _: SessionProof, _: u64, _: TerminalEvidence) -> bool {
        !self.evidence_denied
    }
    fn verify_order(
        &self,
        _: Identity,
        _: SessionProof,
        _: u64,
        _: LegalStage,
        _: &super::super::regulation::Order,
    ) -> bool {
        !self.evidence_denied
    }
    fn verify_enforcement(
        &self,
        _: Identity,
        _: SessionProof,
        _: u64,
        _: &EnforcementOrder,
    ) -> bool {
        !self.evidence_denied
    }
    fn verify_time(&self, _: Principal, _: CommitCut, _: u64, signature: &bool) -> bool {
        *signature
    }
    fn verify_ack(&self, _: &Acknowledgement, signature: &bool) -> bool {
        *signature
    }
    fn approve(&self, _: Identity, _: &Handover, signature: &bool) -> bool {
        *signature
    }
}

pub(super) const FORMER: Identity = Identity {
    principal: 7,
    domain: 0,
    ocid: 107,
    rai: 207,
};
pub(super) const SUCCESSOR: Identity = Identity {
    principal: 8,
    domain: 0,
    ocid: 108,
    rai: 208,
};

pub(super) fn auth(identity: &Identity, session: u64, epoch: u64) -> Credentials<'_, Rules> {
    Credentials {
        token: identity,
        proof: SessionProof { session, epoch },
        signature: &YES,
    }
}

pub(super) fn binding() -> Binding {
    Binding {
        origin: ROOT,
        asset: 17,
        owner: 7,
        destination: 2,
        recipient: 3,
        amount: 5,
    }
}

pub(super) fn contexts(epoch: u64) -> Vec<EndpointContext> {
    let permissions = [
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
    [0, 2]
        .map(|endpoint| EndpointContext {
            endpoint,
            epoch,
            grants: [7, 8]
                .into_iter()
                .flat_map(|actor| {
                    permissions
                        .into_iter()
                        .map(move |op| (actor, Route::Normal, op))
                })
                .collect(),
            dependencies: BTreeMap::new(),
            write_permissions: BTreeSet::from([(7, 17, 9)]),
        })
        .into()
}

pub(super) fn sessions(epoch: u64) -> BTreeMap<SessionId, SessionBinding> {
    BTreeMap::from([
        (
            1,
            SessionBinding {
                principal: 7,
                authority_epoch: epoch,
            },
        ),
        (
            2,
            SessionBinding {
                principal: 7,
                authority_epoch: epoch,
            },
        ),
    ])
}

pub(super) fn genesis(initial: u64, provider: u64) -> Bootstrap {
    let b = binding();
    let scope = SpendScope {
        root: b,
        sender: 3,
        recipient: 4,
        amount: 1,
        kind: SpendKind::Recover,
    };
    let policy = Policy {
        enrollments: vec![Enrollment {
            asset: b.asset,
            source: b.origin.domain,
            receiver: b.destination,
        }],
        legal: [LegalStage::SourceEmission, LegalStage::ReceivingCommit]
            .map(|stage| LegalGrant {
                stage,
                route: RegulatoryRoute::Normal,
                officer: 7,
                jurisdiction: 1,
                legal_basis: 1,
                asset: b.asset,
                action: LegalAction::Freeze,
                epoch: EPOCH,
            })
            .into(),
        spend: vec![SpendGrant {
            route: RegulatoryRoute::Normal,
            actor: 7,
            epoch: EPOCH,
            scope,
            jurisdiction: 1,
            legal_basis: 1,
        }],
        clock_observers: BTreeSet::from([(7, EPOCH)]),
    };
    Bootstrap {
        epoch: EPOCH,
        provider,
        settlement_target: 99,
        contexts: contexts(EPOCH),
        sessions: sessions(EPOCH),
        maintainers: BTreeSet::from([7]),
        balances: BTreeMap::from([(b.source(), initial)]),
        supply: BTreeMap::from([(b.asset, u128::from(initial))]),
        identities: vec![FORMER, SUCCESSOR],
        owners: BTreeMap::from([(b.asset, 7)]),
        regulation: Some(policy),
    }
}

pub(super) type Service = PersistentAuthority<Rules, TestAnchor>;

pub(super) fn attachment(
    profile: RecoveryProfile,
    connected: bool,
) -> Attachment<Rules, (RecoveryProfile, bool)> {
    Attachment {
        profile,
        proof: (profile, connected),
        security: Rules::default(),
        source_connected: connected,
    }
}

pub(super) struct JournalPath(PathBuf);

impl JournalPath {
    pub(super) fn create() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("recovery-fixtures");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "authority-{}-{}.records",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap()
            .sync_all()
            .unwrap();
        Self(path)
    }

    pub(super) fn fork(&self, anchor: &TestAnchor) -> (Self, TestAnchor) {
        let path = Self::create();
        fs::copy(&self.0, &path.0).unwrap();
        path.file().sync_all().unwrap();
        let branch = TestAnchor::new();
        branch.0.lock().unwrap().head = Some(anchor.head());
        (path, branch)
    }

    pub(super) fn file(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.0)
            .unwrap()
    }

    pub(super) fn initialize(
        &self,
        anchor: &TestAnchor,
        profile: RecoveryProfile,
        connected: bool,
        initial: u64,
        provider: u64,
    ) -> Service {
        PersistentAuthority::initialize(
            self.file(),
            anchor.clone(),
            attachment(profile, connected),
            genesis(initial, provider),
        )
        .unwrap()
    }

    pub(super) fn reopen(
        &self,
        anchor: &TestAnchor,
        profile: RecoveryProfile,
        connected: bool,
    ) -> Result<Service, RecoveryError> {
        PersistentAuthority::open(self.file(), anchor.clone(), attachment(profile, connected))
    }
}

impl Drop for JournalPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(super) fn cut(service: &mut Service) -> CommitCut {
    service
        .transact(|product| product.reads.current_cut())
        .unwrap()
}

pub(super) fn payload(service: &mut Service, b: Binding, id: u64, command: Command) -> CallPayload {
    let cut = cut(service);
    let credential = match command {
        Command::Dispatch { generation }
        | Command::Debit { generation }
        | Command::Cancel { generation }
        | Command::Fence { generation }
        | Command::Reconcile { generation, .. }
        | Command::Refund { generation, .. }
        | Command::Write { generation, .. } => Some(generation),
        Command::Credit { .. } => Some(0),
        _ => None,
    }
    .map(|generation| Credential {
        asset: b.asset,
        origin: b.origin,
        holder: 7,
        generation,
        epoch: cut.authority_epoch,
    });
    CallPayload {
        message_id: id,
        origin_epoch: EPOCH,
        endpoint: if matches!(command, Command::Credit { .. }) {
            b.destination
        } else {
            b.origin.domain
        },
        caller: 7,
        session: 2,
        cut,
        binding: b,
        credential,
        versions: if matches!(command, Command::Cancel { .. }) && b.origin.event == 18 {
            vec![(b.asset, 1)]
        } else {
            Vec::new()
        },
        command,
    }
}

pub(super) fn request(payload: &CallPayload, id: u64) -> Request<'_> {
    Request {
        target: payload.endpoint,
        id: CallId {
            namespace: payload.caller,
            sequence: id,
        },
        expected: payload.cut,
        action: ClientAction::Ordinary(payload),
    }
}

pub(super) fn submit(
    service: &mut Service,
    payload: &CallPayload,
    id: u64,
) -> Result<ActionReply, RecoveryError> {
    let worker = auth(&FORMER, payload.session, payload.cut.authority_epoch);
    let owner = auth(&FORMER, 1, payload.cut.authority_epoch);
    service.execute(Entry::Normal, &worker, request(payload, id), Some(&owner))
}

pub(super) fn accepted(result: Result<ActionReply, RecoveryError>, expected: Reply) -> CommitRef {
    match result {
        Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(Collection::Collected(
            Outcome {
                reply: OutcomeReply::Accepted(reply),
                commit: Some(commit),
            },
        )))) if reply == expected => commit,
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

pub(super) fn reserve(service: &mut Service, b: Binding, id: u64) -> CallPayload {
    let call = payload(service, b, id, Command::Reserve { duration: 20 });
    accepted(submit(service, &call, id), Reply::Reserved);
    call
}

fn pending(service: &mut Service, b: Binding) -> CallPayload {
    reserve(service, b, 10);
    let dispatch = payload(service, b, 11, Command::Dispatch { generation: 0 });
    accepted(submit(service, &dispatch, 11), Reply::SourceDispatched);
    let debit = payload(service, b, 12, Command::Debit { generation: 0 });
    accepted(submit(service, &debit, 12), Reply::Debited);
    debit
}

fn read_units(service: &mut Service, account: Account) -> u64 {
    let result = service.read(
        Entry::Normal,
        &auth(&FORMER, 1, EPOCH),
        account.endpoint,
        ReadRequest::Raw(Query::AccountBalance(account)),
        None,
    );
    match result {
        Ok(Observation::Raw(Ok(Value::Units(amount)))) => amount,
        _ => panic!("expected actual units"),
    }
}

fn pending_amount(service: &mut Service, origin: OriginKey) -> u64 {
    let result = service.read(
        Entry::Normal,
        &auth(&FORMER, 1, EPOCH),
        origin.domain,
        ReadRequest::Status(origin),
        None,
    );
    match result {
        Ok(Observation::Status(status)) => status.pending,
        _ => panic!("expected actual source operation"),
    }
}

fn number(row: &Vector<'_>, key: &str, default: u64) -> u64 {
    row.input
        .get(key)
        .map_or(default, |value| value.parse().unwrap())
}

fn vector_profile(row: &Vector<'_>) -> RecoveryProfile {
    RecoveryProfile {
        deployment: number(row, "deployment", 7),
        format: number(row, "format", 1).try_into().unwrap(),
        authority_profile: number(row, "profile", number(row, "trusted_profile", 99)),
    }
}

fn before_after_heads(row: &Vector<'_>) -> String {
    let profile = vector_profile(row);
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, profile, true, 10, 1);
    let original = anchor.head();
    assert_eq!(
        original.sequence,
        number(row, "old_head", number(row, "expected_head", 0))
    );
    if row.operation == "prepare" {
        assert_eq!(row.field("flushed"), "true");
        assert_eq!(row.field("cas"), "false");
        anchor.mode(Cas::LostBefore);
        let call = payload(
            &mut service,
            binding(),
            1,
            Command::Reserve { duration: 20 },
        );
        let before_length = path.file().metadata().unwrap().len();
        let reply = submit(&mut service, &call, 1);
        assert!(path.file().metadata().unwrap().len() > before_length);
        assert_eq!(row.number("candidate"), original.sequence + 1);
        return format!(
            "head={};new_reply_exposed={}",
            anchor.head().sequence,
            reply.is_ok()
        );
    }
    if row.id == "competing-compare-and-set" {
        assert_eq!(row.field("previous_reply_lost"), "true");
        let mut file = path.file();
        let before = exact_image(&mut file, original).unwrap();
        let competitor_call = payload(
            &mut service,
            binding(),
            8,
            Command::Reserve { duration: 20 },
        );
        let mut competitor = before.image.open(profile, Arc::new(Rules::default()), true);
        accepted(
            competitor
                .execute_durable(&auth(&FORMER, 2, EPOCH), request(&competitor_call, 8), None)
                .map_err(RecoveryError::Endpoint),
            Reply::Reserved,
        );
        let competing_record = CommitRecord {
            profile,
            sequence: row.number("current_head"),
            previous: Some(original),
            image: RetainedImage::capture(&competitor),
        };
        let competing = append_record(&mut file, &competing_record, File::sync_all).unwrap();
        assert_eq!(row.number("candidate"), competing.sequence);
        anchor.mode(Cas::Competing(competing));
        let request = payload(
            &mut service,
            binding(),
            1,
            Command::Reserve { duration: 20 },
        );
        let reply = submit(&mut service, &request, 1);
        return format!(
            "head_unchanged={};unconfirmed_reply_exposed={}",
            anchor.head() == competing,
            reply.is_ok()
        );
    }
    if row.id == "uncertain-commit-confirmed-by-head" {
        assert_eq!(row.field("durable"), "true");
        assert_eq!(row.field("cas_applied"), "true");
        assert_eq!(row.field("cas_reply_lost"), "true");
        anchor.mode(Cas::LostAfter);
        let call = payload(
            &mut service,
            binding(),
            1,
            Command::Reserve { duration: 20 },
        );
        let reply = submit(&mut service, &call, 1);
        let after = anchor.head();
        assert_eq!(after.sequence, row.number("candidate"));
        drop(service);
        let mut restored = path.reopen(&anchor, profile, true).unwrap();
        let retry = submit(&mut restored, &call, 1);
        assert_eq!(reply, retry, "uncertain-commit-confirmed-by-head");
        return format!(
            "head={};reply_exposed_after_verified_head={};reexecution={}",
            anchor.head().sequence,
            reply.is_ok(),
            anchor.head() != after
        );
    }

    reserve(&mut service, binding(), 1);
    let latest = anchor.head();
    assert_eq!(
        latest.sequence,
        number(
            row,
            "trusted_head",
            number(row, "candidate", number(row, "head", 1))
        )
    );
    drop(service);
    let mut file = path.file();
    match row.id {
        "head-confirms-the-exact-record" => {
            assert_eq!(row.field("flushed"), "true");
            assert_eq!(row.field("cas"), "true");
            return format!(
                "head={};reopened={}",
                latest.sequence,
                path.reopen(&anchor, profile, true).is_ok()
            );
        }
        "old-valid-record-replay" => {
            assert_eq!(row.field("old_record_valid"), "true");
            assert_eq!(
                row.number("supplied_sequence"),
                exact_image(&mut file, original).unwrap().sequence
            );
            let mut old = vec![0; original.length as usize];
            file.seek(SeekFrom::Start(original.offset)).unwrap();
            file.read_exact(&mut old).unwrap();
            file.seek(SeekFrom::Start(latest.offset)).unwrap();
            file.write_all(&old).unwrap();
        }
        "current-sequence-altered-body" => {
            assert_eq!(row.field("body_changed"), "true");
            let mut altered = exact_image(&mut file, latest).unwrap();
            assert_eq!(altered.sequence, row.number("supplied_sequence"));
            altered.image.provider += 1;
            let bytes = encode(&altered).unwrap();
            assert_eq!(bytes.len() as u64, latest.length);
            file.seek(SeekFrom::Start(latest.offset)).unwrap();
            file.write_all(&bytes).unwrap();
        }
        "missing-anchored-record" => {
            assert_eq!(row.field("record_present"), "false");
            file.set_len(latest.offset).unwrap();
        }
        "wrong-authority-profile" => {
            let supplied = RecoveryProfile {
                authority_profile: row.number("attachment_profile"),
                ..profile
            };
            return format!("reopened={}", path.reopen(&anchor, supplied, true).is_ok());
        }
        other => panic!("unknown anchor vector {other}"),
    }
    file.sync_all().unwrap();
    let reopened = path.reopen(&anchor, profile, true);
    if matches!(
        row.id,
        "old-valid-record-replay" | "missing-anchored-record"
    ) {
        let genesis_fallback = reopened.is_ok() && anchor.head().sequence == 0;
        format!(
            "reopened={};genesis_fallback={genesis_fallback}",
            reopened.is_ok()
        )
    } else {
        format!("reopened={}", reopened.is_ok())
    }
}

fn reply_kind(reply: Result<ActionReply, RecoveryError>) -> &'static str {
    match reply {
        Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(Collection::Collected(outcome)))) => {
            match outcome.reply {
                OutcomeReply::Busy => "busy",
                OutcomeReply::Unavailable => "unavailable",
                OutcomeReply::Accepted(Reply::Debited) => "retained",
                OutcomeReply::Rejected => "rejected",
                _ => panic!("unexpected retained outcome {outcome:?}"),
            }
        }
        other => panic!("unexpected result {other:?}"),
    }
}

fn retry_vector(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let profile = DEFAULT_PROFILE;
    let mut service = path.initialize(&anchor, profile, true, number(row, "source_initial", 10), 1);
    assert_eq!(row.number("actor"), FORMER.principal);
    assert_eq!(row.number("epoch"), EPOCH);
    if row.id == "original-signed-debit-retry" {
        assert_eq!(row.field("exact_original_request"), "true");
        assert_eq!(row.field("cut_advanced"), "true");
        assert_eq!(row.field("reopened"), "true");
        let b = Binding {
            origin: OriginKey {
                domain: row.number("source"),
                event: row.number("event"),
            },
            destination: row.number("receiver"),
            asset: row.number("asset"),
            amount: row.number("amount"),
            ..binding()
        };
        let call = pending(&mut service, b);
        let before = anchor.head();
        drop(service);
        let mut restored = path.reopen(&anchor, profile, true).unwrap();
        let reply = restored.execute(
            Entry::Upgrade,
            &auth(&FORMER, call.session, EPOCH),
            request(&call, 12),
            None,
        );
        return format!(
            "reply={};new_effects={};source_balance={};pending={}",
            reply_kind(reply),
            usize::from(anchor.head() != before),
            read_units(&mut restored, b.source()),
            pending_amount(&mut restored, b.origin)
        );
    }
    assert_eq!(row.number("namespace"), FORMER.principal);
    let id = row.number("sequence");
    let stale = payload(
        &mut service,
        binding(),
        id,
        Command::Reserve { duration: 20 },
    );
    if row.id == "completed-busy-survives-reopen" {
        assert_eq!(row.field("anchor_committed"), "true");
        assert_eq!(row.field("reopened"), "true");
        reserve(&mut service, binding(), 7);
        assert_eq!(
            reply_kind(submit(&mut service, &stale, id)),
            row.field("outcome")
        );
    } else {
        assert_eq!(row.field("authority_reachable"), "true");
        assert_eq!(row.field("source_connected"), "false");
        assert_eq!(row.field("anchor_committed"), "true");
        service.reconnect((profile, false), false).unwrap();
        assert_eq!(reply_kind(submit(&mut service, &stale, id)), "unavailable");
    }
    let before = anchor.head();
    drop(service);
    let mut restored = path.reopen(&anchor, profile, true).unwrap();
    let reply = restored.execute(
        Entry::ForceInclusion,
        &auth(&FORMER, stale.session, EPOCH),
        request(&stale, id),
        None,
    );
    format!(
        "reply={};new_effects={}",
        reply_kind(reply),
        usize::from(anchor.head() != before)
    )
}

fn source_vector(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let b = Binding {
        origin: OriginKey {
            domain: row.number("source"),
            event: row.number("event"),
        },
        destination: row.number("receiver"),
        asset: row.number("asset"),
        amount: row.number("pending"),
        ..binding()
    };
    let mut service = path.initialize(
        &anchor,
        DEFAULT_PROFILE,
        true,
        number(row, "initial", 10),
        1,
    );
    pending(&mut service, b);
    drop(service);
    assert_eq!(row.field("reopened"), "true");
    let mut service = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
    let before = read_units(&mut service, b.source());
    if row.operation == "source-return" {
        assert_eq!(row.field("exact_reversal"), "false");
        let refund = payload(
            &mut service,
            b,
            20,
            Command::Refund {
                generation: 0,
                reference: 9,
            },
        );
        let _ = submit(&mut service, &refund, 20).unwrap();
        let source = read_units(&mut service, b.source());
        assert_eq!(before, row.number("source_balance"));
        return format!(
            "source_balance={source};pending={};refund={}",
            pending_amount(&mut service, b.origin),
            source - before
        );
    }
    let evidence = row
        .input
        .get("evidence_event")
        .map(|event| TerminalEvidence {
            binding: Binding {
                origin: OriginKey {
                    event: event.parse().unwrap(),
                    ..b.origin
                },
                ..b
            },
            kind: TerminalKind::Reversed,
            reference: 0,
        });
    let reply = service.source_probe(&HOST, b.origin, evidence).unwrap();
    let (next, event) = match reply {
        SourceAction::Query(binding) => ("query_exact", binding.origin.event),
        SourceAction::Hold(binding) => ("hold", binding.origin.event),
        SourceAction::ConsiderReversed(binding) => ("consider_reversed", binding.origin.event),
        _ => panic!("unexpected source response {reply:?}"),
    };
    let pending = pending_amount(&mut service, b.origin);
    let source = read_units(&mut service, b.source());
    if evidence.is_some() {
        format!(
            "next={next};event={event};pending={pending};refund={}",
            source - before
        )
    } else {
        assert_eq!(row.field("source_connected"), "true");
        assert_eq!(row.field("evidence"), "none");
        format!("next={next};event={event};pending={pending};source_balance={source}")
    }
}

fn cache_vector(row: &Vector<'_>) -> String {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    assert_eq!(row.field("query"), "application_value");
    assert_eq!(row.field("reopened"), "true");
    let epoch = row.number("epoch");
    let provider = row.number("provider");
    let asset = row.number("asset");
    let query = Query::ApplicationValue(asset);
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, provider);
    let cache = service
        .read(
            Entry::Normal,
            &auth(&FORMER, 1, epoch),
            0,
            ReadRequest::CaptureCache(query),
            None,
        )
        .unwrap();
    let Observation::Cache(Ok(cache)) = cache else {
        panic!("expected actual cache")
    };
    let mut claim = cache.claim().unwrap();
    let original = claim.observed.value;
    assert_eq!(claim.provider, provider);
    if row.field("same_authority") != "true" {
        claim.profile.deployment += 1;
    }
    if row.field("same_cut") != "true" {
        claim.observed.cut.revision += 1;
    }
    let same = row.field("same_value") == "true";
    if !same {
        claim.observed.value = Value::Units(1);
    }
    let read = ReadRequest::Current {
        query,
        expected: cut(&mut service),
    };
    let running = service
        .read(
            Entry::Normal,
            &auth(&FORMER, 1, epoch),
            0,
            read,
            Some(&claim),
        )
        .unwrap();
    drop(service);
    let mut restored = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
    let recovered = restored
        .read(
            Entry::Normal,
            &auth(&FORMER, 1, epoch),
            0,
            read,
            Some(&claim),
        )
        .unwrap();
    let (Observation::Current(running), Observation::Current(recovered)) = (running, recovered)
    else {
        panic!("expected current observation")
    };
    assert_eq!(running, recovered, "cache differs across cold open");
    if same {
        format!(
            "reply={};value_preserved={}",
            if recovered.is_ok() { "current" } else { "busy" },
            recovered.is_ok_and(|reply| reply.value == original)
        )
    } else {
        format!(
            "reply={};forged_value_exposed={}",
            if recovered == Err(ReadError::Busy) {
                "busy"
            } else {
                "current"
            },
            recovered.is_ok_and(|reply| reply.value == claim.observed.value)
        )
    }
}

pub(super) fn fund_root(service: &mut Service) -> (CallPayload, CommitRef) {
    let b = binding();
    let debit = pending(service, b);
    let terminal = payload(
        service,
        b,
        13,
        Command::RecordTerminal(TerminalEvidence {
            binding: b,
            kind: TerminalKind::Confirmed,
            reference: 0,
        }),
    );
    let commit = accepted(submit(service, &terminal, 13), Reply::Recorded);
    let credit = payload(service, b, 14, Command::Credit { reference: 0 });
    assert_eq!(
        submit(service, &credit, 14),
        Ok(ActionReply::Ordinary(CheckedExecution::Forwarded(
            Collection::Waiting
        )))
    );
    let reconcile = payload(
        service,
        b,
        15,
        Command::Reconcile {
            generation: 0,
            reference: 0,
        },
    );
    accepted(submit(service, &reconcile, 15), Reply::Reconciled);
    let publish = payload(service, b, 16, Command::PublishPrimary);
    accepted(submit(service, &publish, 16), Reply::Published);
    (debit, commit)
}

fn trace_action(
    service: &mut Service,
    name: &str,
    debit: &CallPayload,
    terminal: CommitRef,
    key: SettlementKey,
) -> String {
    let b = binding();
    match name {
        "retry" => format!(
            "{:?}",
            service.execute(
                Entry::Upgrade,
                &auth(&FORMER, 2, EPOCH),
                request(debit, 12),
                None
            )
        ),
        "current" => {
            let query = Query::RootBalance(ROOT, b.destination());
            let expected = cut(service);
            let Observation::Current(value) = service
                .read(
                    Entry::Normal,
                    &auth(&FORMER, 1, EPOCH),
                    b.destination,
                    ReadRequest::Current { query, expected },
                    None,
                )
                .unwrap()
            else {
                panic!("expected current")
            };
            assert!(value.is_ok());
            format!("{value:?}")
        }
        "historical" => {
            let query = Query::AccountBalance(b.source());
            let Observation::Historical(value) = service
                .read(
                    Entry::Normal,
                    &auth(&FORMER, 1, EPOCH),
                    b.origin.domain,
                    ReadRequest::Historical { query, revision: 0 },
                    None,
                )
                .unwrap()
            else {
                panic!("expected historical")
            };
            assert!(value.is_ok());
            format!("{value:?}")
        }
        "cancel" => {
            let held = Binding {
                origin: OriginKey { event: 19, ..ROOT },
                ..b
            };
            let cancel = payload(service, held, 20, Command::Cancel { generation: 0 });
            format!(
                "{:?}",
                accepted(submit(service, &cancel, 20), Reply::Closed)
            )
        }
        "terminal" => {
            let binding = Binding {
                origin: OriginKey { event: 21, ..ROOT },
                amount: 0,
                ..b
            };
            let order = super::super::regulation::Order {
                binding,
                action: LegalAction::Freeze,
                officer: 7,
                jurisdiction: 1,
                legal_basis: 1,
                scope: BTreeSet::from([b.asset]),
                issuance_epoch: EPOCH,
                predecessor: None,
                appeal_deadline: None,
                destination: None,
            };
            let mut replies = Vec::new();
            for (stage, target, sequence) in [
                (LegalStage::SourceEmission, 0, 21),
                (LegalStage::ReceivingCommit, 2, 22),
            ] {
                let cut = cut(service);
                let payload = LegalPayload {
                    message_id: sequence,
                    caller: 7,
                    session: 1,
                    cut,
                    binding,
                    action: LegalAction::Freeze,
                    origin_epoch: EPOCH,
                };
                let reply = service
                    .execute(
                        Entry::ForceInclusion,
                        &auth(&FORMER, 1, EPOCH),
                        Request {
                            target,
                            id: CallId {
                                namespace: 7,
                                sequence,
                            },
                            expected: cut,
                            action: ClientAction::Legal {
                                stage,
                                order: &order,
                                payload,
                            },
                        },
                        None,
                    )
                    .unwrap();
                assert!(matches!(
                    reply,
                    ActionReply::Legal(LegalReply::Emitted(_) | LegalReply::Applied(_))
                ));
                replies.push(reply);
            }
            let publish = payload(service, binding, 23, Command::PublishPrimary);
            accepted(submit(service, &publish, 23), Reply::Published);
            format!("{replies:?}")
        }
        "spend" => {
            let scope = SpendScope {
                root: b,
                sender: 3,
                recipient: 4,
                amount: 1,
                kind: SpendKind::Recover,
            };
            let order = EnforcementOrder {
                scope,
                officer: 7,
                jurisdiction: 1,
                legal_basis: 1,
                assets: BTreeSet::from([b.asset]),
                prior_seizure: None,
                appeal_deadline: None,
            };
            let cut = cut(service);
            let payload = SpendPayload {
                message_id: 25,
                caller: 7,
                session: 1,
                cut,
                origin_epoch: EPOCH,
                reference: terminal,
                scope,
            };
            let reply = service
                .execute(
                    Entry::Adapter,
                    &auth(&FORMER, 1, EPOCH),
                    Request {
                        target: 2,
                        id: CallId {
                            namespace: 7,
                            sequence: 25,
                        },
                        expected: cut,
                        action: ClientAction::Spend {
                            payload,
                            enforcement: Some(&order),
                        },
                    },
                    None,
                )
                .unwrap();
            assert!(matches!(
                reply,
                ActionReply::Spend(super::super::regulation::SpendReply::Executed { .. })
            ));
            format!("{reply:?}")
        }
        "handover" => {
            let proposal = Handover {
                asset: b.asset,
                previous: 7,
                successor: 8,
                expected: cut(service),
                old_session: 1,
                new_session: 3,
                epoch: 10,
                contexts: contexts(10),
            };
            let applied = service
                .handover(
                    &HOST,
                    &proposal,
                    Consent {
                        token: &FORMER,
                        signature: &YES,
                    },
                    Consent {
                        token: &SUCCESSOR,
                        signature: &YES,
                    },
                )
                .unwrap();
            assert!(applied);
            format!("{applied}")
        }
        "secondary" => {
            let sent = service.dispatch_secondary(&HOST, key).unwrap().unwrap();
            assert_eq!(sent.commitment.key(), key);
            assert!(service.fail_secondary(&HOST, key).unwrap());
            let sent = service.dispatch_secondary(&HOST, key).unwrap().unwrap();
            assert_eq!(sent.attempts, 2);
            let ack = Acknowledgement {
                key,
                commitment: sent.commitment,
                target: sent.target,
            };
            assert!(service.acknowledge_secondary(&HOST, ack, &YES).unwrap());
            format!("{sent:?}")
        }
        _ => panic!("unknown service action {name}"),
    }
}

fn service_trace(row: &Vector<'_>) -> String {
    let profiles = ["head_valid", "current_profile", "same_authenticated_inputs"];
    for field in profiles {
        assert_eq!(row.field(field), "true");
    }
    let left_path = JournalPath::create();
    let right_path = JournalPath::create();
    let left_anchor = TestAnchor::new();
    let right_anchor = TestAnchor::new();
    let mut left = left_path.initialize(&left_anchor, DEFAULT_PROFILE, true, 10, 1);
    let mut right = right_path.initialize(&right_anchor, DEFAULT_PROFILE, true, 10, 1);
    let (left_debit, left_terminal) = fund_root(&mut left);
    let (right_debit, right_terminal) = fund_root(&mut right);
    let held = Binding {
        origin: OriginKey { event: 19, ..ROOT },
        ..binding()
    };
    reserve(&mut left, held, 19);
    reserve(&mut right, held, 19);
    let left_key = left.enqueue_secondary(&HOST, ROOT).unwrap().unwrap();
    let right_key = right.enqueue_secondary(&HOST, ROOT).unwrap().unwrap();
    drop(right);
    let mut right = right_path
        .reopen(&right_anchor, DEFAULT_PROFILE, true)
        .unwrap();
    let mut same = true;
    for action in row.field("actions").split(',') {
        let first = trace_action(&mut left, action, &left_debit, left_terminal, left_key);
        let second = trace_action(&mut right, action, &right_debit, right_terminal, right_key);
        same &= first == second;
    }
    let left = exact_image(&mut left_path.file(), left_anchor.head()).unwrap();
    let right = exact_image(&mut right_path.file(), right_anchor.head()).unwrap();
    format!(
        "same_replies={same};same_durable_effects={}",
        left.image == right.image
    )
}

#[test]
fn proof_derived_recovery_vectors() {
    let mut seen = BTreeSet::new();
    for row in parse_vectors(VECTORS) {
        assert!(seen.insert(row.id), "duplicate vector {}", row.id);
        let observed = match row.operation {
            "prepare" | "reopen" | "commit" => before_after_heads(&row),
            "retry" => retry_vector(&row),
            "source-probe" | "source-return" => source_vector(&row),
            "current-read" => cache_vector(&row),
            "service-trace" => service_trace(&row),
            other => panic!("unknown recovery vector {other}"),
        };
        assert_eq!(observed, row.expected, "{}", row.id);
    }
    assert_eq!(seen.len(), 17);
}

#[test]
fn flush_error_does_not_advance_head() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    drop(service);
    let head = anchor.head();
    let mut file = path.file();
    let old = exact_image(&mut file, head).unwrap();
    let record = CommitRecord {
        profile: old.profile,
        sequence: 1,
        previous: Some(head),
        image: old.image,
    };
    let attempts = anchor.attempts();
    assert_eq!(
        commit(&mut file, &anchor, &record, |_| Err(io::Error::other(
            "injected synchronization failure"
        ))),
        Err(RecoveryError::Io),
        "flush-error-stops-cas",
    );
    assert_eq!(anchor.attempts(), attempts);
    assert_eq!(anchor.head(), head);
}

#[test]
fn fresh_cut_spoof_and_old_signed_epoch_cannot_use_the_store() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    let stale = payload(
        &mut service,
        binding(),
        2,
        Command::Reserve { duration: 20 },
    );
    let committed = reserve(&mut service, binding(), 1);
    let head = anchor.head();
    let spoof = Request {
        expected: cut(&mut service),
        ..request(&stale, 2)
    };
    assert_eq!(
        service.execute(Entry::Normal, &auth(&FORMER, 2, EPOCH), spoof, None),
        Err(RecoveryError::Endpoint(EndpointError::Rejected)),
        "spoofed-expected-cut"
    );
    assert_eq!(anchor.head(), head);
    assert!(
        service
            .install_epoch(&HOST, 10, contexts(10), sessions(10))
            .unwrap()
    );
    drop(service);
    let mut restored = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
    let head = anchor.head();
    let active = auth(&FORMER, 2, 10);
    assert_eq!(
        restored.receipt(Entry::Upgrade, &active, request(&committed, 1)),
        Err(RecoveryError::Endpoint(EndpointError::Rejected)),
        "old-epoch-retained-result"
    );
    assert_eq!(
        restored.execute(Entry::Upgrade, &active, request(&committed, 1), None),
        Err(RecoveryError::Endpoint(EndpointError::Rejected))
    );
    assert_eq!(anchor.head(), head);
}

#[test]
fn exact_signed_result_precedes_fresh_evidence_verification() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    pending(&mut service, binding());
    let evidence = TerminalEvidence {
        binding: binding(),
        kind: TerminalKind::Reversed,
        reference: 0,
    };
    let recorded = payload(
        &mut service,
        binding(),
        13,
        Command::RecordTerminal(evidence),
    );
    let original = submit(&mut service, &recorded, 13);
    accepted(original, Reply::Recorded);
    let head = anchor.head();
    drop(service);
    let mut attachment = attachment(DEFAULT_PROFILE, true);
    attachment.security.evidence_denied = true;
    let mut recovered = PersistentAuthority::open(path.file(), anchor.clone(), attachment).unwrap();
    assert_eq!(
        submit(&mut recovered, &recorded, 13),
        original,
        "existing-result-before-new-evidence"
    );
    let fresh = payload(
        &mut recovered,
        binding(),
        14,
        Command::RecordTerminal(evidence),
    );
    assert_eq!(
        submit(&mut recovered, &fresh, 14),
        Err(RecoveryError::Endpoint(EndpointError::Rejected))
    );
    assert_eq!(anchor.head(), head);
}

#[test]
fn attachment_authentication_rejects_mismatched_connection() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    let head = anchor.head();
    assert_eq!(
        service.reconnect((DEFAULT_PROFILE, false), true),
        Err(RecoveryError::AttachmentRejected),
        "unverified-connection-cannot-replace-attachment"
    );
    assert_eq!(anchor.head(), head);
}

#[test]
fn cold_reopen_child_entry() {
    let Some(path) = std::env::var_os("OIP_RECOVERY_CHILD_RECORDS") else {
        return;
    };
    let head: AnchorHead =
        serde_json::from_str(&std::env::var("OIP_RECOVERY_CHILD_AUTHENTICATED_HEAD").unwrap())
            .unwrap();
    let anchor = TestAnchor::new();
    // A test-only adapter receives an independently supplied trusted head.
    anchor.0.lock().unwrap().head = Some(head);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut service =
        PersistentAuthority::open(file, anchor, attachment(DEFAULT_PROFILE, true)).unwrap();
    assert_eq!(read_units(&mut service, binding().source()), 5);
    assert_eq!(pending_amount(&mut service, ROOT), 5);
    assert_eq!(
        service.source_probe(&HOST, ROOT, None).unwrap(),
        SourceAction::Query(binding())
    );
}

#[test]
fn records_only_open_from_a_fresh_process() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    pending(&mut service, binding());
    drop(service);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "authority::recovery::vector_tests::cold_reopen_child_entry",
        ])
        .env("OIP_RECOVERY_CHILD_RECORDS", &path.0)
        .env(
            "OIP_RECOVERY_CHILD_AUTHENTICATED_HEAD",
            serde_json::to_string(&anchor.head()).unwrap(),
        )
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if started.elapsed() >= std::time::Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fresh recovery subprocess did not finish");
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

#[test]
fn torn_unanchored_suffix_is_ignored_without_truncating_or_adopting_it() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    let reserved = reserve(&mut service, binding(), 1);
    let head = anchor.head();
    drop(service);
    let mut file = path.file();
    file.seek(SeekFrom::End(0)).unwrap();
    file.write_all(br#"{"profile":{"deployment":7,"format":1"#)
        .unwrap();
    file.sync_all().unwrap();
    let torn_end = file.metadata().unwrap().len();
    drop(file);
    let mut restored = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
    assert_eq!(anchor.head(), head);
    assert!(matches!(
        restored.receipt(
            Entry::Adapter,
            &auth(&FORMER, 2, EPOCH),
            request(&reserved, 1)
        ),
        Ok(Some(Receipt::Ordinary(Collection::Collected(_))))
    ));
    let next = payload(
        &mut restored,
        binding(),
        2,
        Command::Dispatch { generation: 0 },
    );
    accepted(submit(&mut restored, &next, 2), Reply::SourceDispatched);
    assert_eq!(anchor.head().offset, torn_end);
    assert_eq!(anchor.head().sequence, head.sequence + 1);
}

#[test]
fn portable_cache_scope_and_cut_are_revalidated_even_when_values_match() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    let query = Query::ApplicationValue(17);
    let auth = auth(&FORMER, 1, EPOCH);
    let Observation::Cache(Ok(cache)) = service
        .read(
            Entry::Normal,
            &auth,
            0,
            ReadRequest::CaptureCache(query),
            None,
        )
        .unwrap()
    else {
        panic!("expected actual cache")
    };
    let claim = cache.claim().unwrap();
    let request = ReadRequest::Current {
        query,
        expected: cut(&mut service),
    };
    drop(service);
    let mut service = path.reopen(&anchor, DEFAULT_PROFILE, true).unwrap();
    for (label, wrong) in [
        (
            "cache-source-profile",
            CacheClaim {
                profile: RecoveryProfile {
                    deployment: 8,
                    ..claim.profile
                },
                ..claim
            },
        ),
        (
            "cache-provider",
            CacheClaim {
                provider: 2,
                ..claim
            },
        ),
        (
            "cache-cut",
            CacheClaim {
                observed: super::super::reads::CurrentRead {
                    cut: CommitCut {
                        revision: 1,
                        ..claim.observed.cut
                    },
                    ..claim.observed
                },
                ..claim
            },
        ),
    ] {
        assert!(
            matches!(
                service.read(Entry::Normal, &auth, 0, request, Some(&wrong)),
                Ok(Observation::Current(Err(ReadError::Busy)))
            ),
            "{label}"
        );
    }
}

#[test]
fn canonical_bytes_exclude_volatile_runtime_attachment_state() {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut service = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
    reserve(&mut service, binding(), 1);
    let image = exact_image(&mut path.file(), anchor.head()).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&encode(&image).unwrap()).unwrap();
    assert!(
        body.pointer("/image/authority/primary/ledger/connected")
            .is_none()
    );
    assert!(body.pointer("/image/authority/up").is_none());
    assert!(body.pointer("/image/authority/connected").is_none());
    assert!(body.pointer("/image/security").is_none());
}
