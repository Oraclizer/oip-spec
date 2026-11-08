use super::*;
use crate::authority::reads::CurrentRead;
use crate::authority::recovery::RetainedImage;
use crate::authority::recovery::schedule::{Exchange, ScheduleError};
use crate::authority::recovery::vector_tests::{attachment, fund_root, genesis};
use crate::authority::recovery::wire::schedule::{
    WireOccurrence, WireOccurrenceReply, WireScheduleError, WireScheduleReply, WireScheduled,
};
use crate::authority::{SecondaryJob, SettlementStatus};
use std::sync::atomic::AtomicBool;

const ACK_PEER: Identity = Identity {
    principal: 99,
    domain: 99,
    ocid: 199,
    rai: 299,
};
type OrderedService = PersistentAuthority<Rules, OrderedHead<MemoryControl>>;

pub(in crate::authority::recovery) fn dispatched_fixture() -> (JournalPath, TestAnchor, SecondaryJob, CommitCut) {
    let path = JournalPath::create();
    let anchor = TestAnchor::new();
    let mut initial = genesis(10, 1);
    initial.identities.push(ACK_PEER);
    let mut service = PersistentAuthority::initialize(
        path.file(),
        anchor.clone(),
        attachment(DEFAULT_PROFILE, true),
        initial,
    )
    .unwrap();
    fund_root(&mut service);
    let key = service
        .enqueue_secondary(&HOST, binding().origin)
        .unwrap()
        .unwrap();
    let job = service.dispatch_secondary(&HOST, key).unwrap().unwrap();
    (path, anchor, job, cut(&mut service))
}

fn control_for(head: AnchorHead) -> MemoryControl {
    let bytes =
        OrderedHead::<MemoryControl>::initial_value(DEFAULT_PROFILE, Some(head), 1).unwrap();
    MemoryControl(Arc::new(std::sync::Mutex::new(ControlValue {
        revision: 1,
        bytes,
    })))
}

fn schedule_endpoint(
    path: &JournalPath,
    control: MemoryControl,
    hook: Option<Arc<dyn Fn() + Send + Sync>>,
    read_allowed: Option<Arc<AtomicBool>>,
) -> OrderedService {
    let mut attachment = attachment(DEFAULT_PROFILE, true);
    attachment.security.ordered_clock = Some(Arc::new(AtomicU64::new(105)));
    attachment.security.ordered_boundary_hook = hook;
    attachment.security.ordered_read_allowed = read_allowed;
    PersistentAuthority::open(
        path.file(),
        OrderedHead::new(control, DEFAULT_PROFILE, 1),
        attachment,
    )
    .unwrap()
}

pub(in crate::authority::recovery) fn signed_ack(job: SecondaryJob, uuid_tag: u8) -> Vec<u8> {
    let decision = job.commitment.decision;
    let b = decision.binding;
    let mut core = core_with(
        5,
        1,
        b.destination,
        uuid_tag,
        vec![
            b.origin.domain,
            b.origin.event,
            decision.commit.position as u64,
            job.target,
            b.asset,
            b.owner,
            b.destination,
            b.recipient,
            decision.origin_epoch,
            1,
        ],
        vec![uint256(b.amount)],
    );
    core.source_domain = Some(job.target);
    core.principal = Some(ACK_PEER.principal);
    signed(core)
}

pub(in crate::authority::recovery) fn signed_current(cut: CommitCut) -> Vec<u8> {
    signed(core_with(
        4,
        1,
        2,
        60,
        vec![1, cut.revision as u64, 4, 0, 17, 2, 17, 3],
        Vec::new(),
    ))
}

pub(in crate::authority::recovery) fn ack_channel() -> Channel {
    negotiated_from(99, 2, &[6], &[6], 6, true, None).unwrap()
}

pub(in crate::authority::recovery) fn ack_credentials() -> WireCredentials<'static, Rules> {
    WireCredentials {
        token: &ACK_PEER,
        ..wire_auth()
    }
}

fn image(service: &mut OrderedService) -> RetainedImage {
    service
        .transact(|product| RetainedImage::capture(product))
        .unwrap()
}

fn status(service: &mut OrderedService, job: SecondaryJob) -> SettlementStatus {
    service
        .transact(|product| {
            product
                .reads
                .authority
                .secondary_job(job.commitment.key())
                .unwrap()
                .status
        })
        .unwrap()
}

fn result(arrival: Arrival, reply: WireScheduleReply) -> Result<WireScheduled, WireError> {
    Ok(WireScheduled { arrival, reply })
}

#[test]
fn ordered_schedule_exchanges_actual_signed_ack_and_current_read() {
    let (path, anchor, job, current) = dispatched_fixture();
    let (other_path, _) = path.fork(&anchor);
    let left_control = control_for(anchor.head());
    let right_control = control_for(anchor.head());
    let mut left = schedule_endpoint(&path, left_control.clone(), None, None);
    let mut right = schedule_endpoint(&other_path, right_control.clone(), None, None);
    let ack = signed_ack(job, 50);
    let read = signed_current(current);
    let acknowledgement = WireOccurrence {
        label: 501,
        channel: &ack_channel(),
        bytes: &ack,
        credentials: &ack_credentials(),
    };
    let observation = WireOccurrence {
        label: 777,
        channel: &channel(2),
        bytes: &read,
        credentials: &wire_auth(),
    };
    let requests = [acknowledgement, observation];

    assert_eq!(
        left.schedule(&[], &[]),
        Err(ScheduleError::Recovery(RecoveryError::Endpoint(
            crate::authority::identity::EndpointError::Rejected
        ),))
    );
    let exchanged = left.schedule_wire(&requests, &[0]).unwrap();
    let original = right.schedule_wire(&requests, &[]).unwrap();
    assert_eq!(exchanged.exchanges, [Exchange::Exchanged]);
    assert_eq!(exchanged.replies, original.replies);
    assert_eq!(
        exchanged.replies[0],
        WireOccurrenceReply {
            label: 501,
            reply: result(Arrival::First, WireScheduleReply::Acknowledged(true)),
        }
    );
    assert_eq!(
        exchanged.replies[1],
        WireOccurrenceReply {
            label: 777,
            reply: result(
                Arrival::First,
                WireScheduleReply::Current(Ok(CurrentRead {
                    cut: current,
                    value: Value::Units(5)
                }))
            ),
        }
    );
    assert_eq!(status(&mut left, job), SettlementStatus::Completed);
    assert_eq!(image(&mut left), image(&mut right));
    assert_eq!(
        left.anchor.current().unwrap(),
        right.anchor.current().unwrap()
    );
    assert_eq!(
        left.anchor.current().unwrap().unwrap().sequence,
        anchor.head().sequence + 1
    );
    assert!(left_control.current().unwrap() == right_control.current().unwrap());
    let committed = left_control.current().unwrap();
    assert_eq!(committed.revision, 2);
    let length = path.file().metadata().unwrap().len();

    let retry = left.schedule_wire(&requests, &[0, 0]).unwrap();
    assert_eq!(retry.exchanges, [Exchange::Exchanged, Exchange::Exchanged]);
    for (first, replay) in exchanged.replies.iter().zip(retry.replies) {
        assert_eq!(replay.label, first.label);
        assert_eq!(
            replay.reply,
            result(Arrival::Identical, first.reply.unwrap().reply)
        );
    }
    assert!(left_control.current().unwrap() == committed);
    assert_eq!(path.file().metadata().unwrap().len(), length);
}

#[test]
fn ordered_schedule_preserves_shared_slots_and_refused_labels() {
    let (path, anchor, job, current) = dispatched_fixture();
    let control = control_for(anchor.head());
    let mut service = schedule_endpoint(&path, control.clone(), None, None);
    let channel = channel(2);
    let ack_channel = ack_channel();
    let auth = wire_auth();
    let ack_auth = ack_credentials();
    let ack_a = signed_ack(job, 50);
    let ack_b = signed_ack(job, 51);
    let read = signed_current(current);
    let mut tampered = read.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let unsupported = signed(debit_core(current.revision as u64));
    let make_ack = |label, bytes| WireOccurrence {
        label,
        channel: &ack_channel,
        bytes,
        credentials: &ack_auth,
    };
    let make_read = |label, bytes| WireOccurrence {
        label,
        channel: &channel,
        bytes,
        credentials: &auth,
    };

    let first = service
        .schedule_wire(&[make_ack(12, &ack_a), make_ack(11, &ack_b)], &[0])
        .unwrap();
    assert_eq!(first.exchanges, [Exchange::Serialized]);
    assert_eq!(
        first
            .replies
            .iter()
            .map(|entry| entry.label)
            .collect::<Vec<_>>(),
        [12, 11]
    );
    assert!(
        first
            .replies
            .iter()
            .all(|entry| entry.reply
                == result(Arrival::First, WireScheduleReply::Acknowledged(true)))
    );
    assert_eq!(status(&mut service, job), SettlementStatus::Completed);
    assert_eq!(control.current().unwrap().revision, 2);

    let requests = [
        make_read(3, &unsupported),
        make_read(4, &tampered),
        make_read(1, &read),
        make_read(2, &read),
    ];
    assert_eq!(
        service.schedule_wire(&requests, &[0, 1, 2, 0]),
        Err(WireScheduleError::InvalidPlan)
    );
    let report = service.schedule_wire(&requests, &[0, 1, 2]).unwrap();
    assert_eq!(report.exchanges, [Exchange::Serialized; 3]);
    assert_eq!(
        report
            .replies
            .iter()
            .map(|entry| entry.label)
            .collect::<Vec<_>>(),
        [3, 4, 1, 2]
    );
    assert_eq!(report.replies[0].reply, Err(WireError::InvalidFormat));
    assert_eq!(report.replies[1].reply, Err(WireError::InvalidSignature));
    let expected = WireScheduleReply::Current(Ok(CurrentRead {
        cut: current,
        value: Value::Units(5),
    }));
    assert_eq!(report.replies[2].reply, result(Arrival::First, expected));
    assert_eq!(
        report.replies[3].reply,
        result(Arrival::Identical, expected)
    );
    assert_eq!(control.current().unwrap().revision, 3);

    let signed_but_refused = signed_ack(job, 52);
    let refused_auth = WireCredentials {
        signature: &false,
        ..ack_credentials()
    };
    let refused = WireOccurrence {
        label: 8,
        channel: &ack_channel,
        bytes: &signed_but_refused,
        credentials: &refused_auth,
    };
    let report = service
        .schedule_wire(&[refused, make_read(9, &read)], &[0])
        .unwrap();
    assert_eq!(report.exchanges, [Exchange::Serialized]);
    assert_eq!(
        report.replies[0].reply,
        result(Arrival::First, WireScheduleReply::Acknowledged(false))
    );
    assert_eq!(
        report.replies[1].reply,
        result(Arrival::Identical, expected)
    );
    assert_eq!(status(&mut service, job), SettlementStatus::Completed);
}

#[test]
fn ordered_schedule_withholds_prepared_success_after_authority_or_permission_change() {
    for revoke in [true, false] {
        let (path, anchor, job, current) = dispatched_fixture();
        let control = control_for(anchor.head());
        let controller = OrderedHead::new(control.clone(), DEFAULT_PROFILE, 1);
        let allowed = Arc::new(AtomicBool::new(true));
        let gate = allowed.clone();
        let calls = AtomicU64::new(0);
        let hook = Arc::new(move || {
            // Two boundary checks per item, then the first post-flush check.
            if calls.fetch_add(1, Ordering::SeqCst) == 4 {
                if revoke {
                    assert!(controller.revoke(FORMER.principal).unwrap());
                } else {
                    gate.store(false, Ordering::SeqCst);
                }
            }
        });
        let mut service = schedule_endpoint(&path, control.clone(), Some(hook), Some(allowed));
        let before = service.anchor.current().unwrap();
        let length = path.file().metadata().unwrap().len();
        let ack = signed_ack(job, 50);
        let read = signed_current(current);
        let requests = [
            WireOccurrence {
                label: 1,
                channel: &ack_channel(),
                bytes: &ack,
                credentials: &ack_credentials(),
            },
            WireOccurrence {
                label: 2,
                channel: &channel(2),
                bytes: &read,
                credentials: &wire_auth(),
            },
        ];
        let expected = if revoke {
            hold()
        } else {
            WireError::ProductRejected
        };
        assert_eq!(
            service.schedule_wire(&requests, &[]),
            Err(WireScheduleError::Wire(expected))
        );
        assert_eq!(service.anchor.current().unwrap(), before);
        assert_eq!(
            control.current().unwrap().revision,
            if revoke { 2 } else { 1 }
        );
        assert_eq!(status(&mut service, job), SettlementStatus::InFlight);
        assert!(path.file().metadata().unwrap().len() > length);
    }
}
