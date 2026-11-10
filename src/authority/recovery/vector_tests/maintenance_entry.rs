use super::*;
use ordered::{ControlStore, ControlValue, OrderedHead};

const VECTORS: &str = include_str!("../../../../tests/vectors/ordered-maintenance-entry.tsv");

struct FixedControl<'a> {
    verifier: &'a TestAnchor,
    value: ControlValue,
}

impl ControlStore for FixedControl<'_> {
    type AttachmentProof = (RecoveryProfile, bool);

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &Self::AttachmentProof,
    ) -> bool {
        self.verifier.verify_attachment(profile, connected, proof)
    }

    fn current(&self) -> Result<ControlValue, HeadError> {
        Ok(self.value.clone())
    }

    fn replace(&self, _: &ControlValue, _: &[u8]) -> Result<bool, HeadError> {
        panic!("generic maintenance reached ordered publication")
    }
}

fn exercise_entry<H: AuthenticatedHead>(
    service: &mut PersistentAuthority<Rules, H>,
    token: &u64,
    expected: CommitCut,
    ack: Acknowledgement,
    open: bool,
    row: usize,
) {
    let outcome = if open {
        Ok(true)
    } else {
        Err(RecoveryError::Endpoint(EndpointError::Rejected))
    };
    let check = |name, reply| assert_eq!(reply, outcome, "{name}, vector row {row}");

    check(
        "observe_time",
        service.observe_time(token, 1, expected, 1, &YES),
    );
    check(
        "enqueue_secondary",
        service
            .enqueue_secondary(token, ROOT)
            .map(|key| key == Some(ack.key)),
    );
    check(
        "dispatch_secondary",
        service.dispatch_secondary(token, ack.key).map(|job| {
            job.is_some_and(|job| job.commitment == ack.commitment && job.target == ack.target)
        }),
    );
    check("fail_secondary", service.fail_secondary(token, ack.key));
    check(
        "acknowledge_secondary",
        service.acknowledge_secondary(token, ack, &YES),
    );

    let proposal = Handover {
        asset: binding().asset,
        previous: FORMER.principal,
        successor: SUCCESSOR.principal,
        expected: if open {
            service
                .transact(|product| product.reads.current_cut())
                .unwrap()
        } else {
            expected
        },
        old_session: 1,
        new_session: 3,
        epoch: EPOCH + 1,
        contexts: contexts(EPOCH + 1),
    };
    check(
        "handover",
        service.handover(
            token,
            &proposal,
            Consent {
                token: &FORMER,
                signature: &YES,
            },
            Consent {
                token: &SUCCESSOR,
                signature: &YES,
            },
        ),
    );
    let next_epoch = EPOCH + 2;
    check(
        "install_epoch",
        service.install_epoch(
            token,
            next_epoch,
            contexts(next_epoch),
            sessions(next_epoch),
        ),
    );
}

#[test]
fn ordered_maintenance_entry_vectors() {
    let mut lines = VECTORS.lines();
    assert_eq!(
        lines.next(),
        Some("attached_ordered\tconfigured_ordered\tlocal_actor_present\topen")
    );
    let mut cases = BTreeSet::new();
    for (index, line) in lines.enumerate() {
        let [attached, configured, actor_present, open]: [bool; 4] = line
            .split('\t')
            .map(|field| field.parse().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert!(cases.insert((attached, configured, actor_present)));

        let path = JournalPath::create();
        let anchor = TestAnchor::new();
        let mut standalone = path.initialize(&anchor, DEFAULT_PROFILE, true, 10, 1);
        fund_root(&mut standalone);
        let (expected, commitment) = standalone
            .transact(|product| {
                (
                    product.reads.current_cut(),
                    product.reads.authority.primary_publication(ROOT).unwrap(),
                )
            })
            .unwrap();
        drop(standalone);
        let ack = Acknowledgement {
            key: commitment.key(),
            commitment,
            target: 99,
        };
        let token = if actor_present { HOST } else { 0 };
        let row = index + 2;
        let head = anchor.head();
        let journal = fs::read(&path.0).unwrap();
        let checks = || anchor.0.lock().unwrap().attachment_checks;
        let mut attachment = attachment(DEFAULT_PROFILE, true);
        if configured {
            attachment.security.ordered_clock = Some(Arc::new(AtomicU64::new(105)));
        }

        if attached {
            let bytes =
                OrderedHead::<FixedControl<'_>>::initial_value(DEFAULT_PROFILE, Some(head), 1)
                    .unwrap();
            let control = FixedControl {
                verifier: &anchor,
                value: ControlValue { revision: 1, bytes },
            };
            let ordered = OrderedHead::new(control, DEFAULT_PROFILE, 1);
            let mut service = PersistentAuthority::open(path.file(), ordered, attachment).unwrap();
            let before = checks();
            exercise_entry(&mut service, &token, expected, ack, open, row);
            assert_eq!(
                checks(),
                before,
                "ordered attachment opened a transaction, row {row}"
            );
            assert_eq!(service.anchor.current().unwrap(), Some(head));
        } else {
            let mut service =
                PersistentAuthority::open(path.file(), anchor.clone(), attachment).unwrap();
            let before = checks();
            exercise_entry(&mut service, &token, expected, ack, open, row);
            if configured {
                assert_eq!(
                    checks(),
                    before,
                    "ordered security opened a transaction, row {row}"
                );
            }
        }
        if !open {
            assert_eq!(anchor.head(), head, "authority head changed, row {row}");
            assert_eq!(
                fs::read(&path.0).unwrap(),
                journal,
                "journal changed, row {row}"
            );
        }
    }
    assert_eq!(cases.len(), 5);
}
