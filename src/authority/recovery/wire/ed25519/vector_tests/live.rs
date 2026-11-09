use super::*;
use crate::authority::identity::{Entry, Observation};
use crate::authority::recovery::archive::JournalArchive;
use crate::authority::recovery::ordered::etcd::EtcdTransport;
use crate::authority::recovery::ordered::witness::vector_tests::config as etcd_config;
use crate::authority::recovery::ordered::witness::{
    Ed25519WitnessAuthority, WitnessAttachmentIssuer, WitnessHead, WitnessWriter,
};
use crate::authority::recovery::vector_tests::{JournalPath, SUCCESSOR, genesis};
use crate::authority::recovery::wire::response::{ResponseCode, ResponseStatus, admit_response};
use crate::authority::recovery::wire::vector_tests::{core_with, uint256};
use crate::authority::recovery::wire::{DeliveryWindow, WireCredentials, WireReply};
use crate::authority::recovery::{
    Attachment, AuthenticatedHead, PersistentAuthority, RecoveryError,
};
use crate::wire::codec::{encode_core, encode_packet, signing_bytes};
use crate::wire::generated::Packet;
use crate::wire::negotiation::{
    Negotiation, Offer, SignedOffers, confirmation_bytes, negotiate, offer_bytes, select_profile,
};
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::Duration;

fn now() -> u64 {
    SystemClock.unix_seconds().unwrap()
}

fn actual_config() -> Ed25519Profile {
    let mut config = config();
    config.peers.insert(
        8,
        PeerRegistration {
            identity: SUCCESSOR,
            key_id: 12,
            public_key: key(10).verifying_key().to_bytes(),
            sessions: BTreeMap::from([(
                1,
                BTreeMap::from([(
                    0,
                    EndpointGrant {
                        execute: BTreeSet::new(),
                        receipts: BTreeSet::new(),
                        current: Vec::new(),
                        journal: false,
                        ..EndpointGrant::default()
                    },
                )]),
            )]),
        },
    );
    config
}

fn provider() -> Ed25519Security<SystemClock> {
    Ed25519Security::new(actual_config(), key(6), SystemClock).unwrap()
}

fn head(directory: &Path, writer: WitnessWriter) -> WitnessHead<Ed25519WitnessAuthority> {
    head_at(directory, writer, "ed25519")
}

fn head_at(
    directory: &Path,
    writer: WitnessWriter,
    case: &str,
) -> WitnessHead<Ed25519WitnessAuthority> {
    let authority = EtcdTransport::new(etcd_config("AUTHORITY", case)).unwrap();
    let witness = EtcdTransport::new(etcd_config("SELECTOR", case)).unwrap();
    let verifier = Ed25519WitnessAuthority::new(
        key(12).verifying_key().to_bytes(),
        key(13).verifying_key().to_bytes(),
        key(14).verifying_key().to_bytes(),
    )
    .unwrap();
    WitnessHead::new(
        authority,
        witness,
        JournalArchive::new(directory, DEFAULT_PROFILE, 1024 * 1024).unwrap(),
        DEFAULT_PROFILE,
        writer,
        4,
        verifier,
    )
    .unwrap()
}

fn attachment(
    head: &WitnessHead<Ed25519WitnessAuthority>,
    security: Ed25519Security<SystemClock>,
) -> Attachment<Ed25519Security<SystemClock>, [u8; 64]> {
    let proof = WitnessAttachmentIssuer::new(key(12))
        .issue(head, true)
        .unwrap();
    Attachment {
        profile: DEFAULT_PROFILE,
        source_connected: true,
        proof,
        security,
    }
}

fn channel(local: u8, remote: u8) -> Channel {
    channel_at(local, remote, 0, 0)
}

fn channel_at(local: u8, remote: u8, local_domain: u64, remote_domain: u64) -> Channel {
    let offered = |sender, receiver| Offer {
        deployment: 7,
        sender,
        receiver,
        challenge: 81,
        expires: now() + 300,
        versions: BTreeSet::from([6]),
        families: (1..=7).collect(),
        atomicities: (1..=3).collect(),
        schemes: BTreeSet::from([1]),
    };
    let local_offer = offered(local_domain, remote_domain);
    let remote_offer = offered(remote_domain, local_domain);
    let profile = select_profile(&local_offer, &remote_offer, 6, false).unwrap();
    negotiate(
        &Negotiation {
            deployment: 7,
            local: local_domain,
            remote: remote_domain,
            challenge: 81,
            now: now(),
            floor: 6,
            legacy_allowed: false,
            local_key: key(local).verifying_key().to_bytes(),
            remote_key: key(remote).verifying_key().to_bytes(),
        },
        SignedOffers {
            local: &local_offer,
            remote: &remote_offer,
            local_signature: &key(local).sign(&offer_bytes(&local_offer)).to_bytes(),
            remote_signature: &key(remote).sign(&offer_bytes(&remote_offer)).to_bytes(),
            confirmation: &key(remote)
                .sign(&confirmation_bytes(&local_offer, &remote_offer, &profile))
                .to_bytes(),
        },
    )
    .unwrap()
}

fn signed_at(mut core: Core, signer: u8, issued: u64, ttl: u64) -> Vec<u8> {
    core.issued_seconds = Some(issued);
    core.ttl_seconds = Some(ttl);
    let signature = key(signer).sign(&signing_bytes(&encode_core(&core).unwrap()).unwrap());
    encode_packet(&Packet {
        core: Some(core),
        signature: Some(signature.to_bytes().to_vec()),
    })
    .unwrap()
}

fn credentials<'a, C: AuthorityClock>(
    token: &'a SessionToken,
    packet: &'a Vec<u8>,
) -> WireCredentials<'a, Ed25519Security<C>> {
    WireCredentials {
        token,
        signature: packet,
        maintenance: None,
        endorsement: None,
        previous: None,
        successor: None,
    }
}

fn response(original: &[u8], bytes: &[u8], expected: ResponseCode, position: Option<usize>) {
    let peer = channel(7, 6);
    let boundary = Boundary {
        deployment: 7,
        source: 0,
        target: 0,
        principal: 42,
        key_id: 3,
        epoch: 9,
        route_scope: 1,
        now: now(),
        asset_ttl_floor: 2,
        future_skew: 0,
        max_frame: 1024 * 1024,
        max_nesting: 4,
        version_floor: 6,
        critical_allowed: false,
        public_key: key(6).verifying_key().to_bytes(),
    };
    let original = decode_packet(original, original.len()).unwrap();
    let parsed = admit_response(&peer, &boundary, &original, bytes).unwrap();
    assert_eq!(parsed.code, ResponseStatus::Known(expected));
    assert_eq!(parsed.commit.map(|commit| commit.position), position);
}

#[test]
#[ignore = "requires isolated Linux authority and witness etcd with empty ed25519 keys"]
fn reference_ed25519_live_witness_debit_and_receipt() {
    let base = std::env::temp_dir().join(format!("oip-ed25519-live-{}", std::process::id()));
    fs::create_dir(&base).unwrap();
    let archive = base.join("archive");
    fs::create_dir(&archive).unwrap();
    let writer = WitnessWriter {
        generation: 1,
        identity: [21; 32],
    };
    let anchor = head(&archive, writer);
    let issued = provider();
    let issuer = SessionIssuer::new(key(8));
    let client = issuer.issue(&issued, 7, 2, 300).unwrap();
    let read_only = issuer.issue(&issued, 7, 1, 300).unwrap();
    assert!(
        WitnessAttachmentIssuer::new(key(13))
            .issue(&anchor, true)
            .is_err()
    );
    let path = JournalPath::create();
    let mut file = path.file();
    let attached = attachment(&anchor, provider());
    let wrong = key(13)
        .sign(&anchor.attachment_context(true).signing_bytes().unwrap())
        .to_bytes();
    assert_eq!(
        anchor.prepare_genesis(&mut file, genesis(10, 1), provider(), true, &wrong),
        Err(RecoveryError::AttachmentRejected)
    );
    let cut = anchor
        .prepare_genesis(&mut file, genesis(10, 1), provider(), true, &attached.proof)
        .unwrap();
    let cut_bytes = cut.authorization_message().unwrap();
    assert_eq!(
        anchor.provision_genesis(&cut, &attached.proof, &key(14).sign(&cut_bytes).to_bytes()),
        Err(RecoveryError::AttachmentRejected)
    );
    anchor
        .provision_genesis(&cut, &attached.proof, &key(13).sign(&cut_bytes).to_bytes())
        .unwrap();
    let mut service = PersistentAuthority::open(path.file(), anchor, attached).unwrap();
    let channel_in = channel(6, 7);

    let reserve = signed_at(
        core_with(
            3,
            1,
            0,
            5,
            vec![10, 10, 2, 0, 9, 0, 17, 17, 7, 2, 3, 0, 1, 17, 0, 20],
            vec![uint256(5)],
        ),
        7,
        now(),
        20,
    );
    let mut core = debit_core(1);
    let mut dispatch_words = std::mem::take(&mut operation(&mut core).words);
    dispatch_words[0] = 11;
    dispatch_words[1] = 11;
    let dispatch = signed_at(
        core_with(3, 2, 0, 6, dispatch_words, vec![uint256(5)]),
        7,
        now(),
        20,
    );
    for packet in [&reserve, &dispatch] {
        service
            .receive_wire(
                &channel_in,
                Entry::Normal,
                packet,
                &credentials(&client, packet),
                DeliveryWindow::default(),
            )
            .unwrap();
    }
    let before = service.anchor.current().unwrap();
    let mut wrong_epoch = debit_core(2);
    wrong_epoch.authority_epoch = Some(10);
    let mut wrong_scope = debit_core(2);
    wrong_scope.route_scope = Some(9);
    let mut wrong_key = debit_core(2);
    wrong_key.key_id = Some(5);
    for altered in [wrong_epoch, wrong_scope, wrong_key] {
        let packet = signed_at(altered, 7, now(), 20);
        assert_eq!(
            service.receive_wire(
                &channel_in,
                Entry::Normal,
                &packet,
                &credentials(&client, &packet),
                DeliveryWindow::default()
            ),
            Err(WireError::InvalidSource)
        );
    }
    let mut foreign = debit_core(2);
    foreign.principal = Some(8);
    foreign.key_id = Some(12);
    let foreign = signed_at(foreign, 10, now(), 20);
    assert_eq!(
        service.receive_wire(
            &channel(6, 10),
            Entry::Adapter,
            &foreign,
            &credentials(&client, &foreign),
            DeliveryWindow::default()
        ),
        Err(WireError::InvalidSource)
    );
    let mut no_exec = debit_core(2);
    operation(&mut no_exec).words[2] = 1;
    let no_exec = signed_at(no_exec, 7, now(), 20);
    assert_eq!(
        service.receive_wire(
            &channel_in,
            Entry::ForceInclusion,
            &no_exec,
            &credentials(&read_only, &no_exec),
            DeliveryWindow::default()
        ),
        Err(WireError::ProductRejected)
    );
    let old_packet = signed_at(debit_core(2), 7, now(), 20);
    assert_eq!(
        service.receive_wire(
            &channel_in,
            Entry::Normal,
            &old_packet,
            &credentials(&client, &reserve),
            DeliveryWindow::default()
        ),
        Err(WireError::InvalidSignature)
    );
    let mut invalid_signature = old_packet.clone();
    *invalid_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        service.receive_wire(
            &channel_in,
            Entry::Normal,
            &invalid_signature,
            &credentials(&client, &invalid_signature),
            DeliveryWindow::default()
        ),
        Err(WireError::InvalidSignature)
    );
    let mut control = debit_core(2);
    let mut words = std::mem::take(&mut operation(&mut control).words);
    words.pop();
    words.extend([1, 0]);
    let unsupported = signed_at(
        core_with(
            1,
            2,
            0,
            93,
            words,
            vec![uint256(5), b"unconfigured terminal evidence".to_vec()],
        ),
        7,
        now(),
        20,
    );
    assert_eq!(
        service.receive_wire(
            &channel_in,
            Entry::Normal,
            &unsupported,
            &credentials(&client, &unsupported),
            DeliveryWindow::default()
        ),
        Err(WireError::InvalidSource)
    );
    println!("signed but unsupported terminal evidence was refused without a state change");
    assert_eq!(service.anchor.current().unwrap(), before);

    let issued_at = now();
    let ttl = 6;
    let debit = signed_at(debit_core(2), 7, issued_at, ttl);
    let creds = credentials(&client, &debit);
    let accepted = service
        .receive_wire_response(
            &channel_in,
            Entry::Adapter,
            &debit,
            &creds,
            DeliveryWindow::default(),
        )
        .unwrap();
    response(&debit, &accepted, ResponseCode::Debited, Some(2));
    let selected = service.anchor.current().unwrap();
    let retry = service
        .receive_wire_response(
            &channel_in,
            Entry::Normal,
            &debit,
            &creds,
            DeliveryWindow::default(),
        )
        .unwrap();
    response(&debit, &retry, ResponseCode::Debited, Some(2));
    assert_eq!(service.anchor.current().unwrap(), selected);

    let denied = signed_at(
        core_with(4, 1, 0, 91, vec![1, 3, 1, 17], Vec::new()),
        7,
        now(),
        20,
    );
    assert_eq!(
        service.receive_wire(
            &channel_in,
            Entry::Normal,
            &denied,
            &credentials(&read_only, &denied),
            DeliveryWindow::default()
        ),
        Err(WireError::ProductRejected)
    );
    assert_eq!(service.anchor.current().unwrap(), selected);
    let journal = signed_at(core_with(4, 5, 0, 92, vec![1], Vec::new()), 7, now(), 20);
    assert!(
        matches!(service.receive_wire(&channel_in, Entry::Normal, &journal,
        &credentials(&read_only, &journal), DeliveryWindow::default()).unwrap().reply,
        WireReply::Observation(Observation::Journal(ids)) if ids.len() == 3 && ids.iter().all(|id| id.namespace == 7))
    );

    while now() <= issued_at + ttl {
        std::thread::sleep(Duration::from_millis(100));
    }
    let expired = service
        .receive_wire_response(
            &channel_in,
            Entry::Normal,
            &debit,
            &creds,
            DeliveryWindow::default(),
        )
        .unwrap();
    response(&debit, &expired, ResponseCode::TtlExpired, None);
    let resolved = service
        .resolve_wire_debit_response(&channel_in, &debit, &creds, false)
        .unwrap();
    response(&debit, &resolved, ResponseCode::Debited, Some(2));
    println!(
        "actual current Ed25519 ingress, denial, expired original and exact Debited receipt verified"
    );

    let mut changed = actual_config();
    changed
        .peers
        .get_mut(&7)
        .unwrap()
        .sessions
        .get_mut(&1)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .current
        .clear();
    let changed = Ed25519Security::new(changed, key(6), SystemClock).unwrap();
    let same_writer = head(&archive, writer);
    let attached = attachment(&same_writer, changed);
    assert!(matches!(
        PersistentAuthority::open(path.file(), same_writer, attached),
        Err(RecoveryError::AttachmentRejected)
    ));
    let same_writer = head(&archive, writer);
    let mut next_epoch = actual_config();
    next_epoch.authority_epoch = 10;
    let attached = attachment(
        &same_writer,
        Ed25519Security::new(next_epoch, key(6), SystemClock).unwrap(),
    );
    assert!(matches!(
        PersistentAuthority::open(path.file(), same_writer, attached),
        Err(RecoveryError::AttachmentRejected)
    ));

    let replacement = head(
        &archive,
        WitnessWriter {
            generation: 2,
            identity: [22; 32],
        },
    );
    let attached = attachment(&replacement, provider());
    let restored = base.join("restored.records");
    let cut = replacement
        .repair_cut(&restored, true, &attached.proof)
        .unwrap();
    let cut_bytes = cut.authorization_message().unwrap();
    assert!(
        replacement
            .repair_from_archive(&cut, &attached.proof, &key(13).sign(&cut_bytes).to_bytes())
            .is_err()
    );
    assert!(!restored.exists());
    replacement
        .repair_from_archive(&cut, &attached.proof, &key(14).sign(&cut_bytes).to_bytes())
        .unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&restored)
        .unwrap();
    let mut repaired = PersistentAuthority::open(file, replacement, attached).unwrap();
    let resolved = repaired
        .resolve_wire_debit_response(&channel_in, &debit, &creds, false)
        .unwrap();
    response(&debit, &resolved, ResponseCode::Debited, Some(2));
    assert!(repaired.anchor.revoke(7).unwrap());
    let refused = repaired
        .resolve_wire_debit_response(&channel_in, &debit, &creds, false)
        .unwrap();
    response(&debit, &refused, ResponseCode::InvalidSource, None);
    println!(
        "same-epoch and wrong-epoch provider substitution held; distinct repair signer worked; selected revocation fenced receipt"
    );
    drop(repaired);
    drop(service);
    fs::remove_dir_all(base).unwrap();
}

mod terminal;

mod regulatory;
mod sync;

#[cfg(target_os = "linux")]
mod handover;
