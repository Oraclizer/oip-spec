use super::*;
use crate::authority::recovery::ordered::{OrderedHead, WireControl};
use std::convert::Infallible;

const KEY: &str = "/oraclizer/isolated-control";
const INITIAL: &[u8] = b"before \"quoted\" \\ \r\n\0\xff";
const CHANGED: &[u8] = b"after \"quoted\" \\ \n\r\t\0\xc3\xa9\x80\xff";
const LOST_REPLY: &[u8] = b"after write with lost reply \n\0\xfe";

fn header(cluster: u64, revision: i64) -> Header {
    Header {
        cluster_id: cluster,
        member_id: 7,
        revision,
    }
}

fn range() -> RangeResponse {
    RangeResponse {
        header: Some(header(42, 12)),
        kvs: vec![Kv {
            key: KEY.as_bytes().to_vec(),
            mod_revision: 9,
            value: CHANGED.to_vec(),
        }],
        more: false,
        count: 1,
    }
}

#[test]
fn etcd_transport_preserves_bytes_and_rejects_untrusted_range() {
    let result = range_value(&range().encode_to_vec(), 42, KEY.as_bytes(), 256).unwrap();
    assert_eq!(result.revision, 9);
    assert_eq!(result.bytes, CHANGED);

    let mut response = range();
    response.kvs[0].key = b"/different".to_vec();
    assert!(range_value(&response.encode_to_vec(), 42, KEY.as_bytes(), 256).is_err());
    let mut response = range();
    response.kvs[0].mod_revision = 13;
    assert!(range_value(&response.encode_to_vec(), 42, KEY.as_bytes(), 256).is_err());
    response.kvs[0].mod_revision = -1;
    assert!(range_value(&response.encode_to_vec(), 42, KEY.as_bytes(), 256).is_err());
    assert!(range_value(&range().encode_to_vec(), 43, KEY.as_bytes(), 256).is_err());
    assert!(range_value(&range().encode_to_vec(), 42, KEY.as_bytes(), 1).is_err());
    assert!(range_value(&[0xff], 42, KEY.as_bytes(), 256).is_err());

    let mut response = range();
    response.kvs.clear();
    response.count = 0;
    assert!(range_value(&response.encode_to_vec(), 42, KEY.as_bytes(), 256).is_err());
}

fn success() -> TxnResponse {
    TxnResponse {
        header: Some(header(42, 10)),
        succeeded: true,
        responses: vec![ResponseOp {
            put: Some(PutResponse {
                header: None,
                prev_kv: None,
            }),
            ..ResponseOp::default()
        }],
    }
}

#[test]
fn etcd_transport_distinguishes_definite_failure_and_ambiguity() {
    let committed = success();
    assert_eq!(
        txn_revision(&committed.encode_to_vec(), 42, 9),
        Ok(Some(10))
    );
    assert!(txn_revision(&committed.encode_to_vec(), 43, 9).is_err());
    assert!(txn_revision(&committed.encode_to_vec(), 42, 10).is_err());

    let mut refused = success();
    refused.succeeded = false;
    assert!(txn_revision(&refused.encode_to_vec(), 42, 9).is_err());
    refused.responses.clear();
    assert_eq!(txn_revision(&refused.encode_to_vec(), 42, 9), Ok(None));

    let mut forged = success();
    forged.responses[0].range = Some(Vec::new());
    assert!(txn_revision(&forged.encode_to_vec(), 42, 9).is_err());
    let mut forged = success();
    forged.responses[0].put.as_mut().unwrap().header = Some(header(43, 10));
    assert!(txn_revision(&forged.encode_to_vec(), 42, 9).is_err());
    assert!(txn_revision(&[], 42, 9).is_err());
    assert!(txn_revision(&[0xff], 42, 9).is_err());

    let value = ControlValue {
        revision: 10,
        bytes: CHANGED.to_vec(),
    };
    assert!(require_readback(value.clone(), 10, CHANGED).is_ok());
    assert!(require_readback(value.clone(), 11, CHANGED).is_err());
    assert!(require_readback(value, 10, INITIAL).is_err());
}

#[test]
fn etcd_transport_escapes_a_single_transaction_and_pins_the_program() {
    let expected = ControlValue {
        revision: 10,
        bytes: b"\"\\\n\0\xff".to_vec(),
    };
    let input = String::from_utf8(compare_input(KEY, &expected, b"")).unwrap();
    assert_eq!(
        input.lines().collect::<Vec<_>>(),
        [
            r#"mod("/oraclizer/isolated-control") = "10""#,
            r#"value("/oraclizer/isolated-control") = "\"\\\x0a\x00\xff""#,
            "",
            r#"put "/oraclizer/isolated-control" """#,
            "",
            "",
        ],
    );
    assert!(!valid_key("/some/../other"));
    assert!(!valid_key("/some\n/other"));
    assert!(!valid_tls_paths(["/ca.pem", "/same.pem", "/same.pem"]));
    assert!(pinned_executable(&std::env::current_exe().unwrap()).is_err());
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing isolated etcd fixture {name}"))
}

fn live_config() -> EtcdConfig {
    EtcdConfig {
        executable: PathBuf::from(env("OIP_ETCDCTL_PIN")),
        #[cfg(windows)]
        wsl_distribution: env("OIP_ETCD_DISTRO"),
        endpoint: env("OIP_ETCD_ENDPOINT").parse().unwrap(),
        cluster_id: env("OIP_ETCD_CLUSTER").parse().unwrap(),
        key: KEY.into(),
        ca_cert: env("OIP_ETCD_CA"),
        client_cert: env("OIP_ETCD_CLIENT_CERT"),
        client_key: env("OIP_ETCD_CLIENT_KEY"),
        dial_timeout: Duration::from_secs(2),
        rpc_timeout: Duration::from_secs(2),
        process_timeout: Duration::from_secs(10),
        max_control_bytes: 65536,
    }
}

// Tests the store with an uninhabited attachment proof. The fixture opens
// no endpoint through this policy.
struct NoAttachment;

impl DirectAttachmentVerifier for NoAttachment {
    type Proof = Infallible;

    fn verify_direct_attachment(&self, _: RecoveryProfile, _: bool, proof: &Infallible) -> bool {
        match *proof {}
    }
}

#[test]
#[ignore = "requires dedicated isolated mTLS etcd and provisioned transport fixture"]
fn etcd_transport_live_exact_cas() {
    let transport = EtcdTransport::new(live_config()).unwrap();
    let initial = transport.current().unwrap();
    assert_eq!(initial.bytes, INITIAL);

    let mut wrong_revision = initial.clone();
    wrong_revision.revision += 1;
    assert_eq!(transport.replace(&wrong_revision, CHANGED), Ok(false));
    let mut wrong_value = initial.clone();
    wrong_value.bytes[0] ^= 1;
    assert_eq!(transport.replace(&wrong_value, CHANGED), Ok(false));
    assert!(transport.current().unwrap() == initial);

    let mut foreign = live_config();
    foreign.cluster_id ^= 1;
    assert!(
        EtcdTransport::new(foreign)
            .unwrap()
            .replace(&initial, CHANGED)
            .is_err()
    );
    let mut wrong_server = live_config();
    wrong_server.ca_cert = env("OIP_ETCD_WRONG_CA");
    assert!(
        EtcdTransport::new(wrong_server)
            .unwrap()
            .replace(&initial, CHANGED)
            .is_err()
    );
    let mut wrong_client = live_config();
    wrong_client.client_cert = env("OIP_ETCD_WRONG_CLIENT_CERT");
    wrong_client.client_key = env("OIP_ETCD_WRONG_CLIENT_KEY");
    assert!(
        EtcdTransport::new(wrong_client)
            .unwrap()
            .replace(&initial, CHANGED)
            .is_err()
    );
    let mut tiny_timeout = live_config();
    tiny_timeout.process_timeout = Duration::from_nanos(1);
    assert!(
        EtcdTransport::new(tiny_timeout)
            .unwrap()
            .replace(&initial, CHANGED)
            .is_err()
    );
    assert!(transport.current().unwrap() == initial);
    println!(
        "wrong MOD, VALUE, cluster, TLS server and client identities, and tiny timeout left the initial key intact"
    );

    assert_eq!(transport.replace(&initial, CHANGED), Ok(true));
    let changed = transport.current().unwrap();
    assert_eq!(changed.bytes, CHANGED);
    assert!(changed.revision > initial.revision);

    // Commit once, then discard the command reply at the adapter boundary.
    // An independent current read can recover the exact value.
    let discarded = transport
        .run(&["txn"], Some(compare_input(KEY, &changed, LOST_REPLY)))
        .unwrap();
    let actual_revision = txn_revision(&discarded, transport.cluster_id, changed.revision)
        .unwrap()
        .unwrap();
    drop(discarded);
    assert!(txn_revision(&[], transport.cluster_id, changed.revision).is_err());
    require_readback(transport.current().unwrap(), actual_revision, LOST_REPLY).unwrap();
    let recovered = transport.current().unwrap();
    assert_eq!(transport.replace(&recovered, CHANGED), Ok(true));
    assert!(require_readback(transport.current().unwrap(), actual_revision, LOST_REPLY).is_err());
    println!(
        "arbitrary escaped bytes round-tripped; lost reply resolved by exact read; changed readback held"
    );

    let profile = RecoveryProfile {
        deployment: 7,
        format: 1,
        authority_profile: 99,
    };
    let old_bytes =
        OrderedHead::<EtcdControlStore<NoAttachment>>::initial_value(profile, None, 1).unwrap();
    let current = transport.current().unwrap();
    assert_eq!(transport.replace(&current, &old_bytes), Ok(true));
    let writer = OrderedHead::new(
        EtcdControlStore::new(transport, profile, NoAttachment),
        profile,
        1,
    );
    assert!(writer.rotate_writer(2).unwrap());
    assert!(writer.observe().is_err());
    assert!(writer.revoke(7).is_err());
    let new_writer = OrderedHead::new(
        EtcdControlStore::new(
            EtcdTransport::new(live_config()).unwrap(),
            profile,
            NoAttachment,
        ),
        profile,
        2,
    );
    assert!(new_writer.observe().is_ok());
    println!("actual ordered control rotation fenced the prior writer");
}
