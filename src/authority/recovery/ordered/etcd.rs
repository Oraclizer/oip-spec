//! Pinned etcdctl transport for a single, explicitly authenticated control key.

use super::{ControlStore, ControlValue, HeadError, RecoveryProfile};
use prost::Message;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

const PIN: &str = "39cdb8f2ebd12f680e0b7b8d724fe1159644d5939725977e32381ab6bf85ced3";
const RESPONSE_OVERHEAD: usize = 4096;

pub struct EtcdConfig {
    /// Absolute path to the trusted etcdctl 3.7.3 Linux amd64 binary.
    pub executable: PathBuf,
    #[cfg(windows)]
    pub wsl_distribution: String,
    /// One fixed HTTPS endpoint. The server certificate must identify this address.
    pub endpoint: SocketAddr,
    pub cluster_id: u64,
    pub key: String,
    /// Absolute Linux paths, including when the command runs through WSL.
    pub ca_cert: String,
    pub client_cert: String,
    pub client_key: String,
    pub dial_timeout: Duration,
    pub rpc_timeout: Duration,
    pub process_timeout: Duration,
    pub max_control_bytes: usize,
}

pub struct EtcdTransport {
    program: PathBuf,
    args: Vec<OsString>,
    key: String,
    cluster_id: u64,
    endpoint: SocketAddr,
    tls_paths: [String; 3],
    #[cfg(target_os = "linux")]
    trust: TrustIdentity,
    timeout: Duration,
    max_control_bytes: usize,
}

impl EtcdTransport {
    /// Establish the configured transport. Files and the Linux execution
    /// environment belong to the trusted authority host.
    pub fn new(config: EtcdConfig) -> Result<Self, HeadError> {
        if !valid_key(&config.key)
            || config.cluster_id == 0
            || config.endpoint.port() == 0
            || config.endpoint.ip().is_unspecified()
            || config.endpoint.ip().is_multicast()
            || config.process_timeout.is_zero()
            || !valid_tls_paths([&config.ca_cert, &config.client_cert, &config.client_key])
            || config.max_control_bytes == 0
        {
            return Err(HeadError);
        }
        let dial_timeout = timeout_arg(config.dial_timeout)?;
        let rpc_timeout = timeout_arg(config.rpc_timeout)?;
        let send_limit = config
            .max_control_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(RESPONSE_OVERHEAD))
            .ok_or(HeadError)?;
        // The pinned CLI requires its gRPC receive limit to exceed its send
        // limit. The child stdout reader still enforces the smaller reply cap.
        let receive_limit = send_limit.checked_add(1).ok_or(HeadError)?;
        if receive_limit > i32::MAX as usize {
            return Err(HeadError);
        }
        let executable = pinned_executable(&config.executable)?;
        let (program, mut args) = launch(&config, executable)?;
        args.extend([
            format!("--endpoints=https://{}", config.endpoint).into(),
            "--insecure-transport=false".into(),
            "--insecure-skip-tls-verify=false".into(),
            format!("--cacert={}", config.ca_cert).into(),
            format!("--cert={}", config.client_cert).into(),
            format!("--key={}", config.client_key).into(),
            format!("--dial-timeout={dial_timeout}").into(),
            format!("--command-timeout={rpc_timeout}").into(),
            format!("--max-recv-bytes={receive_limit}").into(),
            format!("--max-request-bytes={send_limit}").into(),
            "--write-out=protobuf".into(),
        ]);
        let tls_paths = [config.ca_cert, config.client_cert, config.client_key];
        #[cfg(target_os = "linux")]
        let trust = TrustIdentity::read(&tls_paths)?;
        Ok(Self {
            program,
            args,
            key: config.key,
            cluster_id: config.cluster_id,
            endpoint: config.endpoint,
            tls_paths,
            #[cfg(target_os = "linux")]
            trust,
            timeout: config.process_timeout,
            max_control_bytes: config.max_control_bytes,
        })
    }

    pub(super) fn independent_of(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.cluster_id != other.cluster_id
                && self.endpoint != other.endpoint
                && self
                    .trust
                    .paths
                    .iter()
                    .all(|path| !other.trust.paths.contains(path))
                && self
                    .trust
                    .digests
                    .iter()
                    .all(|digest| !other.trust.digests.contains(digest))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = other;
            false
        }
    }

    pub(in crate::authority::recovery) fn distinct_source_stores(&self, other: &Self) -> bool {
        self.key != other.key && self.independent_of(other)
    }

    pub(in crate::authority::recovery) fn supports_source_value(&self, length: usize) -> bool {
        length <= self.max_control_bytes
    }

    /// Bind the storage resource shared by independently issued reader and
    /// writer credentials. The server trust and exact key remain fixed.
    pub(in crate::authority::recovery) fn source_store_binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"oip/etcd-source-store/v1\0");
        hash.update(self.cluster_id.to_be_bytes());
        let endpoint = self.endpoint.to_string();
        for field in [&endpoint, &self.key] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        #[cfg(target_os = "linux")]
        hash.update(self.trust.digests[0]);
        hash.finalize().into()
    }

    pub(super) fn attachment_binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"oip/etcd-attachment/v1\0");
        hash.update(self.cluster_id.to_be_bytes());
        let endpoint = self.endpoint.to_string();
        for field in [
            &endpoint,
            &self.key,
            &self.tls_paths[0],
            &self.tls_paths[1],
            &self.tls_paths[2],
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        #[cfg(target_os = "linux")]
        for digest in self.trust.digests {
            hash.update(digest);
        }
        hash.finalize().into()
    }

    /// Read one current, linearizable control value. Missing keys fail closed.
    pub fn current(&self) -> Result<ControlValue, HeadError> {
        let stdout = self.run(&["get", "--consistency=l", "--", &self.key], None)?;
        range_value(
            &stdout,
            self.cluster_id,
            self.key.as_bytes(),
            self.max_control_bytes,
        )
    }

    /// Compare the exact previous value and per-key MOD in one transaction.
    /// A false result means the server reported a definite comparison failure.
    /// Any command or confirmation error may be ambiguous.
    pub fn replace(&self, expected: &ControlValue, candidate: &[u8]) -> Result<bool, HeadError> {
        if expected.revision == 0
            || expected.revision > i64::MAX as u64
            || expected.bytes.len() > self.max_control_bytes
            || candidate.len() > self.max_control_bytes
        {
            return Err(HeadError);
        }
        // Bind the configured endpoint before writing. The dedicated TLS
        // identity also applies to the separate connection used by the CAS.
        self.current()?;
        let input = compare_input(&self.key, expected, candidate);
        let stdout = self.run(&["txn"], Some(input))?;
        let Some(revision) = txn_revision(&stdout, self.cluster_id, expected.revision)? else {
            return Ok(false);
        };
        require_readback(self.current()?, revision, candidate)?;
        Ok(true)
    }

    fn run(&self, operation: &[&str], input: Option<Vec<u8>>) -> Result<Vec<u8>, HeadError> {
        #[cfg(target_os = "linux")]
        if TrustIdentity::read(&self.tls_paths)? != self.trust {
            return Err(HeadError);
        }
        let deadline = Instant::now().checked_add(self.timeout).ok_or(HeadError)?;
        let mut command = Command::new(&self.program);
        // Host configuration supplies every etcd option. In particular a
        // process environment must not override the endpoint or TLS policy.
        for (key, _) in std::env::vars_os() {
            if key
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("ETCDCTL_")
            {
                command.env_remove(key);
            }
        }
        #[cfg(windows)]
        command.env_remove("WSLENV");
        let mut child = command
            .args(&self.args)
            .args(operation)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| HeadError)?;
        let result = child_output(
            &mut child,
            input,
            self.max_control_bytes + RESPONSE_OVERHEAD,
            deadline,
        );
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}

/// Supplied by the host's authenticated direct-mode attachment policy.
/// A profile requiring an independent witness cannot use this verifier.
pub trait DirectAttachmentVerifier {
    type Proof;

    fn verify_direct_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &Self::Proof,
    ) -> bool;
}

/// The raw transport can also be used by a separate independent witness.
/// This attachment wrapper serves only an explicitly authorized direct profile.
pub struct EtcdControlStore<A> {
    transport: EtcdTransport,
    profile: RecoveryProfile,
    attachment: A,
}

impl<A: DirectAttachmentVerifier> EtcdControlStore<A> {
    pub fn new(transport: EtcdTransport, profile: RecoveryProfile, attachment: A) -> Self {
        Self {
            transport,
            profile,
            attachment,
        }
    }
}

impl<A: DirectAttachmentVerifier> ControlStore for EtcdControlStore<A> {
    type AttachmentProof = A::Proof;

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        connected: bool,
        proof: &Self::AttachmentProof,
    ) -> bool {
        self.profile == profile
            && self
                .attachment
                .verify_direct_attachment(profile, connected, proof)
    }

    fn current(&self) -> Result<ControlValue, HeadError> {
        self.transport.current()
    }

    fn replace(&self, expected: &ControlValue, candidate: &[u8]) -> Result<bool, HeadError> {
        self.transport.replace(expected, candidate)
    }
}

#[cfg(target_os = "linux")]
#[derive(Eq, PartialEq)]
struct TrustIdentity {
    paths: [PathBuf; 3],
    digests: [[u8; 32]; 3],
}

#[cfg(target_os = "linux")]
impl TrustIdentity {
    fn read(configured: &[String; 3]) -> Result<Self, HeadError> {
        let mut paths = [PathBuf::new(), PathBuf::new(), PathBuf::new()];
        let mut digests = [[0; 32]; 3];
        for ((path, digest), configured) in paths.iter_mut().zip(&mut digests).zip(configured) {
            *path = fs::canonicalize(configured).map_err(|_| HeadError)?;
            let mut file = fs::File::open(&path).map_err(|_| HeadError)?;
            if !file.metadata().map_err(|_| HeadError)?.is_file() {
                return Err(HeadError);
            }
            let mut hash = Sha256::new();
            let bytes = std::io::copy(&mut file, &mut hash).map_err(|_| HeadError)?;
            if bytes == 0 {
                return Err(HeadError);
            }
            *digest = hash.finalize().into();
        }
        Ok(Self { paths, digests })
    }
}

fn valid_key(key: &str) -> bool {
    key.starts_with('/')
        && key.len() > 1
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._".contains(&b))
        && key[1..]
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

fn valid_tls_paths(paths: [&str; 3]) -> bool {
    paths[0] != paths[1]
        && paths[0] != paths[2]
        && paths[1] != paths[2]
        && paths.into_iter().all(|path| {
            path.starts_with('/')
                && path.len() > 1
                && !path.chars().any(char::is_control)
                && path[1..]
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | ".."))
        })
}

fn timeout_arg(duration: Duration) -> Result<String, HeadError> {
    if duration.as_millis() == 0 || duration.as_nanos() > i64::MAX as u128 {
        return Err(HeadError);
    }
    Ok(format!("{}ms", duration.as_millis()))
}

fn pinned_executable(path: &Path) -> Result<PathBuf, HeadError> {
    if !path.is_absolute() {
        return Err(HeadError);
    }
    let path = fs::canonicalize(path).map_err(|_| HeadError)?;
    let expected = crate::wire::legacy::unhex(PIN).map_err(|_| HeadError)?;
    let mut file = fs::File::open(&path).map_err(|_| HeadError)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 16 * 1024];
    loop {
        let count = file.read(&mut bytes).map_err(|_| HeadError)?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
    }
    if hash.finalize().as_slice() != expected {
        return Err(HeadError);
    }
    Ok(path)
}

#[cfg(not(windows))]
fn launch(_: &EtcdConfig, executable: PathBuf) -> Result<(PathBuf, Vec<OsString>), HeadError> {
    Ok((executable, Vec::new()))
}

#[cfg(windows)]
fn launch(config: &EtcdConfig, executable: PathBuf) -> Result<(PathBuf, Vec<OsString>), HeadError> {
    use std::path::{Component, Prefix};
    let distribution = &config.wsl_distribution;
    if distribution.is_empty()
        || distribution.starts_with('-')
        || !distribution
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(HeadError);
    }
    let mut components = executable.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(HeadError);
    };
    let (Prefix::Disk(drive) | Prefix::VerbatimDisk(drive)) = prefix.kind() else {
        return Err(HeadError);
    };
    if components.next() != Some(Component::RootDir) {
        return Err(HeadError);
    }
    let mut linux_path = format!("/mnt/{}", char::from(drive.to_ascii_lowercase()));
    for component in components {
        let Component::Normal(part) = component else {
            return Err(HeadError);
        };
        linux_path.push('/');
        linux_path.push_str(part.to_str().ok_or(HeadError)?);
    }
    Ok((
        PathBuf::from(r"C:\Windows\System32\wsl.exe"),
        vec![
            "--distribution".into(),
            distribution.into(),
            "--exec".into(),
            linux_path.into(),
        ],
    ))
}

fn wait_for<T>(rx: &Receiver<T>, deadline: Instant) -> Result<T, HeadError> {
    rx.recv_timeout(
        deadline
            .checked_duration_since(Instant::now())
            .ok_or(HeadError)?,
    )
    .map_err(|_| HeadError)
}

fn child_output(
    child: &mut Child,
    input: Option<Vec<u8>>,
    output_limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, HeadError> {
    let stdout = child.stdout.take().ok_or(HeadError)?;
    let (output_tx, output_rx) = sync_channel(1);
    thread::Builder::new()
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take((output_limit + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = output_tx.send(result);
        })
        .map_err(|_| HeadError)?;
    let input_rx = if let Some(input) = input {
        let mut stdin = child.stdin.take().ok_or(HeadError)?;
        let (input_tx, input_rx) = sync_channel(1);
        thread::Builder::new()
            .spawn(move || {
                let result = stdin.write_all(&input);
                drop(stdin);
                let _ = input_tx.send(result);
            })
            .map_err(|_| HeadError)?;
        Some(input_rx)
    } else {
        None
    };
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(HeadError)?;
        if let Some(status) = child.try_wait().map_err(|_| HeadError)? {
            if !status.success() {
                return Err(HeadError);
            }
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(2)));
    }
    if let Some(input_rx) = input_rx {
        wait_for(&input_rx, deadline)?.map_err(|_| HeadError)?;
    }
    let bytes = wait_for(&output_rx, deadline)?.map_err(|_| HeadError)?;
    if bytes.is_empty() || bytes.len() > output_limit {
        return Err(HeadError);
    }
    Ok(bytes)
}

// Both Compare and Put use Go %q in the pinned client. Escape by byte so that
// CR/LF, NUL, quoting characters and non-UTF-8 data survive stdin exactly.
fn quoted(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    text.push('"');
    for &byte in raw {
        match byte {
            b'"' | b'\\' => {
                text.push('\\');
                text.push(char::from(byte));
            }
            32..=126 => text.push(char::from(byte)),
            _ => write!(text, "\\x{byte:02x}").expect("writing to a String cannot fail"),
        }
    }
    text.push('"');
    text
}

fn compare_input(key: &str, expected: &ControlValue, candidate: &[u8]) -> Vec<u8> {
    let key = quoted(key.as_bytes());
    let revision = quoted(expected.revision.to_string().as_bytes());
    format!(
        "mod({key}) = {revision}\nvalue({key}) = {}\n\nput {key} {}\n\n\n",
        quoted(&expected.bytes),
        quoted(candidate),
    )
    .into_bytes()
}

// Selected fields of the official etcd v3.7.3 responses emitted by
// etcdctl --write-out=protobuf. Keep storage bytes opaque to this transport.
#[derive(Message)]
struct Header {
    #[prost(uint64, tag = "1")]
    cluster_id: u64,
    #[prost(uint64, tag = "2")]
    member_id: u64,
    #[prost(int64, tag = "3")]
    revision: i64,
}

#[derive(Message)]
struct Kv {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(int64, tag = "3")]
    mod_revision: i64,
    #[prost(bytes = "vec", tag = "5")]
    value: Vec<u8>,
}

#[derive(Message)]
struct RangeResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<Header>,
    #[prost(message, repeated, tag = "2")]
    kvs: Vec<Kv>,
    #[prost(bool, tag = "3")]
    more: bool,
    #[prost(int64, tag = "4")]
    count: i64,
}

#[derive(Message)]
struct TxnResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<Header>,
    #[prost(bool, tag = "2")]
    succeeded: bool,
    #[prost(message, repeated, tag = "3")]
    responses: Vec<ResponseOp>,
}

#[derive(Message)]
struct ResponseOp {
    #[prost(bytes = "vec", optional, tag = "1")]
    range: Option<Vec<u8>>,
    #[prost(message, optional, tag = "2")]
    put: Option<PutResponse>,
    #[prost(bytes = "vec", optional, tag = "3")]
    delete: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    txn: Option<Vec<u8>>,
}

#[derive(Message)]
struct PutResponse {
    #[prost(message, optional, tag = "1")]
    header: Option<Header>,
    #[prost(message, optional, tag = "2")]
    prev_kv: Option<Kv>,
}

fn require_readback(
    observed: ControlValue,
    expected_revision: u64,
    expected_bytes: &[u8],
) -> Result<(), HeadError> {
    if observed.revision != expected_revision || observed.bytes != expected_bytes {
        return Err(HeadError);
    }
    Ok(())
}

fn verified_revision(header: Option<Header>, cluster: u64) -> Result<u64, HeadError> {
    let header = header.ok_or(HeadError)?;
    if header.cluster_id != cluster || header.member_id == 0 || header.revision <= 0 {
        return Err(HeadError);
    }
    Ok(header.revision as u64)
}

fn range_value(
    bytes: &[u8],
    cluster: u64,
    key: &[u8],
    max: usize,
) -> Result<ControlValue, HeadError> {
    let response = RangeResponse::decode(bytes).map_err(|_| HeadError)?;
    let revision = verified_revision(response.header, cluster)?;
    if response.more || response.count != 1 || response.kvs.len() != 1 {
        return Err(HeadError);
    }
    let kv = response.kvs.into_iter().next().ok_or(HeadError)?;
    if kv.key != key
        || kv.mod_revision <= 0
        || kv.mod_revision as u64 > revision
        || kv.value.len() > max
    {
        return Err(HeadError);
    }
    Ok(ControlValue {
        revision: kv.mod_revision as u64,
        bytes: kv.value,
    })
}

fn txn_revision(bytes: &[u8], cluster: u64, expected: u64) -> Result<Option<u64>, HeadError> {
    let response = TxnResponse::decode(bytes).map_err(|_| HeadError)?;
    let revision = verified_revision(response.header, cluster)?;
    match (response.succeeded, response.responses.as_slice()) {
        (false, []) => Ok(None),
        (
            true,
            [
                ResponseOp {
                    range: None,
                    put: Some(put),
                    delete: None,
                    txn: None,
                },
            ],
        ) if revision > expected && put.prev_kv.is_none() => {
            if let Some(header) = &put.header {
                // etcd may omit the nested header or populate only its revision.
                if (header.cluster_id != 0 && header.cluster_id != cluster)
                    || (header.revision != 0 && header.revision as u64 != revision)
                {
                    return Err(HeadError);
                }
            }
            Ok(Some(revision))
        }
        _ => Err(HeadError),
    }
}

#[cfg(test)]
mod vector_tests;
