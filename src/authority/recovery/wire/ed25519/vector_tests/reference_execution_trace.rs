//! Isolated test-only observations; production gates/results are called directly.
use super::*;
use crate::authority::identity::{Action, ActionReply, Entry, Receipt};
use crate::authority::reads::{CheckedExecution, Query};
use crate::authority::recovery::ordered::{ControlStore, ControlValue, OrderedHead};
use crate::authority::recovery::vector_tests::{JournalPath, binding};
use crate::authority::recovery::wire::response::{ResponseStatus, admit_response};
use crate::authority::recovery::wire::vector_tests::{core_with, uint256};
use crate::authority::recovery::wire::{DebitResult, DeliveryWindow, WireCredentials, WireSecurity};
use crate::authority::recovery::{Attachment, AuthenticatedHead, HeadError, PersistentAuthority, RetainedImage};
use crate::authority::{Collection, OutcomeReply};
use crate::wire::admission::TransportKey;
use crate::wire::codec::encode_core;
use crate::wire::negotiation::{Negotiation, Offer, SignedOffers, confirmation_bytes, negotiate, offer_bytes, select_profile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn digest(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }

#[derive(Clone)]
pub(in crate::authority::recovery::wire::ed25519) struct Clock(Arc<AtomicU64>, Arc<Mutex<Vec<u64>>>);
impl AuthorityClock for Clock {
    fn unix_seconds(&self) -> Option<u64> { let now = self.0.load(Ordering::SeqCst); self.1.lock().ok()?.push(now); Some(now) }
}

// The external-store boundary is the existing MemoryControl exact-CAS fixture
// contract: revision + exact bytes equality, one local physical increment.
// All OrderedHead policy, Debit decisions and publication code remain production.
#[derive(Clone)]
pub(in crate::authority::recovery::wire::ed25519) struct Control {
    value: Arc<Mutex<ControlValue>>,
    trace: Arc<Mutex<Vec<Value>>>,
}
fn control_value(value: &ControlValue) -> Value {
    json!({"physical_revision":value.revision,"bytes_hex":hex(&value.bytes),
           "bytes_sha256":digest(&value.bytes),"decoded":serde_json::from_slice::<Value>(&value.bytes).unwrap()})
}
impl ControlStore for Control {
    type AttachmentProof = (RecoveryProfile, bool);
    fn verify_attachment(&self, profile: RecoveryProfile, connected: bool, proof: &Self::AttachmentProof) -> bool {
        (profile, connected) == *proof
    }
    fn current(&self) -> Result<ControlValue, HeadError> {
        let value = self.value.lock().map_err(|_| HeadError)?.clone();
        self.trace.lock().map_err(|_| HeadError)?.push(json!({"api":"current","observed":control_value(&value)}));
        Ok(value)
    }
    fn replace(&self, expected: &ControlValue, candidate: &[u8]) -> Result<bool, HeadError> {
        let mut value = self.value.lock().map_err(|_| HeadError)?;
        let before = value.clone();
        let changed = *value == *expected;
        if changed {
            value.revision += 1;
            value.bytes = candidate.to_vec();
        }
        self.trace.lock().map_err(|_| HeadError)?.push(json!({"api":"replace","expected":control_value(expected),
            "observed":control_value(&before),"candidate_hex":hex(candidate),"changed":changed,"after":control_value(&value)}));
        Ok(changed)
    }
}
pub(in crate::authority::recovery::wire::ed25519) type Service = PersistentAuthority<Ed25519Security<Clock>, OrderedHead<Control>>;

struct Recorder { observations: File }
impl Recorder {
    fn observation(&mut self, id: &str, phase: &str, value: Value) {
        serde_json::to_writer(&mut self.observations,
            &json!({"schema":"oip-reference-observation-v2","id":id,"phase":phase,"observation":value})).unwrap();
        self.observations.write_all(b"\n").unwrap();
        self.observations.flush().unwrap();
        self.observations.sync_all().unwrap();
    }
}

pub(super) fn channel_for(local: u8, remote: u8) -> Channel {
    let offered = || Offer {
        deployment:7, sender:0, receiver:0, challenge:3, expires:200,
        versions:BTreeSet::from([6]), families:(1..=7).collect(),
        atomicities:(1..=3).collect(), schemes:BTreeSet::from([1]),
    };
    let local_offer = offered();
    let remote_offer = offered();
    let profile = select_profile(&local_offer, &remote_offer, 6, false).unwrap();
    negotiate(&Negotiation { deployment:7,local:0,remote:0,challenge:3,now:105,floor:6,legacy_allowed:false,
        local_key:key(local).verifying_key().to_bytes(),remote_key:key(remote).verifying_key().to_bytes() },
        SignedOffers { local:&local_offer,remote:&remote_offer,
            local_signature:&key(local).sign(&offer_bytes(&local_offer)).to_bytes(),
            remote_signature:&key(remote).sign(&offer_bytes(&remote_offer)).to_bytes(),
            confirmation:&key(remote).sign(&confirmation_bytes(&local_offer,&remote_offer,&profile)).to_bytes() }).unwrap()
}

fn credentials<'a>(token: &'a SessionToken, packet: &'a Vec<u8>) -> WireCredentials<'a, Ed25519Security<Clock>> {
    WireCredentials { token, signature:packet, maintenance:None, endorsement:None, previous:None, successor:None }
}
fn token_json(token: &SessionToken) -> Value {
    json!({"claims":token.claims,"claims_signing_bytes_hex":hex(&token.claims.signing_bytes().unwrap()),
        "signature_hex":hex(&token.signature)})
}
fn core_json(packet: &[u8]) -> Value {
    let decoded = decode_packet(packet, packet.len()).unwrap();
    let core = decoded.core();
    let op = match core.body.as_ref().unwrap() {
        Body::StateSync(op)|Body::RegulatoryAction(op)|Body::LockManagement(op)|Body::Query(op)|
        Body::Ack(op)|Body::Heartbeat(op)|Body::Governance(op) => op,
    };
    json!({"version":core.version,"purpose":core.purpose,"deployment":core.deployment,
        "source_domain":core.source_domain,"target_domain":core.target_domain,"principal":core.principal,
        "key_id":core.key_id,"authority_epoch":core.authority_epoch,"issued_seconds":core.issued_seconds,
        "ttl_seconds":core.ttl_seconds,"uuid_hex":core.uuid.as_deref().map(hex),"family":core.family,
        "primary":core.primary,"secondary":core.secondary,"signature_scheme":core.signature_scheme,
        "atomicity":core.atomicity,"priority":core.priority,"route_scope":core.route_scope,
        "body":{"opcode":op.opcode,"words":op.words,"blobs_hex":op.blobs.iter().map(|b|hex(b)).collect::<Vec<_>>(),
            "appeal_deadline_debug":format!("{:?}",op.appeal_deadline)},
        "canonical_core_hex":hex(decoded.core_bytes()),"canonical_core_sha256":digest(decoded.core_bytes()),
        "reencoded_core_hex":hex(&encode_core(core).unwrap()),"transport_key":TransportKey::for_core(core).unwrap(),
        "signing_bytes_hex":hex(&decoded.signing_bytes().unwrap()),"envelope_signature_hex":hex(decoded.signature())})
}
fn request_json(packet: &[u8]) -> Value {
    let decoded = decode_packet(packet, packet.len()).unwrap();
    let operands = decode(decoded.core(), 4).unwrap();
    let request = crate::authority::recovery::wire::request_at(0, &operands).unwrap();
    let Action::Ordinary(payload) = request.action else { panic!("ordinary fixture") };
    json!({"target":request.target,"id":request.id,"request_cut":request.expected,"ordinary_payload":payload})
}
fn receipt_json(receipt: Receipt) -> Value {
    match receipt {
        Receipt::Ordinary(Collection::Collected(outcome)) => json!({"ordinary":{"collected":outcome}}),
        Receipt::Ordinary(Collection::Waiting) => json!({"ordinary":"waiting"}),
        Receipt::Ordinary(Collection::Rejected) => json!({"ordinary":"rejected"}),
        other => json!({"unprojected_debug":format!("{other:?}")}),
    }
}
fn resolution_json(result: Result<DebitResult, WireError>) -> Value {
    match result {
        Ok(DebitResult::Published(receipt)) => json!({"published":receipt_json(receipt)}),
        Ok(DebitResult::Unresolved) => json!({"status":"unresolved"}),
        Ok(DebitResult::Rejected) => json!({"status":"rejected"}),
        Err(error) => json!({"error_debug":format!("{error:?}")}),
    }
}
pub(in crate::authority::recovery::wire::ed25519) fn snapshot(service: &mut Service, control: &Control) -> Value {
    let product = service.transact(|product| {
        let primary = &product.reads.authority.state.primary;
        let ledger = &primary.ledger;
        let b = binding();
        let projection = ledger.project_reads();
        let mut accounts:BTreeSet<_> = projection.balances.keys().copied().collect();
        accounts.extend(projection.root_funding.keys().map(|(_,account)|*account));
        accounts.extend([b.source(),b.destination()]);
        let cut = product.reads.current_cut();
        let query = |query| match product.reads.authority.state.read_history.raw_value(cut.revision,query) {
            Ok(value) => json!({"value":value}), Err(error) => json!({"unavailable_debug":format!("{error:?}")}),
        };
        let account_values:Vec<_> = accounts.into_iter().map(|account|json!({"account":account,
            "account_balance":query(Query::AccountBalance(account)),"source_balance":query(Query::SourceBalance(account)),
            "destination_balance":query(Query::DestinationBalance(account))})).collect();
        json!({"cut":cut,"owners":primary.owners,"ledger":ledger,"accounts":account_values,
            "retained_calls":primary.calls.iter().collect::<Vec<_>>(),
            "wire_bindings":product.reads.authority.state.wire_bindings.iter().map(|(key,core)|
                json!({"key":key,"canonical_core_hex":hex(core),"canonical_core_sha256":digest(core)})).collect::<Vec<_>>(),
            "source_pool":query(Query::SourcePool(b.origin.domain,b.asset)),
            "destination_pool":query(Query::SourcePool(b.destination,b.asset)),
            "current_reservation_generation":ledger.generation(b.origin),"phase":ledger.phase(b.origin),
            "source_balance_raw":ledger.balance(b.source()),"pending":ledger.pending(b.origin),
            "destination_balance_raw":ledger.balance(b.destination()),
            "retained_image":RetainedImage::capture(product)})
    }).unwrap();
    let observed = control.current().unwrap();
    let head = service.anchor.current().unwrap().unwrap();
    let mut file = service.file.try_clone().unwrap();
    file.seek(SeekFrom::Start(head.offset)).unwrap();
    let mut bytes = vec![0;usize::try_from(head.length).unwrap()];
    file.read_exact(&mut bytes).unwrap();
    let actual:[u8;32]=Sha256::digest(&bytes).into(); assert_eq!(actual,head.digest);
    json!({"product":product,"control":control_value(&observed),"head":head,
        "selected_record_hex":hex(&bytes),"selected_record_sha256":digest(&bytes)})
}
fn response_json(original: &[u8], response: &Result<Vec<u8>,WireError>, now:u64) -> Value {
    match response {
        Err(error) => json!({"error_debug":format!("{error:?}")}),
        Ok(bytes) => {
            let original = decode_packet(original,original.len()).unwrap();
            let boundary = Boundary {deployment:7,source:0,target:0,principal:42,key_id:3,epoch:9,route_scope:1,now,
                asset_ttl_floor:2,future_skew:0,max_frame:1024*1024,max_nesting:4,version_floor:6,critical_allowed:false,
                public_key:key(6).verifying_key().to_bytes()};
            let verified = admit_response(&channel_for(7,6),&boundary,&original,bytes).unwrap();
            let (code,category) = match verified.code {
                ResponseStatus::Known(code) => (code as u64,"known"),
                ResponseStatus::Unknown {code,..} => (code,"unknown"),
            };
            json!({"packet_hex":hex(bytes),"sha256":digest(bytes),"verified":{"id":verified.id,"category":category,
                "code":code,"status_debug":format!("{:?}",verified.code),"commit":verified.commit}})
        }
    }
}

fn from_hex(value: &Value) -> Vec<u8> {
    let value = value.as_str().expect("hex string");
    assert!(value.len() % 2 == 0 && value.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    value.as_bytes().chunks_exact(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(),16).unwrap()).collect()
}

fn typed<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap()
}

fn input_token(value: &Value) -> SessionToken {
    let claims = &value["claims"];
    let token = SessionToken {
        claims: SessionClaims {
            profile: typed(&claims["profile"]), epoch: typed(&claims["epoch"]),
            identity: typed(&claims["identity"]), session: typed(&claims["session"]),
            issuer: typed(&claims["issuer"]), grants_sha256: typed(&claims["grants_sha256"]),
            issued_seconds: typed(&claims["issued_seconds"]), expires_seconds: typed(&claims["expires_seconds"]),
        },
        signature: from_hex(&value["signature_hex"]).try_into().unwrap(),
    };
    assert_eq!(token.claims.signing_bytes().unwrap(), from_hex(&value["claims_signing_bytes_hex"]));
    token
}

fn input_genesis(value: &Value) -> crate::authority::identity::Bootstrap {
    let balances: Vec<(crate::lock_finality::Account,u64)> = typed(&value["balances"]);
    let count = balances.len();
    let balances: BTreeMap<_,_> = balances.into_iter().collect();
    assert_eq!(count,balances.len(),"duplicate genesis account");
    crate::authority::identity::Bootstrap {
        epoch: typed(&value["epoch"]), provider: typed(&value["provider"]),
        settlement_target: typed(&value["settlement_target"]), contexts: typed(&value["contexts"]),
        sessions: typed(&value["sessions"]), maintainers: typed(&value["maintainers"]), balances,
        supply: typed(&value["supply"]), identities: typed(&value["identities"]),
        owners: typed(&value["owners"]), regulation: typed(&value["regulation"]),
    }
}

fn exact_input_keys(value: &Value, names: &[&str]) {
    let got: BTreeSet<_> = value.as_object().unwrap().keys().map(String::as_str).collect();
    let expected: BTreeSet<_> = names.iter().copied().collect();
    assert_eq!(got,expected,"input contains unexpected fields or omits fields");
}

struct Episode { _path: JournalPath, service: Service, control: Control, clock: Clock }

fn initialize_input(input: &Value) -> Episode {
    exact_input_keys(input,&["profile","source_connected","clock","control","security_config",
        "security_config_sha256","authority_binding_hex","credential","genesis","fixture_keys"]);
    assert_eq!(input["fixture_keys"],json!({"response_seed":6,"peer_seed":7}),"fixed test-only keys");
    let profile: RecoveryProfile = typed(&input["profile"]);
    let connected = input["source_connected"].as_bool().unwrap();
    let clock = Clock(Arc::new(AtomicU64::new(input["clock"].as_u64().unwrap())),Arc::new(Mutex::new(Vec::new())));
    let config: Ed25519Profile = typed(&input["security_config"]);
    assert_eq!(digest(&serde_json::to_vec(&config).unwrap()),input["security_config_sha256"].as_str().unwrap());
    let security = Ed25519Security::new(config,key(6),clock.clone()).unwrap();
    assert_eq!(security.authority_binding(9).map(|bytes|hex(&bytes)),typed::<Option<String>>(&input["authority_binding_hex"]));
    let raw = from_hex(&input["control"]["bytes_hex"]);
    assert_eq!(digest(&raw),input["control"]["bytes_sha256"].as_str().unwrap());
    assert_eq!(serde_json::from_slice::<Value>(&raw).unwrap(),input["control"]["decoded"]);
    let control = Control { value: Arc::new(Mutex::new(ControlValue {
        revision:input["control"]["physical_revision"].as_u64().unwrap(),bytes:raw })),
        trace: Arc::new(Mutex::new(Vec::new())) };
    let path = JournalPath::create();
    let service = PersistentAuthority::initialize(path.file(),OrderedHead::new(control.clone(),profile,1),
        Attachment {profile,proof:(profile,connected),source_connected:connected,security},input_genesis(&input["genesis"])).unwrap();
    Episode {_path:path,service,control,clock}
}

pub(super) fn output_dir(kind: &str) -> PathBuf {
    if let Some(path) = std::env::var_os("OIP_REFERENCE_OUTPUT_DIR") {
        let path = PathBuf::from(path).join(kind);
        fs::create_dir_all(&path).unwrap();
        return path;
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/reference-observations")
        .join(format!("{}-{now}-{kind}",std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn replay_input_rows(raw:&[u8],expected_sha:&str,expected_ids:&[&str],kind:&str) {
    assert_eq!(digest(raw),expected_sha);
    let rows: Vec<Value> = raw.split(|b|*b == b'\n').filter(|line|!line.is_empty())
        .map(|line|serde_json::from_slice(line).unwrap()).collect();
    assert_eq!(rows.iter().map(|row|row["id"].as_str().unwrap()).collect::<Vec<_>>(),expected_ids);
    let out = output_dir(kind);
    let observations = OpenOptions::new().create_new(true).write(true).open(out.join("observations.jsonl")).unwrap();
    let mut recorder = Recorder {observations};
    let mut episode: Option<Episode> = None;
    let mut financial = BTreeMap::<String,Value>::new();
    let mut responses = BTreeMap::<String,Value>::new();
    let mut episode_name = String::new();
    for row in rows {
        exact_input_keys(&row,&["schema","id","api","input"]);
        assert_eq!(row["schema"],"oip-reference-input-v1");
        let id = row["id"].as_str().unwrap();
        let api = row["api"].as_str().unwrap();
        let input = &row["input"];
        if api == "initialize" {
            if let Some(mut old) = episode.take() {
                let mut file = old.service.file.try_clone().unwrap(); file.seek(SeekFrom::Start(0)).unwrap();
                let mut bytes=Vec::new();file.read_to_end(&mut bytes).unwrap();fs::write(out.join(format!("{episode_name}.records")),bytes).unwrap();
                fs::write(out.join(format!("{episode_name}-control-trace.json")),serde_json::to_vec(old.control.trace.lock().unwrap().as_slice()).unwrap()).unwrap();
            }
            episode_name = id.split('.').next().unwrap().to_owned();
            let mut initial = initialize_input(input);
            recorder.observation(id,"after",json!({"after":snapshot(&mut initial.service,&initial.control),
                "clock_reads":initial.clock.1.lock().unwrap().clone()}));
            episode = Some(initial);
            continue;
        }
        exact_input_keys(input,&["clock","close","credential","packet_hex","signature_packet_hex"]);
        let ep = episode.as_mut().expect("stimulus before genesis");
        let now = input["clock"].as_u64().unwrap(); ep.clock.0.store(now,Ordering::SeqCst);
        let packet = from_hex(&input["packet_hex"]);
        let signed_packet = from_hex(&input["signature_packet_hex"]);
        let token = input_token(&input["credential"]);
        let decoded = decode_packet(&packet,packet.len()).unwrap();
        let operands = decode(decoded.core(),4).unwrap();
        let session = crate::authority::recovery::wire::source_session(&operands).unwrap();
        let current = ep.service.transact(|product|product.reads.current_cut()).unwrap();
        let boundary = ep.service.security.wire_boundary(&channel_for(6,7),decoded.core(),current).unwrap();
        let authenticated = ep.service.security.authenticate_session(&token,SessionProof {session,epoch:current.authority_epoch});
        let request=crate::authority::recovery::wire::request_at(0,&operands).unwrap();
        let Action::Ordinary(payload)=request.action else {panic!("ordinary replay request")};
        let lower_admission=ep.service.transact(|product| {
            let ledger=&product.reads.authority.state.primary.ledger;
            json!({"admitted_normal":ledger.request_admitted(crate::lock_finality::Route::Normal,
                crate::AuthenticatedCaller(payload.caller),payload.request()),
                "admitted_adapter":ledger.request_admitted(crate::lock_finality::Route::Adapter,
                crate::AuthenticatedCaller(payload.caller),payload.request()),
                "credential_none":payload.request().credential.is_none(),"cut":product.reads.current_cut()})
        }).unwrap();
        recorder.observation(id,"before",json!({"precall_reobservation":{
            "source_snapshot":snapshot(&mut ep.service,&ep.control),"authenticated_identity":authenticated,
            "authentication_proof":{"session":session,"epoch":current.authority_epoch},"lower_consumer_admission":lower_admission,
            "boundary":{"deployment":boundary.deployment,"source":boundary.source,"target":boundary.target,
                "principal":boundary.principal,"key_id":boundary.key_id,"epoch":boundary.epoch,"route_scope":boundary.route_scope,
                "now":boundary.now,"asset_ttl_floor":boundary.asset_ttl_floor,"future_skew":boundary.future_skew,
                "max_frame":boundary.max_frame,"max_nesting":boundary.max_nesting,"version_floor":boundary.version_floor,
                "critical_allowed":boundary.critical_allowed,"public_key_hex":hex(&boundary.public_key)}}}));
        let read_start = ep.clock.1.lock().unwrap().len();
        let auth = credentials(&token,&signed_packet);
        let close = input["close"].as_bool();
        let result = match api {
            "receive_wire_response" => {
                assert!(close.is_none());
                let response = ep.service.receive_wire_response(&channel_for(6,7),Entry::Adapter,&packet,&auth,DeliveryWindow::default());
                json!({"response":response_json(&packet,&response,now)})
            },
            "receive_wire" => {
                assert!(close.is_none());
                let result=ep.service.receive_wire(&channel_for(6,7),Entry::Normal,&packet,&auth,DeliveryWindow::default());
                json!({"result_debug":format!("{result:?}")})
            },
            "resolve_wire_debit" => {
                let result=ep.service.resolve_wire_debit(&channel_for(6,7),&packet,&auth,close.unwrap());
                json!({"result":resolution_json(result)})
            },
            "resolve_wire_debit_response" => {
                let response=ep.service.resolve_wire_debit_response(&channel_for(6,7),&packet,&auth,close.unwrap());
                json!({"response":response_json(&packet,&response,now)})
            },
            _ => panic!("unsupported replay API"),
        };
        let after = snapshot(&mut ep.service,&ep.control);
        if matches!(id,"a.3"|"b.3"|"c.1"|"c.2") {financial.insert(id.to_owned(),after.clone());responses.insert(id.to_owned(),result.clone());}
        let mut record = result.as_object().unwrap().clone();
        record.insert("after".to_owned(),after);
        record.insert("clock_reads".to_owned(),json!(&ep.clock.1.lock().unwrap()[read_start..]));
        record.insert("decoded_core".to_owned(),core_json(&packet));
        record.insert("typed_request".to_owned(),request_json(&packet));
        recorder.observation(id,"after",Value::Object(record));
    }
    let ep = episode.as_mut().unwrap();
    let mut file=ep.service.file.try_clone().unwrap();file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes=Vec::new();file.read_to_end(&mut bytes).unwrap();fs::write(out.join(format!("{episode_name}.records")),bytes).unwrap();
    fs::write(out.join(format!("{episode_name}-control-trace.json")),serde_json::to_vec(ep.control.trace.lock().unwrap().as_slice()).unwrap()).unwrap();
    let seeds=expected_ids.iter().filter(|id|id.ends_with(".0")).count();
    fs::write(out.join("input-pin.json"),serde_json::to_vec(&json!({"sha256":digest(raw),"rows":expected_ids.len(),"genesis":seeds,"stimuli":expected_ids.len()-seeds})).unwrap()).unwrap();
    // Fixed regression conclusions are checked only after every raw observation
    // has been persisted. They are never read by the input serializer or model.
    if kind=="replay" {
        assert_eq!(financial["a.3"]["product"]["pending"],5);
        assert_eq!(financial["a.3"]["product"]["source_balance_raw"],5);
        assert_eq!(financial["b.3"]["product"]["pending"],0);
        assert_eq!(financial["b.3"]["product"]["source_balance_raw"],10);
    } else {
        assert_eq!(responses["c.1"]["response"]["verified"]["code"],1);
        assert_eq!(responses["c.2"]["response"]["verified"]["code"],10);
        assert_eq!(financial["c.1"]["product"]["cut"]["revision"],0);
        assert_eq!(financial["c.2"]["product"]["cut"]["revision"],1);
    }
}

#[test]
fn reference_source_trace_replays_input_only_fifteen_rows() {
    replay_input_rows(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/reference-replay-inputs.jsonl")),
        "dbc836771c3e63478fb759740a4fa42d11f74065f74e0fd86d6c48a932cbdbe0",&["a.0","a.1","a.2","a.3","a.4","a.5","a.6","a.7","a.8","a.9","b.0","b.1","b.2","b.3","b.4"],"replay");
}

#[test]
fn reference_source_same_cut_refusal_then_normal_reserve() {
    replay_input_rows(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/reference-same-cut-inputs.jsonl")),
        "7c487b49b6e0ac3d87ca8d01688caa4a1a6da5b02cc80392282ab90ce66f9c3c",&["c.0","c.1","c.2"],"same-cut");
}

pub(in crate::authority::recovery::wire::ed25519) fn dispatcher_probe_setup(config:Ed25519Profile)
    ->(JournalPath,Service,Control,Clock,SessionToken) {
    let fixture:Value=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/vectors/reference-replay-inputs.jsonl")).lines().next().unwrap()).unwrap();
    let profile=config.profile;
    let clock=Clock(Arc::new(AtomicU64::new(105)),Arc::new(Mutex::new(Vec::new())));
    let security=Ed25519Security::new(config,key(6),clock.clone()).unwrap();
    let token=SessionIssuer::new(key(8)).issue(&security,7,2,300).unwrap();
    let bytes=OrderedHead::<Control>::initial_value(profile,None,1).unwrap();
    let control=Control{value:Arc::new(Mutex::new(ControlValue{revision:1,bytes})),trace:Arc::new(Mutex::new(Vec::new()))};
    let path=JournalPath::create();
    let service=PersistentAuthority::initialize(path.file(),OrderedHead::new(control.clone(),profile,1),
        Attachment{profile,proof:(profile,true),source_connected:true,security},input_genesis(&fixture["input"]["genesis"])).unwrap();
    (path,service,control,clock,token)
}
