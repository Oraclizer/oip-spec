# OIP v0.6 canonical message and version profiles

This document is part of OIP v0.6.0. [Conformance scope](conformance.md) defines the requirement key words and separates the protocol core from the reference profile.

## Version coexistence

- Peers select a channel profile from two signed offers and a signed confirmation. These use binary signing inputs separate from the envelope. An offer is ASCII `OIP`, NUL, ASCII `HEARTBEAT-OFFER`, NUL, then the deployment, sender, receiver, challenge and expiry as 8-byte big-endian integers, then the version, family, atomicity and scheme sets. Each set is an 8-byte big-endian count followed by its values in ascending order as 8-byte big-endian integers. The confirmation is ASCII `OIP`, NUL, ASCII `HEARTBEAT-PROFILE`, NUL, then the local and remote offers, each preceded by its length as an 8-byte big-endian integer, then the selected version as an 8-byte big-endian integer and the selected family, atomicity and scheme sets in the same set form. The local offer is signed with the local key. The remote offer and the confirmation are signed with the remote key.
- The selection MUST bind the two peers, the deployment, a fresh challenge supplied by the host, each offer's expiry and complete sets, and the selected profile. The selected version is the highest version that both offers contain at or above the registered peer floor. Version 5 is eligible only when legacy is allowed. The selected sets are the intersections of the offered sets, and an intersection can be empty. Under version 5 the families are limited to QUERY and HEARTBEAT and the schemes to SINGLE. The channel expires at the earlier of the two offer expiries. An unverified, mismatched or expired offer cannot select a profile.
- An offer carries no size or nesting limit. The maximum frame size and nesting depth are configuration values of the receiving host.
- The reference sets up channels out of band. Its host verifies the signed offers and confirmation and installs the resulting channel. The reference does not accept HEARTBEAT frames as deliveries.
- Use explicit v0.5 compatibility only with an authenticated permitted legacy peer and a configured legacy codec. The reference legacy codec is a reference compatibility record and does not interoperate with the wire format of the public v0.5 documents. [v0.5 correspondence](v0.5-correspondence.md) records how this version treats those documents. Deny v0.6-only capabilities in a legacy profile. Parse, signature, timeout and rejection paths cannot trigger fallback. Retire legacy through a trusted allowlist and version floor change after compatible routes and unresolved obligations have been handled.
- A fresh channel MAY negotiate the same profile without changing an already signed origin request. The signed immutable origin core is separate from mutable delivery information. A hop that changes processing MUST carry an authenticated, authorized, linked transformation. This version defines single-hop delivery only, so the reference provides no relay against which this requirement can be tested. The reference validates the immutable origin and its authorized local delivery scope before effect.

## Version check and unknown fields

- On a version 6 channel, a receiver MUST read the declared version of a frame within its size limit before canonical decoding of the rest of the frame. The declared version is the varint value of Core field 1 when the frame starts with Packet field 1 and the embedded Core starts with field 1. A frame that declares a version other than 6 MUST receive UNSUPPORTED_VERSION, whatever fields follow. A frame that declares no version continues to the canonical checks. This check does not precede checks of the installed channel or host configuration.
- The position and encoding of Packet field 1, Core field 1 and its varint form the version selector of the canonical protobuf format. The selector requires the shortest varints for the Packet tag, Core length, Core field-1 tag and unsigned 64-bit version, and requires the complete declared Core payload. It does not scan past a different first field. If any selector component is missing, truncated, overlong or out of range, the selector declares no version and canonical decoding decides the error. In particular, a truncated Core with a visible version prefix does not select that version. The reference version 5 compatibility path uses its configured JSON record decoder without this protobuf version selector; a malformed compatibility record receives INVALID_FORMAT.
- Within a version, a receiver MUST reject an unknown field, an unknown wire type or an out-of-order field as INVALID_FORMAT. A new field can enter the protocol only through a new version that both peers negotiate.
- After canonical decoding, an operation outside the selected version profile MUST receive UNSUPPORTED_VERSION before its source, signature or authority is checked. The selected version profile is the negotiated version together with the operations that the receiver's configuration accepts. The reference configuration accepts 25 of the 31 operations, listed in the "Reference accepts" column of [operations](operations.md). Rust checks the configured operation set in the authority entry paths, including response generation and exact Debit resolution. The generic Rust transport decoder has no configuration-specific operation set. Go exposes the configured check through `ReceiveAccepting`; its generic `Receive` path does not select that set.

## Canonical signed message

- The v0.6 envelope has a canonical protobuf core and signature bytes. The core binds version and purpose, deployment, source and target domain, authenticated principal, key and authority epoch, issued UTC seconds and delivery TTL, the full UUID, declared message family and exactly one matching body. Keep the seven established message family discriminators. Each body is an Operation record with position-based operands determined by family and opcode. [Operations](operations.md) gives the position, type and meaning of every operand, and it is generated from the table [operations.json](operations.json). A request carries its own caller-qualified sequence, session and cut and any exact origin, evidence, role or receipt correlation used by the product consumer. The full transport UUID and durable request and operation identifiers are separate.
- Use ascending known field tags, shortest protobuf varints and lengths, exact wire types, a single encoding for each field, and an exact oneof and presence discipline at every nested record. Varints have at most 10 bytes. Field tags range from 1 to 2^29 - 1, and only wire types 0, 1 and 2 occur. Validate original bytes before the generated parser can normalize duplicates, unknown fields or competing alternatives. The canonical parser preserves signature bytes and the original unknown secondary enum number and presence. Unknown primary values are rejected. An unknown secondary number does not authorize any product effect.
- Deployment, source domain, target domain and principal are registered 64-bit handles, and so are the key identifier, authority epoch and route scope. A receiver compares each with its registrations and the negotiated channel. The core carries no address or chain name text.
- Purpose MUST be 1 in this version. A frame with another purpose receives INVALID_SOURCE.
- The transport UUID MUST be 16 bytes with the version 4 bits and the RFC 4122 variant bits: the high four bits of byte 6 are 4, and the high two bits of byte 8 are binary 10.
- Issued seconds and finite appeal deadlines are UTC seconds since the Unix epoch. Delivery TTL, durations and elapsed values are seconds. Amounts are unsigned integers in base units.
- Preserve the absent deadline, the indefinite deadline and the finite deadline as separate forms on the wire ([deadline modes](operations.md#deadline-modes)). In this version the product gives the absent and the indefinite forms the same meaning: no appeal deadline. Strings use validated UTF-8 and canonical ordering by bytes for sets and maps, with sequence order preserved. Transport UUIDs are 16 bytes and unsigned 256-bit integers have one fixed 32-byte big-endian representation. Product bindings use checked range conversion before effects. Reject malformed lengths and out-of-profile scope rather than truncating values. The maximum frame size and nesting depth are configuration values of the receiving host. A frame larger than the configured maximum MUST be refused as INVALID_FORMAT. Only complete canonical frames enter the validator.
- The immutable origin signing input is ASCII OIP followed by NUL, ASCII ENVELOPE followed by NUL, four big-endian bytes of core length, and the canonical core. Derive it from the authoritative fields and sign the exact bytes. Negotiation uses its own binary signing inputs, and the reference token, policy and source records use the signing inputs in [JSON encodings](json-encodings.md). Verify the scheme and signature with the current authenticated source key and scope.
- SINGLE uses Ed25519 (RFC 8032) with a 32-byte public key and a 64-byte signature. A verifier MUST reject a SINGLE signature unless the public key and the first 32 bytes of the signature (R) are canonical point encodings, with the y coordinate below 2^255 - 19, of points that are not of small order, the last 32 bytes (S) encode an integer below the group order, and the equation [S]B = R + [k]A holds without cofactor multiplication.
- THRESHOLD (scheme 2) has no verifier in this version. The reference has no THRESHOLD adapter and refuses every scheme 2 frame as INVALID_THRESHOLD_SIGNATURE, with no fallback. A THRESHOLD adapter MUST enforce exact current distinct authorized signers and a trusted quorum. With no such adapter in the reference, this requirement cannot be tested against it.

## Admission, replies and retry

- Apply the trusted asset-class minimum TTL when it exceeds the supplied TTL. Accept the inclusive expiry cut and reject expiration, disallowed future skew, arithmetic overflow and obsolete authorization before state effects. The skew allowed for an issued time ahead of the receiver clock is a configuration value. Delivery TTL neither ends a lock nor establishes a source outcome.
- The reference persistent authority MAY configure a maximum signed delivery TTL. A frame whose signed TTL exceeds it MUST receive TTL_INVALID after the signature check and before operand decoding, any transport binding or effect. The default is no limit. In the reference configuration the value is `max_delivery_ttl_seconds`, and an absent value sets no limit. This authority check is not part of the generic Rust or Go transport admission API. This maximum applies to the persistent-authority delivery receive path. Exact authorized Debit resolution does not repeat that maximum check; it revalidates the original using its issued time as the admission time.
- Canonical format, version, domain, current key and epoch, signature and separate source identity checks MUST precede any transport deduplication update. Key that update by authenticated origin and complete UUID. Compare the retained exact signed core for the same key and reject a changed request. Transport deduplication cannot replace caller-bound durable results or original-event consumption.
- A verified request MUST enter the same current product authority and execution path as the matching product action. A raw caller-supplied request cannot replace the validated body. Maintain normal, administrative, force-inclusion, upgrade and adapter authorization at the final consumer.
- The execution credentials that accompany a reference delivery (session token, signature credential, maintenance token, owner endorsement and handover consents) come from host adapters. They are not wire fields. Debit result recovery is an API of the reference authority host that takes the original signed Debit. It is not a wire operation.
- A state-changing request MUST carry the global revision and authority epoch of its signed cut, and the authority MUST execute it only when they equal the current cut. When another write commits in between, the request receives Busy without effect.
- A recorded outcome consumes its call identifier, including a recorded Busy or Unavailable. Sending the same request again returns the recorded outcome. Executing the work again requires a new signed cut, a new call sequence number, a new transport UUID and a new signature.
- In the ordered v0.6 reference configuration, the signed delivery TTL bounds admission. The service deadline bounds how long the caller waits. A wait timeout leaves the result unresolved until an authorized read confirms it. Publication MUST compare the exact observed control state, including the authenticated head, writer generation, revocation and cancellation, in the same authority transaction that selects the flushed record. A prior authority-ordered revocation or cancellation prevents that publication. Publication can occur after the delivery TTL or wait deadline. An expired packet remains ineligible for new delivery.
- Debit result recovery authenticates the current caller and binds the original caller, call identifier and complete canonical signed request. An exact authorized query can recover a published receipt after expiry. A durable rejection of an unresolved original uses the same authority transaction as publication and loses if the effect has already been published. Once an original Debit is known to the authority, another call identifier for the same origin and generation can proceed only after the authorized original is durably rejected.
- A configured strict publication provider separately enforces its time and cancellation conditions at its durable visibility cut. The reference ordered configuration requires an explicit authority binding and does not select the strict or legacy path as a fallback.
- Generate Rust and Go bindings from one pinned schema and regenerate them without edits. Both compiled consumers MUST use the same canonical bytes, semantic values, signing inputs and refusal vectors for the wire and admission functions they implement. Keep format, authorization, version, expiry and conflict errors distinct. The request-admission disclosure described in [constraints of this version](conformance.md#constraints-of-this-version) remains a limitation of the reference profile.

## Refusals before signature verification

- A receiver MUST NOT sign a response to a frame whose own signature it has not verified. A refusal before that verification is an unsigned error.
- The Rust reference response-generation path checks the original's signature with the peer key of the negotiated channel before it signs anything. Checks of the original before that verification read only the frame and the channel, so these unsigned errors do not disclose registration of the principal, key identifier or authority epoch named by the original.
- The reference returns request-admission refusals to its local host as error values. Its ordinary request path can select a boundary, check delivery and cancellation, and refuse INVALID_SOURCE before verifying the envelope signature. This version does not provide registration privacy for those local errors. An unsigned error MUST NOT be treated as an authenticated response or as evidence of a product effect.

## Refusal precedence

The following sequences define the validation order of the reference APIs. A
reference API MUST return the first failure reached in its applicable sequence.
Later checks run only after earlier checks succeed. A decoder or host adapter
contributes the result it returns at its listed step; the caller does not
combine it with failures from checks that have not run. The sequences do not
replace the installed-channel, authenticated-storage or transaction preconditions
of the entry point. A host failure before frame validation retains its host or
recovery error.

These are local error results. A signed Response additionally requires the
preparation and signature checks below. Effect certainty and retry semantics
for publication or delivery failures are defined in [Effect and retry by
code](#effect-and-retry-by-code). The source-registration disclosure of ordinary
request admission is recorded in [Constraints of this
version](conformance.md#constraints-of-this-version).

### Transport receive

Rust `TransportBindings::receive` and Go `TransportBindings.Receive` use this
sequence. Go `ReceiveAccepting` inserts its configured operation check at step 3;
the generic Rust and Go receivers have no such configured operation set.

| Step | Check and first refusal |
| --- | --- |
| 1 | The supplied profile selects version 6; otherwise UNSUPPORTED_VERSION. |
| 2 | The Packet fits `max_frame`; run the version selector and canonical Packet decoder. An oversized or malformed frame receives INVALID_FORMAT; a selected version other than 6 receives UNSUPPORTED_VERSION. |
| 3 | When a configured operation predicate is present, it accepts the decoded operation; otherwise UNSUPPORTED_VERSION. |
| 4 | The negotiated version, version floor, family and atomicity fit; otherwise UNSUPPORTED_VERSION. The purpose, deployment, endpoints, principal, key, epoch, route scope and critical authority fit the boundary; otherwise INVALID_SOURCE. |
| 5 | Effective TTL and allowed future time do not overflow, and the issued time is within the future-skew bound; otherwise TTL_INVALID. The effective expiry has not passed; otherwise TtlExpired (54). |
| 6 | A scheme 2 signature receives INVALID_THRESHOLD_SIGNATURE. Otherwise the scheme is selected and the exact envelope signature verifies; a failure receives INVALID_SIGNATURE. |
| 7 | The independent `attest` callback accepts the Core; otherwise INVALID_SOURCE. |
| 8 | The operation operands decode within `max_nesting`, returning the decoder's first layout or correlation error. |
| 9 | Derive the transport key and compare its retained exact Core. Different retained bytes receive REPLAY_CONFLICT. An absent binding becomes First and equal bytes become Identical. |

This sequence is implemented by [Rust transport admission](../src/wire/admission.rs)
and [Go transport receive](../go/wire/operands.go), with the shared Go scope and
signature gate in [admission.go](../go/wire/admission.go).

### Persistent request admission

The Rust persistent entry first checks its ordered-control configuration and
opens its authenticated transaction. With ordered control installed, a channel
version other than 6 receives UNSUPPORTED_VERSION before the transaction; a
different ordered-revocation profile receives INVALID_SOURCE. A provider that
requires ordered control cannot use an anchor without it. Storage, attachment,
head-observation and transaction failures can prevent frame admission.

Within `consume`, the sequence is:

| Step | Check and first refusal |
| --- | --- |
| 1 | For ordered execution, observe the exact control head or retain the supplied observation. A failed observation or different head holds the request. |
| 2 | The Packet fits the configured frame limit; otherwise INVALID_FORMAT. Select version 6 through the selector and canonical decoder, or use the explicitly configured version 5 compatibility decoder. A different installed version receives UNSUPPORTED_VERSION. |
| 3 | The configured operation set accepts the decoded operation; otherwise UNSUPPORTED_VERSION. The external signing credential matches the exact Packet bytes; otherwise INVALID_SIGNATURE. This credential comparison precedes envelope cryptographic verification. |
| 4 | Construct the current registered boundary and check the channel, peer key, deployment, endpoints, expiry and authority epoch. A mismatch receives INVALID_SOURCE. Then check the boundary frame limit; an excess receives INVALID_FORMAT. |
| 5 | Check the explicit delivery cancellation, then a strict delivery deadline. These return Cancelled (53) and DeadlineExpired (52), respectively. A strict path then checks provider cancellation. Ordered execution handles provider cancellation through its observed control. |
| 6 | Verify the envelope through the scope, time and signature gate in Transport receive steps 4 to 6. Then enforce the configured maximum signed TTL; an excess receives TTL_INVALID. |
| 7 | Decode operands, authenticate the current identity/session, and compare its principal and domain with the Core. A failed identity comparison receives INVALID_SOURCE. Derive the transport key. |
| 8 | For ordered execution, check current caller authority, any required ACK/handover maintainer and recovery endorser, then the pending transport binding. Next compare the retained Core binding. |
| 9 | Check any required trusted-clock observation, determine whether an identical call already has a retained result, and verify fresh operand proof where required. A missing clock observation receives ProductRejected (77); a failed fresh operand proof receives INVALID_SOURCE. |
| 10 | Re-read the current boundary, recheck delivery, and recheck reduced nesting or size limits before re-verifying the envelope. If limits shrank, the operand decode runs before the reduced-size refusal. |
| 11 | Check ordered Debit execution and work-slot disposition where applicable, run the selected final product consumer, and prepare the ordered disposition. Only successful admission reaches transport binding insertion and receipt capture. |

The final consumer keeps its operation-specific authority, credential and
retained-result checks. Its first returned error is the result of step 11.
The [request consumer](../src/authority/recovery/wire.rs) also revalidates the
publication guard before a changing record is selected. That guard checks the
current boundary; ordered identity, permissions and special-role credentials or
strict delivery conditions; frame size; envelope admission; and operands, in
that order. Ordered publication uses the admitted time for the envelope gate,
as specified in [Admission, replies and retry](#admission-replies-and-retry).
An observed revocation, cancellation or authority change can still prevent
publication. A simulated response loss is reported after the transaction.

### Preparing a signed Response

Before `receive_wire_response` executes a call, `response_original` uses the
following sequence. `resolve_wire_debit_response` uses the same preparation
before its exact-resolution API.

1. Require a version 6 channel that selects the ACK response family; otherwise
   UNSUPPORTED_VERSION.
2. Require ordered control, the matching revocation profile, a current channel
   and the matching deployment; otherwise INVALID_SOURCE.
3. Apply the configured frame limit, version selector and canonical decoder.
4. Require an operation accepted by this reference configuration; otherwise
   UNSUPPORTED_VERSION. Compare the decoded version, deployment and two
   endpoints with the channel; a mismatch receives INVALID_SOURCE.
5. Decode the operands with one Core level and obtain a caller-qualified call
   identifier. A non-call body or invalid layout receives INVALID_FORMAT or the
   operand decoder's first error.
6. Select a negotiated response atomicity and encode the largest response
   shape for the original. No selected atomicity receives UNSUPPORTED_VERSION;
   an encoding or size failure receives INVALID_FORMAT.
7. Check scheme 2 as INVALID_THRESHOLD_SIGNATURE; otherwise verify the original
   envelope with the channel's authenticated remote key and selected scheme.
   A signature failure receives INVALID_SIGNATURE.
8. Require the host response signer, then enter persistent request admission or
   exact Debit resolution. Convert its returned outcome to a Response result,
   and encode and sign that result.

Every failure through step 7 is unsigned. Step 8 can also fail to supply or
deliver a signed response. Frame and channel checks in steps 1 to 6 precede
the signature check without consulting the principal/key registration claimed
by that frame. The source of the final response, its result and its complete
original binding are checked by [response.rs](../src/authority/recovery/wire/response.rs).

### Verifying a signed Response

Rust `admit_response` first compares the supplied boundary with the installed
channel: endpoints, deployment, channel expiry and remote public key. A failure
receives INVALID_SOURCE. It then runs the frame limit, version selector and
canonical Packet decoder, followed by Transport receive steps 4 to 6. Only
after envelope verification does it decode the Response operands, decode the
retained expected call, compare the embedded original bytes and caller-qualified
identifier, check the response kind/code/commit shape, and check a known code
against the call type, in that order. A different exact original or call
identifier receives REPLAY_CONFLICT; invalid shape or a known code for another
call type receives INVALID_FORMAT. Nested decoding can return its own earlier
format or source error. The Go operand decoder performs its documented
correlation checks and has no counterpart of this signature-checked API.

Examples of combined failures:

| Entry point and simultaneous defects | First result |
| --- | --- |
| Transport receive: a within-limit complete Core declares version 7 and carries a later unknown field | UNSUPPORTED_VERSION, because the version selector succeeds before canonical decoding |
| Transport receive: the supplied principal differs from the boundary and the envelope signature is invalid | INVALID_SOURCE, from the scope check |
| Transport receive: an invalid envelope signature and an invalid operand tail | INVALID_SIGNATURE, before operand decoding |
| Signed Response preparation: a validly framed accepted call has an invalid operand tail and an invalid envelope signature | The operand decoder's error, before the original-signature check; the error is unsigned |
| Signed Response verification: the installed channel/boundary comparison fails and the response bytes are malformed | INVALID_SOURCE, before Packet decoding |

## Reference outbound Response

The reference authority signs an ACK family operation with opcode 2 after its ordinary receive or exact Debit resolution returns. Its words are the original caller namespace, call sequence, kind, result code, and commit presence, followed by the commit position when present. The only blob is the original canonical Core in its original bytes. The operation has no deadline. The response uses the current configured local issuer, reverses source and target domains, and signs the canonical response Core with the negotiated local Ed25519 key and the envelope signing domain. A response UUID can be reused only for identical response bytes.

The Rust reference response verifier uses the caller's retained canonical original and the current peer policy. It checks the signature, exact original Core, caller-qualified ID, kind, code, request compatibility and commit presence. The boundary's verification key MUST equal the peer key authenticated by the channel; a mismatch receives INVALID_SOURCE. This response path applies the canonical version selector and returns UNSUPPORTED_VERSION for another declared version before canonical decoding. For Debit the commit position is the ledger revision of the original signed cut. Duplicated terminal decisions or settlements use the commit reference in the retained outcome. The reference path handles native calls with a caller-qualified ID. An unidentifiable or noncanonical input produces a transport error without an invented call identifier. The reference signs a response only for an original whose signature verifies with the channel's peer key. An original with an invalid signature receives an unsigned error and no response. Before executing a request, the reference encodes the largest response shape for that original Core, including a commit position and a 64-byte signature. If this exceeds the configured frame limit, the request receives INVALID_FORMAT before any effect. A timeout can be followed by an exact authorized resolution for a delivery status or the durable outcome. Go decodes response operands and their correlation fields but does not implement this signature-checked response-verifier API.

| Kind | Commit | Codes and results |
| --- | --- | --- |
| 1 recorded | Absent | 1 Rejected, 2 Busy, 3 Unavailable, 4 exact original Debit closed without effect |
| 1 recorded | Present | 10 Reserved, 11 SourceDispatched, 12 Debited, 13 Closed, 14 Preempted, 15 TimeObserved, 16 Recorded, 17 Credited, 18 Reconciled, 19 Refunded, 20 DataUpdated, 21 EvidenceRefreshed, 22 Published |
| 1 recorded | Present | 23 DuplicateDecision, 24 DuplicateConfirmed, 25 DuplicateReversed, 26 LegalEmitted, 27 LegalApplied, 28 SpendExecuted |
| 1 recorded | Absent | 30 LegalInvalidAuthority, 31 LegalInvalidState, 32 LegalInvalidBinding, 33 LegalMissingPriorFreeze, 34 LegalMissingPriorSeizure, 35 LegalAppealStillOpen, 36 LegalAppealDeadlineMismatch, 37 LegalMissingDestination, 38 LegalConflictingOrder |
| 2 delivery | Absent | 50 Unresolved, 51 ResponseLost, 52 DeadlineExpired, 53 Cancelled, 54 TtlExpired, 55 DeliveryBusy, 56 DeliveryUnavailable |
| 3 refusal | Absent | 70 InvalidFormat, 71 UnsupportedVersion, 72 InvalidSource, 73 InvalidSignature, 74 InvalidThresholdSignature, 75 TtlInvalid, 76 ReplayConflict, 77 ProductRejected |

Each ordinary effect code applies to the corresponding command. Closed covers Cancel and Fence. Recorded, EvidenceRefreshed and DuplicateDecision cover RecordTerminal. DuplicateConfirmed covers Credit and DuplicateReversed covers Refund. LegalEmitted and LegalApplied cover their respective stages, and legal codes 30 through 38 cover legal calls. SpendExecuted covers Spend. Codes 4 and 12 apply only to Debit. Recorded Rejected, Busy and Unavailable apply only when the exact product outcome is retained. Delivery and refusal codes are independent of the native call type.

A verifier MUST accept a response code that this version does not define when its kind is 1, 2 or 3 and its commit presence fits the kind. For an unknown code, kind 1 permits either an absent or a present commit position; kinds 2 and 3 require it to be absent. Other kinds receive INVALID_FORMAT. A known code MUST have exactly the kind and commit presence listed in the table. The verifier accepts an unknown code as its kind only and MUST NOT report it as a result defined by this version.

## Effect and retry by code

| Codes | Effect of the original call | How to continue | Closest v0.5 code |
| --- | --- | --- | --- |
| 1 Rejected | No effect. The outcome is recorded and consumes the call identifier. | The same request returns this outcome. New work needs a new call. | ACK type REJECTED |
| 2 Busy | No effect, for example because the signed cut was not the current cut. The outcome is recorded and consumes the call identifier. | The same request returns Busy. Send a new signed cut with a new call sequence number, transport UUID and signature. | None |
| 3 Unavailable | No effect. The outcome is recorded and consumes the call identifier. | As for Busy. | None |
| 4 | The original Debit was closed without effect. | The original Debit cannot execute later. | None |
| 10 to 28 | The named effect is committed. | The same request returns the same outcome without another effect. | None |
| 30 to 38 | No legal effect. The outcome is recorded and consumes the call identifier. | New work needs a new call. | 33 FREEZE_REQUIRED_BEFORE_SEIZE, 34 SEIZE_REQUIRED_BEFORE_CONFISCATE, 35 APPEAL_PERIOD_NOT_EXPIRED, 31 INVALID_STATE_TRANSITION |
| 50 Unresolved, 51 ResponseLost, 52 DeadlineExpired | Unknown. The effect can have been committed. | Resolve the original signed request through an exact authorized resolution before reissuing the work. | DELIVERY_TIMEOUT for 50 and 52 |
| 53 Cancelled, 55 DeliveryBusy, 56 DeliveryUnavailable | No effect. | Send a new signed request. | None |
| 54 TtlExpired | No effect. | Send a new signed request with a new transport UUID and issued time. | MESSAGE_TTL_EXPIRED |
| 70 to 75, 77 | No effect. Nothing is recorded, and the call identifier is not consumed. | Correct the cause and send a new signed frame with a new transport UUID. | 70 INVALID_HEADER_FORMAT, 71 UNSUPPORTED_VERSION, 72 INVALID_SOURCE_AUTHENTICATION, 73 INVALID_SIGNATURE, 74 INVALID_THRESHOLD_SIGNATURE |
| 76 ReplayConflict | No effect. The transport UUID is already bound to different bytes, and the earlier request is unchanged. | Use a new transport UUID. Sending the identical bytes returns the retained result. | DEDUPLICATION_DETECTED |

## Ordered acknowledgement and read batches

The ordered schedule accepts canonical v0.6 settlement acknowledgements and current reads up to the host's configured occurrence and swap limits. Each occurrence supplies its own signed frame, negotiated channel and credentials. Labels identify replies. Settlement slots, observed queries and transport UUID keys come from the decoded input. An unsupported shape or invalid occurrence produces a refusal in its original label without blocking other valid occurrences in the batch.

A proposed exchange requires successful acknowledgements or current observations, independent settlement slots or observations, and distinct transport keys. Shared slots and shared UUID keys are evaluated in their original relative order. For each accepted exchange, both orders MUST produce the same retained image and the same response at each original label. Supported acknowledgements and reads preserve the signed product cut.

All successful outcomes are rechecked against current identity, wire signature and product authorization after preparation. A changing batch publishes one flushed record with one exact authority CAS. A batch with no image change reads back the exact observed authority and head. A change to the authority before confirmation withholds the prepared results. Ordered delivery TTL limits admission and does not become a second clock-based condition at publication.

## Canonical field numbers

The packet carries embedded Core at tag 1 and signature bytes at tag 2. Core encodes version and purpose as varints at 1 and 2. Deployment, source domain, target domain, principal, key identifier, authority epoch, issued seconds and delivery TTL are fixed64 at 3 through 10. UUID bytes use 11. Family and authoritative primary code use varints 12 and 13. Optional secondary code is varint 14. Signature scheme is varint 15, with SINGLE 1 and THRESHOLD 2. The body oneof uses the family discriminator plus 15, so its tags are 16 through 22. Atomicity and priority use varints 23 and 24. The registered route scope identifier is fixed64 at 25. Atomicity codes 1 through 3 are BEST_EFFORT, GUARANTEED and ALL_OR_NOTHING. Priorities 0 through 4 are CRITICAL, REGULATORY, HIGH, NORMAL and LOW. CRITICAL uses ALL_OR_NOTHING and current privileged authority. The reference configuration does not admit CRITICAL and refuses it as INVALID_SOURCE. Routing changes MAY add separately authenticated evidence but cannot silently rewrite the core.

All seven body variants use an embedded Operation record. Its opcode is varint tag 1. Ordered words are repeated unpacked fixed64 tag 2. Ordered byte strings are repeated tag 3. The optional appeal deadline is either `appeal_deadline_indefinite` at varint tag 4, whose only valid value is 1, or `appeal_deadline_utc_seconds`, a finite fixed64 UTC timestamp at tag 5. An absent deadline carries neither tag. The family and opcode determine the position, type and count of every operand, as [operations](operations.md) lists, and application admission validates these together. Byte strings that are used for evidence, structured subrecords, UTF-8 names or 256-bit integers MUST satisfy the type selected by the operation.

| Family code | Body operations in opcode order |
|---|---|
| 1 STATE_SYNC | Debit, record terminal evidence, deliver credit, refund, publish primary, ordinary spend |
| 2 REGULATORY_ACTION | Emit legal order, commit legal order, enforcement spend |
| 3 LOCK_MANAGEMENT | Reserve, dispatch, cancel, fence, preempt, reconcile, write, timeout |
| 4 QUERY | Current, historical, raw, operation status, journal, capture cache, owner, exact receipt |
| 5 ACK | Exact settlement acknowledgement, correlated response |
| 6 HEARTBEAT | Capabilities, liveness |
| 7 GOVERNANCE | Owner handover, authorized epoch installation |

Query operations 1 and 2 start with session and revision, followed by the query. Operations 3 and 6 start with session and the query. The query tag is 1 for application asset, 2 for source balance, 3 for destination balance, 4 for root balance, 5 for regulatory state and 6 for terminal receipt. The following operands in order are the asset, source domain and asset, destination domain and asset and holder, origin domain and event and destination domain and asset and holder, domain and asset, or origin domain and event respectively. Operation status uses session and exact origin pair. Journal uses session. Owner uses session and asset. The header fixes the exact target domain and session epoch. The exact receipt carries the original caller-qualified request and consumes the current receipt capability.

## Product operands

Execution operands begin with the internal message reference, caller sequence, session, checked revision and original authority epoch. They are followed by the original domain, original event, asset, funding owner, destination and recipient. The first byte string is the 32-byte unsigned amount. The outer authenticated principal, authority epoch and target are the only caller and current cut authority used by the consumer. An ordinary command then carries the credential presence code, the credential asset, origin pair, holder, generation and epoch when present, and a version count followed by sorted unique asset/version pairs. Its remaining words are fixed by the operation.

| Operation | Exact ordinary tail |
|---|---|
| Reserve or preempt | Duration |
| Dispatch, debit, cancel or fence | Generation |
| Record terminal | Decision kind and evidence reference |
| Deliver | Evidence reference |
| Refund or reconcile | Generation and evidence reference |
| Write | Generation and value |
| Timeout | Elapsed seconds |
| Publish primary | Empty |

A legal order uses the same binding prefix. Its tail is action, officer, jurisdiction, legal basis, issuance epoch, counted sorted unique scope, optional predecessor origin and optional confiscation destination. Its appeal deadline alternative supplies the legal deadline. A spend carries the root binding and its own reference, sender, recipient and kind. The second byte string is the exact spend amount. An enforcement spend adds officer, jurisdiction, legal basis, counted sorted unique scope and optional prior seizure origin. The authenticated source, legal and owner endorsement adapters supply independently validated proof objects for the exact canonical fields. They cannot supply a different request to execute.

Exact receipt uses the current authorized session and the complete immutable original request as a nested canonical record. Nesting the original as receipt data does not admit it again as a delivery. An ACK binds the original event, exact commit position, target, complete primary binding, original epoch and decision kind. A response binds the caller and original request and distinguishes a recorded outcome from a delivery or validation refusal. Heartbeat capabilities bind challenge, expiry and counted sorted unique version, family, atomicity and scheme offers. Governance carries the exact owner proposal or context batch and the separately verified maintenance and owner authorizations.

Counted sets and mappings use canonical ascending numeric keys, exact counts and no duplicates. Counted sequences retain order. A presence code is exactly 0 or 1. Nested proof and context adapters MUST validate the original selected record and compare canonical bytes or a commitment recomputed from authoritative fields before a product transition. A source balance uses the authoritative unallocated source pool at the exact domain and asset. The current or historical cut supplies that pool. Owner handover changes recovery control and cannot select a different source balance or historical producer. Destination and funded accounts carry the explicit holder. No wire field is truncated into a product identifier. A transport UUID binding that affects acceptance is retained under the same authenticated commit as the result. A canonical older retained image with no such field opens as an empty transport binding table without changing its original bytes.


## Ordered reference handover and caller wait

The current registered owner and named successor sign separate Ed25519 consents. Each consent covers its role and registered identity, the exact asset, both principals and sessions, the previous authority epoch and revision, the next epoch and endpoint contexts, and both approved policy fingerprints. The signed governance Core carries those exact consent bytes. The current maintainer MUST hold the handover capability. The independent witness comparison covers revocation of the maintainer and both participants. A selected handover installs the owner, new session bindings and next policy fingerprint together. The next key proves readiness before selection, and the next service attaches only to that exact selected fingerprint. The existing source issuer and quorum registrations continue to verify retained origin epochs.

Cancel, Fence and Preempt carry the current owner's exact signed recovery action in the Core. The existing ledger checks the request's authority cut, lock and applicable holder and generation before an effect. Preempt checks the exact cut and advances the generation of the expired lock. The reference caller submits signed requests to a bounded worker and waits for the earlier of its monotonic deadline and the host-configured maximum. A timeout leaves accepted work with the worker. Resolution uses the original signed Debit and current receipt authority.
