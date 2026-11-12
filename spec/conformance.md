# OIP v0.6.2 conformance scope

This document is part of OIP v0.6.2. It states how the specification documents use requirement key words, which requirements every implementation meets, which statements describe the reference implementation in this repository, and the constraints of this version.

## Requirement key words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in these documents are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in all capitals, as shown here. The same words in lower case have their ordinary English meaning and state no requirement.

## Protocol core and reference profile

Every conforming OIP v0.6.2 implementation uses the same canonical bytes and field numbers, operation layouts, envelope and negotiation signing inputs, version check, response codes and effects, and product rules stated with key words. These requirements form the protocol core.

The reference profile is the configuration of the Rust reference implementation in this repository. It covers its Ed25519 session and maintenance tokens, its JSON signing inputs, its configuration values and accepted operations, its storage and control transports and its host adapters. A statement that names the reference, the reference profile or the reference configuration, and every section whose heading names the reference, describes the reference profile. Another implementation MAY use a different profile when it meets the protocol core. All other key-word statements belong to the protocol core.

## Document map

| Document | Content |
| --- | --- |
| [wire-conformance.md](wire-conformance.md) | Canonical message, version check, admission, responses, error codes and retry |
| [operations.md](operations.md) | Operand positions of every operation, generated from [operations.json](operations.json) |
| [json-encodings.md](json-encodings.md) | JSON governance blobs and reference signing inputs |
| [product-model.md](product-model.md) | Common state and transition boundary |
| [authoritative-outcomes.md](authoritative-outcomes.md) | Call identity, outcomes and publication |
| [current-and-historical-reads.md](current-and-historical-reads.md) | Current and historical observations |
| [identity-handover.md](identity-handover.md) | Caller identity and ownership handover |
| [threshold-signatures.md](threshold-signatures.md) | Threshold group selection, signature field and admission |
| [lock-finality.md](lock-finality.md) | Locks, pending mass and terminal evidence |
| [state-commitment-sync.md](state-commitment-sync.md) | Operation additions, state synchronization and binary source attestations |
| [response-code-extension.md](response-code-extension.md) | Response code assignments, compatibility and retry |
| [parallel-composition.md](parallel-composition.md) | Compatible service actions |
| [persistent-recovery.md](persistent-recovery.md) | Durable authority commit and recovery |
| [regulatory-execution.md](regulatory-execution.md) | Regulatory execution |
| [v0.5-correspondence.md](v0.5-correspondence.md) | Treatment of the public v0.5 documents |

## Constraints of this version

- Operands are position-based. The family and opcode of an operation fix the meaning of each word and byte string, as [operations](operations.md) lists.
- Deployment, domains, principal, key identifier, authority epoch and route scope are registered 64-bit handles. The core carries no address or chain name text.
- Amounts are 32-byte big-endian unsigned integers on the wire. The product accepts an amount only when its first 24 bytes are zero, so an amount is at most 2^64 - 1 base units. For a token with 18 decimal places this is about 18.4 whole tokens.
- The reference supports SINGLE Ed25519 and configured [THRESHOLD envelopes](threshold-signatures.md). A receiver uses the trusted current group when the channel selects THRESHOLD. A canonical scheme 2 request without a usable current group receives INVALID_THRESHOLD_SIGNATURE at signature admission.
- A state-changing request executes only when its signed cut equals the current global revision and authority epoch. A write that commits between signing and execution makes the request Busy without effect, also when the two touch different assets.
- A recorded Busy or Unavailable consumes the call identifier. Executing the work again needs a new signed cut, a new call sequence number, a new transport UUID and a new signature.
- The reference profile signs its tokens, policy bindings, authorizations and terminal source attestations as [JSON text](json-encodings.md). Synchronization uses the dedicated [binary source statement](state-commitment-sync.md#source-attestation).
- The maximum frame size, nesting depth, clock skew allowed for issued times, asset-class TTL floor and maximum delivery TTL are configuration values. This version fixes no numbers for them.
- Channels are set up out of band. The host verifies the signed offers and confirmation and installs the channel, and the reference accepts no HEARTBEAT frame as a delivery.
- Delivery is single hop. No relay that changes processing is defined.
- The reference configuration accepts 28 of the 33 operations when SyncCommitment and CurrentCommitment are enabled. Rust exposes separate flags for the two operations. Timeout, authorized epoch installation, Capabilities, Liveness and inbound correlated responses receive UNSUPPORTED_VERSION.
- The reference implementation assumes a 64-bit host. It converts 64-bit wire values to the host's native size type.
- The Rust persistent authority implements the reference execution, configured delivery TTL limit, signed response generation and signature-checked response verifier. Its signed response entry points require SINGLE in the negotiated schemes. The Go package implements the wire, negotiation, transport admission and operand decoding functions, including response operand correlation, but has no persistent authority or signature-checked response-verifier API.
- Ordinary request admission can refuse source registration, delivery-window or cancellation checks before envelope signature verification. A caller observing the local unsigned error can distinguish an unregistered source from an invalid signature for a registered source. Before signing a response, the response-generation path verifies a SINGLE original with the channel's authenticated peer key, or a THRESHOLD original with the current registered group bound to that channel context.
- The configured version 5 compatibility record uses JSON decoding without the canonical protobuf version selector. It does not interoperate with the public v0.5 wire format.

## Wire format conditions

| Condition | This version | Evidence |
| --- | --- | --- |
| Pinned generator versions and identical regeneration | Rust and Go bindings are generated from one schema with pinned generator versions, and regeneration produces no difference. | `proto/oip.proto`, `scripts/generate-wire.py` |
| Semantic validation | The canonical decoder checks the original bytes before the generated parser, and the operand decoder checks every position against the operation. | `src/wire/codec.rs`, `src/wire/operands.rs`, `spec/operations.json` |
| Absent, indefinite and finite deadlines; large integers and UTF-8 across languages | The three deadline forms are distinct on the wire. In this version the absent and the indefinite form have the same product meaning. Both languages run the same vectors. | `spec/operations.md`, `tests/vectors/wire-conformance.tsv`, `scripts/test-wire-interop.py` |
| Signed fields, order and canonical encoding | The envelope, negotiation and reference JSON signing inputs are defined byte by byte. | `spec/wire-conformance.md`, `spec/json-encodings.md`, `src/wire/negotiation.rs` |
| Size, fragmentation, version coexistence, deadlines, cancellation, errors and safe retry | Size and nesting limits are configuration values and a message fits in one frame. The version check, response codes and retry rules are defined per code. | `spec/wire-conformance.md` |
