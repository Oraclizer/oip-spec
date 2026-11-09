# Changelog

Changes that matter to implementers are recorded here in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
specification versions. The Rust crate and the Go module are not published
as packages.

## [Unreleased]

### Added

- Version 6 operation extension and response allocation rules.
- `SyncCommitment` and `CurrentCommitment`, with binary source attestations, current roster verification and independent source record selection.
- Reference admission and execution for the existing `Write` operation and DATA_UPDATED result.

### Fixed

- Generic mutable entry points now enforce the selected ordered maintenance boundary.

## [0.6.0] - 2026-11-09

Version 0.6.0 defines a signed protobuf message (wire version 6), the checks
a receiver applies before any effect, and the recorded outcome of each
operation. It includes a Rust reference implementation and a Go message
layer, both generated from one schema and tested against shared vectors. The
items under Changed and Fixed come from review of this version before its
release.

### Added

- Specification documents for the common product model, the message format
  and version profiles, locks and finality, identity and ownership handover,
  persistence and recovery, outcomes and publication, current and historical
  reads, regulatory execution, and compatible service actions.
- An operation table, `spec/operations.json` with its JSON Schema, that gives
  the word layout of all 31 operations and marks the 25 that the Ed25519
  reference configuration accepts. `spec/operations.md` is generated from it.
- An error table that states, for each response code, whether an effect may
  have happened, how to retry, and the matching v0.5 behavior.
- A correspondence table for the v0.5 commitments and a section on the
  constraints of this version.
- Response-code and original-request correlation checks in the Go operand
  decoder. Signed response generation and verification remain Rust reference
  authority APIs.
- Test vectors for an unsupported version that carries new fields and for an
  unknown field in a version 6 message.
- Tests for duplicate-decision response codes, unsupported versions, owner
  changes during a lock transfer and regulatory orders without a destination.
- Table-derived operation frames, fixed wire refusals and seeded mutations
  compared at the actual Rust and Go transport receivers, including exact
  retained bindings and unchanged state on refusal.
- Fixed signing inputs for the reference authorization domains, including
  policy digests, deterministic Ed25519 signatures and a source certificate.
- Hosted checks for operation conformance and signed Rust/Go interoperation.
  Private repository copies continue to skip all hosted jobs.
- Source-bound executable conformance for decoded wire values, canonical Core,
  signing preimages, transport keys and the Rust response sender/current-client
  boundary, with separate pinned model identities and exact artifact diagnostics.
- The Apache License 2.0 as the repository license, in `LICENSE` and in
  `go/LICENSE` for the Go module.

### Changed

- The specification separates the protocol from the reference profile and
  uses RFC 2119 keywords.
- The reference configuration refuses operations outside its profile with
  `UNSUPPORTED_VERSION` before admission.
- Responses with unknown codes are classified by their category.
- Deadline fields carry clearer names in the schema and the generated code.
  Field numbers and encoded bytes are unchanged.
- The upper bound on message lifetime is a configuration value, and its
  default and reference values are documented.
- The negotiation text matches the implementation: negotiation signs its own
  binary input, offers carry no size limits, and limits are configuration
  values.
- The byte rules and fixed vectors for JSON signing inputs are specified.
- The Go module path changed to `github.com/Oraclizer/oip-spec/go`.

### Fixed

- Go receiver callbacks receive independent Core copies. Callback changes
  cannot alter the signed message's decoded values or transport key.
- A refusal for a request with an invalid signature is signed only after the
  original signature has been checked with the registered key.
- A request whose response would exceed the frame limit is refused before
  any effect.
- Rust and Go apply the same checks in the same order and reach the same
  decision on the same bytes.
- A message with an unsupported version receives `UNSUPPORTED_VERSION`, also
  when it carries fields that this version does not define.
