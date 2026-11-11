# Operation and signing-input vectors

`wire-operations.jsonl` is generated from `spec/operations.json` by
`scripts/check-operations.py`. The generator expands the word-layout groups,
optional operands, counted fields, tagged queries and typed blobs. It creates
a valid canonical Core for every operation, signs each Packet with the fixed
test key, and adds fixed defects and reproducible seeded mutations. The key
is public test material and must not be used for an operational service.

The existing proof-bound `wire-conformance.tsv` and the Core decoder corpus
under `tests/interop/` are separate inputs and are not regenerated here.

## Schema 1

Each JSON line is one independent transport case:

- `schema`: 1; `layer`: `transport`; `threshold_supported`: false.
- `packet_hex`: the exact raw Packet bytes.
- `profile`: `version`, `families`, `atomicities` and `schemes`.
- `boundary`: `deployment`, `source`, `target`, `principal`, `key_id`, `epoch`,
  `route_scope`, `now`, `asset_ttl_floor`, `future_skew`, `version_floor`,
  `max_frame`, `max_nesting`, `critical_allowed` and `public_key` (32-byte hex).
- `signature_valid` and `attestation_valid`: the two external authentication
  results supplied to an optional model mirror. The real implementations
  verify the actual Ed25519 signature rather than trusting this JSON flag.
- `prior_binding`: the exact canonical Core hex already retained for this
  Packet's transport key, or null. A prior binding is installed directly in
  test state so a historical request need not be admitted under today's clock.
- `expected`: the retained regression outcome, with `verdict` and
  `retained_binding`. The latter is exact canonical Core hex or null.

An accepted verdict is `accept:first` or `accept:identical`. Refusals use the
wire response number: 70 to 76 or 54 for an expired delivery TTL. Every refusal
must preserve the entire retained map. The test adapters compare the exact
retained bytes, not only the number of stored keys.

`id`, `family`, `opcode`, `reference_accepts`, `seed` and `expected` are test
metadata and must not be inputs to a proof-model decision. The normal
transport receiver accepts every negotiated operation; the reference
configuration's operation filter (28 of the 33 operations when both
commitment operations are enabled) is checked separately against the table.

The fixed cases specify their expected outcomes in the generator. The random
cases retain the agreed Rust/Go outcomes as regression data. Agreement between
two implementations is a differential test, not a proof of either decoder.
The optional third mirror must independently decode the raw bytes and operands;
passing it a decoder result or an operand-acceptance boolean is insufficient.

## Reproduction

Run `python3 scripts/check-operations.py` with Cargo and Go on PATH, or pass
`--cargo` and `--go`. The command checks table rendering, regenerates the exact
input cases and signatures, checks the committed bytes and digests, and runs
the real Rust and Go test adapters and the independently pinned executable
model. `--require-mirror` uses the bound artifact lock and rejects custom or
two-language diagnostic overrides. A missing artifact, stale runtime/schema
identity, pending result or missing row fails the check. The full command and
local-artifact recipe are in [the model artifact contract](../model-artifact.md).
No shell is used to run the mirror. Custom `--mirror-command` and explicit
`--two-language-only` modes are diagnostics and do not satisfy required CI.

Only after reviewing an intended change, use `--write` to regenerate the
committed cases and their regression outcomes. This option still requires
Rust/Go agreement and all fixed expectations. The test signing input file is
regenerated separately by setting `OIP_WRITE_SIGNING_VECTORS=1` for the Rust
test `fixed_reference_signing_inputs_and_source_certificate`.

`reference-signing-inputs.json` contains the ten reference JSON signing or
digest domains, the source-record and source-quorum domains, and one canonical
source certificate. Each row records its compact JSON, exact prefixed input,
digest and, for signed inputs, public key and signature. The Rust test builds
typed values, uses the real signing APIs, checks the policy and grants digests,
and verifies the certificate through the configured source verifier. A changed
vote signature must be refused. The fixed values and keys are test fixtures.
The Go byte-level test checks the same exact inputs, digests and strict
Ed25519 signatures without passing JSON integers through floating-point values.
This does not add a Go authority or configured source-certificate API.

`wire-operations.sha256` fixes the operation corpus and signing-input file.
