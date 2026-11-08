# Executable wire value conformance

The normal workflow requires the independently exported typed wire judge.
`check-operations.py` selects that pinned judge by default; `--require-mirror`
is explicit in CI. An unbound artifact, old ABI, missing identity, unsupported
result, absent accepted value or altered source fingerprint fails the check.
The pinned public namespace, model content and source fingerprint are checked
independently. A passing corpus comparison is bounded conformance evidence;
it does not establish general implementation refinement.

The fixed corpus remains 161 fixed plus 512 seeded transport inputs. Each
implementation independently reports:

| Field | Meaning |
| --- | --- |
| `verdict` | Actual first/identical acceptance or exact refusal number |
| `retained_binding` | The transport store's retained canonical Core bytes |
| `reencoded_core_hex` | Re-encoding of the implementation's decoded Core |
| `signing_preimage_hex` | The implementation's actual canonical signing preimage |
| `transport_key_ir` | Actual deployment/source/principal/UUID transport key |
| `typed_operand_ir` | Semantic values produced by the actual operand decoder |

The four value fields are null on refusal. Accepted values use the shared
integer TLV contract in `typed-operands-ir.json`; JSON represents every token
as a decimal string. The comparator checks every field and every token, not
only acceptance and retained bytes. Native tails are not raw words/blob echoes.
Typed proof-byte fields and decoded, re-encoded nested originals are retained;
nested receipt/response summaries also include the recursively decoded values.

Rust projects its existing rich `Operands`. Redundant copied bindings/actions,
spend scopes and ACK origins/commits must agree; a diverged actual field is an
error rather than silently normalized from a header. Go retains semantic values
while its existing decoder reads and validates them, then preserves that exact
decoded result on the accepted packet. It does not use a second raw operand
parser to fabricate the comparison view. The original Go validation order and
refusal checks remain the source behavior; the semantic projection observes
them without redefining their admission decisions.

The new model entry is
`OIP_Wire_Oracle.code_typed_transport_flat_oracle`. Its eight outputs are status,
binding presence/bytes, summary presence, typed IR, canonical Core bytes,
signing-preimage bytes and transport-key IR. The driver calls the distinct
`code_typed_model_identity ()`; the earlier accept/binding ABI and its identity
cannot approve this interface.

The semantic identity has six fields: schema `1`, ABI
`intinf-wire-values-v2`, scope `wire-v6-general-31-values`, the typed entrypoint,
`HOL-Library.Code_Target_Nat`, and the final independently checked source
fingerprint. The model computes these values from its own decoded inputs and
independent identity constants. No source output, expected verdict, public code
commit or model self-hash is injected into it.

## Rust reference boundary

The original reference-path obligation continues beyond common Rust/Go
transport. The dispatcher must forward the exact typed product-boundary values;
the actual returned typed values must drive result conversion, response words,
binding/UUID/signing preimages, exact encoded response bytes and current-client
admission. Product state transitions/storage, identity/evidence callbacks and
cryptographic primitives remain their declared boundaries. An unrelated
`consume_succeeded` boolean or precomputed source result cannot replace them.

The prepared source enum fixture observes actual `ActionReply`, retained
`Receipt`, `DebitResult` and `WireError` before invoking the production result
converter. Its 207 cases preserve full Spend root and commit values, including
different roots with the same commit. Inputs and actual output numbers/commits
are separate streams. This fixture is explicitly a typed boundary fixture and
does not claim dispatcher production provenance.

The normal `check-response-boundary.py` consumes the full sender/client ABI
described in [full-response-consumer.md](full-response-consumer.md). It uses the
distinct Full6 identity and independently executes only model-issued primitive
requests. Its content, public namespace and source fingerprint are separately
pinned and validated.
The result-only codec is a limited diagnostic under the same Full artifact,
not a third identity or a replacement for the original sender/client duty.

The primitive provider accepts only model-issued exact SHA-256/Ed25519 requests
with named preimages/keys/signatures. It uses deterministic public fixture keys.
Source-observed digests, UUIDs and signatures are comparison observations, not
unkeyed primitive answer suppliers. Missing primitive data is incomplete
metadata, never a successful match or a wire refusal.

The existing source replay, same-cut regression and actual signed-response
positive/negative tests remain a separate source regression stage. A financial
co-export, whole product carrier, product-internal replay or storage replay is
not added as a message-layer release condition. Stronger prepared consumers
remain available only under their explicit scope.
