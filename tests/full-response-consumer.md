# Full sender and current-client consumer

The Full consumer checks the original message boundary using the checked
public namespace, independently co-exported identity and unedited Full ML.
Its lock binds exact model, driver, origin and diagnostic content together
with the current source fingerprint. Missing or stale pins fail the check;
interface controls or legacy source identities cannot satisfy it.

The Full identity is exactly six ASCII integer-list fields:

```text
1
intinf-response-full-v1
wire-response-sender-client-v1
OIP_Wire_Response_Boundary.code_response_egress_flat_oracle
HOL-Library.Code_Target_Nat
28500a91beb9478d3de97ed0d9a2913bf7ea3202a5b546627e02df53b998b207
```

`code_response_full_model_identity ()` is a separate fixed constant helper.
The lock's `identity_function` must match this function and its paired
entrypoint; the independent origin repeats both. The typed wire judge retains
its distinct `code_typed_model_identity ()`/typed-entry pair. No public commit,
self-content hash, runtime PASS or caller-supplied fingerprint enters either
model identity.

## Independent request execution

The sender receives only finite getter snapshots, raw original request bytes
and actual typed pre-converter return values. Original-preflight-only cases use
mode 3 with empty reply and retained data. A ready caller with no actual typed
return is incomplete metadata; no dummy Outcome is invented.

The planner emits exact length-prefixed SHA-256, Ed25519-sign and verify requests.
The broker executes each key/preimage/signature request independently with the
current Rust test provider. It fills only unique exact transcript keys. Missing
verification is never false, and missing signing is never an empty signature.
Unfilled requests, status -1/-2, stalled planning, unexpected callback aborts,
unknown output lines or changed artifact diagnostics stop actual execution.
Source-observed digests, UUIDs, preimages, signatures and packets are not sender
answers or inputs. Model-generated sender packet row 12 is forwarded internally
to the combined current-client entry. Standalone clients receive separately
recorded protocol network inputs captured before their actual API call.

Sender success retains all fifteen rows from `response-full-abi.json`. Prefix
observations retain fourteen separate rows. In particular, a signer method
attempt can be rejected by its metadata guard without invoking the curve
primitive. Attempted preimage, guard result, actual curve signature and final
returned packet are distinct observations. The current client returns a typed
nine-field Known/Unknown value, including category, number, id and commit.

The deliberate missing-record control runs in a separate model process. It
requires either exact missing-metadata status or the named missing-primitive
abort after the same model identity has loaded; arbitrary compile/environment
failures do not count as sensitivity evidence. Raw input/stdout/stderr are
preserved before any diagnostic separation.

## Source provenance

The 207 converter/encoder cases remain lower boundary fixtures. Their actual
input enums are captured separately from production conversion, constructor
prefixes, signer calls and final packet/error observations. They do not execute
the original dispatcher or original preflight.

The original-operation fixture has fifteen caller branches, ten noncaller
branches and six configured refusals. It executes the production
`OrderedDispatcher::receive`/submit/wait/shutdown methods and actual message
methods with actual Ed25519 security. A test-only factory compiles the exact
production worker while-body against MemoryCAS plus OrderedHead. Runtime and
static checks require the copied body to remain byte-identical. Production
`OrderedDispatcher::start` and its WitnessHead/Etcd backend are not executed by
this fixture and are explicitly not credited. Actual run_operand and
execute_durable entry/return events are observed when reached; authorization or
proof refusals are not promoted to successful product-boundary execution.

Before and after images are separate source observations. They are not model
states or expected outcomes. A source/model match remains scoped sample
evidence. Identity, source attestation and storage/witness provenance retain
their declared provider contracts; a bounded match does not refine those
providers. Financial co-export, whole-product carriers and internal
storage/world replay are not added as release conditions.

The normal workflow records original source and current-client inputs, executes
the default Full consumer, and requires its existing aggregate status. The
public-only job conditions and exact Ubuntu 24.04 package pins remain intact.
Package custody, genuine Ubuntu model execution and public artifact
availability require separate receipts. An OS label or extraction recipe alone
does not establish any model comparison or hosted CI result.
