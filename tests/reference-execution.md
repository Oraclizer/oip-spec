# Source-bound reference execution

This interface records source regressions separately from executable model
comparisons. A successful Rust observation test is a source test; it does not
establish model agreement or full implementation refinement. The normal wire
consumers have their own typed and Full artifact locks; the stronger financial
and internal replay capabilities below use separate prepared locks.

The source producer reads configuration, genesis, signed session tokens and raw
packets from input-only fixtures. It calls the existing `Ed25519Security`,
`PersistentAuthority` and `OrderedHead` implementations. Its memory control-store
fixture performs exact revision-and-byte CAS. It does not replace a production
admission or financial predicate. The external store and source truth remain
trust boundaries.

| Capability | Input and observation scope | Required model state |
| --- | --- | --- |
| Transport | 180 fixed plus 512 seeded inputs covering admission, retained and re-encoded Core, typed values, signing preimages and transport keys | The independently pinned typed wire export and identity |
| Finite financial slice | Two genesis seeds plus six raw Reserve/Dispatch/Debit steps; original selector, credential/payer, produced financial result and commit projections | A same-source `finite-financial-raw-slice-v1` export and identity |
| Reference replay | Fifteen input rows: two genesis rows and thirteen external stimuli | Full executable model and input-only consumer ABI are not yet received |
| Same-cut regression | Three separate rows: one genesis, duration-zero refusal and a normal Reserve using the same signed cut | Paired current-service model and consumer ABI are not yet received |
| Signed response | Eighteen fixed positive, semantic-negative and Query precedence cases using the actual signer and public admission API | Source-only regression; the separate sender/current-client comparison is specified in [full-response-consumer.md](full-response-consumer.md) |

The original fifteen-row input file is preserved byte-for-byte. The replay
fixture adds explicit, deterministic test-key roles to its genesis configuration;
it adds no stimulus or expected outcome. The same-cut regression has a separate
file, row count and comparison gate. The frozen `wire-conformance.tsv` is unchanged.

Run the source producers from a fresh output path:

```sh
python3 scripts/run-reference-source.py --output target/reference-execution
```

They preserve raw Rust stdout/stderr, before/after product images, retained calls,
wire bindings, actual signed replies, physical control revisions and exact
selected record/head bytes. Physical control revision, product cut and commit
position are distinct coordinates. Neither these observations nor the fixed
regression expectations are accepted as model inputs.

The following explicitly requested stronger prepared comparison is separate from the normal wire release duty:

```sh
python3 scripts/check-reference-execution.py \
  --source-output target/reference-execution \
  --output target/reference-model-comparison --scope all \
  --polyml target/polyml-userspace/bin/poly
```

It fails closed while a mandatory capability, model ABI, same-source identity,
kernel export seal or artifact pin is missing. Unknown, Unsupported, Pending and
skipped results are never matches. A full replay/current-service driver has not been received. This prepared diagnostic is not a new automatic message release gate. Its actual ABI and consumer must be
reviewed when the executable model arrives.

The limited financial check cannot satisfy the stronger `--scope all`
diagnostic and is separate from the normal wire release condition:

```sh
python3 scripts/check-reference-execution.py \
  --source-output target/reference-execution \
  --output target/financial-model-comparison --scope financial \
  --polyml target/polyml-userspace/bin/poly
```

Its serializer reads only genesis/configuration and packet bytes. The model
produces its own runner state, financial outcome and result vector. Only after
execution does the comparator project the saved actual source observation.
The comparison excludes actual token/cryptographic authentication, current
service equality, retained retry/resolver semantics and exact storage bytes.

The six financial identity fields, encoded as ASCII `IntInf.int list list`, are
schema, ABI, semantic scope, raw-step entrypoint, natural-number refinement and
runtime source fingerprint. `OIP_Finite_Financial.code_finite_model_identity ()`
must be exported from the same checked source as the seed, raw step and view.
The identity excludes its own ML digest, origin/kernel seals, result claims and
the public code commit. Model/driver/origin/diagnostic content pins are separate.

All repository-owned Rust consumers, Python helpers, fixture data, schemas and
the finite driver are covered by `runtime-source-files.json`. Alias inspection
precedes filtering or traversal and rejects symbolic links, Windows reparse
points, hard-linked regular files and non-regular entries. Model locks and
downstream commit metadata remain outside the footprint to keep it acyclic.

Model stdout and stderr are saved as original bytes before parsing. Only exact
diagnostic blocks bound to the particular model and driver digests may be
separated. An unknown line, changed warning, unexpected protocol row, missing
identity or result count/order mismatch fails the check. There is no generic
warning or compiler-output ignore rule.
