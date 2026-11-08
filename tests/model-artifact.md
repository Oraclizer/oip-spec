# Executable model artifact

The required operation check compares every selected frame with Rust, Go and
the independently generated executable model. A missing, stale or incomplete
model is a failed check. Two-language or custom-command diagnostics do not
satisfy the required check.

## Content pins and source identity

`model-artifact.lock.json` pins the generated ML, its data driver and an
independent export-origin record and an exact compiler-diagnostic allowlist by SHA-256 and content-only Git blob identity.
The Code repository does not pin a whole formal-verification commit. A separate
consumer manifest in the proof repository binds the final Code commit, so the
two repositories do not require each other's final commit hash.

Publishing a cleaned history gives the public root commit a new identity.
The artifact lock, model identity and export contain neither the development
nor public Code commit. If the runtime/interface bytes and their fingerprint
are unchanged, keep the verified model bytes and update only the proof
repository's separate consumer manifest to the new public Code commit/tree.
Do not regenerate a model merely to follow a changed commit identity.

`runtime-source-files.json` binds every regular file and its relative path in
`src/`, `examples/` and `go/`. This includes the compiled comparison consumers,
the signer, automatically included Go sources and embedded/assembly inputs.
Python source under `scripts/` is also inventoried, including new helper modules.
The operation table and pinned Poly/ML package configuration are explicit inputs.
The inventory is deliberately conservative and includes non-behavioral files.
Generated Python bytecode is outside the source inventory; the interpreter,
compiler and CI host remain trusted. New other transitive data inputs require
policy review.
Keep build outputs outside these source directories. Cargo/Go manifests,
generated bindings and the JSONL judge/schema are also bound; optional project
build/toolchain inputs are bound as present or absent. The artifact lock,
generated model/driver/origin/diagnostics and downstream consumer manifest are excluded.
The policy file is itself included in the fingerprint. A source file addition,
removal or change therefore invalidates the existing model identity pin.

The repository root and each existing source-path component are checked with
`lstat` before suffix filtering or directory traversal. Symbolic links, Windows
junctions/reparse points and regular files with more than one hard link are
rejected, including entries whose suffix would otherwise be ignored. Directory
children are inspected before descending, and optional inputs are absent only
after their existing parents pass inspection. This prevents excluded model
metadata from re-entering the source fingerprint through a filesystem alias.
Use ordinary copied files in a fixed checkout during hashing. The compiler,
interpreter and CI host remain trusted; this is a source-inventory rule.

The executable model reports schema, `intinf-wire-values-v2`, general version-6
transport scope, entrypoint, `HOL-Library.Code_Target_Nat` and runtimeSourceHash
once before any result. The consumer computes its expected source hash from
its own checkout and the fixed lock; it never derives the expectation from the
model's self-report. Hashing the judge source is metadata binding and does not
generate a classifier from expected fixtures. The model never receives the
`expected`, family/opcode labels or regression seed.

The shared 64-bit execution-input domain limits `max_frame` and `max_nesting`
to 0 through 2^63 - 1: Go uses a signed `int` while Rust uses `usize`. Other
unsigned header/boundary integers keep their u64 domain. A value outside the
shared host-size domain is bad adapter metadata and fails as an execution
input; it is not converted to a protocol refusal code. The serializer checks
this before launching the backend, and the model integer ABI must use the
same metadata domain. This does not change the meaning of valid wire frames.

The classifier is independent of its identity constants. No Code commit, test
result, whole-FV commit or self-content hash is inserted into the model.
Code_Target_Nat must be part of the checked export, and the integer ABI must
be IntInf.int. The bound `verified_export_sha256` fixes the actual exported
bytes checked by the producer, not a guessed or hand-translated program.

## Runtime

The Ubuntu 24.04 amd64 CI recipe extracts exact Poly/ML 5.7.1-5build1 package
bytes into a local userspace directory; see [the Linux recipe](linux-model-runtime.md). The interpreter, modules and library package
digests are recorded separately in `tools/polyml-noble-amd64.lock.json`.
Installing a runtime does not by itself establish compatibility with an ML
export; the final artifact must be compiled and compared on that runtime.

The consumer uses `--minheap 16M --maxheap 1024M --gcthreads 1 --error-exit`
and a bounded execution timeout. The heap limit is not a total process-RSS
measurement. Only the data driver and exact generated ML are loaded; no
Isabelle session or saved proof heap is needed for the standalone comparison.
Crypto verification and the independent attestation callback remain explicit
boolean inputs to the model. Raw packet and operand classification are model
code, not adapter rules.

Run the required check with:

```sh
python3 scripts/check-operations.py --require-mirror --polyml target/polyml-userspace/bin/poly
```

For a local copy of the same already verified model, driver, export-origin
and compiler-diagnostics files, pass `--model-artifact-root DIRECTORY` and an explicit standalone
`--polyml EXECUTABLE`. All file and source identity checks still apply. A -1
model status, unknown status, mismatched identity, duplicate or missing row
fails. No shell interpolation is used for the model command.

If Code is published before the pinned proof artifacts, the required model
job may fail with a missing-blob response. It remains a failed intermediate
state. After the exact pinned artifacts are published, rerun the failed job
for the same Code commit and require all final checks to succeed. Do not use
an unpinned fallback, skip or `continue-on-error` to hide that interval.

## Exact compiler output

Both model streams are preserved as raw bytes. The fourth pinned artifact,
`compiler-diagnostics.json`, names the exact model and driver SHA-256 values and
lists only exact permitted diagnostic blocks. The origin also binds that file's
digest. An unrecognized line or altered warning is an error, not ignored text.
No model result or public code commit is introduced into the model identity.

The additional [reference execution capabilities](reference-execution.md) use
separate unbound locks. A finite financial match does not establish whole
replay or current-service equivalence; these stronger prepared consumers are
separate from the normal wire release condition.

## Typed value ABI

The typed interface is described in [wire-values.md](wire-values.md).
It uses `code_typed_model_identity ()`, not the old accept-only identity.
The exact typed values/core/preimage/key must all be produced by the exported
model. A verdict/binding-only model output is incomplete metadata.
The bound `public_namespace`, content and source pins identify the checked
logical export. Public blob availability and normal hosted execution require
separate verification from that namespace export. The public code commit is
excluded from model identity/origin/locks.
