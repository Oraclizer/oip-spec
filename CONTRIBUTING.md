# Contributing

Thank you for looking at OIP. Outside review is how a protocol specification
improves, and a report that comes with a concrete input is the most useful
kind.

The contributions that help most:

- **Counterexamples to the rules.** A message frame or a sequence of requests
  where the specification allows something it should refuse, or refuses
  something it should allow.
- **Differences between Rust and Go.** The same bytes producing a different
  decision, error or response in the two implementations.
- **Ambiguous or contradictory text.** A rule that two careful readers could
  implement differently.
- **Missing vectors.** Cases that the files in `tests/vectors/` do not cover.
- **Reproduction reports** on an operating system or architecture we have not
  tested. A failure report is as useful as a success report.
- **Documentation that was wrong or unclear on first read.**

## What is out of scope

- hand edits to generated files: `src/wire/generated.rs`,
  `go/wirepb/oip.pb.go` and `spec/operations.md`;
- edits to the bytes of an existing vector file;
- changes that mix unrelated topics in one pull request;
- material you do not have the right to submit.

## Issues first

Open an issue before you change normative text, the message schema, response
codes, the operation table or the behavior of either implementation, so that
the approach is agreed before you spend the time. Typo fixes, broken links and
tests that do not change behavior can go straight to a pull request.

Suspected vulnerabilities follow [SECURITY.md](SECURITY.md) and never go in a
public issue.

## Where to start

- [`good first issue`](https://github.com/Oraclizer/oip-spec/labels/good%20first%20issue)
  is scoped and has a clear finish line.
- [`help wanted`](https://github.com/Oraclizer/oip-spec/labels/help%20wanted)
  is work the maintainer wants but is not currently doing.

Comment on an issue before you start, so that two people do not build the
same thing. New readers can start with the [architecture](README.md#architecture)
section of the README and [`spec/wire-conformance.md`](spec/wire-conformance.md).

## Development checks

These are the commands that the hosted workflows run, with the same
arguments. You need Rust 1.96.1 through rustup, [Go 1.25.5](https://go.dev/dl/),
Python 3, [protoc 33.5](https://github.com/protocolbuffers/protobuf/releases/tag/v33.5)
and Node.js 24. The workflows set `GOTOOLCHAIN=local` so that the `go`
command does not switch to another toolchain.

```sh
# Rust reference tests, then a list of the tests that need live services
rustup toolchain install 1.96.1 --profile minimal
cargo +1.96.1 test --locked
cargo +1.96.1 test --locked -- --list --ignored

# Go tests, and protoc-gen-go v1.36.8 built from the module requirements
cd go
go test -mod=readonly ./...
go build -mod=readonly -o /path/to/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go
cd ..

# Generated bindings and the operation name view match their sources
python3 scripts/generate-wire.py --check --protoc /path/to/protoc --go-plugin /path/to/protoc-gen-go
python3 scripts/render-operations.py --check

# Links, vector checksums, workflow pins and public-text rules
node .github/scripts/verify-repository-health.mjs
```

`generate-wire.py` accepts only protoc 33.5 and protoc-gen-go v1.36.8. On
Windows, run `python` in place of `python3`.

### Tests that need live services

Some Rust tests exercise recovery and handover against isolated etcd clusters
with mutual TLS, or replay recorded archives. They are marked `#[ignore]`, so
`cargo test` skips them and the workflow only lists them. Each ignore reason
names the services the test needs.

### How long this takes

Measured on the maintainer's machine (Intel Core Ultra X9 388H, 16 cores,
32 GB RAM):

| Command | Time | Conditions |
| --- | --- | --- |
| `cargo +1.96.1 test --locked` | about 40 s | Linux under WSL 2, empty build directory, crates already downloaded, 8 build jobs |
| `go test -mod=readonly ./...` | about 31 s | Windows, empty Go build cache, modules already downloaded |
| `go build` of protoc-gen-go | about 7 s | Same build cache, after the Go tests |
| `python3 scripts/generate-wire.py --check` | under 1 s | |
| `python3 scripts/render-operations.py --check` | under 1 s | |
| `node .github/scripts/verify-repository-health.mjs` | under 1 s | |

Hosted runners take longer because each job also installs its toolchain and
downloads dependencies.

## Generated files and vectors

- After changing `proto/oip.proto`, regenerate both bindings with
  `python3 scripts/generate-wire.py --protoc /path/to/protoc --go-plugin /path/to/protoc-gen-go`.
- After changing `spec/operations.json`, regenerate the name view with
  `python3 scripts/render-operations.py`.
- Checksum files in `tests/vectors/` use the `sha256sum` format. The inputs
  of the model comparisons are pinned by their lock files or the runtime
  source list instead. Tests and checksums refer to existing files by name,
  so new cases go in a new file with its own checksum or pin.

## Changes that affect the pinned models

The required model comparisons run models exported from the
[proof repository](https://github.com/Oraclizer/formal-verification/tree/main/Oracle_Interoperability_Protocol)
next to the code. Each export carries a fingerprint of the runtime sources
listed in [`tests/runtime-source-files.json`](tests/runtime-source-files.json):
every file in `src/`, `examples/` and `go/`, the Python modules in `scripts/`,
and named files that include the Cargo manifests, `proto/oip.proto`,
`spec/operations.json`, the comparison inputs in `tests/` and the pinned
Poly/ML package in `tools/`. A pull request that changes one of these files,
including a Rust or Go dependency update, fails the Tests result check until
the models with the new fingerprint are exported and pinned again in all three
locks: `tests/model-artifact.lock.json`, `tests/wire-response-artifact.lock.json`
and `tests/threshold-raw-artifact.lock.json`. Say in the pull request that the
change needs a new export. Documentation and other files outside the list do
not affect the models.

For the same reason, Dependabot opens pull requests for Rust and Go
dependencies only for security updates
([`.github/dependabot.yml`](.github/dependabot.yml)). Such a pull request
still changes a fingerprinted file, so it is merged together with a new model
export. Updates to the actions that the workflows use are outside the list
and arrive weekly.

## Commit and branch conventions

Write commit subjects in the imperative mood, in English, under 72
characters:

```text
Add a vector for a version 7 frame with an unknown field

The vectors had no case for a newer version that also carries a field this
version does not define. Add one and check that both implementations refuse
it with UNSUPPORTED_VERSION.
```

- English only, including comments and test names.
- One logical change per pull request.
- Branch names describe the change (`test/unknown-version-vector`), not the
  tool or person that produced it.
- Do not add trailers or generated-by attribution for authoring tools.

## Pull request requirements

A pull request should:

- explain the problem and the effect on implementers;
- name the affected specification sections, response codes and vectors;
- keep Rust and Go consistent, or explain why only one side changes;
- include positive and negative tests;
- add a CHANGELOG line for a change that implementers can observe;
- contain no unrelated changes;
- pass the hosted checks.

The maintainer is not obliged to accept a contribution or to respond within a
set time. Security-sensitive changes may need extra review before they land,
because of the risk they carry.

## Contribution rights and license

By submitting a contribution, you confirm that you have the right to submit
it and that it contains no third-party confidential or restricted material.

Unless you state otherwise, a contribution you intentionally submit for
inclusion is licensed under the [Apache License 2.0](LICENSE), without
additional terms or conditions, as section 5 of the license provides.

Meaningful contributions are credited through Git history, the changelog or a
security advisory, as appropriate.
