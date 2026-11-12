# Disclaimer

## What this repository establishes

The Rust reference builds with the pinned toolchain and dependency versions
and passes its tests, including the shared vectors in `tests/vectors/`. The
Go message layer passes its tests with Go 1.25.5. The committed Rust and Go
bindings are byte-identical to what the pinned generators produce from
`proto/oip.proto`, and the operation name view matches its source table.
Each of these results comes from a command in
[CONTRIBUTING.md](CONTRIBUTING.md#development-checks) that anyone can run on
a given commit, and the hosted workflows run the same commands.

Within those tests, the reference refuses malformed, unsupported, expired,
replayed and wrongly signed messages before any state change, and Rust and Go
reach the same decisions on the vector frames.

The hosted runs also compare the code with formal models. Rust, Go and a
typed transport model exported from the Isabelle/HOL theories in
[Oraclizer/formal-verification](https://github.com/Oraclizer/formal-verification/tree/main/Oracle_Interoperability_Protocol)
agree on 692 transport inputs, Rust and the exported full response model
agree on 261 response inputs, and Rust, Go and the exported threshold
signature model agree on 22 THRESHOLD packets. The model files are pinned by
SHA-256 and Git blob. The theorems about those models hold under the
assumptions they name; the [README](README.md#formal-verification) describes
how the two repositories connect.

## What this repository does not establish

- **Reference scope.** The reference models each state change as one commit
  under exclusive access and takes caller identity, keys, reference time and
  durable storage from trusted adapters. It is not a production service.
  Tests that need live etcd clusters, mutual TLS stores or recorded archives
  are not run in CI.
- **No audit.** Neither the specification nor the code has had an independent
  security audit.
- **Testing scope.** Passing tests and model comparisons cover the tested
  inputs. The correspondence between the Rust source and the models is
  maintained by hand for selected operations. No result proves that every run
  of the compiled Rust or Go code matches the models, and no compiled binary
  or deployment is verified.
- **External facts.** Regulatory operations carry legal decisions made
  elsewhere. OIP checks who sent them and records them. It does not decide
  whether they are lawful, and it does not confirm identity, policy or
  ownership claims made outside the protocol.
- **No advice.** Nothing here is legal, regulatory, financial, investment or
  operational advice.
- **Versions and forks.** These statements apply to the versioned source in
  this repository. A fork, a modified copy or a deployment falls outside them
  until it is checked on its own.

Users are responsible for their own review, testing, security assessment,
deployment decisions and compliance obligations.

The repository is licensed under the [Apache License 2.0](LICENSE). The
license, including its disclaimer of warranty and limitation of liability, is
the controlling legal text, and this summary does not replace it.
