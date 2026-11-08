# Pinned Linux model runtime

The existing lock targets Ubuntu 24.04 amd64 and Poly/ML `5.7.1-5build1`.
Its three package SHA-256 pins are unchanged. Ubuntu 26.04 does not satisfy this
recipe. Changing an OS label, weakening the release guard or accepting a newer
package is not a reproduction of that lock.

The lock's `runtime_compatibility` value records its preparation-time status
and stays in the frozen runtime-source fingerprint. It is not the execution
record for a later selected model. Model-bound execution receipts establish
that model's actual identity, ABI and comparisons on the locked runtime.

The workflow uses an `ubuntu-24.04` GitHub-hosted runner and a local userspace
extraction. Package download and extraction receipts record the locked bytes;
separate model-run receipts record the identity, ABI and value comparison on
that runtime. An extraction or version string alone is not a model execution.

```sh
python3 scripts/prepare-polyml-userspace.py
target/polyml-userspace/bin/poly --version
python3 scripts/check-operations.py --require-mirror \
  --polyml target/polyml-userspace/bin/poly
```

The preparation script checks the real OS/architecture first. It uses the actual
`apt-get download` command to obtain only the three exact versions, verifies all
three package digests, then uses `dpkg-deb --extract` into `target/`. It invokes
neither package maintainer scripts nor a system package installation. A wrapper
selects the extracted shared-library directory. Missing APT metadata, libraries,
an incompatible runtime or unavailable package bytes cause a failure. There is
no latest-version fallback.

Already downloaded and independently byte-checked packages can be supplied with
`--package-dir DIR`. This does not bypass any SHA-256 or OS check. The extraction
receipt is explicitly not a Poly/ML execution receipt.

The source-bound runtime job retains the workflow's public-only execution rule
and is included in the `Tests result` aggregate. Missing or failed model jobs do
not become successful aggregate results. Private copies skip every hosted job
and use reviewed local execution instead.

Official references:

- [GitHub-hosted runner labels and environments](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Ubuntu Noble Poly/ML package](https://packages.ubuntu.com/en/noble/polyml)
- [Ubuntu apt-get download and version selection](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html)
- [Ubuntu dpkg-deb extraction](https://manpages.ubuntu.com/manpages/noble/man1/dpkg-deb.1.html)

Raw model streams are uploaded with the pinned
[upload-artifact v7.0.1 source](https://github.com/actions/upload-artifact/commit/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a).
Their retention is for run review and is separate from the independent,
content-addressed model publication.
