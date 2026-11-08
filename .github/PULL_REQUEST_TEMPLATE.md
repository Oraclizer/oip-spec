## Scope

Describe the problem, the affected specification sections or behavior, and
why this is the smallest complete change.

## Specification and compatibility impact

- [ ] I identified every affected rule, response code, message field and
      stated limitation.
- [ ] Rust and Go stay consistent, or this pull request explains why only one
      side changes.
- [ ] Existing vector files and their checksums are unchanged; new cases are
      in new files.
- [ ] Generated files were regenerated from their sources, not edited by hand.
- [ ] CHANGELOG.md has a line for any change that implementers can observe.

## Verification

- [ ] `cargo +1.96.1 test --locked`
- [ ] `go test -mod=readonly ./...` in `go/`
- [ ] `python3 scripts/generate-wire.py --check` with protoc 33.5 and
      protoc-gen-go v1.36.8
- [ ] `python3 scripts/render-operations.py --check`
- [ ] `node .github/scripts/verify-repository-health.mjs`
- [ ] Positive and negative tests for the changed behavior

## Security and provenance

- [ ] No credentials, personal data, private paths, raw logs or restricted
      material.
- [ ] No trailers or generated-by attribution for authoring tools.
- [ ] I have the right to submit this contribution, and I submit it under
      the Apache License 2.0 as described in CONTRIBUTING.md.
