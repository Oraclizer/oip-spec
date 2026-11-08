# Actual signed-response regression cases

`signed-response-cases.json` is a fixed test description, not a runtime receipt.
The Rust fixture creates an actual Ed25519 profile and channel, verifies the
original signature, and obtains response parameters/signatures from
`Ed25519Security`. The keys are deterministic public test fixtures.

The profile retains principal-keyed peer registrations. Two principals share
domain 0 with different public keys; the response peer projection retains both
`(domain, key)` pairs. The local response principal, local key identifier and
response public key are separate fields. The actual `parameters` call reads
clock value 105 and the actual `sign` call independently reads 106. Neither
the peer projection nor the clock behavior is replaced by the ordered-test
`Rules` provider.

| Expected request | Embedded original | Expected public API result |
| --- | --- | --- |
| Ordinary Debit | Same Core; Debited result and matching commit | Accepted known Debited response |
| Ordinary Debit | Same Core; Reserved success code | InvalidFormat (70) |
| Query 1 through 7 | Same Core and no caller id | InvalidFormat (70) |
| Query 1 through 7 | Different valid ordinary Core | ReplayConflict (76) |
| Query 8 | Same or different original | InvalidFormat (70) from depth-one expected decoding |

For Query 1 through 7, the expected Core decodes before comparison. A byte
mismatch short-circuits the caller lookup, giving 76. Equal bytes reach the
missing caller and give 70. Query 8 fails expected decoding at depth one first.

The separate consumer-removal copy changes only
`original != expected.core_bytes() || id != caller_id(&expected_operands)?`
to `id != caller_id(&expected_operands)?`. It must compile and execute the same
signed inputs, then fail the fixed Query mismatch semantic assertion because
the actual public API returns 70 instead of 76. A compile failure does not
establish that semantic contrast. Raw observations are persisted before the
final assertion, and source/input hashes identify each variant externally.

These are source API regressions, not a claim of full model refinement,
cryptographic library verification or a product defect. The production source
keeps its original comparison predicate.
