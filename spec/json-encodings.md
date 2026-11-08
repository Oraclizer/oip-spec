# OIP v0.6 JSON encodings

This document is part of OIP v0.6.0. [Conformance scope](conformance.md) defines the requirement key words.

Two groups of bytes in OIP v0.6 are JSON text. The governance blobs `endpoint_contexts_json` and `session_bindings_json` are wire bytes of the protocol core, and [operations](operations.md#blob-types) gives their shapes. The reference profile also signs or hashes JSON text for its tokens, policy bindings, authorizations and source attestations.

## Encoding rules

The JSON text of a value is its compact encoding under the rules below. A producer MUST emit exactly these bytes. A receiver of a governance blob MUST decode it, encode the decoded value again and reject the blob unless the two byte strings are equal.

- The text is UTF-8 with no byte order mark and no whitespace outside strings.
- A record is an object. Its keys are the field names in the declaration order of the record, and each key appears at most once.
- An absent optional value appears as `null`. The exception is the reference configuration record and the endpoint grants it contains, which omit some fields when they are empty or absent, so that a configuration without them keeps its bytes.
- An unsigned integer is a JSON number in decimal digits with no sign, leading zero, fraction or exponent. Every value up to 2^64 - 1 appears in full. A reader MUST NOT pass such a value through a floating-point type.
- A fixed byte array, such as a 32-byte key or digest, is an array of numbers from 0 to 255 in byte order.
- An enum value without fields is a string holding the variant name. A variant with fields is an object with one key, the variant name, whose value is the object of its fields.
- A set is an array of its elements in ascending order without duplicates. Integers compare by value, tuples compare element by element, and enum values compare by the declaration order of their variants. A tuple is an array of its elements in order. A sequence keeps its order.
- A map with integer keys is an object whose keys are the decimal strings of the keys in ascending numeric order. The dependency map of an endpoint context is instead an array of `[key, value]` pairs in ascending key order.
- A string escapes the quotation mark, the reverse solidus and the control characters U+0000 to U+001F. The control characters use `\b`, `\t`, `\n`, `\f` and `\r` where those exist and `\u00` followed by two lowercase hexadecimal digits otherwise. No other character is escaped.

## Reference signing inputs

Each reference signing input is an ASCII domain string, one NUL byte, and the JSON text of the value. The signer signs these exact bytes with Ed25519. Where the table says digest, the reference binds the SHA-256 digest of the signing input instead of signing it. The reference verifies these signatures with strict Ed25519 verification and rejects small-order public keys.

| Domain | Value | Use |
| --- | --- | --- |
| `oip/reference-session/v1` | Session claims: `profile`, `epoch`, `identity`, `session`, `issuer`, `grants_sha256`, `issued_seconds`, `expires_seconds` | Session token signed by the configured session issuer |
| `oip/reference-session-grants/v1` | The configured grants of the session | Digest carried in `grants_sha256` |
| `oip/reference-maintenance/v1` | Maintenance claims: `role`, `profile`, `epoch`, `principal`, `issuer`, `issued_seconds`, `expires_seconds` | Maintenance token signed by the configured maintenance issuer |
| `oip/reference-authority-policy/v1` | The authority configuration record | Digest bound into the retained image as the policy fingerprint |
| `oip/reference-ordered-maintenance/v1` | Maintenance request: `profile`, `principal`, `cut`, `selection`, `action` | Signed ordered maintenance action |
| `oip/reference-successor-ready/v1` | Tuple of recovery profile, current binding, next policy fingerprint and endpoint contexts | Readiness signature of the next key before a handover is selected |
| `oip/reference-handover-consent/v1` | Tuple of recovery profile, current binding, next binding, role, identity and handover proposal | Consent of the current owner or of the successor |
| `oip/reference-legal-order/v1` | Tuple of recovery profile, target, stage tag, call identifier, call payload and order | Legal authority signature of an order stage |
| `oip/reference-enforcement-order/v1` | Tuple of recovery profile, target, call identifier, call payload and order | Enforcement authority signature of an enforcement spend |
| `oip/reference-claim-recovery/v1` | Tuple of recovery profile, identity, session, session epoch, target, origin, call identifier and call payload | Owner endorsement of a recovery request |
| `oip/source-terminal-record/v1` | Source statement: `profile`, `origin_epoch`, `evidence` | Source authority signature of its terminal decision |
| `oip/source-terminal-quorum/v1` | Source statement: `profile`, `origin_epoch`, `evidence` | Vote of a registered quorum signer |

A source certificate is the JSON text of the record with `statement` and `votes`, with no domain prefix.

## Fixed vectors

These vectors come from running the reference serializer on the values shown. Each JSON text decodes and encodes again to the same bytes.

An `endpoint_contexts_json` blob with one context: endpoint 2, epoch 9, grants of principal 7 on the normal route for Reserve and Debit, asset 17 depending on assets 17 and 18, and a write permission of principal 7 on asset 17 with value 1. The grants appear in the declaration order of the permission variants. The blob is 142 bytes.

```text
json: [{"endpoint":2,"epoch":9,"grants":[[7,"Normal","Reserve"],[7,"Normal","Debit"]],"dependencies":[[17,[17,18]]],"write_permissions":[[7,17,1]]}]
hex: 5b7b22656e64706f696e74223a322c2265706f6368223a392c226772616e7473223a5b5b372c224e6f726d616c222c2252657365727665225d2c5b372c224e6f726d616c222c224465626974225d5d2c22646570656e64656e63696573223a5b5b31372c5b31372c31385d5d5d2c2277726974655f7065726d697373696f6e73223a5b5b372c31372c315d5d7d5d
```

A `session_bindings_json` blob binding session 5 to principal 7 at authority epoch 9. The blob is 41 bytes.

```text
json: [[5,{"principal":7,"authority_epoch":9}]]
hex: 5b5b352c7b227072696e636970616c223a372c22617574686f726974795f65706f6368223a397d5d5d
```

For the signing inputs below, the input to sign is the domain bytes followed by the JSON text.

Maintenance claims with role `ReferenceControl`, profile deployment 7, format 1 and authority profile 3, epoch 2, principal 9, an issuer key whose first byte is 1 and last byte is 255 with zeros between, issued 1700000000 and expiring 1700000600. The signing input is 274 bytes.

```text
domain hex: 6f69702f7265666572656e63652d6d61696e74656e616e63652f763100
json: {"role":"ReferenceControl","profile":{"deployment":7,"format":1,"authority_profile":3},"epoch":2,"principal":9,"issuer":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255],"issued_seconds":1700000000,"expires_seconds":1700000600}
input hex: 6f69702f7265666572656e63652d6d61696e74656e616e63652f7631007b22726f6c65223a225265666572656e6365436f6e74726f6c222c2270726f66696c65223a7b226465706c6f796d656e74223a372c22666f726d6174223a312c22617574686f726974795f70726f66696c65223a337d2c2265706f6368223a322c227072696e636970616c223a392c22697373756572223a5b312c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3235355d2c226973737565645f7365636f6e6473223a313730303030303030302c22657870697265735f7365636f6e6473223a313730303030303630307d
```

Session claims with the same profile, epoch, issuer and validity window, identity principal 9, domain 4, OCID 11 and RAI 12, session 5, and a grants digest whose second byte is 16 with zeros elsewhere. The signing input is 382 bytes.

```text
domain hex: 6f69702f7265666572656e63652d73657373696f6e2f763100
json: {"profile":{"deployment":7,"format":1,"authority_profile":3},"epoch":2,"identity":{"principal":9,"domain":4,"ocid":11,"rai":12},"session":5,"issuer":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255],"grants_sha256":[0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"issued_seconds":1700000000,"expires_seconds":1700000600}
input hex: 6f69702f7265666572656e63652d73657373696f6e2f7631007b2270726f66696c65223a7b226465706c6f796d656e74223a372c22666f726d6174223a312c22617574686f726974795f70726f66696c65223a337d2c2265706f6368223a322c226964656e74697479223a7b227072696e636970616c223a392c22646f6d61696e223a342c226f636964223a31312c22726169223a31327d2c2273657373696f6e223a352c22697373756572223a5b312c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3235355d2c226772616e74735f736861323536223a5b302c31362c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c305d2c226973737565645f7365636f6e6473223a313730303030303030302c22657870697265735f7365636f6e6473223a313730303030303630307d
```
