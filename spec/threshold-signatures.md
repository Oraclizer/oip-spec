# OIP version 6 threshold envelope signatures

[Wire conformance](wire-conformance.md) defines the canonical Packet and the order of receiver checks. [Conformance](conformance.md) defines the requirement key words.

## Current group selection

For signature scheme 2, Core `key_id` identifies a threshold group. The receiving host MUST select exactly one current registration for the deployment, source domain, principal, key identifier and authority epoch. Two matching registrations make the selection invalid even if their member lists are identical. Registration binds the context to a positive quorum and a set of members. Member identifiers are unsigned 64-bit integers. The identifiers and their Ed25519 public keys MUST be distinct. Each key MUST satisfy the canonical public-key requirements of SINGLE. The quorum MUST be within the registered member count.

The installed channel authenticates the peer and selects the permitted schemes. Its negotiation keys identify the channel peers. The current registered group supplies the member keys for scheme 2. A host must supply the current registration again after opening or transferring a selected authority. A persistent reference authority MUST bind the group to the policy selected for its current cut.

## Signature field

Packet field 2 consists of an unsigned 64-bit big-endian count followed by exactly that many records. Each record holds one unsigned 64-bit big-endian member identifier and a 64-byte Ed25519 signature. Member identifiers MUST increase strictly and the final record MUST end at the end of the field.

The receiver MUST enforce the configured complete Packet size before reading the count. The actual field length is `8 + 72*n`. The receiver MUST derive the available record count from the actual field length and compare it with the declared count and registered member capacity before allocating from the count or verifying the records. Numeric conversions and length arithmetic MUST be checked.

Every member in the field MUST be in the selected current group. Its signature MUST pass the strict SINGLE Ed25519 rule for that member's key and the exact canonical Core envelope signing input. This input includes the scheme, group key identifier and authority epoch. The field must contain at least the registered quorum. The receiver verifies every supplied signature, including signatures beyond the quorum.

## Admission and retries

An unknown scheme and an empty scheme 2 signature field fail canonical format. When a canonical scheme 2 Packet reaches signature admission, an unselected scheme, missing current roster, invalid registration, malformed payload, nonmember, unmet quorum or invalid signature receives INVALID_THRESHOLD_SIGNATURE. Earlier format, scope and delivery-time checks keep their results. A scheme 2 Packet is verified under the selected current threshold group.

The receiver MUST use the exact canonical Packet and the current applicable registration at authoritative execution, publication reauthorization and exact authorized resolution. A check that consumes an earlier admission result MUST bind it to the same selected current policy and Packet. The receiver's transport binding follows authentication and the applicable operand and source checks. An exact retry uses the existing call and transport rules.

The reference verifies the original envelope under its configured scheme before issuing a correlated response. The response issuer uses the installed reference signing key. The Go layer implements configured envelope admission, operand decoding and transport binding. Rust implements the authoritative execution and response paths.
