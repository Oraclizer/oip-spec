# OIP v0.6 response code allocation

This document is part of OIP v0.6.1. [Wire conformance](wire-conformance.md) defines response validation, effects and retry behavior. [Operations](operations.md) defines recorded code compatibility for each call.

A version 6 response code is assigned at most once. An addition MUST preserve every existing code, its response kind, commit presence, compatible call types, effect and retry behavior. An assignment MUST include a fixed kind and commit presence, the effect and retry rule, and the closest v0.5 correspondence or a statement that there is no equivalent. The operation table, its rendered view, the wire text and both implementations MUST agree on each assignment.

| Numeric range | Response kind | Commit position |
| --- | --- | --- |
| 1 to 9 and 30 to 49 | Recorded | Absent |
| 10 to 29 | Recorded | Present |
| 50 to 69 | Delivery | Absent |
| 70 and above | Refusal | Absent |

For an already recognized original request, a version 6 verifier that knows every other response field and does not know the added code applies its unknown-code rule. This rule classifies the response by kind and uses that kind's commit presence conditions. The numeric ranges govern assignment. The unknown-code receiver continues to use the kind and commit presence in the actual response.

| Code | Name | Kind | Commit | Effect and retry | Closest v0.5 |
| ---: | --- | --- | --- | --- | --- | --- |
| 29 | STATE_COMMITMENT_SYNCED | Recorded | Present | The authorized stream entry is committed. An exact authorized retry returns the same recorded result. | ACK type PROCESSED |
| 39 | STATE_COMMITMENT_MISMATCH | Recorded | Absent | The mode or predecessor fails its check. The call identifier is consumed. Use a fresh signed call after obtaining the current entry. | STATE_HASH_MISMATCH |
| 40 | STATE_COMMITMENT_STALE | Recorded | Absent | The source position or origin event fails its freshness check. The call identifier is consumed. New work requires fresh source evidence and a fresh signed call. | None |
| 41 | SOURCE_ATTESTATION_REJECTED | Recorded | Absent | The selected source registry or proof fails validation. The call identifier is consumed. Correct the evidence and use a fresh signed call. | INVALID_DRIVER_ATTESTATION |

The new assignments are recorded outcomes of the synchronization call. A verifier MUST reject a known code with a different kind, incompatible call or different commit presence. Compatibility vectors MUST exercise each assignment with the correct and incorrect commit presence, including the earlier verifier's unknown-code classification at the response status layer.
