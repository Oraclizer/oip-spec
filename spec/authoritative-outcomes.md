# OIP v0.6 authoritative outcomes and publication

This document is part of OIP v0.6.0. [Conformance scope](conformance.md) defines the requirement key words.

## Call identity and completion

- An authority MUST bind a call identifier to the authenticated caller namespace and the entire admitted request, including its operation and any lock credential. The transport message identifier and the original event key have separate meanings.
- The authority MUST record the accepted binding, reply and effect in one durable commit. Authenticated calls that complete with rejection, busy or unavailable MUST record that outcome through the same authority. Caller authentication, endpoint capability and complete signed-request verification are checked on every submission; their failure is refused without recording an outcome or consuming a fresh call identifier. When the authority endpoint is up, an existing call identifier is handled through the retained-result path, including the caller's current result-access authority, before fresh-call checks. For a fresh submission, pre-execution proof authentication, any required recovery endorsement, and consistency between the supplied expected cut and the signed request are checked before recording a new outcome; their failure leaves the call identifier unconsumed. For a fresh admitted ordinary call, an unavailable authority source records Unavailable before staleness is considered. If that source is available, a signed cut that no longer equals the current cut records Busy. A command-specific grant refusal reached by the authoritative ordinary consumer records rejection. A recorded Unavailable outcome is distinct from a transport or storage error that leaves the authoritative outcome undetermined. A client that cannot reach the authority can wait and reconcile, since transport silence cannot establish a completed outcome.
- A retry of the exact admitted call MUST return the existing outcome without executing another effect. Reusing the identifier with different content MUST be rejected. Collection of the existing result still requires the caller's current result-access authority.
- Completion MUST follow the durable authoritative result, the primary publication when the operation requires one, and any release the operation requires. A debit that remains pending retains its obligation and its lock conditions.

## Original event consumption

- Every terminal entry point MUST use one authoritative decision slot for the original event key, independent of the transport message or route. The slot binds the source event, asset, amount, destination, recipient and origin authority epoch.
- An identical binding and decision MUST be recognized as a duplicate. A conflicting binding or decision MUST be rejected before any new financial effect. Updating admissible supporting evidence preserves the committed binding and decision.
- An event has at most one settlement effect. A confirmed decision and a reversed decision for the same original event cannot both take effect.

## Primary publication and secondary settlement

- A committed primary decision MUST remain immutable. Its publishable observation MUST refer to the exact committed decision and its completed financial effect.
- Secondary settlement MUST use a separate queue, keyed by the same route-independent settlement identity on every retry. That identity is derived from the immutable primary commitment and its original event.
- Acknowledgements MUST match the exact queue entry and primary commitment. A wrong acknowledgement cannot complete the entry. Secondary failure or retry cannot change the primary decision, re-open pending source mass, or issue a refund.
