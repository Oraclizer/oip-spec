# OIP v0.6 common product model

This document is part of OIP v0.6.0. It defines the common state and transition boundary for the OIP reference implementation. [Conformance scope](conformance.md) defines the requirement key words.

## Identity and request binding

- A public submission MUST use the authenticated caller identity supplied by its entry point. It MUST bind the call identifier namespace, active session, and claimed caller to that identity. A request body cannot supply the authenticated identity.
- The envelope MUST distinguish the message identifier from the original event key. The signed payload MUST bind those identifiers to the asset, caller, session, authority epoch, revision, and the operation data. The wire specification defines the canonical bytes.
- A new effect MUST use the current authority epoch and revision at its commit cut. The commit cut is the state boundary at which the check and the effect take place. An existing durable outcome is collected through the result path and cannot authorize another effect.
- A lock token MUST bind its asset, lock holder, and generation. The operation consuming the token MUST check the authoritative lock holder and generation before applying an effect.

## Crash and recovery

- The authoritative effect and its recorded result MUST share a durable commit boundary. Durable state includes the original request binding, its outcome, and evidence needed to distinguish an unresolved dispatch from a terminal outcome. A local response cache can be lost independently.
- Crash invalidates the local response cache. Recovery MUST obtain current authoritative state and preserve durable request bindings and outcomes. A recovered endpoint MUST use that state when collecting a prior result. When the current authoritative state is unavailable or conflicts with the supplied recovery evidence, the endpoint MUST hold or reject the operation.
- An unresolved dispatch MUST remain available for reconciliation. Cache loss or a local timeout cannot establish a reversal.

## Interleaving

- When two actions meet the exchange conditions of [compatible service actions](parallel-composition.md), scheduling them in either order MUST preserve each request's result and effect and the state observed by subsequent actions. An action's dependencies include the authority epoch, completion history, and any state or evidence it reads. Different assets alone do not establish that the actions can be exchanged.
- Implementations MUST preserve the order of conflicting actions and the history needed to serve revision-bound reads. A shared authority read can coexist with another read. An authority update can change the result of a concurrent action that reads it.
