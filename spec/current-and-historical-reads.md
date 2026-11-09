# OIP v0.6 current and historical observations

This document is part of OIP v0.6.1. [Conformance scope](conformance.md) defines the requirement key words.

## Current observations

- A current response MUST identify its authoritative revision and authority epoch. The endpoint MUST check the authenticated caller's read permission and the expected cut at the same boundary that supplies the value.
- A cache entry MUST be bound to the source authority, query identity, revision and epoch that supplied its value. The endpoint MUST compare those bindings with the same authoritative cut before serving a current response.
- A query touching a source effect or terminal record awaiting primary publication MUST remain busy at that cut. An application value under an active lock MUST remain busy at that cut. These busy rules apply to current, historical and capture-cache reads. Raw data and operation status reads are observations that reader authorization permits, and they return the recorded value without these busy rules.
- If the expected cut is stale, authority is unavailable, or permission has changed, the endpoint MUST fail closed. A failed current check cannot authorize an effect. A cached result cannot supply authority for an effect.

- A source balance is the unallocated source pool at the requested domain and asset, including its retained funded allocation distinction. The pool comes from the selected current or historical cut. The Registry owner controls recovery and does not select the account for this read.

- [CurrentCommitment](state-commitment-sync.md#current-observation) reads the selected synchronization entry for one asset and origin domain. Its current read grant and signed cut are checked with that observation.

## Historical observations

- A historical request MUST name an explicit revision. The endpoint MUST derive the value from that prefix of the authoritative history and label the response as historical.
- The same publication and lock visibility checks apply to the named historical prefix.
- Reading a historical revision MUST satisfy the current caller's read policy. A historical value cannot be consumed as a current precondition.

## Execution

- An operation relying on a current observation MUST recheck the expected revision and authority epoch inside the same commit boundary that applies the operation.
- Execution uses the operation's own authorization, lock and evidence checks. The publication and lock visibility rules govern observation replies.
- A revision or policy change between the observation and that boundary MUST result in a busy or rejected outcome with no financial effect. A successful operation consumes the cut it checked.
