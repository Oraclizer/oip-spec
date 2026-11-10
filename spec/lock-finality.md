# OIP v0.6 lock and finality rules

This document is part of OIP v0.6.1. It defines the common checks for transfers and related lock operations. [Conformance scope](conformance.md) defines the requirement key words.

## Lock authority

- Every endpoint that changes a lock or consumes its authority MUST check the same authoritative asset, original event key, lock holder, generation, and authority epoch at the operation's commit cut. Reserve and Preempt carry no lock credential and check no lock holder or generation. Reserve requires that no lock exists for the original event and that no active lock covers its footprint. Preempt requires that the existing lock for the same binding has expired and still covers its footprint.
- Reassigning a lock MUST invalidate the previous generation. Changing the authority context MUST invalidate tokens issued under the previous context. Endpoints sharing an authority epoch MUST install the replacement contexts together. Normal, administrative, and adapter entry points MUST enforce these conditions before state changes.
- A lock covers the requested asset and the dependencies designated by its authoritative lock context. Acquisition MUST reserve that entire footprint atomically. A lock-consuming request MUST match the current version of every recorded footprint member. A member that the request's version list omits is compared as version 0. Credit and Preempt do not check versions.
- A lock's holder and the asset's owner are separate roles. Cancellation, fencing, and preemption MUST consume their own required permission at the current cut. Holding one role does not confer another role's permissions.
- Before the source debit, Cancel of a held lock or Fence of a dispatched lock MAY end an obligation, since it prevents any later source effect for that binding. After the source debit, Cancel and Fence MUST be rejected, and Preempt MUST preserve the pending financial obligation and its recovery authority.

## Write in the reference profile

The reference accepts Write at LOCK_MANAGEMENT opcode 7. The operand layout and result code are specified in [Operations](operations.md). Before committing the write, the authority MUST check the signed current cut, the current caller's execution and exact value permission for the asset, the held reservation and current lock credential and generation, and the signed versions of the affected footprint. A reservation that has expired cannot authorize the write. A missing permission, wrong generation or mismatched version MUST leave the application value and its version unchanged.

When these checks hold and the asset version can advance, the authority commits the requested value and the next asset version and records DATA_UPDATED with its commit position. The value, current observation and exact result are retained in the same authoritative history. The same authorized original call returns its retained result on retry, including after reopening the authority. A fresh request at an obsolete cut receives Busy. The existing admission and delivery rules apply before product execution.

## Reference source attestations

A registered external source commits its exact terminal decision to its own durable source journal using its decision key. The source journal accepts one exact decision per origin. A registered quorum signer reads that record through its source reader and signs a purpose-specific statement. The signer receives neither the journal writer handle nor a caller-selected terminal result. Each statement binds the deployment profile, full transfer binding, kind, reference and preserved origin epoch.

The receiving authority verifies distinct signer identifiers and distinct registered public keys against the applicable source and origin epoch. The current caller's authenticated session and epoch are separate. A confirmed credit consumes a retained exact source decision. Refund and reconciliation also verify the matching source proof and the current owner's endorsement of the exact request. Source storage MUST supply its own latest authenticated record. The receiving authority's independent archive and witness protect its own retained consumption.

The reference source uses its own independent selection store with a separate authenticated cluster, endpoint, trust and key. Each quorum signer reads the journal first and the current independent selection last. It signs only if the journal's exact value and key revision match that selection. The source writer reserves one exact signed addition at the witness, prepares the journal, then selects that exact prepared value with a witness compare-and-set. While reserved, unavailable or mismatched, the source cannot issue votes or skip to another addition. Initialization explicitly binds two empty keys. A separately restored journal can resume signing after the trusted writer restores the exact selected bytes and binds their new journal revision. This recovery depends on separate custody of the source witness.

## Pending mass and terminal evidence

- A source debit MUST move the corresponding amount from active mass to a pending obligation bound to its original event and immutable transfer details. Initialization (genesis) MUST establish the initial balance and supply conditions used for conservation.
- Each original debit MUST be consumed at most once. A pending obligation cannot be spent, debited a second time, or reissued. Active mass plus pending mass is conserved by each covered transfer transition.
- Exact confirmed source evidence MAY move the pending amount to the bound destination once. Exact reversal evidence MAY return it to the bound source once. Acceptance MUST check the original event and binding, including the amount, owner, and destination. Once terminal, an obligation cannot reopen or reach the opposite outcome.
- A successful credit consumes pending mass and leaves the reservation in place. A reconciliation with the exact confirmed record and a current unexpired lease releases it without moving funds. An expired lease MUST be reassigned before reconciliation or reversal refund.
- A deadline expiry, missing acknowledgement, or driver failure MAY trigger retry, reconciliation, or escalation. It cannot supply reversal evidence or release pending mass. The source debit obligation is distinct from a publication retry after the authoritative decision.
