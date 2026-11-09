# OIP v0.6 authenticated persistence and recovery

This document is part of OIP v0.6.0. [Conformance scope](conformance.md) defines the requirement key words.

## One durable authority commit

- A registered authority MUST retain one canonical record of the state that supplies its effects and exposed observations. It includes pending source obligations and exact evidence, origin decisions and publication, complete request bindings and authoritative outcomes, completion state, regulatory and spend receipts, ownership and sessions, authoritative historical prefixes, and the separate secondary queue.
- The record MUST bind the deployment, format and authority profile, a monotone commit sequence distinct from the product cut, the preceding record, and a digest recomputed from the exact canonical bytes. The store MUST durably flush the record before advancing the independent rollback-resistant head by compare-and-set. Only an anchored record is committed.
- Mutating endpoints MUST confirm that commit before exposing any resulting reply or outbound work. An unanchored prepare is ignored. A conflicting or uncertain head update MUST be reconciled against the authoritative head and retained committed result before reporting a result. Concurrent execution MUST use the same serialized commit boundary.

## Configured etcd control transport

The direct etcd transport uses a fixed endpoint, pinned etcdctl executable and explicit mTLS credentials. The CA and server identity MUST be dedicated to the configured cluster, and the writer credentials MUST be dedicated to its authority key. A different cluster MUST NOT reuse that trust identity. The preliminary linearizable cluster check and the transaction use separate client connections, so the TLS identity is part of the cluster binding. The authority also validates the deployment, format, profile and writer generation inside the exact control value.

Read one configured key with linearizable consistency and verify its cluster identity, per-key modification revision and exact value bytes. Replace through one transaction that compares both the observed modification revision and its exact value. A definite comparison failure has an empty write branch. Missing, malformed or unauthenticated responses and mismatching readback hold. A transport error can leave the transaction outcome unresolved. The authority MUST NOT expose an outcome before it confirms the exact selected head and its flushed record.

Direct attachment requires a trusted host policy that explicitly authenticates the direct profile. Restore administration and runtime writer credentials have separate custody. An independently restored cluster or replayed control value requires a separately protected selection witness before it can serve authority state. The direct transport itself supplies only current-cluster CAS and readback.

## Independent archive selection

The independent ordered profile uses two configured and independently administered etcd clusters and a dedicated Linux archive directory. Authority and witness have separate endpoints, trust and writer credentials. An archive names the whole prefix of the journal selected by its exact head. It binds the checked prefix length, full prefix digest and the digest and descriptor of the last record. A prepared suffix beyond the head remains outside that archive. New files and their directory entries become eligible only after synchronization, and restore creates a new path.

The authority retains a bounded set of exact preparations for one witness revision and value. An exact witness CAS selects a preparation only after its archive is durable. The witness binds the profile, authority and witness identities, complete ordered control value, writer, archive and repair nonce. No preparation is an authoritative result. A missing authority mirror or lost reply can be reconciled through the exact selected witness and archive. Fresh admission requires an authority mirror or preparation that matches the selected witness. Earlier authority and journal snapshots hold even when their storage revisions have increased.

Provisioning starts from two pre-provisioned empty control keys. It archives a validated product genesis and selects it through a separate exact signed provisioning authorization. Repair uses a separate signed cut for the prospective authority configuration, destination, new writer and selected archive and nonce. A resumed repair MAY verify and reuse the exact existing destination for the same authorization. A changed path or writer MUST consume the current nonce and can never overwrite an existing file. The independent profile uses signed ordered publication. Trusted maintenance actions require their own explicit authority entry.

The reference authority with ordered control MUST execute maintenance through the authenticated, purpose-specific ordered maintenance entry. That entry checks the current policy and revocation state and consumes the selected control cut when publishing the maintenance result. A generic maintenance method that does not carry this ordered authorization MUST reject an invocation on an ordered authority before opening a mutable operation or exposing resulting work. A standalone profile without ordered control continues to apply its configured local maintenance authorization.

The selected cut determines the currently valid maintainer and the exact permitted intent. A change to that cut invalidates the proposed publication. A rejected maintenance request MUST leave the authority record, queue and externally visible maintenance results unchanged.

## Fresh endpoint and retained results

- Reopen MUST reconstruct a fresh endpoint from the exact anchored record and current authenticated authority attachments. Recompute the digest and check the deployment, profile, sequence and exact head before serving. An old valid record, an unanchored record, or an absent or mismatched authenticated record cannot authorize a new endpoint.
- Every exposed retry, current or historical read, cancellation, terminal use and spend MUST consume the reconstructed authority state. Current access and the original signed request remain mandatory. An exact admitted replay at the same epoch reads its retained outcome before any fresh-cut, work or evidence check. A fresh stale request cannot execute. Changed bindings and obsolete epochs cannot read or replace an old result.
- Cache data MUST be revalidated against the same current scope, cut, query, provider and actual authority value, using the same acceptance rules on an uninterrupted or reopened endpoint. Process-local caches and unverified source attachments do not supply effect authority.

## Unresolved effects

- A dispatched source obligation MUST retain its original binding and stay queryable or held until exact source evidence resolves it. Timeout, a missing reply and a mismatched certificate cannot return funds or authorize a fresh source effect. A lawful return consumes an exact bound reversal at the current lock and evidence checks.
- Secondary work MUST retain the exact committed primary and stable settlement key before release to its sender. Retries and acknowledgements use that key and binding; secondary uncertainty does not resolve the original source obligation.
