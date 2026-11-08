# OIP v0.6 regulatory execution

This document is part of OIP v0.6.0. [Conformance scope](conformance.md) defines the requirement key words.

## Trusted reference time

A time-enabled reference profile selects its first trusted Unix-seconds observation before admitting lease and regulatory writes. Later observations use the same clock and exact current witness cut. An authorized clock observer signs the actual observation and the product checks current permission again before publication. An ordinary elapsed-time command cannot advance this clock or open an appeal deadline. Caller timeout leaves any pending balance and source obligation in place.


## Regulatory entry

- The source emission and the receiving commitment MUST apply the same legal admission rules at their respective current authoritative cuts. Normal, administrative, adapter, and force-inclusion entry points MUST use the same final guard.
- An order MUST bind its original event, action, asset and exact scope. Its authority, legal basis, and jurisdiction MUST be verified and authorized at the cut where the order is consumed. A confiscation order MUST identify its exact destination.
- SEIZE requires a completed FREEZE for the same asset and an exact reference to that event. A RESTRICT event does not establish that provenance.
- CONFISCATE requires the current SEIZED state, the exact prior SEIZE and its escalation provenance, confiscation authority, and an elapsed appeal deadline. A timestamp at or after the committed deadline satisfies the elapsed-deadline check.
- UNFREEZE and RELEASE require current authority and the exact active freeze or seizure they reverse. UNRESTRICT requires a current restricted state and authorization.
- A permitted RESTRICT MAY act on a reserved asset and MUST preserve the reservation. Refused orders MUST leave authoritative status, financial balances, supply, and existing terminal records unchanged and report a distinct reason.

## Spending under a completed freeze

- After a completed FREEZE, ordinary spending MUST be rejected while the authoritative freeze protection remains in force. Current regulatory reads use the current published state and its cut.
- A lawful enforcement transfer MUST consume its exact confirmed root, the current enforcement authority and scope, and the bound asset, parties and amount. It remains executable under those conditions even while ordinary spending is blocked.
