# OIP v0.6 identity and ownership handover

This document is part of OIP v0.6.0. [Conformance scope](conformance.md) defines the requirement key words.

## Caller and endpoint

- An endpoint MUST obtain the principal, domain, OCID and RAI from the authenticated identity that its security adapter supplies, and MUST check that this identity equals the registered identity of that principal. It MUST check the complete signed request, call namespace, caller, current authority epoch and live session before dispatch or receipt access. Reusing a numeric session identifier under a new epoch cannot revive an older signed request.
- The target endpoint MUST enforce its current role and capability for the requested operation, domain and asset. Normal, administrative, force-inclusion, upgrade and adapter entry points MUST consume the same final capability and command checks. Authentication, client execution, maintenance, legal authority, signer evidence and read permissions are separate inputs. A client role MUST NOT install authority or act as a signer or legal officer by naming that role.
- A retry MUST prove the original authenticated caller and exact request. A valid session at the same authority epoch MAY retrieve the original result after the source revision advances. A session or request from an older epoch is rejected before inspecting its result.
- Current and historical application and balance data, raw data, operation status and journal observations MUST pass current reader authorization for the authenticated caller, session, target and scope before returning a value, cache entry, history, receipt or existence signal. Raw maintenance and storage handles are available only inside the trusted authority.

## Ed25519 reference authority

The trusted host issues session and maintenance tokens only for registrations in the current configured policy. An independent attachment issuer signs the actual configured witness context. These role-specific issuers stay in host custody. The reference profile uses signed session tokens from its configured issuer. The token binds the registered identity, domain, OCID and RAI, session, epoch, exact configured grants and validity window. The current authority consumes the token's exact session and the canonical signed packet. The final verifier decodes that same packet and checks the decoded call or read, target and scope. An independent signature credential cannot replace it. Journal grants expose the caller's own namespace.

The authority's retained image binds a digest of its configured public keys, key identifiers, peer and issuer registrations, grants and wire settings at the selected epoch. Reopening at that epoch requires the same policy. A reference genesis records that policy as part of its authenticated image. Older images in profiles with no policy binding preserve their canonical bytes. Maintenance uses its own configured issuer and signed role. Attachment, genesis and repair each use separate Ed25519 keys and signing purposes.

The authority's current local response key matches the negotiated local key. Response UUIDs bind the exact original and result and the current issuance context. The response signer uses the v0.6 envelope signing domain. Exact re-resolution of a retained receipt preserves the outcome and commit reference. Current authority revocation also applies to receipt access.

## Atomic owner and session handover

- A handover MUST bind the registered asset, current owner, successor, current authority cut, old session, fresh successor session and strictly greater authority epoch. The current owner and successor MUST authorize the same proposal. Installation of replacement authority contexts and the single authoritative token owner MUST commit together with closing the old session and opening the successor session.
- The handover MUST retain each outstanding origin, full binding, amount, phase, evidence and original settlement destination. It transfers exactly the asset's live recovery rights and outstanding obligations to the successor and leaves other assets' rights unchanged. Registry reads of ownership use the same owner committed by the token authority.
- A recovery action MUST consult the current owner and recovery right for that exact origin, then consume the current lock fence and exact source or terminal evidence. Handover alone neither settles nor returns funds. Old-session retries, cancellation, recovery and enforcement are rejected on every route before effects or receipt access.
