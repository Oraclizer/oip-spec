# Security policy

## Current status

OIP v0.6.0 is an unaudited, prototype-stage specification draft with
reference code. No deployed instance, fork, operator, key-management process
or downstream integration is covered by this policy.

| Version | Security support |
| --- | --- |
| `main` and v0.6.0 | Reports accepted for evaluation |
| Earlier drafts, forks and modified copies | Unsupported |
| Deployments | Unsupported |

This table describes how reports are handled. It is not a warranty or a
statement that the specification or the code is secure.

## Report a vulnerability privately

Use GitHub private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

If the private reporting form is unavailable, email the maintainer at
`jay@oraclizer.io` with the subject `OIP SECURITY`. Do not include secrets,
personal data, production credentials or unrelated private infrastructure
details.

Do not disclose exploit details in a public issue, pull request, social post
or standards forum.

## What to include

- the commit, specification section, file and function;
- a minimal reproduction: a failing test, a message frame or a sequence of
  requests;
- the expected and observed results, including response codes;
- whether Rust and Go behave differently on the same input;
- known preconditions and impact;
- any embargo needs.

## Scope

Security-sensitive surfaces include:

- message decoding, field order and encoding uniqueness, and the handling of
  unknown fields and versions;
- signing inputs, Ed25519 verification and the selection of keys and scopes;
- message lifetime, duplicate detection and the results returned to retries;
- authorization of operations, locks, handover and regulatory steps;
- recovery of recorded outcomes after a timeout or a crash;
- differences between the Rust and Go implementations on the same bytes;
- resource limits and the integrity of dependencies and generated code.

## Handling

The maintainer evaluates whether a report affects the specification or the
reference code and may ask for more information. There is no guaranteed
acknowledgement, remediation, disclosure or release timeline. There is no bug
bounty or financial reward program.

An accepted report may be coordinated through a draft GitHub security
advisory. Credit may be offered in the advisory or the changelog when it is
requested and appropriate.

Public design questions, specification ambiguities that are not sensitive,
and ordinary defects belong in the issue tracker.

## Legal

The repository is provided under the [Apache License 2.0](LICENSE), which
disclaims warranties in section 7 and limits liability in section 8.

This policy does not create a support contract or make a representation
about security, fitness for a purpose, legal compliance or production
readiness. See [DISCLAIMER.md](DISCLAIMER.md).
