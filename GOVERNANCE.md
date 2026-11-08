# Governance

## Who decides

OIP has one maintainer, Jinwook Kim
([@jay-oraclizer](https://github.com/jay-oraclizer)), who has the final say on
scope, review, merges, releases, security coordination and compatibility.

Decisions are made against the criteria below, and a decision that turns down
a contribution names the criterion it failed. If you believe a criterion was
misapplied, say so on the issue, and the reasoning is revisited in the open.
Being turned down is not a judgement of the work. The most common reason is
scope.

## Decision principles

Changes are evaluated for:

- agreement between the specification text, the schema and both
  implementations;
- the effect on bytes that existing implementations accept;
- refusal before any effect when a check fails;
- explicit statements of what a rule does not cover;
- positive and negative tests, and vectors that both languages pass;
- security impact;
- clear public documentation.

Large changes start with an issue that describes the problem, the
alternatives, the effect on compatibility and the planned tests.

## Merge policy

Changes enter `main` through pull requests. Force pushes and reuse of release
tags are not part of the normal workflow. A passing check is evidence for the
reviewed commit only.

## Release policy

A release requires:

- a CHANGELOG entry for the version;
- passing test, generated-file and repository checks on the release commit;
- a review of the public text against the boundaries in
  [DISCLAIMER.md](DISCLAIMER.md);
- an explicit publication decision by the maintainer.

Repository visibility alone does not create a release. A tag is never moved
or reused.

## Security decisions

Vulnerability reports follow [SECURITY.md](SECURITY.md). The maintainer may
withhold details while a fix is coordinated. Bounty, safe-harbor and
service-level terms are not part of this repository.

## Amendments

Governance changes use the same reviewed process as other changes. A
governance document cannot extend a technical, license, security or
deployment claim beyond its evidence.
