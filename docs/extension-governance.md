# Extension governance

`agent-config-linter` now validates rule-pack manifests as data, but it still does not execute third-party rules. This document defines the ecosystem boundary before any future extension mechanism is accepted.

## Rule ID namespaces

- `ACL-*` IDs are reserved for built-in rules maintained in this repository. ACL-* IDs are reserved and must not be used by third-party packs.
- Third-party and organization-specific rule packs MUST use a non-`ACL-*` namespace such as `ORG-*`, `TEAM-*`, `VENDOR-*`, or a short reverse-DNS-style prefix.
- Rule IDs are stable API. A pack must not reuse an ID for a different risk after publication.
- Collision handling: if an external pack proposes an ID that collides with a built-in `ACL-*` rule or another accepted namespace, the pack must rename before it can be documented or used in examples.

## Ownership metadata

Every documented extension idea or rule-pack manifest should include ownership metadata:

- publisher or owning team
- contact or repository URL
- rule-pack version
- rule IDs and names
- default severity and confidence
- remediation text
- risky and safe fixtures
- compatibility notes for any report fields it expects consumers to read

Ownership metadata is required so baselines, policies, and CI reports remain auditable when rules come from more than the built-in catalog.

## Core rule vs policy bundle vs third-party rule pack

| Need | Use | Notes |
| --- | --- | --- |
| A broadly applicable autonomous-agent security risk with stable evidence | Core built-in rule | Requires fixtures, docs, severity/confidence review, and changelog entry. |
| Organization-specific severity, allowlist, confidence, or baseline behavior | Policy bundle | Does not add new findings; adapts existing built-in findings. |
| Environment-specific control that is not broadly applicable yet | Third-party rule pack | Manifest-only today. Future execution requires a separate security design. |

## Review expectations

A rule-pack example is not ready for ecosystem documentation until it has:

1. A non-conflicting namespace and stable rule IDs.
2. One risky fixture and one safe fixture per rule.
3. Severity and confidence rationale.
4. Human-readable evidence and remediation text.
5. Explicit false-positive boundaries.
6. A statement that the pack MUST NOT execute code, install packages, run subprocesses, fetch networks, or evaluate arbitrary expressions during discovery or linting.

## Promotion into the built-in catalog

External ideas can be promoted into core only when they are broadly useful across agent stacks and can be expressed with deterministic evidence paths. Promotion requires:

1. Open an issue or PR describing the risk, evidence, severity, confidence, and false-positive boundary.
2. Add safe and risky regression fixtures under `tests/fixtures/`.
3. Add or update rule metadata in the built-in registry.
4. Update README, `docs/rules.md`, `docs/rule-coverage.md`, and changelog entries.
5. Keep the original external rule ID as a migration note when users may already have baselines or policies referencing it.

Until that review is complete, external pack content remains manifest-only and is not evaluated during normal lint runs.
