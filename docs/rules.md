# Agent Config Linter Rules

Stable rule IDs are included in JSON findings and SARIF output so CI systems, baselines, and documentation can reference findings without depending on mutable titles.

| Rule ID | Finding ID | Severity | What it catches |
| --- | --- | --- | --- |
| ACL-001 | `shell_enabled` | high | Shell, terminal, subprocess, or language-runtime execution enabled. |
| ACL-002 | `filesystem_broad_access` | high | Broad filesystem roots such as `/`, `~`, `$HOME`, `*`, or unrestricted host mappings. |
| ACL-003 | `browser_private_network` | high | Browser access to localhost, LAN, or private network ranges. |
| ACL-004 | `lethal_trifecta` | critical | Untrusted inputs, private data access, and outbound actions enabled together. |
| ACL-005 | `prompt_injection_exfiltration_bridge` | critical | Untrusted input can reach code execution with secrets and network egress. |
| ACL-006 | `unattended_dangerous_tools` | critical | Scheduled/autonomous runs can use dangerous tools without explicit approvals. |
| ACL-007 | `privileged_infra_control` | critical | Infrastructure-control tools have credentials and network egress. |
| ACL-008 | `approval_gate_missing` | critical | Approval policy disables gates for high-risk actions. |
| ACL-009 | `weak_model_risk` | medium | Model name suggests small, local, uncensored, or weak-guardrail routing. |
| ACL-010 | `filesystem_write_access` | high | Filesystem configuration permits write-capable access. |

## Severity model

- `critical`: unsafe capability combinations that can plausibly turn prompt injection or autonomy into data exfiltration, infrastructure control, destructive changes, or high-impact outbound actions.
- `high`: a single high-risk capability that should normally be constrained before autonomous use.
- `medium`: a risk amplifier that becomes more important when combined with high-impact tools.
- `low`: informational findings.

## Output formats

- JSON: complete native report with `rule_id` and `rule_name` on every finding.
- Markdown: human-readable report suitable for PR comments and chat handoff.
- SARIF: GitHub code scanning compatible output keyed by stable rule IDs.

## Filesystem semantics

`ACL-002 filesystem_broad_access` is reserved for broad roots such as `/`, `~`, `$HOME`, `*`, or unrestricted host mappings. Project-scoped writable paths such as `./workspace` or `~/project` no longer raise `ACL-002` solely because they are write-capable; they raise `ACL-010 filesystem_write_access` instead. This may reduce high-severity `ACL-002` counts in existing baselines while preserving the write-access finding for scoped writable mounts.
