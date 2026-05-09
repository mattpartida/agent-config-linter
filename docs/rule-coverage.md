# Rule coverage

Every rule should have at least one fixture-backed example before its detection logic changes. Risky fixtures prove the rule fires for a representative unsafe configuration; safe fixtures cover common false-positive boundaries.

## Regression fixture corpus

| Rule | Purpose | Risky fixture coverage | Safe/negative fixture coverage |
| --- | --- | --- | --- |
| ACL-001 `shell-enabled` | Code or shell execution is available. | `tests/fixtures/regression/risky-unattended-tool-use.yaml`, `tests/fixtures/regression/risky-weak-approval-gates.yaml` | `tests/fixtures/regression/safe-approval-gated-shell.yaml` keeps approval-gated shell from escalating to missing-approval or unattended findings. |
| ACL-002 `filesystem-broad-access` | Filesystem access is broad enough to expose private data. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-readonly-project-files.yaml` covers project-scoped read-only access. |
| ACL-003 `browser-private-network` | Browser automation can reach localhost, LAN, or private network addresses. | `tests/fixtures/regression/risky-private-network-browser.yaml` | `tests/fixtures/regression/safe-browser-public-only.yaml` covers public browsing with private-network access disabled. |
| ACL-004 `lethal-trifecta` | Untrusted input, private data, and outbound action are enabled together. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-browser-public-only.yaml` lacks private-data access. |
| ACL-005 `prompt-injection-exfiltration-bridge` | Untrusted input can reach execution, secrets, and egress. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-browser-public-only.yaml` lacks code execution and secrets. |
| ACL-006 `unattended-dangerous-tools` | Unattended execution can use dangerous tools without approvals. | `tests/fixtures/regression/risky-unattended-tool-use.yaml` | `tests/fixtures/regression/safe-approval-gated-shell.yaml` has explicit approvals and no unattended mode. |
| ACL-007 `privileged-infra-control` | Infra-control tools combine credentials with network egress. | Covered by unit test `test_detects_privileged_infra_control_with_credentials_and_network`; add a dedicated fixture when this rule changes. | No dedicated negative fixture yet. |
| ACL-008 `approval-gate-missing` | Dangerous action approval gates are disabled. | `tests/fixtures/regression/risky-weak-approval-gates.yaml` | `tests/fixtures/regression/safe-approval-gated-shell.yaml` keeps approvals enabled. |
| ACL-009 `weak-model-risk` | Model name suggests weak local/small/uncensored behavior. | Covered by unit test `test_hermes_personal_local_fixture_detects_weak_local_model_and_broad_files`; add a dedicated fixture when this rule changes. | `tests/fixtures/regression/safe-approval-gated-shell.yaml` uses a stronger model name. |
| ACL-010 `filesystem-write-access` | Filesystem configuration permits write access. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-readonly-project-files.yaml` covers read-only project paths. |

## Adding or changing rules

1. Add or update a risky fixture under `tests/fixtures/regression/` that should trigger the rule.
2. Add or update a safe fixture for an important false-positive boundary.
3. Update `tests/test_regression_fixtures.py` expected rule IDs.
4. Update this coverage table with fixture paths and the behavior they prove.
5. Run `PYTHONPATH=src python -m unittest discover -s tests -q` before opening a PR.
