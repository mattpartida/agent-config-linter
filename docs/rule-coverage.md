# Rule coverage

Every rule should have at least one fixture-backed example before its detection logic changes. Risky fixtures prove the rule fires for a representative unsafe configuration; safe fixtures cover common false-positive boundaries.

## Regression fixture corpus

| Rule | Purpose | Risky fixture coverage | Safe/negative fixture coverage |
| --- | --- | --- | --- |
| ACL-001 `shell-enabled` | Code or shell execution is available. | `tests/fixtures/regression/risky-unattended-tool-use.yaml`, `tests/fixtures/regression/risky-weak-approval-gates.yaml` | `tests/fixtures/regression/safe-approval-gated-shell.yaml` keeps approval-gated shell from escalating to missing-approval or unattended findings. |
| ACL-002 `filesystem-broad-access` | Filesystem access is broad enough to expose private data. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-readonly-project-files.yaml` covers project-scoped read-only access; `tests/fixtures/regression/safe-project-scoped-write-files.yaml` confirms scoped `mode: rw` raises only `ACL-010`. |
| ACL-003 `browser-private-network` | Browser automation can reach localhost, LAN, or private network addresses. | `tests/fixtures/regression/risky-private-network-browser.yaml` | `tests/fixtures/regression/safe-browser-public-only.yaml` covers public browsing with private-network access disabled. |
| ACL-004 `lethal-trifecta` | Untrusted input, private data, and outbound action are enabled together. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-browser-public-only.yaml` lacks private-data access. |
| ACL-005 `prompt-injection-exfiltration-bridge` | Untrusted input can reach execution, secrets, and egress. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-browser-public-only.yaml` lacks code execution and secrets. |
| ACL-006 `unattended-dangerous-tools` | Unattended execution can use dangerous tools without approvals. | `tests/fixtures/regression/risky-unattended-tool-use.yaml` | `tests/fixtures/regression/safe-approval-gated-shell.yaml` has explicit approvals and no unattended mode. |
| ACL-007 `privileged-infra-control` | Infra-control tools combine credentials with network egress. | `tests/fixtures/regression/risky-privileged-infra-control.yaml` | `tests/fixtures/regression/safe-privileged-infra-readonly.yaml` lacks credentials and egress. |
| ACL-008 `approval-gate-missing` | Dangerous action approval gates are disabled. | `tests/fixtures/regression/risky-weak-approval-gates.yaml` | `tests/fixtures/regression/safe-approval-gated-shell.yaml` keeps approvals enabled. |
| ACL-009 `weak-model-risk` | Model name suggests weak local/small/uncensored behavior. | `tests/fixtures/regression/risky-weak-model.yaml` | `tests/fixtures/regression/safe-strong-model.yaml` uses a stronger model name. |
| ACL-010 `filesystem-write-access` | Filesystem configuration permits write access. | `tests/fixtures/regression/risky-prompt-injection-exfiltration.yaml` | `tests/fixtures/regression/safe-readonly-project-files.yaml` covers read-only project paths. |
| ACL-011 `unpinned-remote-tool-source` | Remote MCP/tool package, URL, or command is not version/commit/digest pinned. | `tests/fixtures/regression/risky-supply-chain-network-boundary.yaml` | `tests/fixtures/regression/safe-pinned-scoped-network.yaml` uses a pinned local tool source. |
| ACL-012 `runtime-package-install` | Runtime package installation is enabled or package-manager install commands can run. | `tests/fixtures/regression/risky-supply-chain-network-boundary.yaml` | `tests/fixtures/regression/safe-pinned-scoped-network.yaml` disables runtime package installation. |
| ACL-013 `unrestricted-network-egress` | Network egress allows all destinations. | `tests/fixtures/regression/risky-supply-chain-network-boundary.yaml` | `tests/fixtures/regression/safe-pinned-scoped-network.yaml` limits egress to `api.github.com`. |
| ACL-014 `secret-env-to-dangerous-tool` | Secret/env access is exposed to shell, MCP, package-install, or outbound tools. | `tests/fixtures/regression/risky-supply-chain-network-boundary.yaml` | `tests/fixtures/regression/safe-pinned-scoped-network.yaml` lacks dangerous tools with exposed secrets. |

## Config-shape fixture corpus

`examples/config-shapes/` includes risky and safe examples for Hermes, OpenClaw, MCP, GitHub Actions, Cursor, Windsurf, LangGraph/LangChain, CrewAI, and AutoGen-style snippets. Adapter tests assert both the selected `schema.adapter` and behaviorally important finding IDs so unsupported fields remain ignored until fixture-backed.

## Adding or changing rules

1. Add or update a risky fixture under `tests/fixtures/regression/` that should trigger the rule.
2. Add or update a safe fixture for an important false-positive boundary.
3. Update `tests/test_regression_fixtures.py` expected rule IDs.
4. Update this coverage table with fixture paths and the behavior they prove.
5. Run `PYTHONPATH=src python -m unittest discover -s tests -q` before opening a PR.
