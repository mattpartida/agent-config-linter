# Precision boundaries

Precision fixtures document safe configuration patterns that should not trigger the guarded high/critical finding. They are intentionally negative examples: if a future rule change starts emitting one of the guarded findings for these files, the tests fail and the rule change needs an explicit review.

The fixture group lives in `tests/fixtures/precision-boundaries/` and is covered by `tests/test_phase5_precision_rule_packs.py`.

| Fixture | Guarded findings | Why this is a safe boundary |
| --- | --- | --- |
| `safe-disabled-shell.yaml` | `shell_enabled` | Shell settings may appear in config, but the tool is explicitly disabled. |
| `safe-readonly-domain-egress.yaml` | `filesystem_broad_access`, `filesystem_write_access`, `unrestricted_network_egress` | Filesystem access is read-only and scoped to `./src`; network egress is limited to `api.github.com`. |
| `safe-public-browser-no-private.yaml` | `browser_private_network`, `lethal_trifecta`, `prompt_injection_exfiltration_bridge` | Public web input is enabled, but localhost/private-network access, memory, and secrets are disabled. |
| `safe-review-only-autonomy.yaml` | `unattended_dangerous_tools`, `approval_gate_missing` | Autonomy is review-only and shell execution still requires approval. |
| `safe-infra-readonly-no-secrets.yaml` | `privileged_infra_control` | Infrastructure tooling is limited to planning/read-only behavior and does not expose secrets. |
| `safe-pinned-remote-tools.yaml` | `unpinned_remote_tool_source`, `runtime_package_install` | Remote tool source is pinned and runtime package installation is disabled. |
| `safe-secret-names-no-dangerous-tools.yaml` | `secret_env_to_dangerous_tool` | Secret names are declared as metadata, but they are not connected to shell, MCP, package-install, or outbound tools. |

## Updating a boundary

1. Add or update the safe fixture under `tests/fixtures/precision-boundaries/`.
2. Add the guarded finding IDs to `PrecisionBoundaryFixtureTests`.
3. Update this table and `docs/rule-coverage.md`.
4. Run the full verification suite before changing rule behavior.
