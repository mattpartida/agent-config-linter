# agent-config-linter

Dependency-light risk linter for autonomous-agent configuration files.

The first MVP scans JSON configs for unsafe capability combinations in agent runtimes: untrusted inputs, private data access, outbound actions, persistence, shell/filesystem/browser access, weak approval gates, and weaker model choices.

## Why

Agent risk is usually not one setting. The dangerous failures appear when capabilities combine:

```text
untrusted content + private data + outbound action = lethal trifecta
```

This repo turns that into repeatable checks that can run locally or in CI.

## Install for local development

```bash
python -m pip install -e .
```

Or run without installing:

```bash
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --format json
```

## CLI

```bash
agent-config-lint path/to/agent.json --format json
agent-config-lint path/to/agent.json --format markdown
agent-config-lint path/to/agent.json --format sarif > agent-config-linter.sarif
```

Output includes:

- `risk_level`: `low`, `medium`, `high`, or `critical`
- `score`
- `signals.lethal_trifecta`
- `signals.enabled_capabilities`
- structured `findings`, including stable `rule_id` and `rule_name` fields
- `recommended_next_actions`

Formats:

- `json`: full machine-readable report.
- `markdown`: human-readable report for PR comments, issues, or chat handoff.
- `sarif`: GitHub code scanning compatible report.

## Example

```bash
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --format json
```

## MVP checks

- Shell/terminal/subprocess enabled
- Broad filesystem access
- Browser access to localhost/LAN/private network
- Untrusted inputs from web/messaging/email/webhooks
- Private data access through files/memory/email/drive/GitHub/secrets/env
- Outbound action/exfiltration through email/messaging/HTTP/GitHub/browser
- Missing approval gates for dangerous actions
- Small/local/uncensored model risk hints
- Lethal-trifecta detection

## Unsafe capability-combination checks

Beyond single risky toggles, the linter now flags higher-order combinations that commonly turn prompt injection into real-world impact:

- `prompt_injection_exfiltration_bridge`: untrusted inputs combined with code execution, secrets/credentials access, and network egress.
- `unattended_dangerous_tools`: autonomous or scheduled runs that can use shell, destructive, or outbound tools without explicit approvals.
- `privileged_infra_control`: Docker/Kubernetes/cloud/IaC-style controls combined with credentials and network egress.

These checks are intentionally conservative: they are meant to catch configs that deserve human review before being used in an autonomous runtime.

## Rule IDs

Findings include stable rule IDs for baselines and CI integrations. See [docs/rules.md](docs/rules.md) for the current catalog.

| Rule ID | Finding ID | Default severity |
| --- | --- | --- |
| ACL-001 | `shell_enabled` | high |
| ACL-002 | `filesystem_broad_access` | high |
| ACL-003 | `browser_private_network` | high |
| ACL-004 | `lethal_trifecta` | critical |
| ACL-005 | `prompt_injection_exfiltration_bridge` | critical |
| ACL-006 | `unattended_dangerous_tools` | critical |
| ACL-007 | `privileged_infra_control` | critical |
| ACL-008 | `approval_gate_missing` | critical |
| ACL-009 | `weak_model_risk` | medium |

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
python -m compileall -q src tests
```

CI also runs `ruff`, `compileall`, and `pytest`.

## Roadmap

- YAML/TOML support
- Recursive directory discovery
- Hermes/OpenClaw config schema fixtures
- Baseline/suppressions file
- GitHub Actions example that uploads SARIF to code scanning
