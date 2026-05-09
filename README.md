# agent-config-linter

Dependency-light risk linter for autonomous-agent configuration files.

The first MVP scans JSON, YAML, and TOML configs for unsafe capability combinations in agent runtimes: untrusted inputs, private data access, outbound actions, persistence, shell/filesystem/browser access, weak approval gates, and weaker model choices.

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
agent-config-lint path/to/agent.yaml --format markdown
agent-config-lint path/to/config-directory --format sarif > agent-config-linter.sarif
agent-config-lint path/to/config-directory --baseline agent-config-linter-baseline.json --format json
agent-config-lint path/to/config-directory --policy agent-config-linter-policy.json --format json
agent-config-lint path/to/config-directory --generate-baseline agent-config-linter-baseline.json --format json
agent-config-lint path/to/config-directory --baseline agent-config-linter-baseline.json --fail-on-stale-baseline --format json
agent-config-lint path/to/config-directory --min-severity medium --fail-on high --format json
agent-config-lint --version
```

Output includes:

- `risk_level`: `low`, `medium`, `high`, or `critical`
- `score`
- `signals.lethal_trifecta`
- `signals.enabled_capabilities`
- structured `findings`, including stable `rule_id` and `rule_name` fields
- optional `policy_suppressed_findings` and `policy_suppressed_summary` when a policy disables or allowlists findings
- optional `suppressed_findings` and `suppressed_summary` when a baseline is provided
- optional `baseline.stale_suppressions`/`baseline.stale_count` for baseline cleanup
- optional `filtered_findings`/`filtered_summary` when `--min-severity` filters low-priority findings
- optional `exit_policy` when `--fail-on` is used for CI gating
- `recommended_next_actions`

Formats:

- Config inputs: `.json`, `.yaml`, `.yml`, and `.toml` files.
- Directory inputs: scanned recursively for supported config files; unsupported files are ignored during directory scans.
- Report output `json`: full machine-readable report.
- Report output `markdown`: human-readable report for PR comments, issues, or chat handoff.
- Report output `sarif`: GitHub code scanning compatible report.

## Example

```bash
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --format json
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.yaml --format markdown
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.toml --format sarif
PYTHONPATH=src python -m agent_config_linter.cli examples/config-shapes --format json
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --baseline examples/agent-config-linter-baseline.json --format json
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --policy examples/agent-config-linter-policy.json --format json
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --generate-baseline /tmp/agent-config-linter-baseline.json --format json
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --min-severity medium --fail-on high --format json
PYTHONPATH=src python -m agent_config_linter.cli --version
```

## GitHub code scanning

Use the example workflow at [`.github/workflows/agent-config-linter-code-scanning.yml`](.github/workflows/agent-config-linter-code-scanning.yml) to generate SARIF and upload findings to GitHub code scanning:

```yaml
- name: Generate SARIF report
  run: agent-config-lint . --format sarif > agent-config-linter.sarif

- name: Upload SARIF to GitHub code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agent-config-linter.sarif
```

For downstream repos, replace `.` with the config file or directory path that should be scanned.

## Policy configuration

Use `--policy` to adapt default findings to org-specific risk decisions while keeping the linter deterministic without a policy. Policies can be JSON, YAML, or TOML files.

```json
{
  "severity_overrides": {
    "ACL-001": "medium"
  },
  "disabled_rules": ["weak_model_risk"],
  "allowlists": {
    "tools": ["shell"],
    "rules": ["ACL-009"],
    "paths": [
      {
        "path": "examples/dev-*.json",
        "rule_id": "ACL-001",
        "reason": "Development-only shell access is reviewed separately."
      }
    ]
  }
}
```

- `severity_overrides` (or `severities`) accepts stable rule IDs, rule names, or finding IDs and one of `critical`, `high`, `medium`, or `low`.
- `disabled_rules` (or `rule_disables`) removes matching findings from active results and reports them under `policy_suppressed_findings`.
- `allowlists.tools` suppresses findings whose evidence points at an allowed `tools.<name>` path.
- `allowlists.rules` suppresses matching rule IDs, rule names, or finding IDs.
- `allowlists.paths` suppresses matching path globs, optionally narrowed by `rule_id` or `id`.

Invalid policy files are rejected before linting with exit code `2`.

## Baselines and suppressions

Use `--baseline` to suppress accepted findings while keeping an audit trail in JSON output. Baselines can be JSON, YAML, or TOML files with a `suppressions` list:

```json
{
  "suppressions": [
    {
      "path": "examples/high-risk-agent.json",
      "rule_id": "ACL-009",
      "reason": "Example fixture intentionally uses a weak/local model to demonstrate the rule.",
      "owner": "security-team",
      "ticket": "SEC-123",
      "expires_at": "2026-12-31"
    }
  ]
}
```

Each suppression must include `rule_id`, `finding_id`, or `id`, plus an optional `path` glob. Matching, unexpired findings are removed from `findings` and reported under `suppressed_findings` with `suppressed_summary` counts. Optional lifecycle metadata includes:

- `owner`: team or person responsible for revisiting the suppression.
- `ticket`: tracking issue/change record.
- `expires_at`: ISO `YYYY-MM-DD` date. Expired suppressions do not match active findings.

Use `--generate-baseline path/to/baseline.json` to write the current active findings as suppressions with TODO lifecycle metadata. When an existing baseline is supplied, stale suppressions that no longer match any finding are reported under `baseline.stale_suppressions`; add `--fail-on-stale-baseline` to return exit code `1` when cleanup is needed.

## CI and developer experience

Use staged severity filters and exit-code gates to adopt the linter without blocking on every low-priority finding immediately:

```bash
agent-config-lint configs/ --min-severity medium --fail-on high --format json
```

- `--min-severity {critical,high,medium,low}` keeps only active findings at or above the threshold and reports lower-severity findings under `filtered_findings`/`filtered_summary`.
- `--fail-on {critical,high,medium,low}` returns exit code `1` when remaining active findings meet or exceed the threshold and records the decision under `exit_policy`.
- Validation/config errors still return exit code `2`.
- `--fail-on-stale-baseline` also returns exit code `1` when stale baseline cleanup is needed.

Examples for local adoption are included in:

- `examples/pre-commit-config.yaml`
- `examples/Taskfile.yml`
- `docs/sample-agent-config-linter.sarif`

## Packaging and releases

Package metadata in `pyproject.toml` includes classifiers, keywords, project URLs, and author metadata for distribution. Use `agent-config-lint --version` to verify installed versions. Tagged releases matching `v*` run `.github/workflows/release.yml`, build distributions with `python -m build`, and publish via PyPI trusted publishing. See `CHANGELOG.md` and `docs/release-checklist.md` before tagging.

## Config-shape fixtures

The `examples/config-shapes/` directory contains representative Hermes, OpenClaw, MCP, and GitHub Actions shapes used by tests and smoke checks:

- `hermes-discord-shared.yaml`: shared Discord/group-chat agent with terminal, files, secrets, persistence, and network egress.
- `hermes-personal-local.yaml`: personal local runtime with a local model and broad filesystem access.
- `openclaw-browser-agent.json`: OpenClaw-style browser/web agent with private-network browser access.
- `claude-desktop-risky-mcp.json` / `claude-desktop-safe-mcp.json`: MCP server maps that exercise shell/secrets/outbound normalization and the safe read-only boundary.
- `github-actions-agent-risky.yml` / `github-actions-agent-safe.yml`: workflow snippets that exercise write permissions, secrets, unattended shell tools, and a read-only workflow boundary.

Use these fixtures as starting points when adding schema-specific rules or testing integrations.

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
| ACL-010 | `filesystem_write_access` | high |

## Schema-aware adapters

The linter normalizes known agent config shapes before applying rules. Reports include `schema.adapter` so downstream tooling can see which adapter was used.

Supported adapters:

- `generic`: existing direct `inputs`, `tools`, `enabled_toolsets`, `secrets`, `memory`, `approvals`, and `model` fields.
- `hermes`: nested `hermes.enabled_toolsets`, `hermes.toolsets`, `hermes.channels`/`hermes.bindings`, `hermes.secrets`, and `hermes.network.egress`.
- `openclaw`: nested `openclaw.browser.enabled`, `openclaw.browser.allowPrivateNetwork`/`privateNetwork`, `openclaw.browser.localhost`, and `openclaw.web`.
- `openai`: OpenAI-compatible `tools` arrays, including `code_interpreter`, `computer_use`, and function tools whose names imply outbound sends such as email, Slack, Discord, Telegram, HTTP, or webhooks.
- `mcp`: Claude Desktop / MCP-style `mcpServers` maps, including server command/arg names that imply shell, filesystem, or outbound tools, plus server `env` as credential access.
- `github_actions`: GitHub Actions workflow snippets with `jobs`, `steps`, write-capable `permissions`, `${{ secrets.* }}` references, and unattended agent runs.

Unsupported fields are ignored until they have fixture-backed tests. Add representative configs under `examples/config-shapes/` or `tests/fixtures/` before expanding adapter behavior.

## Roadmap

The previous MVP roadmap is complete: policy files, baselines, staged CI gates, packaging/release automation, schema adapters, and the first security regression corpus have shipped. The current roadmap now lives in [docs/roadmap.md](docs/roadmap.md).

Next focus areas:

1. Precision and coverage: close fixture gaps for all rules, improve composite evidence paths/SARIF locations, and split broad filesystem risk from scoped write access.
2. Real-world schema support: add fixture-backed adapters for more agent runtimes and improve policy validation/docs.
3. Adoption and distribution: harden the first public release, improve PR-comment/chat-friendly output, and explore a lightweight rule-pack architecture.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
python -m compileall -q src tests
```

CI also runs `ruff`, `compileall`, and `pytest`.
