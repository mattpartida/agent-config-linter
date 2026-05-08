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
```

Output includes:

- `risk_level`: `low`, `medium`, `high`, or `critical`
- `score`
- `signals.lethal_trifecta`
- `signals.enabled_capabilities`
- structured `findings`, including stable `rule_id` and `rule_name` fields
- optional `suppressed_findings` and `suppressed_summary` when a baseline is provided
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

## Baselines and suppressions

Use `--baseline` to suppress accepted findings while keeping an audit trail in JSON output. Baselines can be JSON, YAML, or TOML files with a `suppressions` list:

```json
{
  "suppressions": [
    {
      "path": "examples/high-risk-agent.json",
      "rule_id": "ACL-009",
      "reason": "Example fixture intentionally uses a weak/local model to demonstrate the rule."
    }
  ]
}
```

Each suppression must include `rule_id`, `finding_id`, or `id`, plus an optional `path` glob. Matching findings are removed from `findings` and reported under `suppressed_findings` with `suppressed_summary` counts.

## Config-shape fixtures

The `examples/config-shapes/` directory contains representative Hermes/OpenClaw-style shapes used by tests and smoke checks:

- `hermes-discord-shared.yaml`: shared Discord/group-chat agent with terminal, files, secrets, persistence, and network egress.
- `hermes-personal-local.yaml`: personal local runtime with a local model and broad filesystem access.
- `openclaw-browser-agent.json`: OpenClaw-style browser/web agent with private-network browser access.

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

## Roadmap

The MVP is now usable as a local/CI linter. The next roadmap focuses on making findings more precise, easier to adopt in real repos, and safer to run as a security gate.

### 1. Rule precision and evidence paths

- Add JSON/YAML/TOML source-location hints for findings so SARIF can point at the risky field instead of line 1.
- Include evidence paths in each finding, for example `tools.shell.enabled` or `enabled_toolsets[2]`.
- Split broad detections into narrower rules where remediation differs, especially filesystem read-all vs write-all access.
- Add tests that assert findings include deterministic evidence paths for representative nested configs.

### 2. Schema-aware adapters

- Add explicit adapters for Hermes, OpenClaw, and generic OpenAI-compatible agent config shapes.
- Normalize common aliases into an internal capability map before rule evaluation.
- Add fixture coverage for approval policies, tool allowlists, per-channel tool exposure, cron jobs, memory, browser private-network access, and outbound messaging.
- Document which schema fields are supported and which are intentionally ignored.

### 3. Policy and severity configuration

- Add a `--policy` flag for JSON/YAML/TOML policy files.
- Let teams override severity, disable selected rules, and set org-specific path/tool allowlists.
- Preserve stable default severities when no policy is supplied.
- Validate policy files with clear errors before linting configs.

### 4. Baseline lifecycle tooling

- Add a `--generate-baseline` command that writes current findings as suppressions.
- Add `expires_at`, `owner`, and `ticket` fields to suppression examples and validation.
- Warn on stale suppressions that no longer match any finding.
- Support `--fail-on-stale-baseline` for CI cleanup.

### 5. CI and developer-experience polish

- Add documented exit-code modes, including fail on `high` or `critical` findings only.
- Add `--min-severity` and `--fail-on` flags for staged adoption.
- Add examples for GitHub Actions, pre-commit, and local make/task runners.
- Publish a small sample SARIF artifact in docs so users can preview code-scanning output.

### 6. Packaging and distribution

- Add release automation for tagged PyPI publishes.
- Add version output via `agent-config-lint --version`.
- Add a changelog and release checklist.
- Add package metadata classifiers, keywords, and project URLs.

### 7. Security regression corpus

- Build `tests/fixtures/regression/` with known risky and safe configs.
- Add regression cases for prompt-injection-to-exfiltration bridges, unattended tool use, private-network browser exposure, and weak approval gates.
- Add safe negative fixtures to reduce false positives.
- Track rule coverage in docs so new rules require fixture-backed examples.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
python -m compileall -q src tests
```

CI also runs `ruff`, `compileall`, and `pytest`.
