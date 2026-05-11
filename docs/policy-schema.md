# Policy schema

Policy files let teams adapt default `agent-config-linter` findings without changing built-in rules. Policies may be JSON, YAML, or TOML and are loaded with `--policy path/to/policy.{json,yaml,toml}`.

Invalid policies fail before linting with exit code `2`. JSON output includes both a human message and a machine-readable `field` path such as `severity_overrides.ACL-001` or `allowlists.paths[0].rule_id`.

## Fields

| Field | Type | Purpose |
| --- | --- | --- |
| `metadata.policy_bundle_version` | string | Policy bundle version expected by `--check-policy-drift`. |
| `covered_rules` | list of stable built-in rule IDs | Declares which built-in rules the policy bundle has reviewed for drift checks. |
| `severity_overrides` | object mapping rule/finding IDs to `critical`, `high`, `medium`, or `low` | Reclassify default severities for local policy. Alias: `severities`. |
| `disabled_rules` | list of strings | Move matching findings into `policy_suppressed_findings`. Entries may be stable rule IDs, rule names, or finding IDs. Alias: `rule_disables`. |
| `min_confidence` | string: `high`, `medium`, or `low` | Keep only active findings at or above the requested confidence and report lower-confidence entries under `confidence_filtered_findings`. |
| `allowlists.tools` | list of strings | Suppress findings whose evidence path points at an allowed `tools.<name>` entry. |
| `allowlists.rules` | list of strings | Suppress matching stable rule IDs, rule names, or finding IDs. |
| `allowlists.paths` | list of objects | Suppress findings for matching config path globs, optionally narrowed by `rule_id` or `id`. |

Each `allowlists.paths[]` object supports:

| Field | Type | Required | Purpose |
| --- | --- | --- | --- |
| `path` | string | yes | File path or glob, matched against the full config path and file name. |
| `rule_id` | string | no | Stable rule ID to suppress, e.g. `ACL-001`. |
| `id` | string | no | Finding ID to suppress, e.g. `shell_enabled`. |
| `reason` | string | no | Human explanation for the allowlist entry. |

## Minimal policy

```json
{
  "severity_overrides": {
    "ACL-009": "low"
  }
}
```

YAML equivalent:

```yaml
severity_overrides:
  ACL-009: low
```

TOML equivalent:

```toml
[severity_overrides]
ACL-009 = "low"
```

## Staged adoption policy

Ready-to-copy policy bundles live in `examples/policies/`:

- `examples/policies/local-dev.yaml` for developer machines and exploratory rollout.
- `examples/policies/staged-ci.yaml` for non-blocking-to-gradual CI adoption.
- `examples/policies/strict-ci.yaml` for mature repositories paired with `--fail-on high`.

Use severity overrides and narrow allowlists while introducing the linter without blocking all existing findings at once.

```json
{
  "severity_overrides": {
    "ACL-001": "medium",
    "weak_model_risk": "low"
  },
  "allowlists": {
    "paths": [
      {
        "path": "examples/dev-*.json",
        "rule_id": "ACL-001",
        "reason": "Development sandbox shell access is reviewed separately."
      }
    ]
  }
}
```

## Strict CI policy

Use a strict policy for mature repositories that want fewer local exceptions and explicit disabled-rule auditing.

```json
{
  "disabled_rules": [],
  "allowlists": {
    "tools": [],
    "rules": [],
    "paths": []
  },
  "severity_overrides": {
    "ACL-004": "critical",
    "ACL-005": "critical",
    "ACL-006": "critical",
    "ACL-007": "critical"
  }
}
```

Run with an exit gate:

```bash
agent-config-lint configs/ --policy agent-config-linter-policy.json --fail-on high --format json
```

## Policy drift checks

Run drift checks when policies are maintained as versioned bundles:

```bash
agent-config-lint configs/ --policy examples/policies/staged-ci.yaml --check-policy-drift --fail-on-policy-drift --format json
```

`policy_drift` reports:

- `unknown_rules`: policy references that do not match a built-in rule ID or finding ID.
- `missing_rules`: built-in `ACL-*` rules absent from `covered_rules`.
- `stale_fields`: currently `policy_bundle_version` when `metadata.policy_bundle_version` differs from the linter's expected bundle version.

This gate is independent from severity gates such as `--fail-on high`, so teams can require policy-bundle hygiene even during non-blocking finding rollout.

## Validation examples

Malformed policies return precise field paths:

- `severity_overrides` must be a mapping.
- `severity_overrides.ACL-001` must be one of `critical`, `high`, `medium`, or `low`.
- `disabled_rules[0]` must be a string.
- `allowlists.paths` must be a list.
- `allowlists.paths[0].path` is required.
- `allowlists.paths[0].rule_id` must be a string when present.
