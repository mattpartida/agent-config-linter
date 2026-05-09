# Report stability

`agent-config-linter` reports are intended for CI systems, SARIF uploaders, baselines, policy tooling, and downstream automation. Changes to JSON, Markdown, or SARIF shape should be deliberate and reviewed.

## Golden report update workflow

Golden fixtures live under `tests/fixtures/golden/` and cover the same high-risk example in all stable report formats:

- `high-risk-agent.json.golden.json`
- `high-risk-agent.markdown.golden.md`
- `high-risk-agent.sarif.golden.json`

When an output change is intentional:

1. Run the normal test first and confirm `python -m pytest tests/test_report_golden.py -q` fails only because the report shape changed.
2. Regenerate the affected golden file(s) from `examples/high-risk-agent.json`.
3. Review the diff carefully for field additions, removals, renamed keys, severity changes, SARIF location changes, or Markdown section changes.
4. If machine-readable JSON or SARIF keys changed incompatibly, consider bumping `schema_version` and updating README compatibility notes.
5. Rerun `python -m pytest tests/test_report_golden.py -q` and the full quality bar.

Example regeneration commands:

```bash
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --format json > tests/fixtures/golden/high-risk-agent.json.golden.json
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --format markdown > tests/fixtures/golden/high-risk-agent.markdown.golden.md
PYTHONPATH=src python -m agent_config_linter.cli examples/high-risk-agent.json --format sarif > tests/fixtures/golden/high-risk-agent.sarif.golden.json
```

## `schema_version` checklist

Keep `schema_version` stable for additive fields that preserve existing consumers. Consider a version bump when a change removes or renames fields, changes severity summary semantics, changes finding identity fields, changes SARIF rule IDs, or changes baseline/policy suppression semantics.
