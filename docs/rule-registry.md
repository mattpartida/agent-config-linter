# Rule registry architecture

The built-in rule registry keeps stable metadata, default confidence, and the evidence collector contract for every in-repo `ACL-*` rule in one place. The registry is intentionally in-repo only: third-party rules are documented as a future design topic, and plugin loading is intentionally out of scope until the built-in API is stable.

## Current shape

`src/agent_config_linter/rules.py` exposes `RULE_REGISTRY`, keyed by finding ID. Each registry entry includes:

- Stable rule ID, for example `ACL-001`.
- Stable rule name, for example `shell-enabled`.
- Default severity.
- Default confidence (`high`, `medium`, or `low`).
- Title, evidence text, and remediation text.
- Evidence collector callable.

All current built-in findings (`ACL-001` through `ACL-010`) have registry entries. The linter can still compose rule-specific evidence paths before adding a finding, but the report metadata comes from the registry so output text and identifiers do not drift across call sites.

## Evidence provenance

Findings include two evidence path fields:

- `evidence_paths`: normalized paths used by the rule engine, such as `tools.shell`.
- `source_evidence_paths`: original config paths that caused adapter-normalized evidence, such as `mcpServers.agent.command` or `jobs.scan.steps[0].run`.

For generic configs these fields are usually identical. For schema adapters, `normalize_config()` returns a provenance map from normalized paths to source paths, and SARIF source-line lookup prefers `source_evidence_paths` so reviewers land on the original config field.

## Built-in rule checklist

When adding or migrating a built-in rule:

1. Choose a stable rule ID and finding ID before writing implementation code.
2. Add a `RuleDefinition` entry containing default severity, default confidence, title, evidence, remediation, and an evidence collector.
3. Add risky and safe/negative fixtures when the rule changes detection behavior.
4. Update `tests/test_regression_fixtures.py` and `docs/rule-coverage.md`.
5. Update `docs/rules.md`, README rule tables, and golden reports when output shape or text intentionally changes.
6. If adapter normalization causes a finding, add or update `source_evidence_paths` provenance tests.
7. Run the full quality bar from `docs/roadmap.md`.

## Third-party rules

Third-party rules are a likely future extension, but plugin loading is intentionally out of scope for this roadmap. The next design step should define a stable metadata schema, deterministic evidence collector contract, version compatibility rules, and safe loading boundaries before executing external code.
