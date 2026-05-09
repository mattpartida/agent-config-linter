# Rule registry architecture

The first rule-registry pass keeps built-in rule metadata and the evidence collector for a prototype rule together without changing report output. The registry is intentionally in-repo only: third-party rules are documented as a future design topic, and plugin loading is intentionally out of scope until the built-in API is stable.

## Current shape

`src/agent_config_linter/rules.py` exposes `RULE_REGISTRY`, keyed by finding ID. Each registry entry includes:

- Stable rule ID, for example `ACL-001`.
- Stable rule name, for example `shell-enabled`.
- Default severity.
- Title, evidence text, and remediation text.
- Evidence collector callable.

The initial prototype moves `shell_enabled` into the registry while preserving the existing JSON, Markdown, and SARIF output shape.

## Built-in rule checklist

When adding or migrating a built-in rule:

1. Choose a stable rule ID and finding ID before writing implementation code.
2. Add a `RuleDefinition` entry containing default severity, title, evidence, remediation, and an evidence collector.
3. Add risky and safe/negative fixtures when the rule changes detection behavior.
4. Update `tests/test_regression_fixtures.py` and `docs/rule-coverage.md`.
5. Update `docs/rules.md`, README rule tables, and golden reports when output shape or text intentionally changes.
6. Run the full quality bar from `docs/roadmap.md`.

## Third-party rules

Third-party rules are a likely future extension, but plugin loading is intentionally out of scope for this roadmap. The next design step should define a stable metadata schema, deterministic evidence collector contract, version compatibility rules, and safe loading boundaries before executing external code.
