# Roadmap

`agent-config-linter` has a usable local/CI MVP: stable rule IDs, JSON/Markdown/SARIF output, schema adapters, policy files, baselines, release automation, and a regression fixture corpus. The next phase should make the linter more accurate on real agent repos, easier to adopt at scale, and credible as a security gate.

## Guiding principles

- Prefer deterministic checks over opaque model calls.
- Every rule or adapter expansion needs fixture-backed risky and safe examples.
- Optimize for actionable CI output: clear evidence paths, clear suppression lifecycle, clear remediation.
- Keep the package dependency-light unless a dependency materially improves parser accuracy or distribution quality.
- Preserve backward-compatible report fields whenever possible.

## Near term: precision and coverage

### 1. Complete regression coverage for every existing rule

**Status:** Shipped. `ACL-007` and `ACL-009` now have dedicated risky and safe fixtures, and `docs/rule-coverage.md` lists risky plus negative coverage for every existing `ACL-*` rule.

**Why:** `docs/rule-coverage.md` still notes fixture gaps for `ACL-007` and dedicated weak-model fixtures. Closing these gaps makes future rule edits safer.

**Deliverables:**

- Add risky and safe fixtures for `ACL-007 privileged_infra_control`.
- Add dedicated risky and safe fixtures for `ACL-009 weak_model_risk`.
- Update `tests/test_regression_fixtures.py` to assert the new fixtures.
- Update `docs/rule-coverage.md` so no rule says "add a dedicated fixture when this rule changes."

**Acceptance:**

- `python -m pytest tests/test_regression_fixtures.py -q` passes.
- `docs/rule-coverage.md` lists at least one risky fixture and one safe/negative fixture for each `ACL-*` rule.

### 2. Improve evidence paths and source locations

**Status:** Shipped. Composite findings now emit evidence paths, and SARIF source-line mapping covers nested YAML/TOML plus indexed array/toolset evidence paths.

**Why:** SARIF and PR-comment consumers need precise line numbers and evidence paths, especially for nested YAML/TOML configs and normalized schema adapters.

**Deliverables:**

- Include evidence paths for composite findings such as `lethal_trifecta`, `prompt_injection_exfiltration_bridge`, `unattended_dangerous_tools`, and `privileged_infra_control`.
- Improve `_source_line_for_evidence` so paths with arrays and nested keys map to the most relevant source line.
- Add tests with YAML, TOML, and JSON examples that validate SARIF line numbers.

**Acceptance:**

- SARIF results for composite rules include non-empty `properties.evidence_paths`.
- Source-line tests cover nested YAML/TOML plus at least one array/toolset path.

### 3. Split broad filesystem and write-access semantics

**Status:** Shipped. `ACL-002` now focuses on broad roots/unrestricted filesystem mappings, while project-scoped writable paths raise `ACL-010` without also raising `ACL-002`. `docs/rules.md` includes the migration note.

**Why:** `filesystem_broad_access` currently treats write-capable project-scoped access as broad. That is conservative, but users need clearer distinction between broad read access and scoped write access.

**Deliverables:**

- Keep `ACL-010 filesystem_write_access` for write-capable paths.
- Make `ACL-002 filesystem_broad_access` focus on broad roots like `/`, `~`, `$HOME`, `*`, host mounts, and unrestricted workspace mappings.
- Add migration note explaining any summary/risk changes.

**Acceptance:**

- Project-scoped `mode: rw` triggers `ACL-010` but not `ACL-002`.
- Root/home/unrestricted paths still trigger `ACL-002`.

## Mid term: real-world schema support

### 4. Add adapter fixtures for more agent runtimes

**Status:** Shipped. Added fixture-backed `mcp` and `github_actions` adapters, with risky and safe examples under `examples/config-shapes/`; README documents the supported fields and ignored-fields boundary.

**Why:** The linter becomes more useful when it understands how popular runtimes encode tools, approvals, secrets, memory, and egress.

**Candidate adapters:**

- Claude Desktop / MCP server configs.
- Cursor or Windsurf workspace agent settings.
- LangGraph/LangChain deployment-style config snippets.
- CrewAI/AutoGen-style tool and autonomy configs.
- GitHub Actions agent workflows that expose secrets and write tokens.

**Deliverables:**

- Add representative examples under `examples/config-shapes/`.
- Normalize only fields backed by tests.
- Document supported fields in README and/or adapter-specific docs.

**Acceptance:**

- Each new adapter has at least one risky fixture and one safe fixture.
- Unsupported fields remain ignored rather than guessed.

### 5. Add policy schema documentation and validation output

**Why:** Policy files are adoption-critical. Users need copy-pasteable schemas and better validation errors before wiring this into CI.

**Deliverables:**

- Add `docs/policy-schema.md` with JSON/YAML/TOML examples.
- Emit validation errors with field paths, e.g. `allowlists.paths[0].rule_id`.
- Add tests for invalid policy types, malformed path allowlists, and unknown severity values.

**Acceptance:**

- Invalid policy output identifies the exact invalid field.
- Docs show minimal, staged-adoption, and strict CI policy examples.

### 6. Add report stability tests

**Why:** CI users will integrate against JSON fields and SARIF shape. Report drift should be deliberate.

**Deliverables:**

- Add golden-output fixtures for JSON, Markdown, and SARIF reports.
- Add a focused update workflow in docs for intentional report changes.
- Consider a `schema_version` bump checklist when output changes.

**Acceptance:**

- Golden tests fail on unreviewed report-shape changes.
- README documents compatibility expectations for `schema_version`.

## Later: adoption and distribution

### 7. First public release hardening

**Why:** The project has release automation but still needs pre-release polish before broader adoption.

**Deliverables:**

- Update `CHANGELOG.md` with the regression corpus and roadmap docs.
- Add an install smoke test from built wheel/sdist.
- Verify PyPI trusted publishing config against a test tag or dry run.
- Add `SECURITY.md` with vulnerability reporting expectations.

**Acceptance:**

- `python -m build` succeeds locally or in CI.
- Built wheel can run `agent-config-lint --version` in a clean environment.

### 8. Better developer and reviewer UX

**Why:** The fastest path to adoption is a useful report in PRs, not just machine-readable CI artifacts.

**Deliverables:**

- Add `--format github-markdown` or a concise Markdown mode tuned for PR comments.
- Add `--summary-only` for chat/CI logs.
- Add examples that post Markdown findings as a PR comment.

**Acceptance:**

- Markdown output has stable sections and no noisy empty tables.
- Example workflow can run without requiring write permissions unless PR comments are explicitly enabled.

### 9. Rule-pack architecture exploration

**Why:** Different orgs will want different checks without forking the whole linter.

**Deliverables:**

- Design a minimal in-repo rule registry that keeps stable IDs, default severities, remediation text, and evidence collectors together.
- Prototype one rule moved into the registry without changing output.
- Document how third-party rules might work later, but do not add plugin loading until needed.

**Acceptance:**

- Existing tests pass with identical report output.
- Adding a new built-in rule has a documented checklist and less boilerplate than today.

## Ongoing quality bar

Before merging roadmap work, run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
python -m compileall -q src tests
python -m pytest -q
python -m ruff check .
```

For rule or adapter changes, also update:

- `tests/fixtures/regression/`
- `tests/test_regression_fixtures.py`
- `docs/rule-coverage.md`
- `docs/rules.md` and README rule tables when rule IDs or default severities change
