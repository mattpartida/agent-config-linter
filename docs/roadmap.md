# Roadmap

`agent-config-linter` has completed its first MVP roadmap: stable `ACL-*` rule IDs, JSON/Markdown/GitHub-Markdown/SARIF output, policy files, baselines, schema adapters, release automation, report stability tests, and a fixture-backed regression corpus. The next roadmap focuses on becoming a more precise security gate for real agent repositories and an easier tool to operate across teams.

## Guiding principles

- Prefer deterministic checks over opaque model calls.
- Every new rule, semantic change, or adapter expansion needs fixture-backed risky and safe examples.
- Keep output actionable: stable rule IDs, clear evidence paths, source locations, remediation, and suppression lifecycle.
- Preserve backward-compatible report fields whenever possible; use `docs/report-stability.md` before intentional output changes.
- Keep the package dependency-light unless a dependency materially improves parser accuracy, packaging quality, or user trust.
- Do not load third-party rule code until the built-in rule registry contract is stable and reviewed.

## Phase 1: rule-engine maturity

**Phase 1 status: Shipped.** The built-in rules now share a complete registry, findings include additive confidence and source provenance fields, policy files support `min_confidence`, and SARIF locations prefer adapter source paths when available.

### 1. Complete the built-in rule registry migration

**Status: Shipped.** All `ACL-*` metadata now lives in `src/agent_config_linter/rules.py`, and tests compare the registry against `docs/rules.md` and README.

**Why:** `ACL-001` is now registry-backed, but the remaining rules still keep metadata and evidence logic split across the linter. Moving the rest into a registry reduces boilerplate and makes future rule additions safer.

**Deliverables:**

- Move all current `ACL-*` rule metadata into `src/agent_config_linter/rules.py`.
- Keep stable finding IDs, rule IDs, default severities, titles, evidence text, and remediation text unchanged unless a golden fixture update explicitly documents the change.
- Add tests proving registry metadata matches `docs/rules.md` and README rule tables.
- Update `docs/rule-registry.md` with the final built-in rule authoring pattern.

**Acceptance:**

- `python -m pytest tests/test_report_golden.py -q` passes without unintentional output drift.
- A test fails if any documented rule is missing from `RULE_REGISTRY`.
- Adding a rule requires one registry entry plus tests/fixtures/docs, not edits scattered across the linter.

### 2. Add rule-level confidence and precision annotations

**Status: Shipped.** Findings now include additive `confidence`; SARIF and Markdown expose it; policy files can filter lower-confidence findings with `min_confidence`.

**Why:** CI users need to distinguish high-confidence dangerous combinations from heuristic risk hints when deciding what should block merges.

**Deliverables:**

- Add deterministic `confidence` values such as `high`, `medium`, and `low` to findings.
- Document confidence semantics in `docs/rules.md` and README.
- Preserve backward compatibility by treating `confidence` as an additive JSON/SARIF property.
- Add policy support for `min_confidence` filtering if it can be implemented without complicating existing severity gates.

**Acceptance:**

- Existing reports gain `confidence` without removing or renaming fields.
- Golden fixtures cover JSON, Markdown, GitHub-Markdown, and SARIF confidence output.
- Docs explain when to gate on severity, confidence, or both.

### 3. Improve evidence provenance for normalized adapters

**Status: Shipped.** Adapter-backed findings now preserve normalized `evidence_paths` and original `source_evidence_paths`; SARIF source-line lookup prefers the original source paths.

**Why:** Adapter-normalized findings can currently point at normalized capability paths rather than the original source shape. Reviewers need to know which original config field caused a finding.

**Deliverables:**

- Track adapter provenance from original config paths to normalized evidence paths.
- Add `source_evidence_paths` or equivalent additive field to findings.
- Improve SARIF locations to prefer original source paths when available.
- Add nested fixture tests for MCP, GitHub Actions, Hermes, OpenClaw, and OpenAI-compatible tool arrays.

**Acceptance:**

- SARIF locations for adapter-backed findings point to the source config line that caused the finding.
- JSON findings preserve both normalized evidence and original source evidence where they differ.
- Unsupported adapter fields remain ignored rather than guessed.

## Phase 2: real-world coverage expansion

### 4. Add Cursor, Windsurf, and editor-agent config adapters

**Why:** Developers increasingly grant editor agents shell, file, browser, and MCP access from workspace-local settings. These configs are high-value CI targets.

**Deliverables:**

- Add risky and safe fixtures under `examples/config-shapes/` for Cursor and Windsurf-style settings.
- Normalize only tested fields for tool execution, file access, approvals, MCP servers, environment/secrets access, and network egress.
- Document supported and ignored fields in README.

**Acceptance:**

- Each adapter has at least one risky fixture and one safe fixture.
- `tests/test_config_shapes.py` asserts adapter names and expected rule IDs.
- CLI smoke over `examples/config-shapes/` includes the new adapters.

### 5. Add LangGraph/LangChain and CrewAI/AutoGen deployment snippets

**Why:** Agent frameworks encode tool permissions and autonomous execution differently from runtime configs. The linter should catch common dangerous deployment patterns without pretending to understand full Python code.

**Deliverables:**

- Add minimal YAML/JSON deployment-snippet fixtures for LangGraph/LangChain and CrewAI/AutoGen-style configs.
- Detect explicit tool lists, scheduled/autonomous execution, outbound integrations, secrets/env references, and write/delete actions.
- Document parsing boundaries: config snippets only, not static analysis of arbitrary application code.

**Acceptance:**

- Risky fixtures trigger relevant existing `ACL-*` rules.
- Safe fixtures avoid false positives for read-only/review-only agents.
- README documents the config-only boundary clearly.

### 6. Expand rule coverage for supply-chain and network boundaries

**Why:** Current rules cover dangerous agent capabilities, but real incidents often involve unpinned tools, broad package install permissions, or unrestricted egress.

**Candidate rules:**

- Unpinned remote MCP/tool source.
- Runtime package installation enabled without approval.
- Unrestricted network egress versus domain-scoped allowlists.
- Secret-bearing environment variables exposed to shell or MCP tools.

**Deliverables:**

- Design stable rule IDs and severities before implementation.
- Add risky and safe fixtures for each accepted new rule.
- Update `docs/rule-coverage.md`, `docs/rules.md`, README rule tables, and golden reports.

**Acceptance:**

- Every new rule has positive and negative regression fixtures.
- Rules produce deterministic evidence paths and remediation.
- Existing policy/baseline suppression semantics work with the new rule IDs.

## Phase 3: adoption and operations

### 7. Build baseline aging and owner reporting

**Why:** Baselines are useful only if accepted risk has owners, expiry, and cleanup pressure.

**Deliverables:**

- Add summary fields grouped by suppression owner and expiration status.
- Add a `--fail-on-expired-baseline` gate distinct from stale-baseline cleanup.
- Add docs and examples for baseline review workflows.

**Acceptance:**

- Expired suppressions are machine-readable in JSON output.
- CI can fail on expired suppressions without failing on merely stale suppressions unless requested.
- Docs include a copy-pasteable baseline review command.

### 8. Add organization policy bundles

**Why:** Teams need repeatable policy presets for local adoption, staged CI, and strict security gates.

**Deliverables:**

- Add `examples/policies/` with `local-dev`, `staged-ci`, and `strict-ci` policy files.
- Add docs explaining when each preset is appropriate.
- Add tests validating every example policy file with the CLI.

**Acceptance:**

- Example policies parse successfully and produce expected suppression/filtering behavior.
- README links to the policy presets.
- Strict CI preset fails on high/critical active findings by default when paired with documented command examples.

### 9. Improve GitHub Actions integration ergonomics

**Why:** Adoption should require copying one workflow and changing a path, not designing CI from scratch.

**Deliverables:**

- Add workflows for code scanning, PR summary, staged enforcement, and baseline cleanup under `examples/` or `.github/workflows/` as appropriate.
- Document least-privilege permissions for each workflow.
- Add tests that parse workflow YAML and assert key commands, permissions, and SARIF upload paths.

**Acceptance:**

- Example workflows avoid write permissions unless comments or code scanning explicitly require them.
- Workflow tests catch deprecated GitHub actions or missing permissions.
- README has a one-screen quick-start for GitHub users.

## Phase 4: distribution, compatibility, and trust

### 10. Prepare a stable `0.2.0` release

**Why:** The project now has enough surface area that users need a clear compatibility point before broader use.

**Deliverables:**

- Confirm version metadata in `pyproject.toml` and `src/agent_config_linter/__init__.py`.
- Update `CHANGELOG.md` with all roadmap changes since `0.1.0`.
- Run `python scripts/install-smoke.py` locally and in release CI.
- Decide whether report `schema_version` remains `0.1` or bumps for additive fields such as confidence/provenance.

**Acceptance:**

- Built wheel and sdist install successfully in a clean environment.
- Release checklist is complete before tagging.
- JSON/SARIF compatibility decisions are documented in `docs/report-stability.md`.

### 11. Add compatibility test matrix

**Why:** Users will run the linter on multiple Python versions and operating systems, and path/source-line logic can drift across platforms.

**Deliverables:**

- Expand CI to test supported Python versions from `pyproject.toml`.
- Add OS-sensitive tests for path matching and filesystem evidence semantics where practical.
- Keep local commands simple for contributors.

**Acceptance:**

- CI exercises the supported Python version range.
- Path-matching tests cover POSIX and Windows-style paths.
- README development instructions stay accurate.

### 12. Design safe third-party rule-pack loading, but do not implement execution yet

**Why:** External rule packs are useful but risky. The project needs a security design before it executes third-party code.

**Deliverables:**

- Write `docs/rule-packs.md` describing metadata schema, trust boundaries, versioning, and sandbox expectations.
- Define non-executable rule-pack manifest examples if useful.
- Document explicit non-goals for dynamic plugin execution until the model is reviewed.

**Acceptance:**

- The design explains how rule IDs, default severities, docs, fixtures, and report compatibility would work for rule packs.
- The implementation still does not load arbitrary external code.
- Future implementation tasks are small enough to execute with TDD.

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
- `tests/test_config_shapes.py` when adapter behavior changes
- `docs/rule-coverage.md`
- `docs/rules.md` and README rule tables when rule IDs, default severities, confidence, or remediation text change
- `tests/fixtures/golden/` only when report-shape changes are intentional
