# Roadmap

`agent-config-linter` has completed its first MVP and `0.2.0` readiness roadmaps: stable `ACL-*` rule IDs, JSON/Markdown/GitHub-Markdown/SARIF output, policy files, baselines, schema adapters, release automation, report stability tests, a fixture-backed regression corpus, compatibility testing, and manifest-only rule-pack design. The next roadmap focuses on turning the linter from a strong standalone CLI into a safer ecosystem component: more precise declarative rules, better repository discovery, actionable autofix guidance, and trustable adoption workflows.

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

**Phase 2 status: Shipped.** Cursor, Windsurf, LangGraph/LangChain, CrewAI, and AutoGen-style config snippets are now fixture-backed adapters, and `ACL-011` through `ACL-014` cover supply-chain and network-boundary risks.

### 4. Add Cursor, Windsurf, and editor-agent config adapters

**Status: Shipped.** Risky and safe Cursor/Windsurf fixtures live under `examples/config-shapes/`, adapters preserve source evidence for tested fields, and README documents supported/ignored behavior.

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

**Status: Shipped.** Minimal risky/safe framework-deployment fixtures are covered for LangGraph, CrewAI, and AutoGen-style snippets, with docs explicitly scoped to config snippets rather than arbitrary Python static analysis.

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

**Status: Shipped.** Added stable rules `ACL-011` through `ACL-014` for unpinned remote tool sources, runtime package installs, unrestricted egress, and secret-bearing environments exposed to dangerous tools. Each new rule has risky and safe regression coverage plus README/rules/coverage docs.

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

Phase 3 status: Shipped. Baseline owner/expiry reporting, policy bundles, GitHub Actions workflow examples, and adoption docs are implemented and covered by regression tests.

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

Phase 4 status: Shipped. The `0.2.0` compatibility point is documented, CI now exercises the supported Python/OS matrix, filesystem evidence has POSIX and Windows-style path coverage, and safe third-party rule-pack loading is designed as a manifest-only trust boundary with no external code execution.

### 10. Prepare a stable `0.2.0` release

**Status: Shipped.** Version metadata is aligned at `0.2.0`, the changelog summarizes roadmap changes since `0.1.0`, release CI runs the installed-wheel smoke test, and `docs/report-stability.md` documents that additive confidence/provenance fields keep report `schema_version` at `0.1`.

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

**Status: Shipped.** CI now runs on Python 3.11 and 3.12 across Ubuntu, macOS, and Windows, and regression tests cover POSIX and Windows-style broad filesystem roots without changing contributor-local commands.

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

**Status: Shipped.** `docs/rule-packs.md` defines manifest metadata, trust boundaries, rule identity, fixtures, compatibility expectations, and explicit non-goals for dynamic execution; `examples/rule-packs/metadata-only-rule-pack.yaml` is a non-executable manifest sketch.

**Why:** External rule packs are useful but risky. The project needs a security design before it executes third-party code.

**Deliverables:**

- Write `docs/rule-packs.md` describing metadata schema, trust boundaries, versioning, and sandbox expectations.
- Define non-executable rule-pack manifest examples if useful.
- Document explicit non-goals for dynamic plugin execution until the model is reviewed.

**Acceptance:**

- The design explains how rule IDs, default severities, docs, fixtures, and report compatibility would work for rule packs.
- The implementation still does not load arbitrary external code.
- Future implementation tasks are small enough to execute with TDD.

## Phase 5: precision and rule-pack foundations

Phase 5 status: Planned. This phase should make built-in and future third-party rules more declarative, easier to review, and safer to extend without executing external code.

### 13. Build a manifest parser and validator for non-executable rule packs

**Why:** `docs/rule-packs.md` defines the trust boundary, but users need validation tooling before any rule-pack ecosystem exists.

**Deliverables:**

- Add a `RulePackManifest` parser for local YAML/JSON manifests that validates metadata only.
- Reject executable-looking fields such as command, entry point, module, script, hook, package installer, or dynamic import references.
- Add CLI support to validate or inspect a manifest without running rules.
- Keep dynamic rule execution explicitly unsupported.

**Acceptance:**

- Risky manifest fixtures with executable-looking fields fail validation with clear errors.
- Safe metadata-only fixtures parse and round-trip deterministic metadata.
- Reports and lint behavior remain unchanged when no rule-pack validation command is used.

### 14. Move built-in rule predicates toward declarative match specs

**Why:** Declarative matching is easier to audit, document, and eventually share with rule packs than ad hoc Python branches spread across helpers.

**Deliverables:**

- Identify a small subset of existing simple rules suitable for declarative match specs.
- Define a minimal internal spec for path fragments, enabled-state checks, value allowlists, and evidence path collection.
- Migrate one or two low-risk rules while preserving exact finding IDs, severity, confidence, and evidence output.
- Document which rules remain custom Python and why.

**Acceptance:**

- Golden reports do not drift except for intentional, reviewed evidence-path ordering changes.
- Migrated rules retain risky/safe regression fixture behavior.
- The internal spec cannot call code, import modules, or evaluate expressions.

### 15. Add precision-focused negative fixture packs

**Why:** The linter has broad positive coverage, but adoption depends on suppressing false positives for common safe patterns.

**Deliverables:**

- Add negative fixtures for read-only filesystem access, domain-scoped egress, review-only autonomy, pinned remote tools, and secret names that are not exposed to dangerous tools.
- Add a `docs/precision-boundaries.md` guide explaining why each negative fixture is safe.
- Track false-positive boundaries in tests so future rule changes must update fixtures deliberately.

**Acceptance:**

- Every high/critical rule has at least one explicit negative fixture for its most likely false-positive boundary.
- `docs/rule-coverage.md` links to the new precision-boundary fixture group.
- Full regression tests fail if a boundary fixture starts producing the guarded finding.

## Phase 6: repository-scale discovery and developer UX

Phase 6 status: Planned. This phase should make the linter useful on real repositories where configs are scattered across hidden directories, CI workflows, examples, and framework deployment snippets.

### 16. Add recursive repo scanning with config-shape discovery

**Why:** Users should be able to point the tool at a repository root and get useful results without hand-selecting every config file.

**Deliverables:**

- Add a repo scan mode that discovers supported config files under common paths such as `.github/workflows/`, `.cursor/`, `.windsurf/`, MCP settings, examples, and deployment directories.
- Skip vendored/cache/build directories by default.
- Report discovered files, ignored files, parser failures, and adapter selection.
- Keep single-file lint behavior unchanged.

**Acceptance:**

- Fixtures cover nested repo trees with supported, ignored, malformed, and safe files.
- JSON output distinguishes active findings from scan diagnostics.
- CLI docs include copy-pasteable repo scan examples.

### 17. Add explain output for one finding at a time

**Why:** CI findings should be understandable by developers who do not know the rule catalog.

**Deliverables:**

- Add an `explain`-style output mode or flag that expands one finding into rule intent, evidence paths, source evidence paths, confidence, remediation, and suppression guidance.
- Link each finding to `docs/rules.md` or a generated per-rule anchor.
- Include examples for terminal and PR-comment usage.

**Acceptance:**

- Explain output is deterministic and covered by golden tests.
- The output never hides the machine-readable rule ID needed for baselines and policy files.
- README documents the shortest developer workflow from CI finding to remediation.

### 18. Produce remediation patches only as suggestions

**Why:** Developers need actionable fixes, but automated security edits should be reviewable and opt-in.

**Deliverables:**

- Add structured remediation suggestions for selected rules, such as adding approval gates, narrowing filesystem roots, pinning tool sources, or replacing unrestricted egress with a placeholder allowlist.
- Emit suggestions in JSON and Markdown without modifying files by default.
- Consider a separate `--write-suggestions` artifact output, not in-place edits.

**Acceptance:**

- Suggestions are clearly labeled as review-required and never applied automatically by default.
- Tests cover suggested patch text for at least three common rule families.
- Suggestions preserve stable finding IDs and baseline matching behavior.

## Phase 7: CI adoption, metrics, and governance

Phase 7 status: Planned. This phase should help teams operate the linter over time instead of treating it as a one-off scanner.

### 19. Add trendable summary artifacts

**Why:** Security teams need to know whether findings are getting better or worse across runs.

**Deliverables:**

- Add optional summary output designed for time-series ingestion: counts by rule, severity, confidence, adapter, path prefix, baseline state, and owner.
- Keep the artifact stable and compact.
- Document how to archive it in GitHub Actions.

**Acceptance:**

- Trend summaries are deterministic and covered by tests.
- Existing JSON reports remain backward compatible.
- Docs include a minimal GitHub Actions upload-artifact example.

### 20. Add policy drift and bundle version checks

**Why:** Organization policy bundles can become stale or diverge from recommended defaults.

**Deliverables:**

- Add metadata versions to example policy bundles.
- Report when a policy file omits known rules or references retired/unknown rules.
- Add docs for upgrading policy bundles between releases.

**Acceptance:**

- Unknown, missing, and stale policy references are machine-readable.
- Strict CI can fail on policy drift independently from finding severity.
- Example policies remain valid under the new drift checks.

### 21. Harden GitHub Actions supply-chain posture

**Why:** The project ships workflow examples and its own CI; those should model secure defaults.

**Deliverables:**

- Decide whether project workflows and examples should pin third-party actions by major version, full SHA, or documented exception.
- Add tests that catch deprecated or unexpectedly broad permissions.
- Document upgrade workflow for pinned actions.

**Acceptance:**

- Workflow examples have explicit permission rationale.
- Tests prevent accidental `contents: write` or broad token scopes where not required.
- The release workflow remains compatible with PyPI trusted publishing.

## Phase 8: release quality and ecosystem readiness

Phase 8 status: Planned. This phase should prepare a future `0.3.0` release with fewer footguns and clearer ecosystem boundaries.

### 22. Prepare a stable `0.3.0` compatibility point

**Why:** The next release should bundle repo scanning, precision fixtures, and manifest validation behind a clear compatibility decision.

**Deliverables:**

- Update version metadata only after the planned `0.3.0` feature set is implemented and verified.
- Decide whether repo-scan diagnostics or trend artifacts require a `schema_version` bump.
- Update `CHANGELOG.md`, `docs/report-stability.md`, and `docs/release-checklist.md` before tagging.

**Acceptance:**

- Install smoke passes from built wheel and sdist.
- Compatibility decisions are documented before tagging.
- The changelog separates breaking changes, additive report fields, and docs-only changes.

### 23. Add documented extension governance

**Why:** If third-party rule packs become possible later, the project needs a governance model before accepting ecosystem contributions.

**Deliverables:**

- Document naming rules for non-`ACL-*` rule IDs.
- Define review expectations for rule-pack examples, fixtures, severity, confidence, and remediation text.
- Add an explicit process for promoting an external rule idea into the built-in catalog.

**Acceptance:**

- `docs/rule-packs.md` distinguishes manifest validation from future rule execution.
- Governance docs define collision handling and ownership metadata.
- Future contributors can tell whether a rule belongs in core, a policy bundle, or a third-party pack.

### 24. Build an examples gallery for common agent stacks

**Why:** Adoption improves when users can compare their setup against realistic safe and risky examples.

**Deliverables:**

- Add a curated examples index covering local coding agents, CI agents, MCP desktop configs, editor agents, framework deployments, and organization policy bundles.
- Label examples as safe, risky, or intentionally vulnerable.
- Add smoke tests that lint every gallery example.

**Acceptance:**

- Every gallery example has a documented expected result.
- Safe examples remain clean for guarded high/critical rules.
- Risky examples trigger stable rule IDs without relying on brittle line numbers.

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
