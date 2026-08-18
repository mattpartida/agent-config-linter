# Changelog

All notable changes to `agent-config-linter` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses semantic versioning once releases are tagged.

## [Unreleased]

### Added

- Phase 11 stored-report comparison: `--compare-reports BEFORE.json AFTER.json` securely loads and validates two archived `0.1` JSON reports, derives missing legacy fingerprints, rejects duplicate active identities, and emits deterministic new/persisting/resolved finding arrays without rescanning or executing external resources.
- Phase 11 CI regression gate: comparison-only `--fail-on-new` preserves the full JSON comparison contract and exits `1` only when new active findings are present.
- Stored-report hardening bounds structural arrays, paths, diagnostics, and final comparison output; types complete repository-scan metadata; rejects mixed file-set/repository scopes, contradictory summaries, incomplete discovery metadata, and duplicate normalized file identities; and preserves compatibility with authentic pre-provenance `0.1` reports.
- Phase 10 report JSON Schema: `--report-schema --format json` and `docs/report-schema.json` publish the additive Draft 2020-12 contract for stable JSON report, file, and finding fields; the integration manifest advertises schema discovery.
- Phase 10 stored report validation: `--validate-report <report.json>` validates archived reports locally against the published stable schema subset without rescanning configs, executing tools/plugins, or fetching remote resources; deterministic validation errors distinguish contract failures from load errors.
- Phase 10 finding fingerprints: generated JSON findings and SARIF results include deterministic `sha256:` fingerprints derived from rule ID, normalized report path, and sorted unique evidence paths for cross-run new/persisting/resolved comparison; SARIF also publishes the value through `partialFingerprints`.
- Phase 9 developer discovery: `--list-rules` emits the built-in rule catalog as stable JSON or Markdown without requiring config paths.
- Phase 9 report-schema fixture contracts: published representative JSON/SARIF payloads (clean, risky, policy-suppressed, baseline-suppressed, repo-scan) under `docs/report-contracts/` with stable-vs-diagnostic field documentation in `docs/report-contracts.md`; drift-checked by `tests/test_phase9_report_contracts.py`.
- Phase 9 integration manifest: `--integration-manifest` emits a machine-readable capability manifest (package/report-schema versions, input/output formats, exit codes, flags, optional report sections) for wrappers, editors, and dashboards; README documents an Exit codes section, and agreement is enforced by `tests/test_phase9_integration_manifest.py`.

## [0.3.0] - 2026-05-17

### Breaking changes

- None. Report `schema_version` remains `0.1` for the `0.3.0` compatibility point.

### Additive report fields

- Phase 5-7 fields remain additive: repository scan diagnostics, explanation payloads, review-only suggestions, `trend_summary`, and policy-drift outputs do not remove or rename existing report keys.

### Docs-only changes

- Phase 8 release quality and ecosystem readiness: installed sdist smoke coverage, `0.3.0` release checklist updates, extension governance for future rule-pack ecosystems, and an examples gallery for common agent stacks.

### Added

- Phase 7 CI adoption, metrics, and governance: `--trend-summary` time-series counts, `--check-policy-drift` / `--fail-on-policy-drift`, versioned example policy bundles, workflow permission governance tests, and a trend-summary artifact workflow.
- Phase 6 repository-scale discovery and developer UX: `--repo-scan` diagnostics for discovered/ignored/parser-failed files, deterministic `--explain` output for one finding, and review-only JSON/Markdown remediation suggestions.
- Phase 5 precision and rule-pack foundations: metadata-only `RulePackManifest` validation with `--validate-rule-pack`, executable-field rejection, non-executable `match_spec` metadata for simple built-in rules, and precision-boundary fixtures/docs for likely false-positive cases.
- Post-`0.2.0` roadmap covering precision/rule-pack foundations, repository-scale discovery, developer UX, CI governance, and future `0.3.0` readiness.

## [0.2.0] - 2026-05-10

### Added

- Phase 1 rule-engine maturity: complete built-in `ACL-*` rule registry metadata, finding confidence, policy `min_confidence`, adapter `source_evidence_paths` provenance for SARIF/source-location consumers, and the regression fixture corpus for every built-in rule.
- Phase 2 real-world coverage: Cursor, Windsurf, LangGraph/LangChain, CrewAI, and AutoGen-style config-shape adapters with risky/safe fixtures.
- Phase 2 supply-chain and network-boundary rules `ACL-011` through `ACL-014` for unpinned remote tools, runtime package installation, unrestricted egress, and secret environments exposed to dangerous tools.
- Phase 3 adoption and operations: baseline owner summaries, expired-suppression reporting, `--fail-on-expired-baseline`, organization policy bundles, and GitHub Actions adoption workflows.
- Phase 4 distribution and trust: `0.2.0` package metadata, Python/OS compatibility CI matrix, Windows/POSIX filesystem evidence tests, non-executable rule-pack design, and roadmap status updates.

### Changed

- Package metadata now marks the project as beta-ready for broader testing.
- Report `schema_version` remains `0.1` for `0.2.0` because confidence and provenance fields are additive and do not remove or rename existing JSON/SARIF keys.

## [0.1.0] - 2026-05-08

### Added

- Initial autonomous-agent config risk linter.
- JSON, YAML, TOML, Markdown, and SARIF output support.
- Rule IDs, evidence paths, schema adapters, and GitHub code scanning example.
