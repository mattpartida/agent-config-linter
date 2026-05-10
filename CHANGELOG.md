# Changelog

All notable changes to `agent-config-linter` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses semantic versioning once releases are tagged.

## [Unreleased]

### Added

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
