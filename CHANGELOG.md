# Changelog

All notable changes to `agent-config-linter` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses semantic versioning once releases are tagged.

## [Unreleased]

### Added

- Policy files with severity overrides, disabled rules, and allowlists.
- Baseline lifecycle tooling with generated suppressions, metadata validation, stale suppression reporting, and stale-baseline failure mode.
- CI/developer-experience flags for staged adoption: `--min-severity` and `--fail-on`.
- `agent-config-lint --version` for release verification.
- Packaging metadata and trusted-publishing release automation.

## [0.1.0] - 2026-05-08

### Added

- Initial autonomous-agent config risk linter.
- JSON, YAML, TOML, Markdown, and SARIF output support.
- Rule IDs, evidence paths, schema adapters, and GitHub code scanning example.
