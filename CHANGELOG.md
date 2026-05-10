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
- regression fixture corpus coverage for every `ACL-*` rule, including dedicated safe/negative fixtures.
- Roadmap documentation for shipped precision, adapter, policy-schema, and report-stability work.
- PR-friendly `github-markdown` output, `--summary-only`, and a GitHub Actions summary example.
- Lightweight built-in rule registry prototype for `ACL-001 shell_enabled`.
- Release hardening docs and install smoke test from the built wheel.
- Complete built-in rule registry metadata, finding confidence, policy `min_confidence`, and adapter source evidence provenance.
- Cursor, Windsurf, LangGraph/LangChain, CrewAI, and AutoGen-style config-shape adapters with risky/safe fixtures.
- Supply-chain and network-boundary rules `ACL-011` through `ACL-014` for unpinned remote tools, runtime package installation, unrestricted egress, and secret environments exposed to dangerous tools.

## [0.1.0] - 2026-05-08

### Added

- Initial autonomous-agent config risk linter.
- JSON, YAML, TOML, Markdown, and SARIF output support.
- Rule IDs, evidence paths, schema adapters, and GitHub code scanning example.
