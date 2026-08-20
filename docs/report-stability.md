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

## 0.2.0 compatibility decision

For the `0.2.0` release, report `schema_version` remains `0.1`. The release adds fields such as `confidence` and `source_evidence_paths`, but they are additive JSON/SARIF properties: existing keys, finding IDs, rule IDs, severity summary semantics, baseline matching, and policy suppression behavior remain compatible with `0.1` consumers.

Consumers should ignore unknown additive fields unless they explicitly want to gate on confidence or prefer original-source provenance over normalized `evidence_paths`. A future schema bump is reserved for incompatible changes such as removing or renaming fields, changing finding identity keys, changing SARIF rule IDs, or changing suppression lifecycle semantics.

## Finding fingerprint identity

Every newly generated JSON finding and SARIF result includes an additive
`fingerprint` in `sha256:<lowercase-hex>` form. SARIF publishes the same value
under both `properties.fingerprint` and the standard
`partialFingerprints["agentConfigLinter/v1"]` map. Its identity boundary is exactly
the rule ID, normalized report path, and sorted unique evidence paths. The
canonical payload is UTF-8 JSON with sorted keys and compact separators before
SHA-256 hashing.

Report paths are normalized lexically: backslashes become forward slashes,
redundant `.` path segments are removed, Windows drive-relative and UNC roots
are preserved, and uppercase Windows drive letters are lowercased. Paths are
not resolved against the filesystem. Evidence-path order
and duplicates do not affect identity; changing the rule, report path, or
evidence-path set does. Severity, confidence, remediation text, source line,
adapter name, and suppression state are intentionally excluded so the same
finding persists across presentation and policy changes.

The field is additive and optional in the published `0.1` JSON Schema so stored
pre-fingerprint reports remain valid. Consumers may use it to classify findings
as new, persisting, or resolved, but should not attempt to reverse or treat the
hash as a security boundary.

## Stored-report comparison

`agent-config-lint --compare-reports BEFORE.json AFTER.json --format json`
compares only active findings under `files[*].findings`. Both inputs pass through
the same 10 MiB, regular-file, UTF-8, finite-number, bounded-nesting loader used
by `--validate-report`, and both must satisfy the published `schema_version`
`0.1` contract before comparison. The operation does not rescan configs, execute
plugins or tools, perform arbitrary imports, render untrusted strings as
Markdown, or access the network.

Validation bounds both input and diagnostic work: files are limited to 10 MiB,
file-report paths to 4,096 characters, schema-declared arrays to 4,096 items,
and reported schema errors to 100. Operational path and exception diagnostics
are capped at 512 UTF-8 bytes. When
more validation errors exist, `--validate-report` uses additive
`errors_truncated` and `error_limit` metadata; comparison error envelopes use
`validation_errors_truncated` and `validation_error_limit`. Both make truncation
explicit and deterministic.

Comparison output is deterministic: compact entries and the `new_findings`,
`persisting_findings`, and `resolved_findings` arrays are ordered by fingerprint.
Preflight projection and final serialization both enforce an 8 MiB comparison
output budget before a payload is returned.
Persisting entries use after-report metadata. For accepted legacy `0.1` findings
that omit additive fingerprint, confidence, or source-provenance fields, the
command derives identity from the rule ID, containing file-report path, and
evidence paths using the algorithm above, without mutating either loaded report.
Duplicate active fingerprints within one input are rejected because they make
identity ambiguous.
Comparison also rejects contradictory per-file active severity summaries,
duplicate normalized file-report paths, and repository-scan discovery metadata
that does not agree with file reports and parser failures. These checks establish
structural consistency, not artifact provenance or authenticity; use signed or
otherwise integrity-protected reports when hostile parties can rewrite artifacts.

The comparison `scope` is `repository` only when both reports contain complete
`scan` objects with `discovered_files`, `ignored_paths`, and `parser_failures`;
otherwise both reports must be explicit `file-set` scope. Mixed scopes are
rejected. A file-set comparison makes no repository-completeness claim. Because
scope metadata is not authenticated, integrity-protected reports remain required
when an attacker could consistently rewrite both artifacts.

A successful comparison exits `0` even when new findings exist. The explicit
`--fail-on-new` CI gate preserves the complete comparison payload on stdout, adds a
deterministic `gate` object, and exits `1` only when new active findings exist.
Stored-report schema failures and duplicate-fingerprint ambiguity also exit `1`;
load, JSON, non-object, and unsupported-format errors exit `2`.

Comparison output supports `json`, `markdown`, and `github-markdown`. Markdown
uses the same deterministic comparison object and output budget, escapes table
pipes/newlines, and neutralizes `@everyone`/`@here` mass mentions copied from
stored report paths or finding titles. `--summary-only` is available for the two
Markdown formats and emits counts plus gate status without finding tables. A
triggered Markdown `--fail-on-new` gate keeps the rendered summary on stdout so
CI can append it to `GITHUB_STEP_SUMMARY` before enforcing the non-zero exit.

## 0.3.0 compatibility decision

For the `0.3.0` release, report `schema_version` remains `0.1`. The post-`0.2.0` roadmap adds repository scan diagnostics, explanation payloads, review-only suggestions, `trend_summary`, and policy-drift data as additive top-level or finding-adjacent fields. Existing JSON keys, SARIF rule IDs, finding identity fields, severity summary semantics, baseline matching, and policy suppression behavior remain compatible with `0.1` consumers.

The `0.3.0` changelog separates breaking changes, additive report fields, and docs-only changes so automation owners can review compatibility before tagging. Consumers that do not use repo-scan diagnostics, trend artifacts, or policy-drift checks can continue ignoring unknown additive fields.
