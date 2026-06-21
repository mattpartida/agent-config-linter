# Report-schema fixture contracts

Downstream consumers (CI wrappers, dashboards, SARIF uploaders, baseline/policy
tooling) need small, representative report payloads they can validate parsers
against **without running the scanner**. This directory publishes those payloads
and documents which fields are stable consumer contracts versus advisory or
diagnostic output that may shift between runs.

For the compatibility decisions behind these shapes, see
[`docs/report-stability.md`](report-stability.md). Report `schema_version`
remains `0.1` for the `0.3.0` release; every field below is either a stable
contract or an explicitly additive/optional surface.

## Fixture index

Each fixture is a committed, deterministic CLI output. Inputs live under
`tests/fixtures/report-contracts/`; `repo-scan` reuses
`tests/fixtures/repo-scan`.

| Fixture | Command shape | Demonstrates |
| --- | --- | --- |
| [`clean.json`](report-contracts/clean.json) | `cli clean.yaml` | Zero findings, zero signals, `risk_level: low`. |
| [`risky.json`](report-contracts/risky.json) | `cli risky.yaml` | Active findings, per-file `findings[]` with full finding shape. |
| [`policy-suppressed.json`](report-contracts/policy-suppressed.json) | `cli risky.yaml --policy disable-shell-policy.json` | Per-file `policy_suppressed_findings` / `policy_suppressed_summary`. |
| [`baseline-suppressed.json`](report-contracts/baseline-suppressed.json) | `cli risky.yaml --baseline suppressions.json` | Top-level `baseline` review block + per-file `suppressed_findings` / `suppressed_summary`. |
| [`repo-scan.json`](report-contracts/repo-scan.json) | `cli --repo-scan tests/fixtures/repo-scan` | Top-level `scan` discovery diagnostics. |
| [`risky.sarif.json`](report-contracts/risky.sarif.json) | `cli risky.yaml --format sarif` | SARIF 2.1.0 shape with results and tool driver metadata. |

## Top-level fields

**Stable consumer contracts** (present on every JSON report):

| Field | Meaning |
| --- | --- |
| `schema_version` | Report schema version. Currently `0.1`; bumped only on incompatible shape changes. |
| `files` | List of per-file reports. Empty only when no files were linted. |
| `errors` | List of load/parse/policy errors. Empty on a clean run. |

**Conditional stable surfaces** (present only when the corresponding flag is used):

| Field | When present | Meaning |
| --- | --- | --- |
| `baseline` | `--baseline` | Suppression review metadata: `stale_*`, `expired_*`, `owner_summary`. |
| `scan` | `--repo-scan` | Discovery diagnostics: `discovered_files`, `ignored_paths`, `parser_failures`. |
| `explanations` | `--explain` | Expanded single-finding explanations. |
| `policy_drift` | `--check-policy-drift` | `missing_rules` / `unknown_rules` drift reporting. |

## Per-file fields

**Stable** (present on every entry in `files[]`):

`path`, `schema_version`, `schema` (incl. `adapter`), `risk_level`, `score`,
`signals`, `summary`, `findings`, `recommended_next_actions`.

**Conditional stable** (present only when relevant):

`policy_suppressed_findings` / `policy_suppressed_summary` (`--policy`),
`suppressed_findings` / `suppressed_summary` (`--baseline`), `trend_summary`
(`--trend-summary`).

## Finding fields

**Stable**: `id`, `rule_id`, `rule_name`, `severity`, `title`, `evidence`,
`evidence_paths`, `source_evidence_paths`, `remediation`, `confidence`.

**Conditional**: `suggestions` (`--suggestions`), `policy` (on
policy-suppressed findings), `suppression` (on baseline-suppressed findings).

## Stable vs diagnostic/advisory

- **Stable** fields have consistent keys and semantics across runs and versions
  (additive only). Gate CI, build baselines, and parse SARIF against these.
- **Advisory / diagnostic** fields are informational and may change value or
  ordering between runs without a schema bump: `score`, `signals`,
  `recommended_next_actions`, `scan.ignored_paths`, `scan.parser_failures`,
  `baseline.stale_*` / `baseline.expired_*` / `baseline.owner_summary`, and
  `trend_summary`. Use them for display and review, not for identity or gating.

## Keeping fixtures honest

`tests/test_phase9_report_contracts.py` reloads each committed fixture,
validates it parses with `schema_version` `0.1`, asserts its distinguishing
field, and **regenerates it from its documented input** to fail on drift. When a
report-shape change is intentional, regenerate the affected fixture from its
input and update this doc; see `docs/report-stability.md` before bumping
`schema_version`.
