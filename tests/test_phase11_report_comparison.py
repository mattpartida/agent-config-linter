"""Phase 11, item 31: compare stored reports without rescanning configs."""

import copy
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from agent_config_linter import cli
from agent_config_linter.cli import run

ROOT = Path(__file__).resolve().parents[1]
RISKY_REPORT = ROOT / "docs" / "report-contracts" / "risky.json"
LEGACY_REPORT = ROOT / "tests" / "fixtures" / "report-contracts" / "legacy-0.1-pre-provenance.json"


class StoredReportComparisonTests(unittest.TestCase):
    def _set_findings(self, report, findings):
        file_report = report["files"][0]
        file_report["findings"] = findings
        file_report["summary"] = {
            severity: sum(finding["severity"] == severity for finding in findings)
            for severity in cli.SEVERITIES
        }

    def _reports(self):
        source = json.loads(RISKY_REPORT.read_text())
        first, second = copy.deepcopy(source["files"][0]["findings"])
        third = copy.deepcopy(first)
        third.update(
            {
                "id": "autonomous_execution",
                "rule_id": "ACL-004",
                "rule_name": "autonomous-execution",
                "severity": "critical",
                "title": "Autonomous execution is enabled",
                "evidence_paths": ["autonomy.enabled"],
                "source_evidence_paths": ["autonomy.enabled"],
            }
        )
        path = source["files"][0]["path"]
        third["fingerprint"] = cli._finding_fingerprint(third["rule_id"], path, third["evidence_paths"])

        before = copy.deepcopy(source)
        after = copy.deepcopy(source)
        self._set_findings(before, [second, first])
        self._set_findings(after, [third, second])
        after["files"][0]["findings"][1]["title"] = "After metadata wins"
        return before, after

    def _run_with_reports(self, before, after, extra_args=()):
        with tempfile.TemporaryDirectory() as directory:
            before_path = Path(directory) / "before.json"
            after_path = Path(directory) / "after.json"
            before_path.write_text(json.dumps(before))
            after_path.write_text(json.dumps(after))
            exit_code, output = run(
                ["--compare-reports", str(before_path), str(after_path), *extra_args]
            )
        return exit_code, json.loads(output), str(before_path), str(after_path)

    def test_classifies_new_persisting_and_resolved_with_auditable_entries(self):
        before, after = self._reports()
        exit_code, payload, before_path, after_path = self._run_with_reports(before, after)

        self.assertEqual(exit_code, 0, payload)
        self.assertEqual(set(payload), {"schema_version", "report_comparison", "errors"})
        comparison = payload["report_comparison"]
        self.assertEqual(
            set(comparison),
            {
                "schema_version",
                "scope",
                "before",
                "after",
                "summary",
                "new_findings",
                "persisting_findings",
                "resolved_findings",
            },
        )
        self.assertEqual(
            comparison["summary"],
            {"before": 2, "after": 2, "new": 1, "persisting": 1, "resolved": 1},
        )
        self.assertEqual(comparison["before"]["path"], before_path)
        self.assertEqual(comparison["after"]["path"], after_path)
        self.assertEqual(comparison["persisting_findings"][0]["title"], "After metadata wins")
        for section in ("new_findings", "persisting_findings", "resolved_findings"):
            self.assertEqual(len(comparison[section]), 1)
            self.assertEqual(
                set(comparison[section][0]),
                {"fingerprint", "report_path", "rule_id", "finding_id", "severity", "title"},
            )

    def test_output_arrays_are_sorted_by_fingerprint_and_repeat_deterministically(self):
        before, after = self._reports()
        self._set_findings(before, [])
        exit_code, first, _, _ = self._run_with_reports(before, after)
        second_exit, second, _, _ = self._run_with_reports(before, after)

        self.assertEqual(exit_code, 0)
        self.assertEqual(second_exit, 0)
        entries = first["report_comparison"]["new_findings"]
        self.assertEqual([entry["fingerprint"] for entry in entries], sorted(entry["fingerprint"] for entry in entries))
        self.assertEqual(
            first["report_comparison"]["new_findings"],
            second["report_comparison"]["new_findings"],
        )

    def test_derives_missing_legacy_fingerprints_without_mutating_reports(self):
        before, after = self._reports()
        for report in (before, after):
            for finding in report["files"][0]["findings"]:
                finding.pop("fingerprint", None)
        original_before = copy.deepcopy(before)
        original_after = copy.deepcopy(after)

        comparison = cli._compare_stored_reports(before, after)

        self.assertEqual(comparison["summary"]["persisting"], 1)
        self.assertEqual(before, original_before)
        self.assertEqual(after, original_after)
        for section in ("new_findings", "persisting_findings", "resolved_findings"):
            self.assertRegex(comparison[section][0]["fingerprint"], r"^sha256:[0-9a-f]{64}$")

    def test_accepts_authentic_pre_provenance_schema_0_1_report(self):
        legacy = json.loads(LEGACY_REPORT.read_text())
        original = copy.deepcopy(legacy)

        exit_code, payload, _, _ = self._run_with_reports(legacy, legacy)

        self.assertEqual(exit_code, 0, payload)
        self.assertEqual(payload["report_comparison"]["summary"]["persisting"], 6)
        self.assertEqual(payload["report_comparison"]["summary"]["new"], 0)
        self.assertEqual(legacy, original)

    def test_rejects_stale_supplied_fingerprint_at_deterministic_location(self):
        before, after = self._reports()
        before["files"][0]["findings"][0]["fingerprint"] = "sha256:" + "0" * 64

        exit_code, payload, before_path, _ = self._run_with_reports(before, after)

        self.assertEqual(exit_code, 1)
        error = payload["errors"][0]
        self.assertEqual(error["role"], "before")
        self.assertEqual(error["path"], before_path)
        self.assertEqual(error["finding_path"], "$.files[0].findings[0].fingerprint")
        self.assertIn("does not match canonical identity", error["message"])

    def test_rejects_duplicate_active_fingerprints_and_identifies_both_locations(self):
        before, after = self._reports()
        duplicate = copy.deepcopy(before["files"][0]["findings"][0])
        self._set_findings(before, [*before["files"][0]["findings"], duplicate])

        exit_code, payload, before_path, _ = self._run_with_reports(before, after)

        self.assertEqual(exit_code, 1)
        self.assertIsNone(payload["report_comparison"])
        error = payload["errors"][0]
        self.assertEqual(error["role"], "before")
        self.assertEqual(error["path"], before_path)
        self.assertIn("duplicate active fingerprint", error["message"])
        self.assertEqual(
            error["finding_paths"],
            ["$.files[0].findings[0]", "$.files[0].findings[2]"],
        )

    def test_rejects_incomplete_reports_without_false_resolutions(self):
        before, after = self._reports()
        cases = (
            ("top-level errors", {**copy.deepcopy(after), "errors": [{"path": "broken", "message": "scan failed"}]}),
            (
                "parser failures",
                {
                    **copy.deepcopy(after),
                    "scan": {
                        "discovered_files": [
                            after["files"][0]["path"],
                            "broken",
                        ],
                        "ignored_paths": [],
                        "parser_failures": [
                            {"path": "broken", "message": "parse failed"}
                        ],
                    },
                },
            ),
            ("no file reports", {**copy.deepcopy(after), "files": []}),
        )
        for expected, incomplete in cases:
            with self.subTest(expected=expected):
                exit_code, payload, _, _ = self._run_with_reports(before, incomplete)
                self.assertEqual(exit_code, 1)
                self.assertEqual(payload["errors"][0]["role"], "after")
                self.assertIn(expected, payload["errors"][0]["message"])

    def test_rejects_contradictory_summary_duplicate_files_and_scan_omissions(self):
        before, after = self._reports()

        contradictory = copy.deepcopy(after)
        contradictory["files"][0]["findings"] = []

        duplicate_file = copy.deepcopy(after)
        second_file = copy.deepcopy(duplicate_file["files"][0])
        second_file["path"] = f"./{second_file['path']}"
        second_file["findings"] = []
        second_file["summary"] = {severity: 0 for severity in cli.SEVERITIES}
        duplicate_file["files"].append(second_file)

        incomplete_scan = copy.deepcopy(after)
        incomplete_scan["scan"] = {
            "discovered_files": [after["files"][0]["path"], "omitted.json"],
            "ignored_paths": [],
            "parser_failures": [],
        }

        for expected, invalid in (
            ("summary does not match", contradictory),
            ("duplicate normalized file path", duplicate_file),
            ("discovered files do not match", incomplete_scan),
        ):
            with self.subTest(expected=expected):
                exit_code, payload, _, _ = self._run_with_reports(before, invalid, ("--fail-on-new",))
                self.assertEqual(exit_code, 1)
                self.assertIsNone(payload["report_comparison"])
                self.assertIn(expected, payload["errors"][0]["message"])

    def test_validation_errors_are_bounded_with_deterministic_truncation_metadata(self):
        before, after = self._reports()
        after["files"] = [{} for _ in range(cli.MAX_VALIDATION_ERRORS + 1)]

        exit_code, payload, _, _ = self._run_with_reports(before, after)

        self.assertEqual(exit_code, 1)
        error = payload["errors"][0]
        self.assertEqual(len(error["validation_errors"]), cli.MAX_VALIDATION_ERRORS)
        self.assertTrue(error["validation_errors_truncated"])
        self.assertEqual(error["validation_error_limit"], cli.MAX_VALIDATION_ERRORS)
        self.assertLess(len(json.dumps(payload)), 100_000)

    def test_structural_array_limit_rejects_oversized_reports_without_expansion(self):
        before, after = self._reports()
        after["files"] = [{} for _ in range(cli.MAX_SCHEMA_ARRAY_ITEMS + 1)]

        exit_code, payload, _, _ = self._run_with_reports(before, after)

        self.assertEqual(exit_code, 1)
        error = payload["errors"][0]
        self.assertEqual(len(error["validation_errors"]), 1)
        self.assertEqual(error["validation_errors"][0]["path"], "$.files")
        self.assertIn("at most", error["validation_errors"][0]["message"])
        self.assertNotIn("validation_errors_truncated", error)
        self.assertLess(len(json.dumps(payload)), 2_000)

    def test_malformed_and_oversized_scan_metadata_fails_closed(self):
        before, after = self._reports()
        malformed_values = (
            None,
            7,
            "config.json",
            {},
            [7],
            ["config.json"] * (cli.MAX_SCHEMA_ARRAY_ITEMS + 1),
        )
        for discovered_files in malformed_values:
            with self.subTest(discovered_files=type(discovered_files).__name__):
                invalid = copy.deepcopy(after)
                invalid["scan"] = {
                    "discovered_files": discovered_files,
                    "ignored_paths": [],
                    "parser_failures": [],
                }
                exit_code, payload, _, _ = self._run_with_reports(
                    before,
                    invalid,
                    ("--fail-on-new",),
                )
                self.assertEqual(exit_code, 1)
                self.assertIsNone(payload["report_comparison"])
                self.assertEqual(payload["errors"][0]["role"], "after")
                self.assertIn("validation_errors", payload["errors"][0])

    def test_scan_scope_downgrade_and_partial_scan_metadata_fail_closed(self):
        before, after = self._reports()
        for report in (before, after):
            report["scan"] = {
                "discovered_files": [report["files"][0]["path"]],
                "ignored_paths": [],
                "parser_failures": [],
            }

        stripped_after = copy.deepcopy(after)
        stripped_after.pop("scan")
        exit_code, payload, _, _ = self._run_with_reports(
            before,
            stripped_after,
            ("--fail-on-new",),
        )
        self.assertEqual(exit_code, 1)
        self.assertIsNone(payload["report_comparison"])
        self.assertIn("scope mismatch", payload["errors"][0]["message"])

        for missing in ("ignored_paths", "parser_failures"):
            with self.subTest(missing=missing):
                partial_after = copy.deepcopy(after)
                partial_after["scan"].pop(missing)
                exit_code, payload, _, _ = self._run_with_reports(before, partial_after)
                self.assertEqual(exit_code, 1)
                self.assertIn("validation_errors", payload["errors"][0])

    def test_shared_report_paths_and_total_comparison_output_are_bounded(self):
        before, after = self._reports()
        oversized_path = "p" * 100_000
        after["files"][0]["path"] = oversized_path
        exit_code, payload, _, _ = self._run_with_reports(before, after)
        self.assertEqual(exit_code, 1)
        self.assertIn("validation_errors", payload["errors"][0])
        self.assertLess(len(json.dumps(payload)), 10_000)

        budgeted = copy.deepcopy(after)
        budgeted["files"][0]["path"] = "p" * cli.MAX_REPORT_PATH_CHARS
        template = copy.deepcopy(budgeted["files"][0]["findings"][0])
        findings = []
        for index in range(2_200):
            finding = copy.deepcopy(template)
            finding.pop("fingerprint", None)
            finding["evidence_paths"] = [f"evidence.{index}"]
            findings.append(finding)
        self._set_findings(budgeted, findings)
        exit_code, payload, _, _ = self._run_with_reports(before, budgeted)
        self.assertEqual(exit_code, 1)
        self.assertIsNone(payload["report_comparison"])
        self.assertIn("output budget", payload["errors"][0]["message"])
        self.assertLess(len(json.dumps(payload)), 2_000)

    def test_operational_path_and_exception_diagnostics_are_bounded(self):
        long_path = "missing-" + "x" * 10_000

        exit_code, output = run(["--compare-reports", long_path, long_path])

        self.assertEqual(exit_code, 2)
        payload = json.loads(output)
        error = payload["errors"][0]
        self.assertIn("truncated", error["path"])
        self.assertIn("truncated", error["message"])
        self.assertLess(len(output), 2_000)

    def test_schema_validation_failures_identify_role_and_path(self):
        before, after = self._reports()
        del after["files"]

        exit_code, payload, _, after_path = self._run_with_reports(before, after)

        self.assertEqual(exit_code, 1)
        self.assertIsNone(payload["report_comparison"])
        self.assertEqual(payload["errors"][0]["role"], "after")
        self.assertEqual(payload["errors"][0]["path"], after_path)
        self.assertEqual(payload["errors"][0]["validation_errors"][0]["path"], "$.files")

    def test_load_json_and_non_object_errors_identify_role_and_use_exit_two(self):
        before, after = self._reports()
        cases = (("before", "{"), ("after", "[]"))
        for role, invalid_content in cases:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                before_path = Path(directory) / "before.json"
                after_path = Path(directory) / "after.json"
                before_path.write_text(json.dumps(before))
                after_path.write_text(json.dumps(after))
                target = before_path if role == "before" else after_path
                target.write_text(invalid_content)

                exit_code, output = run(["--compare-reports", str(before_path), str(after_path)])
                payload = json.loads(output)

                self.assertEqual(exit_code, 2)
                self.assertIsNone(payload["report_comparison"])
                self.assertEqual(payload["errors"][0]["role"], role)
                self.assertEqual(payload["errors"][0]["path"], str(target))

    def test_duplicate_json_keys_are_rejected_for_validation_and_comparison(self):
        before, after = self._reports()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate_top = root / "duplicate-top.json"
            duplicate_top.write_text(
                '{"schema_version":"0.1","schema_version":"0.1","files":[],"errors":[]}'
            )
            exit_code, output = run(["--validate-report", str(duplicate_top)])
            self.assertEqual(exit_code, 2)
            self.assertIn("duplicate JSON object key", json.loads(output)["errors"][0]["message"])

            long_key = "x" * 10_000
            duplicate_long = root / "duplicate-long.json"
            duplicate_long.write_text(
                json.dumps({long_key: 1})[:-1] + f", {json.dumps(long_key)}: 2}}"
            )
            exit_code, output = run(["--validate-report", str(duplicate_long)])
            self.assertEqual(exit_code, 2)
            self.assertIn("duplicate JSON object key", output)
            self.assertIn("truncated", output)
            self.assertLess(len(output), 1_000)

            before_path = root / "before.json"
            after_path = root / "after.json"
            before_path.write_text(json.dumps(before))
            raw_after = json.dumps(after)
            raw_after = raw_after.replace('"id": ', '"id": "shadow", "id": ', 1)
            after_path.write_text(raw_after)
            exit_code, output = run(["--compare-reports", str(before_path), str(after_path)])
            payload = json.loads(output)
            self.assertEqual(exit_code, 2)
            self.assertEqual(payload["errors"][0]["role"], "after")
            self.assertIn("duplicate JSON object key", payload["errors"][0]["message"])

    def test_compare_mode_rejects_conflicts_before_opening_inputs(self):
        conflicts = (
            ["config.yaml"],
            ["--summary-only"],
            ["--validate-report", "other.json"],
            ["--list-rules"],
            ["--policy", "policy.json"],
            ["--trend-summary"],
            ["--version"],
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict), patch(
                "agent_config_linter.cli._load_stored_report"
            ) as load_report, patch("agent_config_linter.cli._load_config") as load_config, patch(
                "agent_config_linter.cli.lint_config"
            ) as lint_config:
                exit_code, output = run(
                    [*conflict, "--compare-reports", "before.json", "after.json"]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("cannot be combined", json.loads(output)["errors"][0]["message"])
            load_report.assert_not_called()
            load_config.assert_not_called()
            lint_config.assert_not_called()

    def test_comparison_contract_handles_reordering_empty_sets_and_active_transitions(self):
        before, after = self._reports()
        same_after = copy.deepcopy(before)
        same_after["files"] = list(reversed(same_after["files"]))
        same_after["unknown_additive_field"] = {"ignored": True}
        same_after["files"][0]["findings"] = list(reversed(same_after["files"][0]["findings"]))

        exit_code, same_payload, _, _ = self._run_with_reports(before, same_after)
        self.assertEqual(exit_code, 0)
        comparison = same_payload["report_comparison"]
        self.assertEqual(comparison["schema_version"], "0.1")
        self.assertEqual(comparison["summary"], {"before": 2, "after": 2, "new": 0, "persisting": 2, "resolved": 0})
        self.assertEqual(comparison["new_findings"], [])
        self.assertEqual(comparison["resolved_findings"], [])

        empty_before = copy.deepcopy(before)
        self._set_findings(empty_before, [])
        exit_code, all_new, _, _ = self._run_with_reports(empty_before, after)
        self.assertEqual(exit_code, 0)
        self.assertEqual(all_new["report_comparison"]["summary"]["new"], 2)

        empty_after = copy.deepcopy(after)
        self._set_findings(empty_after, [])
        exit_code, all_resolved, _, _ = self._run_with_reports(before, empty_after)
        self.assertEqual(exit_code, 0)
        self.assertEqual(all_resolved["report_comparison"]["summary"]["resolved"], 2)

        suppressed_after = copy.deepcopy(before)
        moved = suppressed_after["files"][0]["findings"].pop()
        self._set_findings(suppressed_after, suppressed_after["files"][0]["findings"])
        suppressed_after["files"][0]["suppressed_findings"] = [moved]
        exit_code, transition, _, _ = self._run_with_reports(before, suppressed_after)
        self.assertEqual(exit_code, 0)
        self.assertEqual(transition["report_comparison"]["summary"]["resolved"], 1)

    def test_comparison_is_json_only_and_does_not_load_or_lint_configs(self):
        before, after = self._reports()
        with patch("agent_config_linter.cli.lint_config") as lint_config, patch(
            "agent_config_linter.cli._load_config"
        ) as load_config:
            exit_code, payload, _, _ = self._run_with_reports(before, after)
        self.assertEqual(exit_code, 0, payload)
        lint_config.assert_not_called()
        load_config.assert_not_called()

        with patch("agent_config_linter.cli._load_stored_report") as load_report:
            exit_code, output = run(
                ["--compare-reports", "missing-before.json", "missing-after.json", "--format", "markdown"]
            )
        self.assertEqual(exit_code, 2)
        self.assertIn("supports only json", json.loads(output)["errors"][0]["message"])
        load_report.assert_not_called()

    def test_fail_on_new_is_opt_in_and_preserves_comparison_output(self):
        before, after = self._reports()
        self._set_findings(before, [])

        default_exit, default_payload, _, _ = self._run_with_reports(before, after)
        gated_exit, gated_payload, _, _ = self._run_with_reports(
            before,
            after,
            ("--fail-on-new",),
        )

        self.assertEqual(default_exit, 0)
        self.assertNotIn("gate", default_payload["report_comparison"])
        self.assertEqual(gated_exit, 1)
        self.assertEqual(
            set(gated_payload["report_comparison"]),
            {
                "schema_version",
                "scope",
                "before",
                "after",
                "summary",
                "new_findings",
                "persisting_findings",
                "resolved_findings",
                "gate",
            },
        )
        self.assertEqual(
            gated_payload["report_comparison"]["gate"],
            {"fail_on_new": True, "triggered": True},
        )
        self.assertEqual(
            gated_payload["report_comparison"]["new_findings"],
            default_payload["report_comparison"]["new_findings"],
        )
        self.assertEqual(gated_payload["errors"], [])

    def test_fail_on_new_succeeds_when_comparison_has_no_new_findings(self):
        before, _ = self._reports()
        after = copy.deepcopy(before)

        exit_code, payload, _, _ = self._run_with_reports(
            before,
            after,
            ("--fail-on-new",),
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            payload["report_comparison"]["gate"],
            {"fail_on_new": True, "triggered": False},
        )

    def test_triggered_gate_keeps_machine_readable_comparison_on_stdout(self):
        before, after = self._reports()
        self._set_findings(before, [])
        with tempfile.TemporaryDirectory() as directory:
            before_path = Path(directory) / "before.json"
            after_path = Path(directory) / "after.json"
            before_path.write_text(json.dumps(before))
            after_path.write_text(json.dumps(after))
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli.main(
                    [
                        "--compare-reports",
                        str(before_path),
                        str(after_path),
                        "--fail-on-new",
                    ]
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["report_comparison"]["gate"]["triggered"])
        self.assertEqual(len(payload["report_comparison"]["new_findings"]), 2)

    def test_comparison_errors_remain_on_stderr(self):
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli.main(
                ["--compare-reports", "missing-before.json", "missing-after.json"]
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        payload = json.loads(stderr.getvalue())
        self.assertIsNone(payload["report_comparison"])

    def test_fail_on_new_requires_compare_mode_before_scanning(self):
        with patch("agent_config_linter.cli._load_config") as load_config, patch(
            "agent_config_linter.cli.lint_config"
        ) as lint_config:
            exit_code, output = run(["config.yaml", "--fail-on-new"])

        self.assertEqual(exit_code, 2)
        self.assertIn(
            "requires --compare-reports",
            json.loads(output)["errors"][0]["message"],
        )
        load_config.assert_not_called()
        lint_config.assert_not_called()

    def test_manifest_and_docs_advertise_only_shipped_comparison_behavior(self):
        exit_code, output = run(["--integration-manifest", "--format", "json"])
        self.assertEqual(exit_code, 0, output)
        manifest = json.loads(output)
        self.assertEqual(manifest["flags"]["compare_reports"], "--compare-reports")
        self.assertEqual(manifest["outputs"]["report_comparison_formats"], ["json"])
        self.assertTrue(manifest["capabilities"]["stored_report_comparison"])
        self.assertEqual(manifest["flags"]["fail_on_new"], "--fail-on-new")

        readme = (ROOT / "README.md").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()
        stability = (ROOT / "docs" / "report-stability.md").read_text()
        roadmap = (ROOT / "docs" / "roadmap.md").read_text()
        self.assertIn("--compare-reports", readme)
        self.assertIn("stored-report comparison", changelog.lower())
        self.assertIn("Stored-report comparison", stability)
        self.assertIn("validation_errors_truncated", stability)
        self.assertIn("validation_error_limit", stability)
        phase_11 = roadmap[roadmap.index("## Phase 11") : roadmap.index("## Ongoing quality bar")]
        item_31 = phase_11[phase_11.index("### 31.") : phase_11.index("### 32.")]
        self.assertIn("Phase 11 status: In progress.", phase_11)
        self.assertIn("**Status: Shipped.**", item_31)
        self.assertIn("**Status: Planned.**", phase_11[phase_11.index("### 32.") :])
        self.assertIn("--fail-on-new", readme)
        item_32 = phase_11[phase_11.index("### 32.") : phase_11.index("### 33.")]
        self.assertIn("**Status: Shipped.**", item_32)


if __name__ == "__main__":
    unittest.main()
