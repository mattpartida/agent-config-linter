"""Phase 10, item 29: validate stored reports without rescanning configs."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_config_linter.cli import run

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = (
    "clean.json",
    "risky.json",
    "policy-suppressed.json",
    "baseline-suppressed.json",
    "repo-scan.json",
)


class ValidateReportCliTests(unittest.TestCase):
    def test_validates_committed_contract_reports_without_linting(self):
        for name in CONTRACTS:
            report_path = ROOT / "docs" / "report-contracts" / name
            with self.subTest(name=name), patch("agent_config_linter.cli.lint_config") as lint_config:
                exit_code, output = run(["--validate-report", str(report_path), "--format", "json"])
                payload = json.loads(output)

                self.assertEqual(exit_code, 0, output)
                self.assertTrue(payload["report_validation"]["valid"])
                self.assertEqual(payload["report_validation"]["schema_version"], "0.1")
                self.assertEqual(payload["report_validation"]["errors"], [])
                lint_config.assert_not_called()

    def test_rejects_incompatible_schema_version_with_machine_readable_path(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "future.json"
            report_path.write_text(json.dumps({"schema_version": "9.0", "files": [], "errors": []}))

            exit_code, output = run(["--validate-report", str(report_path)])
            payload = json.loads(output)

        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["report_validation"]["valid"])
        self.assertEqual(payload["report_validation"]["errors"][0]["path"], "$.schema_version")
        self.assertIn("expected constant '0.1'", payload["report_validation"]["errors"][0]["message"])

    def test_reports_all_stable_field_errors_and_allows_additive_fields(self):
        report = {
            "schema_version": "0.1",
            "files": [
                {
                    "path": "agent.json",
                    "schema_version": "0.1",
                    "schema": {"adapter": "generic", "future_adapter_field": True},
                    "risk_level": "high",
                    "score": "not-an-integer",
                    "signals": {"enabled_capabilities": [], "lethal_trifecta": False},
                    "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                    "findings": [
                        {
                            "id": "shell_enabled",
                            "rule_id": "NOT-ACL",
                            "rule_name": "shell_enabled",
                            "severity": "urgent",
                            "title": "Shell enabled",
                            "evidence": "shell is enabled",
                            "evidence_paths": ["tools.shell"],
                            "source_evidence_paths": ["tools.shell"],
                            "remediation": "Disable shell.",
                            "confidence": "certain",
                            "future_field": {"kept": True},
                        }
                    ],
                    "recommended_next_actions": [],
                    "future_file_field": True,
                }
            ],
            "errors": [],
            "future_top_level": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "invalid.json"
            report_path.write_text(json.dumps(report))
            exit_code, output = run(["--validate-report", str(report_path)])
            errors = json.loads(output)["report_validation"]["errors"]

        self.assertEqual(exit_code, 1)
        paths = {error["path"] for error in errors}
        self.assertIn("$.files[0].score", paths)
        self.assertIn("$.files[0].findings[0].rule_id", paths)
        self.assertIn("$.files[0].findings[0].severity", paths)
        self.assertIn("$.files[0].findings[0].confidence", paths)
        self.assertNotIn("$.future_top_level", paths)
        self.assertNotIn("$.files[0].future_file_field", paths)

    def test_missing_required_fields_are_reported_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "missing.json"
            report_path.write_text(json.dumps({"schema_version": "0.1"}))
            exit_code, output = run(["--validate-report", str(report_path)])
            errors = json.loads(output)["report_validation"]["errors"]

        self.assertEqual(exit_code, 1)
        self.assertEqual([error["path"] for error in errors], ["$.errors", "$.files"])

    def test_invalid_json_and_non_object_reports_are_load_errors(self):
        for content, message in (("{", "valid JSON"), ("[]", "JSON object")):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                report_path = Path(directory) / "invalid.json"
                report_path.write_text(content)
                exit_code, output = run(["--validate-report", str(report_path)])
                payload = json.loads(output)

                self.assertEqual(exit_code, 2)
                self.assertIsNone(payload["report_validation"])
                self.assertIn(message, payload["errors"][0]["message"])

    def test_rejects_non_finite_json_constants(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as directory:
                report_path = Path(directory) / "non-finite.json"
                report_path.write_text('{"schema_version":"0.1","files":[],"errors":[],"future":' + token + "}")
                exit_code, output = run(["--validate-report", str(report_path)])

                self.assertEqual(exit_code, 2)
                self.assertIn("non-standard numeric constant", json.loads(output)["errors"][0]["message"])

    def test_rejects_excessive_json_nesting_without_raising(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "deep.json"
            report_path.write_text("[" * 1200 + "0" + "]" * 1200)
            exit_code, output = run(["--validate-report", str(report_path)])

        self.assertEqual(exit_code, 2)
        self.assertIn("nesting", json.loads(output)["errors"][0]["message"].lower())

    def test_rejects_oversized_and_non_regular_inputs_at_read_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.json"
            with oversized.open("wb") as stream:
                stream.truncate(10 * 1024 * 1024 + 1)
            exit_code, output = run(["--validate-report", str(oversized)])
            self.assertEqual(exit_code, 2)
            self.assertIn("10 MiB", json.loads(output)["errors"][0]["message"])

            if hasattr(os, "mkfifo"):
                fifo = Path(directory) / "report.fifo"
                os.mkfifo(fifo)
                exit_code, output = run(["--validate-report", str(fifo)])
                self.assertEqual(exit_code, 2)
                self.assertIn("regular file", json.loads(output)["errors"][0]["message"])

    def test_bounded_reader_handles_short_reads_until_eof(self):
        report = b'{"schema_version":"0.1","files":[],"errors":[]}'
        chunks = [report[:8], report[8:19], report[19:], b""]
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "short-reads.json"
            report_path.write_bytes(report)
            with patch("agent_config_linter.cli.os.read", side_effect=chunks) as read_call:
                exit_code, output = run(["--validate-report", str(report_path)])

        self.assertEqual(exit_code, 0, output)
        self.assertGreaterEqual(read_call.call_count, 4)

    def test_bounded_reader_rejects_limit_plus_one_across_short_reads(self):
        first = b'{"schema_version":"0.1","files":[],"errors":[]}'
        filler = b" " * (10 * 1024 * 1024 + 1 - len(first))
        chunks = [first, filler[:1000], filler[1000:], b""]
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "short-oversized.json"
            report_path.write_bytes(first)
            with patch("agent_config_linter.cli.os.read", side_effect=chunks):
                exit_code, output = run(["--validate-report", str(report_path)])

        self.assertEqual(exit_code, 2)
        self.assertIn("10 MiB", json.loads(output)["errors"][0]["message"])

    def test_rejects_non_json_output_format_without_loading_report(self):
        missing_path = ROOT / "does-not-exist.json"
        exit_code, output = run(["--validate-report", str(missing_path), "--format", "markdown"])
        payload = json.loads(output)

        self.assertEqual(exit_code, 2)
        self.assertIsNone(payload["report_validation"])
        self.assertIn("--validate-report supports only json", payload["errors"][0]["message"])
        self.assertNotIn("does-not-exist", payload["errors"][0]["message"])

    def test_integration_manifest_and_docs_advertise_report_validation(self):
        exit_code, output = run(["--integration-manifest", "--format", "json"])
        self.assertEqual(exit_code, 0, output)
        manifest = json.loads(output)
        self.assertEqual(manifest["flags"]["validate_report"], "--validate-report")
        self.assertEqual(manifest["inputs"]["stored_report_formats"], ["json"])
        code_one = next(item for item in manifest["exit_codes"] if item["code"] == 1)
        self.assertIn("stored-report contract", code_one["meaning"])

        roadmap = (ROOT / "docs" / "roadmap.md").read_text()
        readme = (ROOT / "README.md").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()
        item_29 = roadmap[roadmap.index("### 29.") : roadmap.index("### 30.")]
        self.assertIn("**Status: Shipped.**", item_29)
        self.assertIn("--validate-report", readme)
        self.assertIn("stored report validation", changelog.lower())
        self.assertIn("stored-report contract validation failed", readme)


if __name__ == "__main__":
    unittest.main()
