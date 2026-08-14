"""Phase 9, item 26: report-schema fixture contracts.

Validates that the published fixtures under docs/report-contracts/ parse with
schema_version 0.1, expose their distinguishing field, and stay byte-identical
to what the CLI currently emits from their documented inputs (drift detection).
"""

import json
import unittest
from pathlib import Path

from agent_config_linter.cli import run

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "docs" / "report-contracts"
INPUTS = ROOT / "tests" / "fixtures" / "report-contracts"


def _repo_path(path):
    """Keep committed contract paths stable across checkout locations and OSes."""
    return path.relative_to(ROOT).as_posix()


def _read_json(name):
    return json.loads((CONTRACTS / name).read_text())


class ReportContractShapeTests(unittest.TestCase):
    def test_clean_contract_has_no_findings_or_signals(self):
        payload = _read_json("clean.json")
        file_report = payload["files"][0]

        self.assertEqual(payload["schema_version"], "0.1")
        self.assertEqual(file_report["findings"], [])
        self.assertEqual(file_report["signals"]["enabled_capabilities"], [])
        self.assertEqual(file_report["risk_level"], "low")

    def test_risky_contract_has_active_findings_with_full_shape(self):
        payload = _read_json("risky.json")
        findings = payload["files"][0]["findings"]

        self.assertGreater(len(findings), 0)
        finding = findings[0]
        for key in (
            "id",
            "rule_id",
            "rule_name",
            "severity",
            "title",
            "evidence",
            "evidence_paths",
            "source_evidence_paths",
            "remediation",
            "confidence",
            "fingerprint",
        ):
            self.assertIn(key, finding, f"finding missing stable key {key}")

    def test_policy_suppressed_contract_carries_per_file_suppressions(self):
        payload = _read_json("policy-suppressed.json")
        file_report = payload["files"][0]

        self.assertIn("policy_suppressed_findings", file_report)
        self.assertIn("policy_suppressed_summary", file_report)
        self.assertGreater(len(file_report["policy_suppressed_findings"]), 0)
        # The active findings list excludes the suppressed ones.
        suppressed_ids = {f["id"] for f in file_report["policy_suppressed_findings"]}
        active_ids = {f["id"] for f in file_report["findings"]}
        self.assertEqual(suppressed_ids & active_ids, set())

    def test_baseline_suppressed_contract_has_top_level_block_and_per_file(self):
        payload = _read_json("baseline-suppressed.json")
        file_report = payload["files"][0]

        self.assertIn("baseline", payload)
        for key in ("stale_count", "expired_count", "owner_summary"):
            self.assertIn(key, payload["baseline"])
        self.assertIn("suppressed_findings", file_report)
        self.assertIn("suppressed_summary", file_report)
        self.assertGreater(len(file_report["suppressed_findings"]), 0)

    def test_repo_scan_contract_has_top_level_scan_diagnostics(self):
        payload = _read_json("repo-scan.json")

        self.assertIn("scan", payload)
        for key in ("discovered_files", "ignored_paths", "parser_failures"):
            self.assertIn(key, payload["scan"])
        self.assertGreater(len(payload["scan"]["discovered_files"]), 0)

    def test_sarif_contract_is_valid_sarif_21(self):
        sarif = _read_json("risky.sarif.json")

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "agent-config-linter")
        self.assertGreater(len(sarif["runs"][0]["results"]), 0)


class ReportContractDriftTests(unittest.TestCase):
    """Committed fixtures must match current CLI output from their inputs."""

    def _assert_matches(self, fixture_name, argv):
        expected = (CONTRACTS / fixture_name).read_text()
        exit_code, output = run(argv)
        self.assertEqual(exit_code, 0, f"{fixture_name}: CLI exited {exit_code}\n{output}")
        self.assertEqual(output, expected, f"{fixture_name} drifted from current CLI output")

    def test_clean_fixture_matches_cli_output(self):
        self._assert_matches("clean.json", [_repo_path(INPUTS / "clean.yaml")])

    def test_risky_fixture_matches_cli_output(self):
        self._assert_matches("risky.json", [_repo_path(INPUTS / "risky.yaml")])

    def test_policy_suppressed_fixture_matches_cli_output(self):
        self._assert_matches(
            "policy-suppressed.json",
            [_repo_path(INPUTS / "risky.yaml"), "--policy", _repo_path(INPUTS / "disable-shell-policy.json")],
        )

    def test_baseline_suppressed_fixture_matches_cli_output(self):
        self._assert_matches(
            "baseline-suppressed.json",
            [_repo_path(INPUTS / "risky.yaml"), "--baseline", _repo_path(INPUTS / "suppressions.json")],
        )

    def test_repo_scan_fixture_matches_cli_output(self):
        self._assert_matches("repo-scan.json", ["--repo-scan", str(ROOT / "tests" / "fixtures" / "repo-scan")])

    def test_sarif_fixture_matches_cli_output(self):
        self._assert_matches("risky.sarif.json", [_repo_path(INPUTS / "risky.yaml"), "--format", "sarif"])


if __name__ == "__main__":
    unittest.main()
