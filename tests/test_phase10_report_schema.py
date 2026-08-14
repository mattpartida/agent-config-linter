"""Phase 10, item 28: discoverable JSON Schema report contract."""

import json
import unittest
from pathlib import Path

from agent_config_linter.cli import run

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "report-schema.json"
CONTRACTS = (
    "clean.json",
    "risky.json",
    "policy-suppressed.json",
    "baseline-suppressed.json",
    "repo-scan.json",
)


class ReportSchemaCliTests(unittest.TestCase):
    def test_report_schema_emits_draft_2020_12_json_without_paths(self):
        exit_code, output = run(["--report-schema", "--format", "json"])

        self.assertEqual(exit_code, 0, output)
        schema = json.loads(output)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(
            schema["$id"],
            "https://raw.githubusercontent.com/mattpartida/agent-config-linter/main/docs/report-schema.json",
        )
        self.assertEqual(schema["title"], "agent-config-linter JSON report")
        self.assertEqual(set(schema["required"]), {"schema_version", "files", "errors"})
        self.assertEqual(schema["properties"]["schema_version"]["const"], "0.1")
        self.assertEqual(schema["properties"]["files"]["items"]["$ref"], "#/$defs/file_report")
        self.assertEqual(schema["$defs"]["finding"]["properties"]["severity"]["enum"], ["critical", "high", "medium", "low"])

    def test_committed_schema_matches_cli_and_covers_contract_fixtures(self):
        exit_code, output = run(["--report-schema", "--format", "json"])
        self.assertEqual(exit_code, 0, output)
        self.assertTrue(SCHEMA_PATH.is_file())
        self.assertEqual(SCHEMA_PATH.read_text(), output)

        schema = json.loads(output)
        top_required = set(schema["required"])
        file_required = set(schema["$defs"]["file_report"]["required"])
        finding_required = set(schema["$defs"]["finding"]["required"])
        for name in CONTRACTS:
            report = json.loads((ROOT / "docs" / "report-contracts" / name).read_text())
            self.assertLessEqual(top_required, report.keys(), name)
            for file_report in report["files"]:
                self.assertLessEqual(file_required, file_report.keys(), name)
                for finding in file_report["findings"]:
                    self.assertLessEqual(finding_required, finding.keys(), name)

    def test_report_schema_rejects_non_json_formats_with_typed_error(self):
        exit_code, output = run(["--report-schema", "--format", "markdown"])

        self.assertEqual(exit_code, 2)
        payload = json.loads(output)
        self.assertIsNone(payload["report_schema"])
        self.assertIn("--report-schema supports only json", payload["errors"][0]["message"])

    def test_integration_manifest_discovers_report_schema(self):
        exit_code, output = run(["--integration-manifest", "--format", "json"])
        self.assertEqual(exit_code, 0, output)
        manifest = json.loads(output)
        self.assertEqual(manifest["outputs"]["report_schema_formats"], ["json"])
        self.assertEqual(manifest["flags"]["report_schema"], "--report-schema")

    def test_known_optional_filter_fields_keep_typed_schema_contracts(self):
        exit_code, output = run(["--report-schema", "--format", "json"])
        self.assertEqual(exit_code, 0, output)
        file_properties = json.loads(output)["$defs"]["file_report"]["properties"]

        for field in ("filtered_findings", "confidence_filtered_findings"):
            self.assertEqual(file_properties[field]["type"], "array")
            self.assertEqual(file_properties[field]["items"]["$ref"], "#/$defs/finding")
        for field in ("filtered_summary", "confidence_filtered_summary"):
            self.assertEqual(file_properties[field]["$ref"], "#/$defs/severity_summary")

        _, manifest_output = run(["--integration-manifest", "--format", "json"])
        optional_sections = json.loads(manifest_output)["optional_report_sections"]
        for field in (
            "filtered_findings",
            "filtered_summary",
            "confidence_filtered_findings",
            "confidence_filtered_summary",
        ):
            self.assertIn(field, optional_sections)


class ReportSchemaDocumentationTests(unittest.TestCase):
    def test_docs_publish_schema_contract_and_roadmap_truth(self):
        report_contracts = (ROOT / "docs" / "report-contracts.md").read_text()
        readme = (ROOT / "README.md").read_text()
        roadmap = (ROOT / "docs" / "roadmap.md").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()

        self.assertIn("report-schema.json", report_contracts)
        self.assertIn("confidence_filtered_findings", report_contracts)
        self.assertIn("filtered_findings", report_contracts)
        self.assertIn("--report-schema", readme)
        self.assertIn("Phase 10 report validation", readme)
        self.assertIn("Phase 10 status: Shipped", roadmap)
        item_28 = roadmap[roadmap.index("### 28.") : roadmap.index("### 29.")]
        self.assertIn("**Status: Shipped.**", item_28)
        self.assertIn("Phase 10 report JSON Schema", changelog)


if __name__ == "__main__":
    unittest.main()
