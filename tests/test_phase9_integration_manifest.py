"""Phase 9, item 27: integration manifest for wrappers and dashboards.

Validates the ``--integration-manifest`` CLI surface and that the manifest stays
in agreement with README/docs on output formats and exit codes.
"""

import json
import unittest
from pathlib import Path

from agent_config_linter import __version__
from agent_config_linter.cli import run

ROOT = Path(__file__).resolve().parents[1]


class IntegrationManifestShapeTests(unittest.TestCase):
    def test_manifest_emits_valid_json_without_config_paths(self):
        exit_code, output = run(["--integration-manifest", "--format", "json"])

        self.assertEqual(exit_code, 0, output)
        manifest = json.loads(output)
        self.assertEqual(manifest["schema_version"], "0.1")
        self.assertEqual(manifest["package_version"], __version__)
        self.assertEqual(manifest["report_schema_version"], "0.1")
        self.assertEqual(manifest["tool"]["name"], "agent-config-linter")

    def test_manifest_documents_outputs_inputs_exit_codes_and_flags(self):
        exit_code, output = run(["--integration-manifest", "--format", "json"])
        manifest = json.loads(output)

        self.assertEqual(set(manifest["outputs"]["formats"]), {"json", "markdown", "github-markdown", "sarif"})
        self.assertEqual(set(manifest["inputs"]["formats"]), {"json", "yaml", "toml"})
        self.assertTrue(manifest["inputs"]["repo_scan"])
        self.assertEqual({entry["code"] for entry in manifest["exit_codes"]}, {0, 1, 2})
        for flag in (
            "policy",
            "baseline",
            "min_severity",
            "fail_on",
            "repo_scan",
            "explain",
            "suggestions",
            "trend_summary",
            "check_policy_drift",
            "list_rules",
            "integration_manifest",
        ):
            self.assertIn(flag, manifest["flags"])
        for section in ("baseline", "scan", "explanations", "policy_drift", "trend_summary", "suggestions"):
            self.assertIn(section, manifest["optional_report_sections"])

    def test_manifest_markdown_output_works_and_sarif_is_rejected(self):
        exit_code, _ = run(["--integration-manifest", "--format", "markdown"])
        self.assertEqual(exit_code, 0)

        exit_code, output = run(["--integration-manifest", "--format", "sarif"])
        self.assertEqual(exit_code, 2)
        payload = json.loads(output)
        self.assertIsNone(payload["integration_manifest"])
        self.assertIn("--integration-manifest supports only json and markdown", payload["errors"][0]["message"])


class IntegrationManifestAgreementTests(unittest.TestCase):
    def test_manifest_output_formats_agree_with_readme(self):
        _, output = run(["--integration-manifest", "--format", "json"])
        manifest = json.loads(output)
        readme = (ROOT / "README.md").read_text()

        for fmt in manifest["outputs"]["formats"]:
            self.assertIn(fmt, readme, f"README missing documented output format {fmt}")

    def test_manifest_exit_codes_agree_with_readme(self):
        _, output = run(["--integration-manifest", "--format", "json"])
        manifest = json.loads(output)
        readme = (ROOT / "README.md").read_text()

        self.assertIn("## Exit codes", readme)
        for entry in manifest["exit_codes"]:
            self.assertIn(str(entry["code"]), readme, f"README missing documented exit code {entry['code']}")

    def test_manifest_input_formats_agree_with_readme(self):
        _, output = run(["--integration-manifest", "--format", "json"])
        manifest = json.loads(output)
        readme = (ROOT / "README.md").read_text()

        # README's compatibility section documents supported config inputs.
        for fmt in manifest["inputs"]["formats"]:
            self.assertIn(f".{fmt}", readme, f"README missing documented input format .{fmt}")


if __name__ == "__main__":
    unittest.main()
