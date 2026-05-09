import json
import unittest
from pathlib import Path


class ReportGoldenTests(unittest.TestCase):
    maxDiff = None

    def test_json_markdown_and_sarif_reports_match_golden_outputs(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        config_path = repo_root / "examples" / "high-risk-agent.json"
        golden_dir = repo_root / "tests" / "fixtures" / "golden"

        json_exit, json_output = run([str(config_path.relative_to(repo_root)), "--format", "json"])
        markdown_exit, markdown_output = run([str(config_path.relative_to(repo_root)), "--format", "markdown"])
        sarif_exit, sarif_output = run([str(config_path.relative_to(repo_root)), "--format", "sarif"])

        self.assertEqual(json_exit, 0)
        self.assertEqual(markdown_exit, 0)
        self.assertEqual(sarif_exit, 0)
        self.assertEqual(json.loads(json_output), json.loads((golden_dir / "high-risk-agent.json.golden.json").read_text()))
        self.assertEqual(markdown_output, (golden_dir / "high-risk-agent.markdown.golden.md").read_text())
        self.assertEqual(json.loads(sarif_output), json.loads((golden_dir / "high-risk-agent.sarif.golden.json").read_text()))

    def test_report_stability_docs_explain_update_workflow_and_schema_version(self):
        repo_root = Path(__file__).resolve().parents[1]
        docs = (repo_root / "docs" / "report-stability.md").read_text()
        readme = (repo_root / "README.md").read_text()

        self.assertIn("Golden report update workflow", docs)
        self.assertIn("schema_version", docs)
        self.assertIn("python -m pytest tests/test_report_golden.py -q", docs)
        self.assertIn("schema_version", readme)
        self.assertIn("Report compatibility", readme)


if __name__ == "__main__":
    unittest.main()
