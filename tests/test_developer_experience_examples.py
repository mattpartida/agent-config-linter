import unittest
from pathlib import Path

import yaml


class DeveloperExperienceArtifactTests(unittest.TestCase):
    def test_pre_commit_example_runs_linter_with_fail_threshold(self):
        config = yaml.safe_load(Path("examples/pre-commit-config.yaml").read_text())
        hook = config["repos"][0]["hooks"][0]

        self.assertEqual(hook["id"], "agent-config-linter")
        self.assertIn("agent-config-lint", hook["entry"])
        self.assertIn("--fail-on high", hook["entry"])
        self.assertIn("--min-severity medium", hook["entry"])
        self.assertIn("json", hook["types_or"])
        self.assertIn("yaml", hook["types_or"])

    def test_taskfile_example_includes_local_ci_and_sarif_tasks(self):
        taskfile = Path("examples/Taskfile.yml").read_text()

        self.assertIn("lint-agent-configs:", taskfile)
        self.assertIn("agent-config-lint examples --fail-on high --min-severity medium", taskfile)
        self.assertIn("agent-config-sarif:", taskfile)
        self.assertIn("--format sarif", taskfile)

    def test_sample_sarif_artifact_is_valid_preview(self):
        import json

        sarif = json.loads(Path("docs/sample-agent-config-linter.sarif").read_text())

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "agent-config-linter")
        self.assertTrue(sarif["runs"][0]["results"])
        self.assertIn("ruleId", sarif["runs"][0]["results"][0])


if __name__ == "__main__":
    unittest.main()
