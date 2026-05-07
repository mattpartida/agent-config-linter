import unittest
from pathlib import Path

import yaml


class GitHubActionsExampleTests(unittest.TestCase):
    def test_code_scanning_workflow_uploads_agent_config_linter_sarif(self):
        workflow_path = Path(".github/workflows/agent-config-linter-code-scanning.yml")

        workflow = yaml.safe_load(workflow_path.read_text())
        job = workflow["jobs"]["agent-config-linter"]
        steps = job["steps"]
        run_commands = "\n".join(step.get("run", "") for step in steps)
        used_actions = {step.get("uses") for step in steps if "uses" in step}

        self.assertEqual(workflow["name"], "Agent Config Linter Code Scanning")
        self.assertIn(("security-events", "write"), job["permissions"].items())
        self.assertIn(("contents", "read"), job["permissions"].items())
        self.assertIn("agent-config-lint", run_commands)
        self.assertIn("--format sarif", run_commands)
        self.assertIn("agent-config-linter.sarif", run_commands)
        self.assertIn("github/codeql-action/upload-sarif@v3", used_actions)
        upload_step = next(step for step in steps if step.get("uses") == "github/codeql-action/upload-sarif@v3")
        self.assertEqual(upload_step["with"]["sarif_file"], "agent-config-linter.sarif")


if __name__ == "__main__":
    unittest.main()
