import json
import unittest
from pathlib import Path

import yaml

from agent_config_linter.linter import lint_config

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "examples" / "config-shapes"


def load_config(path):
    if path.suffix == ".json":
        return json.loads(path.read_text())
    return yaml.safe_load(path.read_text())


class ConfigShapeFixtureTests(unittest.TestCase):
    def test_hermes_discord_shared_fixture_detects_untrusted_shell_and_exfiltration(self):
        report = lint_config(load_config(FIXTURE_DIR / "hermes-discord-shared.yaml"))

        finding_ids = {finding["id"] for finding in report["findings"]}
        self.assertEqual(report["risk_level"], "critical")
        self.assertIn("shell_enabled", finding_ids)
        self.assertIn("prompt_injection_exfiltration_bridge", finding_ids)
        self.assertIn("untrusted_inputs", report["signals"]["enabled_capabilities"])

    def test_hermes_personal_local_fixture_detects_weak_local_model_and_broad_files(self):
        report = lint_config(load_config(FIXTURE_DIR / "hermes-personal-local.yaml"))

        finding_ids = {finding["id"] for finding in report["findings"]}
        self.assertIn(report["risk_level"], {"high", "critical"})
        self.assertIn("filesystem_broad_access", finding_ids)
        self.assertIn("weak_model_risk", finding_ids)

    def test_openclaw_browser_agent_fixture_detects_private_network_browser(self):
        report = lint_config(load_config(FIXTURE_DIR / "openclaw-browser-agent.json"))

        finding_ids = {finding["id"] for finding in report["findings"]}
        self.assertIn(report["risk_level"], {"high", "critical"})
        self.assertIn("browser_private_network", finding_ids)
        self.assertIn("browser_private_network", report["signals"]["enabled_capabilities"])


if __name__ == "__main__":
    unittest.main()
