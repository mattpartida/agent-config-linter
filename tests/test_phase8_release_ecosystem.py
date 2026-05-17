import json
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

from agent_config_linter import __version__
from agent_config_linter.cli import run as cli_run

ROOT = Path(__file__).resolve().parents[1]


class Phase8ReleaseEcosystemTests(unittest.TestCase):
    def test_030_release_metadata_and_compatibility_docs_are_current(self):
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        changelog = (ROOT / "CHANGELOG.md").read_text()
        report_stability = (ROOT / "docs" / "report-stability.md").read_text()
        release_checklist = (ROOT / "docs" / "release-checklist.md").read_text()
        roadmap = (ROOT / "docs" / "roadmap.md").read_text()

        self.assertEqual(metadata["version"], "0.3.0")
        self.assertEqual(__version__, "0.3.0")
        self.assertIn("## [0.3.0]", changelog)
        self.assertIn("Breaking changes", changelog)
        self.assertIn("Additive report fields", changelog)
        self.assertIn("Docs-only changes", changelog)
        self.assertIn("0.3.0 compatibility decision", report_stability)
        self.assertIn("schema_version` remains `0.1", report_stability)
        self.assertIn("repository scan diagnostics", report_stability)
        self.assertIn("trend_summary", report_stability)
        self.assertIn("agent-config-lint --version", release_checklist)
        self.assertIn("python scripts/install-smoke.py --skip-build --artifact sdist", release_checklist)
        self.assertIn("Phase 8 status: Shipped", roadmap)

    def test_install_smoke_can_exercise_built_wheel_and_sdist(self):
        completed = subprocess.run(
            [sys.executable, "scripts/install-smoke.py", "--artifact", "sdist"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=240,
            check=False,
        )

        self.assertNotEqual(completed.returncode, 2, completed.stdout)
        self.assertIn("Installed sdist smoke passed", completed.stdout)
        self.assertIn("agent-config-linter 0.3.0", completed.stdout)

    def test_extension_governance_defines_non_acl_namespaces_and_promotion_path(self):
        governance = (ROOT / "docs" / "extension-governance.md").read_text()
        rule_packs = (ROOT / "docs" / "rule-packs.md").read_text()

        required = [
            "Rule ID namespaces",
            "Collision handling",
            "Ownership metadata",
            "Promotion into the built-in catalog",
            "Core rule vs policy bundle vs third-party rule pack",
            "MUST NOT execute",
        ]
        for phrase in required:
            self.assertIn(phrase, governance)
        self.assertIn("ORG-", governance)
        self.assertIn("VENDOR-", governance)
        self.assertIn("ACL-* IDs are reserved", governance)
        self.assertIn("docs/extension-governance.md", rule_packs)

    def test_examples_gallery_indexes_common_stacks_and_smoke_lints_entries(self):
        gallery_path = ROOT / "examples" / "gallery.json"
        gallery_doc = (ROOT / "docs" / "examples-gallery.md").read_text()
        gallery = json.loads(gallery_path.read_text())

        categories = {entry["category"] for entry in gallery["examples"]}
        self.assertGreaterEqual(len(gallery["examples"]), 6)
        self.assertTrue(
            {
                "local-coding-agent",
                "ci-agent",
                "mcp-desktop-config",
                "editor-agent",
                "framework-deployment",
                "organization-policy-bundle",
            }.issubset(categories)
        )
        self.assertIn("Expected result", gallery_doc)
        self.assertIn("safe", gallery_doc)
        self.assertIn("risky", gallery_doc)
        self.assertIn("intentionally-vulnerable", gallery_doc)

        for entry in gallery["examples"]:
            with self.subTest(path=entry["path"]):
                path = ROOT / entry["path"]
                self.assertTrue(path.exists(), entry)
                self.assertIn(entry["expected"], {"safe", "risky", "intentionally-vulnerable"})
                if entry["kind"] in {"config", "config-directory"}:
                    exit_code, output = cli_run([str(path), "--format", "json"])
                    self.assertEqual(exit_code, 0, output)
                    report = json.loads(output)
                    findings = report.get("findings", [])
                    for file_report in report.get("files", []):
                        findings.extend(file_report.get("findings", []))
                    rule_ids = {finding["rule_id"] for finding in findings}
                    for expected_rule in entry.get("expected_rule_ids", []):
                        self.assertIn(expected_rule, rule_ids)

    def test_phase8_does_not_add_executable_rule_pack_loading(self):
        completed = subprocess.run(
            [sys.executable, "-m", "agent_config_linter.cli", "--help"],
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src")},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        cli_help = completed.stdout
        rule_packs = (ROOT / "docs" / "rule-packs.md").read_text()

        self.assertEqual(completed.returncode, 0, cli_help)

        self.assertNotIn("--load-rule-pack", cli_help)
        self.assertNotIn("--enable-rule-pack", cli_help)
        self.assertIn("manifest-only", rule_packs)
        self.assertIn("not evaluated during normal lint runs", rule_packs)


if __name__ == "__main__":
    unittest.main()
