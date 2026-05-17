import re
import tomllib
import unittest
from pathlib import Path

from agent_config_linter import __version__
from agent_config_linter.linter import lint_config


class Phase4DistributionCompatibilityTrustTests(unittest.TestCase):
    def test_release_metadata_targets_stable_030(self):
        metadata = tomllib.loads(Path("pyproject.toml").read_text())["project"]

        self.assertEqual(metadata["version"], "0.3.0")
        self.assertEqual(__version__, "0.3.0")
        self.assertIn("Development Status :: 4 - Beta", metadata["classifiers"])
        self.assertIn("Programming Language :: Python :: 3.12", metadata["classifiers"])
        self.assertIn("Typing :: Typed", metadata["classifiers"])

    def test_changelog_has_020_release_notes_for_all_phase_buckets(self):
        changelog = Path("CHANGELOG.md").read_text()

        self.assertIn("## [0.2.0]", changelog)
        self.assertIn("Phase 1", changelog)
        self.assertIn("Phase 2", changelog)
        self.assertIn("Phase 3", changelog)
        self.assertIn("Phase 4", changelog)
        self.assertRegex(changelog, r"schema_version.*0\.1")

    def test_ci_matrix_covers_supported_python_versions_and_operating_systems(self):
        workflow = Path(".github/workflows/ci.yml").read_text()

        self.assertIn("strategy:", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertRegex(workflow, r"python-version:\s*\[.*3\.11.*3\.12.*\]")
        self.assertRegex(workflow, r"os:\s*\[.*ubuntu-latest.*macos-latest.*windows-latest.*\]")
        self.assertIn("${{ matrix.os }}", workflow)
        self.assertIn("${{ matrix.python-version }}", workflow)

    def test_filesystem_broad_access_flags_posix_and_windows_broad_roots(self):
        cases = [
            {"tools": {"filesystem": {"enabled": True, "paths": ["/"]}}},
            {"tools": {"filesystem": {"enabled": True, "paths": ["~/"]}}},
            {"tools": {"filesystem": {"enabled": True, "paths": ["$HOME/"]}}},
            {"tools": {"filesystem": {"enabled": True, "paths": ["C:\\\\"]}}},
            {"tools": {"filesystem": {"enabled": True, "paths": ["%USERPROFILE%"]}}},
            {"tools": {"filesystem": {"enabled": True, "paths": ["%USERPROFILE%\\\\"]}}},
            {"tools": {"filesystem": {"enabled": True, "paths": ["C:\\\\Users"]}}},
        ]

        for config in cases:
            with self.subTest(config=config):
                findings = {finding["id"] for finding in lint_config(config)["findings"]}
                self.assertIn("filesystem_broad_access", findings)

    def test_project_scoped_posix_and_windows_paths_are_not_broad(self):
        cases = [
            {"tools": {"filesystem": {"enabled": True, "paths": ["./src"], "mode": "ro"}}},
            {"tools": {"filesystem": {"enabled": True, "paths": ["C:\\\\repo\\\\project"], "mode": "ro"}}},
        ]

        for config in cases:
            with self.subTest(config=config):
                findings = {finding["id"] for finding in lint_config(config)["findings"]}
                self.assertNotIn("filesystem_broad_access", findings)

    def test_report_stability_documents_schema_version_decision_for_020(self):
        report_stability = Path("docs/report-stability.md").read_text()

        self.assertIn("0.2.0 compatibility decision", report_stability)
        self.assertIn("schema_version` remains `0.1", report_stability)
        self.assertIn("confidence", report_stability)
        self.assertIn("source_evidence_paths", report_stability)

    def test_rule_pack_design_is_non_executable_and_trust_bounded(self):
        design = Path("docs/rule-packs.md").read_text()

        expected_sections = [
            "## Non-goals for now",
            "## Trust boundaries",
            "## Manifest schema",
            "## Rule identity and compatibility",
            "## Fixtures and documentation",
            "## Future implementation tasks",
        ]
        for section in expected_sections:
            self.assertIn(section, design)
        self.assertIn("MUST NOT execute", design)
        self.assertIn("non-executable manifest", design)
        self.assertIn("ACL-", design)
        self.assertIn("schema_version", design)

    def test_rule_pack_manifest_example_is_metadata_only(self):
        manifest = Path("examples/rule-packs/metadata-only-rule-pack.yaml").read_text()

        self.assertIn("schema_version: rule-pack/v0", manifest)
        self.assertIn("rules:", manifest)
        self.assertIn("default_severity:", manifest)
        self.assertNotRegex(manifest, re.compile(r"\b(command|entry_point|module|python|exec|subprocess)\b", re.IGNORECASE))

    def test_roadmap_marks_phase4_shipped(self):
        roadmap = Path("docs/roadmap.md").read_text()

        self.assertIn("Phase 4 status: Shipped", roadmap)
        for heading in (
            "### 10. Prepare a stable `0.2.0` release",
            "### 11. Add compatibility test matrix",
            "### 12. Design safe third-party rule-pack loading, but do not implement execution yet",
        ):
            index = roadmap.index(heading)
            next_chunk = roadmap[index : index + 240]
            self.assertIn("**Status: Shipped.**", next_chunk)


if __name__ == "__main__":
    unittest.main()
