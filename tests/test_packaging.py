import tomllib
import unittest
from pathlib import Path


class PackagingTests(unittest.TestCase):
    def test_project_metadata_is_ready_for_distribution(self):
        metadata = tomllib.loads(Path("pyproject.toml").read_text())["project"]

        self.assertIn("Development Status :: 3 - Alpha", metadata["classifiers"])
        self.assertIn("Topic :: Security", metadata["classifiers"])
        self.assertIn("agent", metadata["keywords"])
        self.assertIn("security", metadata["keywords"])
        self.assertEqual(metadata["authors"], [{"name": "Matt Partida", "email": "mattpartida@gmail.com"}])
        self.assertIn("Homepage", metadata["urls"])
        self.assertIn("Repository", metadata["urls"])
        self.assertIn("Issues", metadata["urls"])

    def test_release_workflow_publishes_to_pypi_on_version_tags(self):
        workflow_path = Path(".github/workflows/release.yml")
        workflow_text = workflow_path.read_text()

        self.assertIn("name: Release", workflow_text)
        self.assertIn("tags:", workflow_text)
        self.assertIn("'v*'", workflow_text)
        self.assertIn("id-token: write", workflow_text)
        self.assertIn("python -m build", workflow_text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", workflow_text)

    def test_changelog_and_release_checklist_exist(self):
        changelog = Path("CHANGELOG.md").read_text()
        checklist = Path("docs/release-checklist.md").read_text()

        self.assertIn("## [Unreleased]", changelog)
        self.assertIn("agent-config-lint --version", checklist)
        self.assertIn("python -m build", checklist)
        self.assertIn("git tag v", checklist)


if __name__ == "__main__":
    unittest.main()
