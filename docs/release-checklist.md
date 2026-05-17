# Release checklist

Use this checklist before tagging and publishing `agent-config-linter`.

## Preflight

- [ ] Confirm the working tree is clean: `git status --short`.
- [ ] Run tests and lint locally:
  - `python -m pytest -q`
  - `python -m ruff check .`
  - `python -m compileall -q src tests`
- [ ] Verify the CLI version: `agent-config-lint --version`.
- [ ] Run the installed-wheel smoke test: `python scripts/install-smoke.py --artifact wheel`.
- [ ] Run the installed-sdist smoke test: `python scripts/install-smoke.py --artifact sdist`.
- [ ] Confirm `CHANGELOG.md` has release notes for the target version.
- [ ] Confirm `src/agent_config_linter/__init__.py` and `pyproject.toml` agree on the version.

## Build

- [ ] Install build tooling if needed: `python -m pip install --upgrade build`.
- [ ] Build distributions: `python -m build`.
- [ ] Smoke-test the built wheel in a clean virtual environment: `python scripts/install-smoke.py --skip-build --artifact wheel`.
- [ ] Smoke-test the built source distribution in a clean virtual environment: `python scripts/install-smoke.py --skip-build --artifact sdist`.
- [ ] Inspect `dist/` for exactly one wheel and one source distribution.

## Tag and publish

- [ ] Commit release metadata updates.
- [ ] Tag the release: `git tag v0.3.0`.
- [ ] Push the tag: `git push origin v0.3.0`.
- [ ] Watch the `Release` workflow publish through PyPI trusted publishing.
- [ ] Verify the package page and install smoke test after publication.
