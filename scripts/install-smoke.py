#!/usr/bin/env python3
"""Build and smoke-test an installed agent-config-linter wheel in a clean venv."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def isolated_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return env


def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env or isolated_env(),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise SystemExit(f"Command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout}")
    return completed.stdout


def newest_artifact(kind: str) -> Path:
    suffix = ".whl" if kind == "wheel" else ".tar.gz"
    artifacts = sorted((ROOT / "dist").glob(f"agent_config_linter-*{suffix}"), key=lambda path: path.stat().st_mtime)
    if not artifacts:
        raise SystemExit(f"No built {kind} found under dist/. Run without --skip-build to build first.")
    return artifacts[-1]


def build_distribution() -> None:
    """Build distributions, preferring python -m build and falling back to pip wheel."""

    build_check = subprocess.run(
        [sys.executable, "-m", "build", "--version"],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if build_check.returncode == 0:
        run([sys.executable, "-m", "build"])
        return

    print("python -m build is unavailable; using a temporary build environment")
    with tempfile.TemporaryDirectory(prefix="agent-config-linter-build-") as tmpdir:
        venv = Path(tmpdir) / "venv"
        run([sys.executable, "-m", "venv", str(venv)])
        bin_dir = "Scripts" if os.name == "nt" else "bin"
        python = venv / bin_dir / "python"
        run([str(python), "-m", "pip", "install", "--upgrade", "pip", "build"])
        run([str(python), "-m", "build"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="Use the newest existing artifact in dist/ instead of running python -m build")
    parser.add_argument(
        "--artifact",
        choices=["wheel", "sdist"],
        default="wheel",
        help="Distribution artifact to install during the smoke test",
    )
    args = parser.parse_args(argv)

    if not args.skip_build:
        shutil.rmtree(ROOT / "dist", ignore_errors=True)
        build_distribution()

    artifact = newest_artifact(args.artifact)
    with tempfile.TemporaryDirectory(prefix="agent-config-linter-smoke-") as tmpdir:
        venv = Path(tmpdir) / "venv"
        run([sys.executable, "-m", "venv", str(venv)])
        bin_dir = "Scripts" if os.name == "nt" else "bin"
        python = venv / bin_dir / "python"
        cli = venv / bin_dir / ("agent-config-lint.exe" if os.name == "nt" else "agent-config-lint")
        run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
        run([str(python), "-m", "pip", "install", str(artifact)])
        if cli.exists():
            output = run([str(cli), "--version"])
        else:
            output = run([str(python), "-m", "agent_config_linter.cli", "--version"])

    print(f"Installed {args.artifact} smoke passed: {artifact.name}")
    print(output.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
