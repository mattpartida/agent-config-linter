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


def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise SystemExit(f"Command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout}")
    return completed.stdout


def newest_wheel() -> Path:
    wheels = sorted((ROOT / "dist").glob("agent_config_linter-*.whl"), key=lambda path: path.stat().st_mtime)
    if not wheels:
        raise SystemExit("No built wheel found under dist/. Run without --skip-build to build first.")
    return wheels[-1]


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
    parser.add_argument("--skip-build", action="store_true", help="Use the newest existing wheel in dist/ instead of running python -m build")
    args = parser.parse_args(argv)

    if not args.skip_build:
        shutil.rmtree(ROOT / "dist", ignore_errors=True)
        build_distribution()

    wheel = newest_wheel()
    with tempfile.TemporaryDirectory(prefix="agent-config-linter-smoke-") as tmpdir:
        venv = Path(tmpdir) / "venv"
        run([sys.executable, "-m", "venv", str(venv)])
        bin_dir = "Scripts" if os.name == "nt" else "bin"
        python = venv / bin_dir / "python"
        cli = venv / bin_dir / ("agent-config-lint.exe" if os.name == "nt" else "agent-config-lint")
        run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
        run([str(python), "-m", "pip", "install", str(wheel)])
        if cli.exists():
            output = run([str(cli), "--version"])
        else:
            output = run([str(python), "-m", "agent_config_linter.cli", "--version"])

    print(f"Installed wheel smoke passed: {wheel.name}")
    print(output.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
